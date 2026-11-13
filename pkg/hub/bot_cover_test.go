package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// The bot cover rule: a TeknoirBot (Device botDevice) is opened with its
// creator's rights, so only its creator may open it, plus the teamspace admins
// while its access is read or none.

const (
	botNS         = "acme"
	botDevice     = "tb-scout"
	botCreator    = "creator@example.com"
	botAdmin      = "admin@example.com"
	botOther      = "other@example.com"
	botMsgRead    = "only this TeknoirBot's creator and teamspace admins can open it"
	botMsgOnly    = "this TeknoirBot acts as its creator; only its creator can open it"
	botMsgUnknown = "this TeknoirBot's access is not known yet"
)

// botEntry is the flags entry of botDevice, as the flags watcher writes it.
func botEntry(access, creator string) *api.FlagsEntry {
	return &api.FlagsEntry{
		Device: botDevice, Namespace: botNS, Exists: true,
		BotKnown: true, Bot: "scout", BotCreator: creator, BotAccess: access,
	}
}

func TestCanOpenBotCover(t *testing.T) {
	cases := []struct {
		name string
		// entry is the device's flags entry; nil means no entry at all.
		entry *api.FlagsEntry
		email string
		// device overrides botDevice.
		device string
		// allow is the expected canOpen result.
		allow bool
		// msg, when set, must be contained in the denial message.
		msg string
		// adminCalls is the expected number of CanAdmin calls.
		adminCalls int
		// decision is the expected wghub_bot_cover_total label that moved.
		decision string
	}{
		{"creator access: creator", botEntry(api.BotAccessCreator, botCreator), botCreator, "", true, "", 0, "creator"},
		{"creator access: admin", botEntry(api.BotAccessCreator, botCreator), botAdmin, "", false, botMsgOnly, 0, "deny"},
		{"creator access: other", botEntry(api.BotAccessCreator, botCreator), botOther, "", false, botMsgOnly, 0, "deny"},
		{"creator access: empty creator", botEntry(api.BotAccessCreator, ""), botCreator, "", false, botMsgOnly, 0, "deny"},
		{"read access: creator", botEntry(api.BotAccessRead, botCreator), botCreator, "", true, "", 0, "creator"},
		{"read access: admin", botEntry(api.BotAccessRead, botCreator), botAdmin, "", true, "", 1, "admin"},
		{"read access: other", botEntry(api.BotAccessRead, botCreator), botOther, "", false, botMsgRead, 1, "deny"},
		{"read access: empty creator, admin", botEntry(api.BotAccessRead, ""), botAdmin, "", true, "", 1, "admin"},
		{"read access: empty creator, other", botEntry(api.BotAccessRead, ""), botOther, "", false, botMsgRead, 1, "deny"},
		{"none access: creator", botEntry(api.BotAccessNone, botCreator), botCreator, "", true, "", 0, "creator"},
		{"none access: admin", botEntry(api.BotAccessNone, botCreator), botAdmin, "", true, "", 1, "admin"},
		{"none access: other", botEntry(api.BotAccessNone, botCreator), botOther, "", false, botMsgRead, 1, "deny"},
		{"unknown access: creator", botEntry("weird", botCreator), botCreator, "", true, "", 0, "creator"},
		{"unknown access: admin", botEntry("weird", botCreator), botAdmin, "", false, botMsgOnly, 0, "deny"},
		{"unknown access: other", botEntry("weird", botCreator), botOther, "", false, botMsgOnly, 0, "deny"},
		{"missing access: creator", botEntry("", botCreator), botCreator, "", true, "", 0, "creator"},
		{"missing access: admin", botEntry("", botCreator), botAdmin, "", false, botMsgOnly, 0, "deny"},
		{"missing access: other", botEntry("", botCreator), botOther, "", false, botMsgOnly, 0, "deny"},
		{"tb- without bot label: other", &api.FlagsEntry{Device: botDevice, Namespace: botNS, Exists: true, BotKnown: true}, botOther, "", false, botMsgUnknown, 0, "unknown"},
		{"tb- with a mismatched label: creator", &api.FlagsEntry{Device: botDevice, Namespace: botNS, Exists: true, BotKnown: true, Bot: "other", BotCreator: botCreator, BotAccess: api.BotAccessCreator}, botCreator, "", false, botMsgUnknown, 0, "unknown"},
		{"no entry: creator", nil, botCreator, "", false, botMsgUnknown, 0, "unknown"},
		{"no entry: admin", nil, botAdmin, "", false, botMsgUnknown, 0, "unknown"},
		{"no entry: other", nil, botOther, "", false, botMsgUnknown, 0, "unknown"},
		{"older watcher: creator", &api.FlagsEntry{Device: botDevice, Namespace: botNS, Exists: true}, botCreator, "", false, botMsgUnknown, 0, "unknown"},
		{"non-bot device: member", nil, botOther, "cam-1", true, "", 0, ""},
		{"non-bot device: known bot fields", &api.FlagsEntry{Device: "cam-1", Namespace: botNS, Exists: true, BotKnown: true}, botCreator, "cam-1", true, "", 0, ""},
	}
	for _, mode := range []string{OrgGateOff, OrgGateAudit, OrgGateEnforce} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				device := c.device
				if device == "" {
					device = botDevice
				}
				a := newFakeAuthz()
				for _, e := range []string{botCreator, botAdmin, botOther} {
					a.set(e, botNS, true)
				}
				a.setAdmin(botAdmin, botNS, true)
				flags := newFakeFlags()
				if c.entry != nil {
					e := *c.entry
					if c.device != "" { // a non-bot device keeps its own name
						e.Device = c.device
					}
					flags.SetEntry(e)
				}
				h := gateHub(mode, a, newFakeOrg(), flags)
				den, err := h.canOpen(context.Background(), c.email, botNS, device)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if allowed := den == nil; allowed != c.allow {
					t.Fatalf("allow=%v, want %v (denial %+v)", allowed, c.allow, den)
				}
				if c.msg != "" && (den == nil || !strings.Contains(den.msg, c.msg)) {
					t.Fatalf("denial message %+v, want it to contain %q", den, c.msg)
				}
				if n := a.adminCallsMade(); n != c.adminCalls {
					t.Fatalf("CanAdmin called %d times, want %d", n, c.adminCalls)
				}
				for _, d := range []string{"creator", "admin", "deny", "unknown"} {
					want := 0.0
					if d == c.decision {
						want = 1
					}
					if got := counterValue(t, h.met.botCover, d); got != want {
						t.Fatalf("bot cover %q = %v, want %v", d, got, want)
					}
				}
			})
		}
	}
}

// The creator annotation is matched case-insensitively and without surrounding
// spaces; the subject email is already lowercase.
func TestCanOpenBotCoverNormalizesCreator(t *testing.T) {
	flags := newFakeFlags()
	flags.SetEntry(*botEntry(api.BotAccessCreator, " Creator@Example.COM "))
	a := newFakeAuthz()
	a.set(botCreator, botNS, true)
	h := gateHub(OrgGateEnforce, a, newFakeOrg(), flags)
	den, err := h.canOpen(context.Background(), botCreator, botNS, botDevice)
	if err != nil || den != nil {
		t.Fatalf("creator not matched: %v %+v", err, den)
	}
}

// The creator never waits on the admin SAR, and an admin SAR error fails
// closed (the error is returned, not cached as a deny).
func TestCanOpenBotCoverAdminErrors(t *testing.T) {
	a := newFakeAuthz()
	for _, e := range []string{botCreator, botOther} {
		a.set(e, botNS, true)
	}
	a.adminErr = errors.New("api down")
	flags := newFakeFlags()
	flags.SetEntry(*botEntry(api.BotAccessRead, botCreator))
	h := gateHub(OrgGateEnforce, a, newFakeOrg(), flags)
	ctx := context.Background()

	if den, err := h.canOpen(ctx, botOther, botNS, botDevice); err == nil || den != nil {
		t.Fatalf("admin SAR error must be returned: %v %+v", err, den)
	}
	if n := a.adminCallsMade(); n != 1 {
		t.Fatalf("CanAdmin called %d times, want 1", n)
	}
	if den, err := h.canOpen(ctx, botCreator, botNS, botDevice); err != nil || den != nil {
		t.Fatalf("the creator must not depend on the admin SAR: %v %+v", err, den)
	}
	if n := a.adminCallsMade(); n != 1 {
		t.Fatalf("the creator called CanAdmin: %d calls", n)
	}
}

// The teamspace SAR comes first: without it the cover rule (and its SAR) is
// never reached.
func TestCanOpenBotCoverAfterTeamspaceSAR(t *testing.T) {
	a := newFakeAuthz() // no CanExec grant at all
	flags := newFakeFlags()
	flags.SetEntry(*botEntry(api.BotAccessRead, botCreator))
	h := gateHub(OrgGateEnforce, a, newFakeOrg(), flags)
	den, err := h.canOpen(context.Background(), botOther, botNS, botDevice)
	if err != nil || den == nil || den.msg != "no access to this teamspace" {
		t.Fatalf("%v %+v", err, den)
	}
	if n := a.adminCallsMade(); n != 0 {
		t.Fatalf("the cover rule ran before the teamspace SAR: %d admin calls", n)
	}
	if got := counterValue(t, h.met.botCover, "deny"); got != 0 {
		t.Fatalf("cover rule counted a decision: %v", got)
	}
}

// Only ASCII case is folded: a creator annotation that is no valid ASCII email
// (here with the Kelvin sign, which Unicode folds to "k") matches nobody.
func TestCanOpenBotCoverCreatorIsASCII(t *testing.T) {
	const kim = "kim@example.com"
	flags := newFakeFlags()
	flags.SetEntry(*botEntry(api.BotAccessCreator, "\u212Aim@example.com"))
	a := newFakeAuthz()
	a.set(kim, botNS, true)
	h := gateHub(OrgGateEnforce, a, newFakeOrg(), flags)
	den, err := h.canOpen(context.Background(), kim, botNS, botDevice)
	if err != nil || den == nil || den.msg != botMsgOnly {
		t.Fatalf("a non-ASCII creator must match nobody: %v %+v", err, den)
	}
	for raw, want := range map[string]string{
		" Creator@Example.COM ": botCreator,
		"":                      "",
		"not an email":          "",
		"\u212Aim@example.com":  "",
	} {
		if got := normBotCreator(raw); got != want {
			t.Errorf("normBotCreator(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The cover rule comes on top of the org gate: a creator who passes it is
// still refused by the gate in enforce when the bot is outside the creator's
// units, and only logged (would_deny) in audit.
func TestCanOpenBotCoverWithOrgGate(t *testing.T) {
	ctx := context.Background()
	setup := func() (*fakeOrg, *fakeFlags) {
		org, flags := newFakeOrg(), newFakeFlags()
		org.set(orgDocOf(botNS, botCreator, "u1"))
		e := *botEntry(api.BotAccessCreator, botCreator)
		e.OrgKnown = true
		e.OrgPath = "x/y"
		flags.SetEntry(e)
		return org, flags
	}
	t.Run("enforce refuses out of scope", func(t *testing.T) {
		org, flags := setup()
		h := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags)
		den, err := h.canOpen(ctx, botCreator, botNS, botDevice)
		if err != nil || den == nil || den.msg != orgMsgScope {
			t.Fatalf("%v %+v", err, den)
		}
		if got := counterValue(t, h.met.botCover, "creator"); got != 1 {
			t.Fatalf("the cover rule must have allowed the creator first: %v", got)
		}
	})
	t.Run("audit allows and counts would_deny", func(t *testing.T) {
		org, flags := setup()
		h := gateHub(OrgGateAudit, allowAllSAR{}, org, flags)
		if den, err := h.canOpen(ctx, botCreator, botNS, botDevice); den != nil || err != nil {
			t.Fatalf("%+v %v", den, err)
		}
		if n := counterValue(t, h.met.orgGate, "audit", "would_deny", orgReasonScope); n != 1 {
			t.Fatalf("would_deny count %v", n)
		}
	})
}
