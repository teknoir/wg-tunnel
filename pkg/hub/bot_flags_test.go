package hub

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// desiredEntry mirrors the bot fields only when the label and the name agree.

func botDeviceMeta(ns, name, label string, ann map[string]string) *metav1.PartialObjectMetadata {
	m := deviceMeta(ns, name, ann)
	if label != "" {
		m.Labels = map[string]string{api.LabelTeknoirBot: label}
	}
	return m
}

func TestDesiredEntryBotFields(t *testing.T) {
	both := map[string]string{
		api.AnnotationWireGuard:    "enabled",
		api.AnnotationBotCreatedBy: " Creator@Example.com ",
		api.AnnotationBotAccess:    api.BotAccessRead,
	}
	cases := []struct {
		name string
		m    *metav1.PartialObjectMetadata
		bot  string
		// creator and access are expected verbatim (raw annotations).
		creator, access string
	}{
		{"bot", botDeviceMeta("acme", "tb-scout", "scout", both), "scout", " Creator@Example.com ", api.BotAccessRead},
		{"label does not match the name", botDeviceMeta("acme", "tb-scout", "other", both), "", "", ""},
		{"plain device", botDeviceMeta("acme", "cam-1", "", both), "", "", ""},
		{"plain device without annotations", botDeviceMeta("acme", "cam-1", "", nil), "", "", ""},
		{"label without the prefix", botDeviceMeta("acme", "scout", "scout", both), "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := desiredEntry(c.m, time.Unix(0, 0))
			if !e.BotKnown {
				t.Fatal("BotKnown must always be set")
			}
			if e.Bot != c.bot || e.BotCreator != c.creator || e.BotAccess != c.access {
				t.Fatalf("bot %q creator %q access %q, want %q %q %q", e.Bot, e.BotCreator, e.BotAccess, c.bot, c.creator, c.access)
			}
		})
	}
}

func TestSameBotFields(t *testing.T) {
	base := func() *metav1.PartialObjectMetadata {
		return botDeviceMeta("acme", "tb-scout", "scout", map[string]string{
			api.AnnotationWireGuard:    "enabled",
			api.AnnotationBotCreatedBy: "a@example.com",
			api.AnnotationBotAccess:    api.BotAccessRead,
			api.AnnotationOrgPath:      "u1",
		})
	}
	cases := []struct {
		name   string
		change func(*metav1.PartialObjectMetadata)
		same   bool
	}{
		{"nothing", func(*metav1.PartialObjectMetadata) {}, true},
		{"unrelated annotation", func(m *metav1.PartialObjectMetadata) { m.Annotations["unrelated"] = "x" }, true},
		{"label", func(m *metav1.PartialObjectMetadata) { m.Labels[api.LabelTeknoirBot] = "other" }, false},
		{"label added", func(m *metav1.PartialObjectMetadata) { m.Labels = nil }, false},
		{"creator", func(m *metav1.PartialObjectMetadata) { m.Annotations[api.AnnotationBotCreatedBy] = "b@example.com" }, false},
		{"access", func(m *metav1.PartialObjectMetadata) { m.Annotations[api.AnnotationBotAccess] = api.BotAccessNone }, false},
		{"wireguard annotation", func(m *metav1.PartialObjectMetadata) { m.Annotations[api.AnnotationWireGuard] = "disabled" }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := base(), base()
			c.change(b)
			if got := sameBotFields(a, b); got != c.same {
				t.Fatalf("sameBotFields = %v, want %v", got, c.same)
			}
		})
	}
	if !sameBotFields(nil, nil) || sameBotFields(nil, base()) || sameBotFields(base(), nil) {
		t.Fatal("nil metadata must only equal nil")
	}
}

// patchLabel merge-patches a Device label, as teknoirbot-controller would.
func (r *watcherRig) patchLabel(ns, device, key, val string) {
	r.t.Helper()
	body := []byte(`{"metadata":{"labels":{"` + key + `":"` + val + `"}}}`)
	if _, err := r.mc.Resource(DeviceGVR).Namespace(ns).Patch(context.Background(), device,
		"application/merge-patch+json", body, metav1.PatchOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

func TestFlagsWatcherMirrorsTheBotFields(t *testing.T) {
	// The Device carries a ztna annotation too, so the watcher gives it a flags
	// ConfigMap like any tunnel device.
	r := newWatcherRig(t, botDeviceMeta("acme", "tb-scout", "scout", map[string]string{
		api.AnnotationWireGuard:    "enabled",
		api.AnnotationBotCreatedBy: " Creator@Example.com ",
		api.AnnotationBotAccess:    api.BotAccessRead,
	}))
	e, ok := r.flags("acme", "tb-scout")
	waitFor(t, "bot flags", func() bool { e, ok = r.flags("acme", "tb-scout"); return ok })
	if !e.BotKnown || e.Bot != "scout" || e.BotCreator != " Creator@Example.com " || e.BotAccess != api.BotAccessRead {
		t.Fatalf("entry %+v", e)
	}

	// A change of either annotation reaches the entry.
	r.patch("acme", "tb-scout", api.AnnotationBotAccess, api.BotAccessNone)
	waitFor(t, "access mirrored", func() bool { e, _ := r.flags("acme", "tb-scout"); return e.BotAccess == api.BotAccessNone })
	r.patch("acme", "tb-scout", api.AnnotationBotCreatedBy, "next@example.com")
	waitFor(t, "creator mirrored", func() bool { e, _ := r.flags("acme", "tb-scout"); return e.BotCreator == "next@example.com" })

	// A change of the label reaches the entry (and one that no longer matches
	// the name clears the bot fields).
	r.patchLabel("acme", "tb-scout", api.LabelTeknoirBot, "other")
	waitFor(t, "label change clears the bot", func() bool { e, _ := r.flags("acme", "tb-scout"); return e.BotKnown && e.Bot == "" })
	r.patchLabel("acme", "tb-scout", api.LabelTeknoirBot, "scout")
	waitFor(t, "label change restores the bot", func() bool { e, _ := r.flags("acme", "tb-scout"); return e.Bot == "scout" })

	// An unrelated annotation change alone writes nothing.
	before := r.writes.Load()
	r.patch("acme", "tb-scout", "unrelated", "x")
	time.Sleep(200 * time.Millisecond)
	if after := r.writes.Load(); after != before {
		t.Fatalf("%d needless ConfigMap writes", after-before)
	}
}

// A plain Device gets BotKnown and nothing else; a tb- Device whose label does
// not match its name is not a bot.
func TestFlagsWatcherBotKnownForPlainDevices(t *testing.T) {
	r := newWatcherRig(t,
		deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}),
		botDeviceMeta("acme", "tb-mislabeled", "other", map[string]string{
			api.AnnotationWireGuard:    "enabled",
			api.AnnotationBotCreatedBy: "a@example.com",
			api.AnnotationBotAccess:    api.BotAccessRead,
		}),
	)
	for _, dev := range []string{"cam-1", "tb-mislabeled"} {
		var e api.FlagsEntry
		var ok bool
		waitFor(t, dev+" flags", func() bool { e, ok = r.flags("acme", dev); return ok })
		if !e.BotKnown || e.Bot != "" || e.BotCreator != "" || e.BotAccess != "" {
			t.Fatalf("%s: %+v", dev, e)
		}
	}
}
