package hub

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ---- sticky void across epochs ----

func TestVoidedIdentityIsNeverReadmittedInALaterEpoch(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	k1 := *r.dev
	k1fp := k1.fingerprint()

	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	waitFor(t, "pin to be voided", func() bool { return r.ids.entry(testNS, testDevice).Voided })
	if got := r.ids.entry(testNS, testDevice); !slices.Equal(got.VoidedFingerprints, []string{k1fp}) {
		t.Fatalf("voided history %v, want [%s]", got.VoidedFingerprints, k1fp)
	}

	// An admin clears the flag and opens a new window (epoch 2).
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
	p := r.policy
	p.EnrollmentEpoch, p.EnrollmentGeneration, p.ApprovedFingerprint = "epoch-2", 2, ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)

	// The compromised key enrolls again: refused, recorded as a conflict, no pin.
	tok, req := k1.enrollRequest(t, r.clock.Now())
	st, body := r.enroll(tok, req)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	got := r.ids.entry(testNS, testDevice)
	if got.EnrollmentEpoch != "epoch-1" || !got.Voided || got.Conflicts != 1 {
		t.Fatalf("a refused voided key must change nothing but the conflict count: %+v", got)
	}
	// And it can neither open a session nor be approved into one.
	r.approve() // approval of K1's fingerprint, e.g. a stale annotation
	tok2, sreq, _ := k1.sessionRequest(t, r.clock.Now())
	st, body = r.post(api.DeviceSessionPath, tok2, sreq)
	if st == http.StatusCreated {
		t.Fatalf("voided identity got a session: %s", body)
	}

	// A fresh key enrolls; the history (and the conflict) is kept.
	r.dev.newIdentity(t)
	etok, ereq := r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(etok, ereq); st != http.StatusCreated {
		t.Fatalf("new key: %d %s", st, body)
	}
	got = r.ids.entry(testNS, testDevice)
	if got.EnrollmentEpoch != "epoch-2" || got.Voided || got.Fingerprint != r.dev.fingerprint() {
		t.Fatalf("new pin %+v", got)
	}
	if !slices.Equal(got.VoidedFingerprints, []string{k1fp}) || got.Conflicts != 1 {
		t.Fatalf("history lost: voided %v conflicts %d", got.VoidedFingerprints, got.Conflicts)
	}

	// The history survives a second round: K2 voided in epoch 2, epoch 3 opens;
	// K1 and K2 are both refused, K3 is fine.
	k2 := *r.dev
	r.approve()
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
	waitFor(t, "second void", func() bool { return r.ids.entry(testNS, testDevice).Voided })
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
	p = r.policy
	p.EnrollmentEpoch, p.EnrollmentGeneration, p.ApprovedFingerprint = "epoch-3", 3, ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)
	for name, c := range map[string]deviceCreds{"K1": k1, "K2": k2} {
		tok, req := c.enrollRequest(t, r.clock.Now())
		st, body := r.enroll(tok, req)
		if st != http.StatusConflict {
			t.Fatalf("%s: %d %s", name, st, body)
		}
	}
	r.dev.newIdentity(t)
	etok, ereq = r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(etok, ereq); st != http.StatusCreated {
		t.Fatalf("K3: %d %s", st, body)
	}
	got = r.ids.entry(testNS, testDevice)
	if !slices.Equal(got.VoidedFingerprints, []string{k1fp, k2.fingerprint()}) || got.Conflicts != 3 {
		t.Fatalf("history %v conflicts %d", got.VoidedFingerprints, got.Conflicts)
	}
}

func TestVoidedFingerprintHistoryIsBoundedAndDeduplicated(t *testing.T) {
	var list []string
	for i := range api.MaxVoidedFingerprints + 10 {
		list = appendVoided(list, fmt.Sprintf("fp-%d", i))
	}
	if len(list) != api.MaxVoidedFingerprints || list[len(list)-1] != fmt.Sprintf("fp-%d", api.MaxVoidedFingerprints+9) || list[0] != "fp-10" {
		t.Fatalf("not bounded to the newest: %d %v ... %v", len(list), list[0], list[len(list)-1])
	}
	again := appendVoided(list, "fp-20")
	if len(again) != api.MaxVoidedFingerprints || again[len(again)-1] != "fp-20" || slices.Index(again, "fp-20") != len(again)-1 {
		t.Fatalf("duplicate not moved to the newest slot")
	}
	if list[len(list)-1] == "fp-20" {
		t.Fatal("appendVoided modified its input")
	}
	e := VoidEntry(api.IdentityEntry{Fingerprint: "fp-x"}, "r", time.Unix(1, 0))
	e = VoidEntry(e, "r", time.Unix(2, 0))
	if !slices.Equal(e.VoidedFingerprints, []string{"fp-x"}) {
		t.Fatalf("voiding twice duplicated: %v", e.VoidedFingerprints)
	}
}

func TestK8sIdentityStoreKeepsVoidedHistoryAcrossEpochs(t *testing.T) {
	s := NewK8sIdentityStore(fake.NewSimpleClientset(), api.HubNamespace)
	ctx := context.Background()
	at := time.Unix(5, 0).UTC()

	if _, _, err := s.Pin(ctx, idEntryE(1, "epoch-1", "keyA")); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordConflict(ctx, "acme", "cam-1", at); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Void(ctx, "acme", "cam-1", api.RevokeCompromised, at); err != nil || !changed {
		t.Fatal(changed, err)
	}
	cur, _, _ := s.Get(ctx, "acme", "cam-1")
	if !slices.Equal(cur.VoidedFingerprints, []string{"SHA256:keyA"}) {
		t.Fatalf("void did not record the fingerprint: %+v", cur)
	}

	// The voided key cannot be pinned in the next epoch, nothing is written.
	if _, created, err := s.Pin(ctx, idEntryE(2, "epoch-2", "keyA")); err != ErrFingerprintVoided || created {
		t.Fatalf("voided key: created=%v err=%v", created, err)
	}
	if got, _, _ := s.Get(ctx, "acme", "cam-1"); got.EnrollmentEpoch != "epoch-1" || !got.Voided {
		t.Fatalf("a refused pin must not touch the store: %+v", got)
	}
	// A new key replaces the pin and inherits the history and the conflicts.
	cur, created, err := s.Pin(ctx, idEntryE(2, "epoch-2", "keyB"))
	if err != nil || !created {
		t.Fatal(created, err)
	}
	if cur.Voided || !slices.Equal(cur.VoidedFingerprints, []string{"SHA256:keyA"}) || cur.Conflicts != 1 || !cur.LastConflictAt.Equal(at) {
		t.Fatalf("history not carried over: %+v", cur)
	}
	// The same epoch's pin stays, whatever key asks.
	if cur, created, _ := s.Pin(ctx, idEntryE(2, "epoch-2", "keyC")); created || cur.IdentityPublicKey != "keyB" {
		t.Fatalf("first wins per epoch: %+v %v", cur, created)
	}
	// A pin voided before the history existed still counts.
	legacy := idEntryE(3, "epoch-3", "keyL")
	legacy.Voided = true
	if _, _, err := s.Pin(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Pin(ctx, idEntryE(4, "epoch-4", "keyL")); err != ErrFingerprintVoided {
		t.Fatalf("legacy voided pin: %v", err)
	}
	cur, _, err = s.Pin(ctx, idEntryE(4, "epoch-4", "keyM"))
	if err != nil || !slices.Contains(cur.VoidedFingerprints, "SHA256:keyL") || !slices.Contains(cur.VoidedFingerprints, "SHA256:keyA") {
		t.Fatalf("legacy voided fingerprint not carried over: %+v %v", cur, err)
	}
}

// ---- client IP trust ----

func TestClientIPHeaderIgnoresNonPublicAddresses(t *testing.T) {
	h := &Hub{cfg: Config{ClientIPHeader: testIPHeader}}
	for _, ip := range []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.2.166",
		"100.64.0.1", "100.127.255.254", "169.254.1.1", "fe80::1", "fd00::1",
		"0.0.0.0", "::", "224.0.0.1", "::ffff:10.0.0.1", "::ffff:127.0.0.1",
	} {
		r, _ := http.NewRequest(http.MethodPost, "http://x/", nil)
		r.RemoteAddr = "203.0.113.77:1234"
		r.Header.Set(testIPHeader, ip)
		got, trusted := h.clientIP(r)
		if trusted || got != "203.0.113.77" {
			t.Errorf("%s: trusted=%v ip=%s; a non-public address must not be a limiter key", ip, trusted, got)
		}
	}
	for _, ip := range []string{"198.51.100.1", "203.0.113.5", "100.63.255.255", "100.128.0.1", "2001:db8::1", "::ffff:198.51.100.2"} {
		r, _ := http.NewRequest(http.MethodPost, "http://x/", nil)
		r.RemoteAddr = "10.0.0.1:1"
		r.Header.Set(testIPHeader, ip)
		got, trusted := h.clientIP(r)
		want := netip.MustParseAddr(ip).Unmap().String()
		if !trusted || got != want {
			t.Errorf("%s: trusted=%v ip=%s", ip, trusted, got)
		}
	}
}

func TestPrivateClientIPHeaderFallsBackToTheGlobalBackstop(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.IPRate = 0.001
		c.IPBurst = 1
		c.GlobalRate = 0.001
		c.GlobalBurst = 5
		c.ClientIPHeader = testIPHeader
	})
	var perIP, global int
	for range 8 {
		// servicelb shows the node address for every caller.
		_, e := r.junkClientRequest(r.srv.URL, "10.42.0.1")
		if e.Reason == api.ReasonRateLimited {
			global++
		} else {
			perIP++
		}
	}
	if perIP != 5 || global != 3 {
		t.Fatalf("passed %d, limited %d; want the global burst (5/3), not the per-IP burst 1", perIP, global)
	}
}
