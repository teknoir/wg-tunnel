package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Identity pins are kept when a Device is deleted, by design: the entry is the
// device name's enrollment and revocation history (generation seed, voided
// fingerprints, distrusted device keys). These tests pin down what that means
// for the two cases an operator meets:
//
//   - a Device deleted and created again under the same name (a NEW enrollment
//     epoch): the old pin never blocks it and its conflict count is not
//     inherited;
//   - the SAME Device bootstrapped again with a wiped agent state directory
//     (the SAME epoch, a new identity key): what the hub answers and what
//     brings the device back without anybody logging in to it.

// liveIdentityFunc returns a reader of the hub's own record of the pin, as
// Backstage gets it from the status API. Call it right after newRig.
func (r *rig) liveIdentityFunc() func() *api.LiveIdentity {
	r.t.Helper()
	r.h.deps.Status, r.h.cfg.BackstageSA = &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	r.t.Cleanup(srv.Close)
	return func() *api.LiveIdentity {
		r.t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+api.StatusDevicePath+testNS+"/"+testDevice, nil)
		req.Header.Set("Authorization", "Bearer "+backstageToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			r.t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return decodeStatus(r.t, b).Identity
	}
}

// deleteDevice is what the hub sees of a deleted Device: device-controller's
// finalizer removed the policy and the flags watcher the flags entry. Nothing
// removes the identity pin.
func (r *rig) deleteDevice() {
	r.t.Helper()
	r.pol.Delete(testNS, testDevice)
	r.flags.Delete(testNS, testDevice)
	waitFor(r.t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
}

// recreateDevice is what the hub sees of a Device created again under the same
// name with the credentials creds: device-controller seeds the generation from
// the pin that stayed (one above it), draws a new random epoch and opens a
// window. No device key is trusted and nothing is approved yet.
func (r *rig) recreateDevice(creds *deviceCreds, epoch string) {
	r.t.Helper()
	r.dev = creds
	r.setPolicy(api.PolicyEntry{
		Device: testDevice, Namespace: testNS, State: api.StateActive, RSAPublicCert: creds.certPEM,
		AllowedPorts: []int{22}, EnrollmentGeneration: r.ids.entry(testNS, testDevice).EnrollmentGeneration + 1,
		EnrollmentEpoch: epoch, EnrollUntil: r.clock.Now().Add(15 * time.Minute),
	})
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
}

func (r *rig) sessionOf(c *deviceCreds) (int, []byte) {
	r.t.Helper()
	tok, req, _ := c.sessionRequest(r.t, r.clock.Now())
	return r.post(api.DeviceSessionPath, tok, req)
}

// predecessor enrolls the rig's device with the trusted device key dk, gives
// it a live session and two enrollment conflicts (somebody else holding the
// device's RSA key tried twice).
func predecessor(t *testing.T) (r *rig, dk testHostKey, live func() *api.LiveIdentity) {
	t.Helper()
	r = newRig(t)
	live = r.liveIdentityFunc()
	dk = newTestHostKey(t, "ed25519")
	r.trust(dk)
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
		t.Fatalf("enroll: %d %s", st, body)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
	squatter := r.otherDevice(t)
	st, body := r.enrollWith(squatter, nil)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	r.clock.Advance(time.Second)
	st, body = r.attestedEnroll(squatter, newTestHostKey(t, "ed25519"))
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	if got := r.ids.entry(testNS, testDevice); got.Conflicts != 2 || !got.LastConflictAt.Equal(r.clock.Now()) {
		t.Fatalf("predecessor conflicts %d at %v", got.Conflicts, got.LastConflictAt)
	}
	if id := live(); id == nil || id.Conflicts != 2 || !id.Current {
		t.Fatalf("predecessor live identity %+v", id)
	}
	return r, dk, live
}

// wantOldPin asserts the pin is still the predecessor's, with want conflicts.
func (r *rig) wantOldPin(old *deviceCreds, conflicts int) {
	r.t.Helper()
	got := r.ids.entry(testNS, testDevice)
	if got.EnrollmentEpoch != "epoch-1" || got.EnrollmentGeneration != 1 || got.Fingerprint != old.fingerprint() || got.Conflicts != conflicts {
		r.t.Fatalf("the old pin must stay as it was (conflicts %d): %+v", conflicts, got)
	}
}

// wantFreshPin asserts the pin is c's of the given epoch and generation 2,
// without any conflict history.
func (r *rig) wantFreshPin(c *deviceCreds, epoch string) api.IdentityEntry {
	r.t.Helper()
	got := r.ids.entry(testNS, testDevice)
	if got.EnrollmentEpoch != epoch || got.EnrollmentGeneration != 2 || got.Fingerprint != c.fingerprint() || got.Voided {
		r.t.Fatalf("pin %+v", got)
	}
	if got.Conflicts != 0 || !got.LastConflictAt.IsZero() || got.Replacements != 0 {
		r.t.Fatalf("a new epoch must start without the predecessor's counts: %+v", got)
	}
	return got
}

// A Device deleted and created again under the same name gets a new epoch. The
// pin its predecessor left behind does not block it, and the conflicts counted
// against the predecessor are not shown for it.
func TestRecreatedDeviceOfTheSameNameIsNotBlockedByTheOldPin(t *testing.T) {
	t.Run("it enrolls inside the window and starts at zero conflicts", func(t *testing.T) {
		r, _, live := predecessor(t)
		old := r.dev
		r.deleteDevice()
		// The pin stays after the deletion (history of the name).
		r.wantOldPin(old, 2)

		// A new Device has new keys.
		r.recreateDevice(newDeviceCreds(t), "epoch-recreated")
		// While nothing is pinned for the new epoch the status marks the old pin
		// as not current; device-controller shows nothing of it.
		if id := live(); id == nil || id.Current {
			t.Fatalf("the predecessor's pin must not be current: %+v", id)
		}
		// The predecessor's hardware is out: its identity is told to enroll
		// again, and its RSA key no longer opens an enrollment.
		st, body := r.sessionOf(old)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)
		tok, req := old.enrollRequest(t, r.clock.Now())
		st, body = r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		r.wantOldPin(old, 2)

		if st, body := r.enrollWith(r.dev, nil); st != http.StatusCreated {
			t.Fatalf("new device inside the window: %d %s", st, body)
		}
		r.wantFreshPin(r.dev, "epoch-recreated")
		if id := live(); id == nil || !id.Current || id.Conflicts != 0 || id.Fingerprint != r.dev.fingerprint() {
			t.Fatalf("live identity of the new device %+v", id)
		}
		st, body = r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
		r.approve()
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session of the new device: %d %s", st, body)
		}
		st, body = r.sessionOf(old)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})

	t.Run("outside the window only the trusted device key gets it in", func(t *testing.T) {
		r, _, _ := predecessor(t)
		old := r.dev
		r.deleteDevice()
		r.recreateDevice(newDeviceCreds(t), "epoch-recreated")
		r.closeWindow()

		// No device key trusted: the window decides.
		st, body := r.enrollWith(r.dev, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)

		dk2 := newTestHostKey(t, "ed25519")
		r.trust(dk2)
		st, body = r.enrollWith(r.dev, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		st, body = r.attestedEnroll(r.dev, newTestHostKey(t, "ed25519"))
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
		// None of this touched the old pin, not even its conflict count.
		r.wantOldPin(old, 2)

		if st, body := r.attestedEnroll(r.dev, dk2); st != http.StatusCreated {
			t.Fatalf("attested by the trusted device key, outside the window: %d %s", st, body)
		}
		if got := r.wantFreshPin(r.dev, "epoch-recreated"); got.AttestedHostKey != dk2.fp || got.ActivatedBy != api.ActivatedByDeviceKey {
			t.Fatalf("pin %+v", got)
		}
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session: %d %s", st, body)
		}
	})

	t.Run("an attestation made for the old epoch is refused", func(t *testing.T) {
		// The worst case for the old epoch: the Device was created again from a
		// saved copy, so the RSA key and the device key are the predecessor's.
		r, dk, _ := predecessor(t)
		old := *r.dev
		stale := signAttestation(t, dk, r.dev, r.challengeOK(r.dev)) // nonce of epoch 1, never used
		r.deleteDevice()
		r.recreateDevice(r.dev, "epoch-recreated")
		r.trust(dk)
		r.closeWindow()

		st, body := r.enrollWith(r.dev, attestCaps, stale)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		// A nonce of the new epoch under a statement for the old one.
		ch := r.challengeOK(r.dev)
		st, body = r.enrollWith(r.dev, attestCaps, signStatement(t, dk, testNS, testDevice, r.dev.fingerprint(), "epoch-1", 1, ch.Nonce))
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		r.wantOldPin(&old, 2)

		// The agent's own way back: its session is answered reenroll, it
		// generates a new identity and attests it for the new epoch.
		st, body = r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)
		r.dev.newIdentity(t)
		if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
			t.Fatalf("attested for the new epoch: %d %s", st, body)
		}
		r.wantFreshPin(r.dev, "epoch-recreated")
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session: %d %s", st, body)
		}
	})

	t.Run("the void history and the distrusted keys are inherited, the conflicts are not", func(t *testing.T) {
		r, dk, _ := predecessor(t)
		old := *r.dev
		r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		waitFor(t, "pin to be voided", func() bool { return r.ids.entry(testNS, testDevice).Voided })
		r.deleteDevice()
		// Created again from a saved copy (same RSA key), and an admin turned
		// Tunneling on (device-controller's revocation tombstone keeps it off
		// until then).
		r.recreateDevice(r.dev, "epoch-recreated")

		// The voided identity is refused in the new window as in any other.
		// That attempt is counted on the predecessor's pin and ends with it.
		st, body := r.enrollWith(&old, nil)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
		if got := r.ids.entry(testNS, testDevice); got.EnrollmentEpoch != "epoch-1" || !got.Voided || got.Conflicts != 3 {
			t.Fatalf("old pin %+v", got)
		}

		r.dev.newIdentity(t)
		if st, body := r.enrollWith(r.dev, nil); st != http.StatusCreated {
			t.Fatalf("new identity: %d %s", st, body)
		}
		got := r.wantFreshPin(r.dev, "epoch-recreated")
		if !slices.Equal(got.VoidedFingerprints, []string{old.fingerprint()}) || !slices.Equal(got.DistrustedKeys, []string{dk.fp}) {
			t.Fatalf("history lost: voided %v distrusted %v", got.VoidedFingerprints, got.DistrustedKeys)
		}

		// From here on the count is that of the new epoch.
		st, body = r.enrollWith(&old, nil)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
		if got := r.ids.entry(testNS, testDevice); got.Conflicts != 1 || got.Fingerprint != r.dev.fingerprint() {
			t.Fatalf("pin %+v", got)
		}
		// And the key that attested the flagged pin stays distrusted.
		r.trust(dk)
		another := r.otherDevice(t)
		st, body = r.attestedEnroll(another, dk)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
}

// ReplacePin is the one place a pin of another epoch or generation is
// replaced: the conflict count stays with the pin it was counted against.
func TestReplacePinStartsTheConflictCountAtZero(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	cur := api.IdentityEntry{
		Fingerprint: "fp1", EnrollmentGeneration: 1, EnrollmentEpoch: "e1",
		Conflicts: 7, LastConflictAt: at, Replacements: 2, LastReplacedAt: at, LastReplacedFingerprint: "fp0",
		VoidedFingerprints: []string{"fp0"}, DistrustedKeys: []string{"SHA256:a"},
	}
	for name, entry := range map[string]api.IdentityEntry{
		"new epoch and generation":       {Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e2"},
		"new epoch, generation restarts": {Fingerprint: "fp2", EnrollmentGeneration: 1, EnrollmentEpoch: "e2"},
		"new generation, same epoch":     {Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e1"},
		"same identity key, new epoch":   {Fingerprint: "fp1", EnrollmentGeneration: 2, EnrollmentEpoch: "e2"},
	} {
		next, same, err := ReplacePin(&cur, entry)
		if err != nil || same {
			t.Fatalf("%s: same=%v err=%v", name, same, err)
		}
		if next.Conflicts != 0 || !next.LastConflictAt.IsZero() {
			t.Errorf("%s: conflicts %d at %v carried over", name, next.Conflicts, next.LastConflictAt)
		}
		if next.Replacements != 0 || !next.LastReplacedAt.IsZero() || next.LastReplacedFingerprint != "" {
			t.Errorf("%s: replacements carried over: %+v", name, next)
		}
		if !slices.Equal(next.VoidedFingerprints, []string{"fp0"}) || !slices.Equal(next.DistrustedKeys, []string{"SHA256:a"}) {
			t.Errorf("%s: history lost: %+v", name, next)
		}
		if next.Fingerprint != entry.Fingerprint || next.EnrollmentEpoch != entry.EnrollmentEpoch || next.EnrollmentGeneration != entry.EnrollmentGeneration {
			t.Errorf("%s: not the new entry: %+v", name, next)
		}
	}
	// The pin of the same epoch and generation stays, count included.
	if _, same, err := ReplacePin(&cur, api.IdentityEntry{Fingerprint: "fp2", EnrollmentGeneration: 1, EnrollmentEpoch: "e1"}); !same || err != nil {
		t.Fatalf("same epoch: same=%v err=%v", same, err)
	}
	if cur.Conflicts != 7 || !cur.LastConflictAt.Equal(at) {
		t.Fatalf("ReplacePin changed its input: %+v", cur)
	}
	// What the entry itself brings is kept (nothing in the hub sets it today).
	next, _, _ := ReplacePin(&cur, api.IdentityEntry{Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e2", Conflicts: 1, LastConflictAt: at})
	if next.Conflicts != 1 || !next.LastConflictAt.Equal(at) {
		t.Fatalf("the entry's own count: %+v", next)
	}
	// Nothing stored: the entry as it is.
	if next, same, err := ReplacePin(nil, cur); err != nil || same || next.Conflicts != 7 {
		t.Fatalf("no pin yet: %+v %v %v", next, same, err)
	}
}

// The same Device (same policy epoch, same RSA key) is bootstrapped again and
// the agent's state directory (/var/lib/teknoir/wg-agent) was wiped: the agent
// comes back with a NEW identity key and meets the live pin of its old one.
// First wins per epoch, so the hub does not take the new identity on the RSA
// key alone (that key is widely exposed). What it answers, and what brings the
// device back, depends on the device key. None of the ways back needs a login
// on the device: they need the hub, and for a delivered key the device's MQTT
// config (device-controller seals the key into it; not part of these tests).
func TestRebootstrapOfTheSameDeviceWithAWipedIdentityDir(t *testing.T) {
	t.Run("device key still held: back by itself once the old session is gone", func(t *testing.T) {
		r := newRig(t)
		dk := newTestHostKey(t, "ed25519")
		r.trust(dk)
		if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		old := r.dev.fingerprint()
		wiped := r.otherDevice(t)

		// The hub does not know the new key: one answer for every stranger.
		st, body := r.sessionOf(wiped)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		// While the hub still holds the session of the old identity (it lives
		// up to SessionTTL, 3 minutes, without a renewal) the new one is a conflict.
		st, body = r.attestedEnroll(wiped, dk)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != old || got.Conflicts != 1 {
			t.Fatalf("pin %+v", got)
		}

		// The agent keeps trying. The dead session expires, and the device key
		// proves it is the same device: the pin is replaced without an admin.
		r.clock.Advance(r.h.cfg.SessionTTL + time.Second)
		r.h.reap()
		if d, _ := r.h.sessionCounts(); d != 0 {
			t.Fatal("the session of the wiped agent must expire")
		}
		if st, body := r.attestedEnroll(wiped, dk); st != http.StatusCreated {
			t.Fatalf("replacement: %d %s", st, body)
		}
		got := r.ids.entry(testNS, testDevice)
		if got.Fingerprint != wiped.fingerprint() || got.EnrollmentEpoch != "epoch-1" || got.Replacements != 1 ||
			got.ActivatedBy != api.ActivatedByDeviceKey || !slices.Contains(got.VoidedFingerprints, old) {
			t.Fatalf("pin %+v", got)
		}
		// Same epoch: the conflict counted above stays.
		if got.Conflicts != 1 {
			t.Fatalf("conflicts %d", got.Conflicts)
		}
		r.dev = wiped
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session of the new identity: %d %s", st, body)
		}
	})

	t.Run("device key trusted but lost with the state: attest_required until a rotated key arrives", func(t *testing.T) {
		r := newRig(t)
		dk := newTestHostKey(t, "ed25519")
		r.trust(dk)
		if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		old := r.dev.fingerprint()
		// The delivered device key was in the wiped directory too.
		wiped := r.otherDevice(t)

		st, body := r.sessionOf(wiped)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		st, body = r.enrollWith(wiped, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		st, body = r.enrollWith(wiped, attestCaps)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		// The pin is untouched; the console shows the attempts as conflicts.
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != old || got.Conflicts != 2 {
			t.Fatalf("pin %+v", got)
		}

		// Admin action "Rotate device key": device-controller trusts a new key
		// in the policy and delivers it sealed in the device's MQTT config. The
		// agent attests with it and displaces the pin of the lost identity,
		// which was attested by the key that is no longer trusted.
		dk2 := newTestHostKey(t, "ed25519")
		r.trust(dk2)
		if st, body := r.attestedEnroll(wiped, dk2); st != http.StatusCreated {
			t.Fatalf("attested by the rotated key: %d %s", st, body)
		}
		got := r.ids.entry(testNS, testDevice)
		if got.Fingerprint != wiped.fingerprint() || got.EnrollmentEpoch != "epoch-1" || got.AttestedHostKey != dk2.fp ||
			got.ActivatedBy != api.ActivatedByDeviceKey || !slices.Contains(got.VoidedFingerprints, old) {
			t.Fatalf("pin %+v", got)
		}
		r.dev = wiped
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session of the new identity: %d %s", st, body)
		}
	})

	t.Run("device key trusted but lost with the state: Reset enrollment alone does not help", func(t *testing.T) {
		r := newRig(t)
		dk := newTestHostKey(t, "ed25519")
		r.trust(dk)
		if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		old := r.dev.fingerprint()
		wiped := r.otherDevice(t)

		// Admin action "Reset enrollment": a new epoch and an open window. The
		// policy still trusts a device key the agent does not hold, and an
		// unattested enrollment is refused before the window is looked at.
		p := r.policy
		p.EnrollmentEpoch, p.EnrollmentGeneration = "epoch-2", 2
		p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
		r.setPolicy(p)
		st, body := r.enrollWith(wiped, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != old || got.EnrollmentEpoch != "epoch-1" {
			t.Fatalf("pin %+v", got)
		}
		// It takes the rotated key here as well.
		dk2 := newTestHostKey(t, "ed25519")
		r.trust(dk2)
		if st, body := r.attestedEnroll(wiped, dk2); st != http.StatusCreated {
			t.Fatalf("attested by the rotated key: %d %s", st, body)
		}
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != wiped.fingerprint() || got.EnrollmentEpoch != "epoch-2" || got.Conflicts != 0 {
			t.Fatalf("pin %+v", got)
		}
	})

	t.Run("no device key (manual approval): enroll_conflict until Reset enrollment", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK() // enrolled, approved by an admin, online
		old := r.dev.fingerprint()
		wiped := r.otherDevice(t)

		st, body := r.sessionOf(wiped)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		st, body = r.enrollWith(wiped, nil)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
		// Also once the old session is gone: nothing but the RSA key speaks for
		// the new identity.
		r.clock.Advance(r.h.cfg.SessionTTL + time.Second)
		r.h.reap()
		st, body = r.enrollWith(wiped, nil)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != old || got.Conflicts != 2 {
			t.Fatalf("pin %+v", got)
		}

		// Admin action "Reset enrollment": new epoch, open window, the approval
		// is dropped. The agent, still retrying, enrolls; the admin approves the
		// new fingerprint. The conflicts above ended with the old epoch.
		p := r.policy
		p.EnrollmentEpoch, p.EnrollmentGeneration, p.ApprovedFingerprint = "epoch-2", 2, ""
		p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
		r.setPolicy(p)
		if st, body := r.enrollWith(wiped, nil); st != http.StatusCreated {
			t.Fatalf("enroll after the reset: %d %s", st, body)
		}
		if got := r.ids.entry(testNS, testDevice); got.Fingerprint != wiped.fingerprint() || got.EnrollmentEpoch != "epoch-2" || got.Conflicts != 0 {
			t.Fatalf("pin %+v", got)
		}
		r.dev = wiped
		st, body = r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
		r.approve()
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("session after approval: %d %s", st, body)
		}
	})
}
