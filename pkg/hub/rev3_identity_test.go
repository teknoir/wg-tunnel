package hub

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
)

// ---- admin approval of the pinned identity ----

func (r *rig) deviceSessionStatus() (int, []byte) {
	r.t.Helper()
	tok, req, _ := r.dev.sessionRequest(r.t, r.clock.Now())
	return r.post(api.DeviceSessionPath, tok, req)
}

func TestDeviceSessionNeedsAdminApproval(t *testing.T) {
	r := newRig(t)
	r.enrollOK()

	// Pinned, but nobody approved it: no session, however valid the token.
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	if r.tun.peerCount() != 0 {
		t.Fatal("a pending identity must not get a peer")
	}

	// An approval of some other fingerprint is not an approval.
	p := r.policy
	p.ApprovedFingerprint = "SHA256:somebody-else"
	r.setPolicy(p)
	st, body = r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)

	r.approve()
	st, body = r.deviceSessionStatus()
	if st != http.StatusCreated {
		t.Fatalf("approved identity: %d %s", st, body)
	}
}

func TestApprovalWithdrawnEndsTheDeviceSession(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	c := r.clientSessionOK()

	p := r.policy
	p.ApprovedFingerprint = ""
	r.setPolicy(p)
	waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
	_ = c

	// The same goes for a renewal that races the enforcer.
	r2 := newRig(t)
	dev := r2.deviceSessionOK()
	r2.policy.ApprovedFingerprint = "SHA256:other"
	r2.pol.mu.Lock()
	r2.pol.m[devKey{testNS, testDevice}] = r2.policy // no notification: the renewal must catch it
	r2.pol.mu.Unlock()
	tok := r2.dev.renewToken(t, r2.clock.Now(), dev.pub.Base64())
	st, body := r2.tunnelPost(api.RenewPath, dev.Address, tok, nil)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	if d, _ := r2.h.sessionCounts(); d != 0 {
		t.Fatal("session must be torn down")
	}
}

// A member who read the legacy RSA key from the catalog and enrolled first
// gets a pin, but never a session: the admin compares fingerprints and does not
// approve it, and the real device (conflict) needs a reset to get in.
func TestAttackerWinningTheEnrollmentRaceGetsNoSession(t *testing.T) {
	r := newRig(t)
	attacker := *r.dev
	attacker.newIdentity(t)
	tok, req := attacker.enrollRequest(t, r.clock.Now())
	if st, body := r.enroll(tok, req); st != http.StatusCreated {
		t.Fatalf("attacker enroll: %d %s", st, body)
	}
	atok, areq, _ := attacker.sessionRequest(t, r.clock.Now(), hostKey(t))
	st, body := r.post(api.DeviceSessionPath, atok, areq)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)

	// The real device is locked out of the window and shows up as a conflict.
	rtok, rreq := r.dev.enrollRequest(t, r.clock.Now())
	st, body = r.enroll(rtok, rreq)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	if r.ids.entry(testNS, testDevice).Conflicts != 1 {
		t.Fatal("conflict not recorded")
	}
	if d, _ := r.h.sessionCounts(); d != 0 {
		t.Fatal("attacker has a session")
	}
	if len(r.logs.String()) > 0 && !contains(r.logs.String(), "waiting for admin approval") {
		t.Fatal("the pin must be logged as waiting for approval")
	}

	// Admin resets enrollment (new epoch): the real device enrolls, the admin
	// approves ITS fingerprint, and only it gets in.
	p := r.policy
	p.EnrollmentEpoch = "epoch-2"
	p.ApprovedFingerprint = ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)
	rtok, rreq = r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(rtok, rreq); st != http.StatusCreated {
		t.Fatalf("real device enroll after reset: %d %s", st, body)
	}
	r.approve()
	if st, body = r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("real device session: %d %s", st, body)
	}
	atok, areq, _ = attacker.sessionRequest(t, r.clock.Now())
	st, body = r.post(api.DeviceSessionPath, atok, areq)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated) // not the pinned key any more
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---- enrollment epoch ----

// Disabling and re-enabling WireGuard (or recreating the Device) restarts the
// generation counter, but never the epoch: the old pin can not revive.
func TestPinOfAnotherEpochCannotRevive(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	oldID := *r.dev // the (possibly stolen) old identity

	// device-controller: disable (policy deleted), enable (generation 1 again,
	// but a fresh epoch and a new window; no approval yet).
	r.pol.Delete(testNS, testDevice)
	waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
	p := r.policy
	p.EnrollmentGeneration = 1
	p.EnrollmentEpoch = "epoch-reborn"
	p.ApprovedFingerprint = ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)

	tok, req, _ := oldID.sessionRequest(t, r.clock.Now())
	st, body := r.post(api.DeviceSessionPath, tok, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)

	// A generation that merely matches by number, from another epoch, is void too.
	pin := r.ids.entry(testNS, testDevice)
	if pin.EnrollmentGeneration != 1 || pin.EnrollmentEpoch != "epoch-1" {
		t.Fatalf("old pin %+v", pin)
	}

	// A re-provisioned device (new identity) enrolls inside the new window and
	// replaces the void pin instead of getting enroll_conflict.
	r.dev.newIdentity(t)
	etok, ereq := r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(etok, ereq); st != http.StatusCreated {
		t.Fatalf("re-enroll: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.EnrollmentEpoch != "epoch-reborn" || got.IdentityPublicKey != r.dev.idPubB64 {
		t.Fatalf("pin %+v", got)
	}
	// The old identity is no longer the pinned key at all.
	tok, req, _ = oldID.sessionRequest(t, r.clock.Now())
	st, body = r.post(api.DeviceSessionPath, tok, req)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
}

func TestPinIsValidOnlyForExactEpochAndGeneration(t *testing.T) {
	pol := api.PolicyEntry{EnrollmentGeneration: 3, EnrollmentEpoch: "e3"}
	for name, tc := range map[string]struct {
		pin  api.IdentityEntry
		want bool
	}{
		"exact":             {api.IdentityEntry{EnrollmentGeneration: 3, EnrollmentEpoch: "e3"}, true},
		"older generation":  {api.IdentityEntry{EnrollmentGeneration: 2, EnrollmentEpoch: "e3"}, false},
		"newer generation":  {api.IdentityEntry{EnrollmentGeneration: 4, EnrollmentEpoch: "e3"}, false},
		"same gen, epoch":   {api.IdentityEntry{EnrollmentGeneration: 3, EnrollmentEpoch: "other"}, false},
		"missing epoch":     {api.IdentityEntry{EnrollmentGeneration: 3}, false},
		"voided but exact":  {api.IdentityEntry{EnrollmentGeneration: 3, EnrollmentEpoch: "e3", Voided: true}, false},
		"higher gen, epoch": {api.IdentityEntry{EnrollmentGeneration: 9, EnrollmentEpoch: "zzz"}, false},
	} {
		if got := pinCurrent(tc.pin, pol); got != tc.want {
			t.Errorf("%s: pinCurrent = %v, want %v", name, got, tc.want)
		}
	}
}

func TestEnrollReplacementNeedsAnOpenWindow(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	p := r.policy
	p.EnrollmentEpoch = "epoch-2"
	p.ApprovedFingerprint = ""
	p.EnrollUntil = r.clock.Now().Add(-time.Minute) // already closed
	r.setPolicy(p)
	r.dev.newIdentity(t)
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	st, body := r.enroll(tok, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	if got := r.ids.entry(testNS, testDevice); got.EnrollmentEpoch != "epoch-1" {
		t.Fatalf("the old pin must stay untouched outside a window: %+v", got)
	}
}

// ---- sticky void ----

func TestFlagVoidsThePinStickily(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	oldID := *r.dev

	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "True"})
	waitFor(t, "pin to be voided", func() bool { return r.ids.entry(testNS, testDevice).Voided })
	if got := r.ids.entry(testNS, testDevice); got.VoidedReason != api.RevokeCompromised || got.VoidedAt.IsZero() {
		t.Fatalf("void details %+v", got)
	}
	waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })

	// The flag is cleared, device-controller never noticed (policy unchanged:
	// same epoch and generation, same approval). The old identity is still dead.
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
	tok, req, _ := oldID.sessionRequest(t, r.clock.Now())
	st, body := r.post(api.DeviceSessionPath, tok, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)

	// A new identity cannot enroll in the same window either: first wins per
	// epoch, and the epoch is over.
	r.dev.newIdentity(t)
	etok, ereq := r.dev.enrollRequest(t, r.clock.Now())
	st, body = r.enroll(etok, ereq)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)

	// The controller finally opens a new window (new epoch and generation).
	p := r.policy
	p.EnrollmentGeneration, p.EnrollmentEpoch, p.ApprovedFingerprint = 2, "epoch-2", ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)
	etok, ereq = r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(etok, ereq); st != http.StatusCreated {
		t.Fatalf("enroll in the new window: %d %s", st, body)
	}
	r.approve()
	if st, body = r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("new identity: %d %s", st, body)
	}
}

func TestVoidTriggersAndSkips(t *testing.T) {
	t.Run("health check flag", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
		waitFor(t, "void", func() bool { return r.ids.entry(testNS, testDevice).VoidedReason == api.RevokeHealthCheckFailed })
	})
	t.Run("policy revoked with a reason", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		p := r.policy
		p.State, p.Reasons = api.StateRevoked, []string{api.RevokeCompromised}
		r.setPolicy(p)
		waitFor(t, "void", func() bool { return r.ids.entry(testNS, testDevice).Voided })
	})
	t.Run("an ordinary disable does not void", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		r.flags.Set(testNS, testDevice, map[string]string{})
		waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
		time.Sleep(50 * time.Millisecond)
		if r.ids.entry(testNS, testDevice).Voided {
			t.Fatal("disabling WireGuard must not void the pin")
		}
	})
	t.Run("nothing pinned, nothing to void", func(t *testing.T) {
		r := newRig(t)
		r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		time.Sleep(100 * time.Millisecond)
		if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
			t.Fatal("voiding must not create a pin")
		}
	})
	t.Run("a failing identity store is retried", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		r.ids.mu.Lock()
		r.ids.voidErr = ErrUnavailable
		r.ids.mu.Unlock()
		r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
		if r.ids.entry(testNS, testDevice).Voided {
			t.Fatal("void must not succeed while the store is down")
		}
		r.ids.mu.Lock()
		r.ids.voidErr = nil
		r.ids.mu.Unlock()
		deadline := time.Now().Add(8 * time.Second) // the retry timer is 2 s
		for !r.ids.entry(testNS, testDevice).Voided {
			if time.Now().After(deadline) {
				t.Fatal("void was never retried")
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// ---- unauthenticated callers learn nothing ----

func TestUnauthenticatedDeviceCallersGetOneAnswer(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()

	t.Run("unknown device", func(t *testing.T) {
		other := newDeviceCreds(t)
		other.name = "no-such-device"
		tok, req, _ := other.sessionRequest(t, r.clock.Now())
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("known device, bad signature, stale epoch", func(t *testing.T) {
		// The pin is stale (new epoch), but a stranger without the pinned
		// key must not learn that an enrollment window is open.
		p := r.policy
		p.EnrollmentEpoch = "epoch-2"
		r.setPolicy(p)
		stranger := *r.dev
		stranger.newIdentity(t)
		tok, req, _ := stranger.sessionRequest(t, r.clock.Now())
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		// The device itself (valid signature) does hear reenroll.
		tok, req, _ = r.dev.sessionRequest(t, r.clock.Now())
		st, body = r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)
	})
	t.Run("pending approval is not disclosed either", func(t *testing.T) {
		r := newRig(t)
		r.enrollOK() // pinned, not approved
		stranger := *r.dev
		stranger.newIdentity(t)
		tok, req, _ := stranger.sessionRequest(t, r.clock.Now())
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("no pin yet: same answer as a stranger", func(t *testing.T) {
		// A device in the policy that has never enrolled (fresh window): the
		// anonymous answer must not tell a stranger that nobody is pinned.
		r := newRig(t)
		for name, c := range map[string]*deviceCreds{"the device": r.dev, "a stranger": func() *deviceCreds { s := *r.dev; s.newIdentity(t); return &s }()} {
			tok, req, _ := c.sessionRequest(t, r.clock.Now())
			st, body := r.post(api.DeviceSessionPath, tok, req)
			if st != http.StatusUnauthorized {
				t.Fatalf("%s: %d %s", name, st, body)
			}
			wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		}
	})
	t.Run("pin that cannot be read is not disclosed either", func(t *testing.T) {
		r := newRig(t)
		r.enrollOK()
		r.ids.mu.Lock()
		e := r.ids.m[devKey{testNS, testDevice}]
		e.IdentityPublicKey = "!!not-a-key!!"
		r.ids.m[devKey{testNS, testDevice}] = e
		r.ids.mu.Unlock()
		tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("enroll for an unknown device", func(t *testing.T) {
		other := newDeviceCreds(t)
		other.name = "no-such-device"
		tok, req := other.enrollRequest(t, r.clock.Now())
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
}

// ---- allowed ports reach the device ----

func TestPortsAddedToThePolicyReachTheDevice(t *testing.T) {
	r := newRig(t)
	dev := r.deviceSessionOK()
	if len(dev.AllowedPorts) != 1 || dev.AllowedPorts[0] != 22 {
		t.Fatalf("ports %v", dev.AllowedPorts)
	}
	// A reordering is no change.
	p := r.policy
	p.AllowedPorts = []int{22}
	r.setPolicy(p)
	time.Sleep(50 * time.Millisecond)
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("an unchanged port set must not end the session")
	}

	// A port is added: the live agent has no listener for it, so its session
	// ends and the agent reconnects to learn the new set.
	p.AllowedPorts = []int{22, 8080}
	r.setPolicy(p)
	waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
	if !contains(r.logs.String(), `"reason":"ports_changed"`) {
		t.Fatalf("the end must be logged with its reason:\n%s", r.logs.String())
	}
	again := r.deviceSessionOK()
	if len(again.AllowedPorts) != 2 {
		t.Fatalf("reconnected device got ports %v", again.AllowedPorts)
	}
	// Order is irrelevant.
	p.AllowedPorts = []int{8080, 22}
	r.setPolicy(p)
	time.Sleep(50 * time.Millisecond)
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("reordered ports must not end the session")
	}
}

func TestInvalidPortsAreNotHandedToDevices(t *testing.T) {
	r := newRig(t)
	p := r.policy
	p.AllowedPorts = []int{22, 0, -1, 70000, 22, 8080}
	r.setPolicy(p)
	dev := r.deviceSessionOK()
	if len(dev.AllowedPorts) != 2 || dev.AllowedPorts[0] != 22 || dev.AllowedPorts[1] != 8080 {
		t.Fatalf("ports %v: out-of-range ports would make every agent reject the session", dev.AllowedPorts)
	}
}

func TestIdentityFingerprintHelper(t *testing.T) {
	r := newRig(t)
	pub, _ := identity.ParsePublicKey(r.dev.idPubB64)
	if r.dev.fingerprint() != identity.Fingerprint(pub) {
		t.Fatal("test helper disagrees with the identity package")
	}
}

// Every anonymous failure on the device paths must produce the same bytes: a
// differing message would tell a stranger whether a device has a policy, a
// pin, or an open enrollment window.
func TestUnauthenticatedDeviceBodiesAreIdentical(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	var bodies []string

	unknown := newDeviceCreds(t)
	unknown.name = "no-such-device"
	tok, req, _ := unknown.sessionRequest(t, r.clock.Now())
	_, b := r.post(api.DeviceSessionPath, tok, req)
	bodies = append(bodies, string(b))

	stranger := *r.dev
	stranger.newIdentity(t)
	tok, req, _ = stranger.sessionRequest(t, r.clock.Now())
	_, b = r.post(api.DeviceSessionPath, tok, req)
	bodies = append(bodies, string(b))

	fresh := newRig(t) // in the policy, never enrolled
	tok, req, _ = fresh.dev.sessionRequest(t, fresh.clock.Now())
	_, b = fresh.post(api.DeviceSessionPath, tok, req)
	bodies = append(bodies, string(b))

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("anonymous answer %d differs:\n%s\nvs\n%s", i, bodies[i], bodies[0])
		}
	}
}
