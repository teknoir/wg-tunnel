package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
)

func TestEnrollPinsAndIsIdempotent(t *testing.T) {
	r := newRig(t)
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	st, body := r.enroll(tok, req)
	if st != http.StatusCreated {
		t.Fatalf("first enroll: %d %s", st, body)
	}
	var resp api.EnrollResponse
	_ = json.Unmarshal(body, &resp)
	pub, _ := identity.ParsePublicKey(r.dev.idPubB64)
	if resp.Fingerprint != identity.Fingerprint(pub) || resp.EnrollmentGeneration != 1 {
		t.Fatalf("response %+v", resp)
	}
	if got := r.ids.entry(testNS, testDevice); got.IdentityPublicKey != r.dev.idPubB64 || got.EnrollmentGeneration != 1 {
		t.Fatalf("pin %+v", got)
	}

	// Same key again (new token): 200, nothing changes.
	tok2, req2 := r.dev.enrollRequest(t, r.clock.Now())
	st, body = r.enroll(tok2, req2)
	if st != http.StatusOK {
		t.Fatalf("repeat enroll: %d %s", st, body)
	}
	// Even after the window closed, the same key may confirm its own pin.
	r.clock.Advance(time.Hour)
	tok3, req3 := r.dev.enrollRequest(t, r.clock.Now())
	if st, body = r.enroll(tok3, req3); st != http.StatusOK {
		t.Fatalf("idempotent enroll after window: %d %s", st, body)
	}
	if r.ids.conflicts != 0 {
		t.Fatal("no conflict expected")
	}
}

func TestEnrollWindowClosed(t *testing.T) {
	r := newRig(t)
	r.clock.Advance(16 * time.Minute) // EnrollUntil was +15m
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	st, body := r.enroll(tok, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
		t.Fatal("nothing may be pinned outside the window")
	}
}

func TestEnrollConflictIsRecorded(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	// An attacker holding the exposed legacy RSA key enrols a different identity.
	attacker := *r.dev
	attacker.newIdentity(t)
	tok, req := attacker.enrollRequest(t, r.clock.Now())
	st, body := r.enroll(tok, req)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	if got := r.ids.entry(testNS, testDevice); got.IdentityPublicKey != r.dev.idPubB64 || got.Conflicts != 1 {
		t.Fatalf("pin must be unchanged and the conflict counted: %+v", got)
	}
	// Repeated attempts are counted again, also after the window closed.
	r.clock.Advance(time.Hour)
	tok, req = attacker.enrollRequest(t, r.clock.Now())
	st, body = r.enroll(tok, req)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	if got := r.ids.entry(testNS, testDevice); got.Conflicts != 2 {
		t.Fatalf("conflicts %d", got.Conflicts)
	}
}

func TestEnrollReenrollGeneration(t *testing.T) {
	r := newRig(t)
	r.enrollOK()

	// Admin resets enrollment: generation 2, new window.
	p := r.policy
	p.EnrollmentGeneration = 2
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)

	// The old identity is void: sessions need re-enrollment.
	tok, sreq, _ := r.dev.sessionRequest(t, r.clock.Now())
	st, body := r.post(api.DeviceSessionPath, tok, sreq)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonReenroll)

	// The old key cannot be pinned again for generation 2? It can: same device
	// key, new window. The point of the generation is that a NEW key replaces it.
	r.dev.newIdentity(t)
	etok, ereq := r.dev.enrollRequest(t, r.clock.Now())
	st, body = r.enroll(etok, ereq)
	if st != http.StatusCreated {
		t.Fatalf("re-enrol: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.EnrollmentGeneration != 2 || got.IdentityPublicKey != r.dev.idPubB64 {
		t.Fatalf("pin %+v", got)
	}
	// And the new identity can now create a session.
	stok, sreq2, _ := r.dev.sessionRequest(t, r.clock.Now())
	if st, body = r.post(api.DeviceSessionPath, stok, sreq2); st != http.StatusCreated {
		t.Fatalf("session after re-enrol: %d %s", st, body)
	}
}

func TestEnrollRequiresActiveDevice(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rig)
		reason string
	}{
		{"compromised", func(r *rig) {
			r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		}, api.ReasonDeviceRevoked},
		{"wireguard disabled", func(r *rig) { r.flags.Set(testNS, testDevice, map[string]string{}) }, api.ReasonDeviceDisabled},
		{"policy revoked", func(r *rig) { p := r.policy; p.State = api.StateRevoked; r.setPolicy(p) }, api.ReasonDeviceRevoked},
		{"no policy", func(r *rig) { r.pol.Delete(testNS, testDevice) }, api.ReasonDeviceUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.mutate(r)
			tok, req := r.dev.enrollRequest(t, r.clock.Now())
			st, body := r.enroll(tok, req)
			wantReason(t, st, body, http.StatusForbidden, tc.reason)
		})
	}
}

func TestEnrollRejectsBadCredentials(t *testing.T) {
	r := newRig(t)
	now := r.clock.Now()
	good := func() (string, api.EnrollRequest) { return r.dev.enrollRequest(t, now) }

	t.Run("no bearer", func(t *testing.T) {
		_, req := good()
		st, body := r.enroll("", req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("signed by another RSA key", func(t *testing.T) {
		other := newDeviceCreds(t)
		tok, req := other.enrollRequest(t, now)
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("idk differs from request key", func(t *testing.T) {
		tok, req := good()
		o := newDeviceCreds(t)
		req.IdentityPublicKey = o.idPubB64
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("proof made by another key", func(t *testing.T) {
		tok, req := good()
		o := newDeviceCreds(t)
		req.Proof = identity.ProveEnroll(o.idPriv, r.dev.sub(), "whatever")
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("expired token", func(t *testing.T) {
		tok, req := r.dev.enrollRequest(t, now.Add(-10*time.Minute))
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("token for another device", func(t *testing.T) {
		tok, jti, _ := identity.MintEnrollJWTAt(r.dev.rsaPEM, api.DeviceSubject(testNS, "cam-2"), r.dev.idPubB64, 30*time.Second, now)
		_ = jti
		_, req := good()
		st, body := r.enroll(tok, req)
		// cam-2 has no policy.
		wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceUnknown)
	})
	t.Run("malformed subject", func(t *testing.T) {
		tok, _, _ := identity.MintEnrollJWTAt(r.dev.rsaPEM, "no-slash", r.dev.idPubB64, 30*time.Second, now)
		_, req := good()
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("identity (EdDSA) token on the enroll endpoint", func(t *testing.T) {
		tok, _, _ := r.dev.sessionRequest(t, now)
		_, req := good()
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("posture", func(t *testing.T) {
		tok, req := good()
		req.Posture.Software = "curl"
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPosture)
	})
	t.Run("malformed body", func(t *testing.T) {
		tok, _ := good()
		st, body := r.post(api.DeviceEnrollPath, tok, []byte("{nope"))
		wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	})
	if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
		t.Fatal("nothing may have been pinned")
	}
}

func TestEnrollTokenReplay(t *testing.T) {
	r := newRig(t)
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	if st, body := r.enroll(tok, req); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	st, body := r.enroll(tok, req)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonReplay)
}

func TestEnrollIdentityStoreOutageFailsClosed(t *testing.T) {
	r := newRig(t)
	r.ids.getErr = ErrUnavailable
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	st, _ := r.enroll(tok, req)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("status %d", st)
	}
	if strings.Contains(r.logs.String(), tok) {
		t.Fatal("token leaked into logs")
	}
}
