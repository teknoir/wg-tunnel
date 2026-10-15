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

// Device-key (rev 3) behaviour of the hub: the trusted key admits and
// activates an enrollment outside the window, replaces the pin of an offline
// device, and upgrades pins that were pending or approved before a key existed.
// The key itself is an ordinary Ed25519 SSHSIG key, as in the attestation tests.

func (r *rig) closeWindow() { r.clock.Advance(time.Hour) }

func TestTrustedKeyAdmitsAnAttestedEnrollmentOutsideTheWindow(t *testing.T) {
	r := newRig(t)
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	r.closeWindow()

	// The nonce is issued and the enrollment pins and activates: no window needed.
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
		t.Fatalf("attested enrollment after the window: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != dk.fp || got.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v", got)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
}

func TestOutsideTheWindowOnlyTheTrustedKeyIsAdmitted(t *testing.T) {
	dk := newTestHostKey(t, "ed25519")

	t.Run("an enrollment without attestation stays closed", func(t *testing.T) {
		r := newRig(t)
		r.trust(dk)
		r.closeWindow()
		st, body := r.enrollWith(r.dev, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		if _, ok, _ := r.ids.Get(t.Context(), testNS, testDevice); ok {
			t.Fatal("pinned an unattested identity outside the window")
		}
	})
	t.Run("an enrollment attested by another key stays closed", func(t *testing.T) {
		r := newRig(t)
		r.trust(dk)
		r.closeWindow()
		st, body := r.attestedEnroll(r.dev, newTestHostKey(t, "ed25519"))
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
		if _, ok, _ := r.ids.Get(t.Context(), testNS, testDevice); ok {
			t.Fatal("pinned an identity attested by an untrusted key outside the window")
		}
	})
	t.Run("without a trusted key the window decides", func(t *testing.T) {
		r := newRig(t)
		r.closeWindow()
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
		tok, req := r.dev.enrollRequest(t, r.clock.Now())
		st, body = r.enroll(tok, req)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	})
	t.Run("a shared device key does not open the window", func(t *testing.T) {
		r := newRig(t)
		r.trust(dk)
		p := r.policy
		p.DuplicateHostKey = true
		r.setPolicy(p)
		r.closeWindow()
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	})
	t.Run("a trusted key opens the nonce, an untrusted one does not", func(t *testing.T) {
		r := newRig(t)
		r.closeWindow()
		if st, _ := r.challenge(r.dev); st != http.StatusForbidden {
			t.Fatalf("challenge without a trusted key: %d", st)
		}
		r.trust(dk)
		if st, body := r.challenge(r.dev); st != http.StatusOK {
			t.Fatalf("challenge with a trusted key: %d %s", st, body)
		}
	})
}

// A device that lost its identity (re-image) while its pin is trusted gets a
// new pin when it proves itself with the device key, but only while it is offline.
func TestOfflineTrustedPinIsReplacedByTheDeviceKey(t *testing.T) {
	r := newRig(t)
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	old := r.dev.fingerprint()
	r.clock.Advance(time.Minute)

	reimaged := r.otherDevice(t)
	st, body := r.attestedEnroll(reimaged, dk)
	if st != http.StatusCreated {
		t.Fatalf("replacement: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.IdentityPublicKey != reimaged.idPubB64 || got.ActivatedBy != api.ActivatedByDeviceKey ||
		got.Replacements != 1 || got.LastReplacedFingerprint != old || !got.LastReplacedAt.Equal(r.clock.Now()) ||
		!slices.Contains(got.VoidedFingerprints, old) || got.Conflicts != 0 {
		t.Fatalf("pin %+v", got)
	}
	// The old identity is voided for good.
	st, body = r.attestedEnroll(r.dev, dk)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	// The new identity gets its session.
	r.dev = reimaged
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session of the new identity: %d %s", st, body)
	}
}

func TestOnlineTrustedPinIsNotReplaced(t *testing.T) {
	r := newRig(t)
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	clone := r.otherDevice(t)
	st, body := r.attestedEnroll(clone, dk)
	wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	got := r.ids.entry(testNS, testDevice)
	if got.IdentityPublicKey != r.dev.idPubB64 || got.Conflicts != 1 || got.Replacements != 0 {
		t.Fatalf("pin %+v", got)
	}
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("the live session of the trusted pin must stay")
	}
}

func TestOfflineApprovedPinIsReplacedByTheDeviceKey(t *testing.T) {
	r := newRig(t)
	dk := newTestHostKey(t, "ed25519")
	r.enrollOK()
	r.approve()
	r.trust(dk)
	reimaged := r.otherDevice(t)
	if st, body := r.attestedEnroll(reimaged, dk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.IdentityPublicKey != reimaged.idPubB64 || got.Replacements != 1 || got.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v", got)
	}
}

// The rtx2000 case: an approved, active pin keeps its session when a device
// key is first set, and records the key when the agent attests again.
func TestApprovedPinSurvivesTheFirstDeviceKey(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	approved := r.ids.entry(testNS, testDevice)
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	time.Sleep(100 * time.Millisecond) // the enforcer would have ended it by now
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("the approved session must stay when a key is trusted")
	}
	// The agent attests the SAME identity with the new key.
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusOK {
		t.Fatalf("re-attestation: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != dk.fp || got.ActivatedBy != api.ActivatedByApproval || !got.ActivatedAt.Equal(approved.ActivatedAt) ||
		got.IdentityPublicKey != approved.IdentityPublicKey || got.Replacements != 0 {
		t.Fatalf("pin %+v", got)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
	// The approval can go now: the device key carries the activation.
	p := r.policy
	p.ApprovedFingerprint = ""
	r.setPolicy(p)
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session without the approval: %d %s", st, body)
	}
}

// The vd-wg-1 case: a pin made before any device key existed, attested by the
// SSH host key, waits for approval; after the window closed the same identity
// attests with the device key and activates.
func TestPendingHostKeyPinActivatesOnReattestationWithTheDeviceKey(t *testing.T) {
	r := newRig(t)
	sshHK, dk := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
	if st, body := r.attestedEnroll(r.dev, sshHK); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	r.closeWindow()
	r.trust(dk)
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)

	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusOK {
		t.Fatalf("re-attestation: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != dk.fp || got.ActivatedBy != api.ActivatedByDeviceKey || got.ActivatedAt.IsZero() {
		t.Fatalf("pin %+v", got)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
}

// Rotation: a new device key is trusted; the pin attested by the old key falls
// back to pending and the same identity activates when it attests with the new one.
func TestRotatedDeviceKeyActivatesTheSameIdentityAgain(t *testing.T) {
	r := newRig(t)
	old, rotated := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
	r.trust(old)
	if st, body := r.attestedEnroll(r.dev, old); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	r.closeWindow()
	r.trust(rotated)
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	// The agent holds both keys during the rotation and signs with each.
	ch1, ch2 := r.challengeOK(r.dev), r.challengeOK(r.dev)
	st, body = r.enrollWith(r.dev, attestCaps, signAttestation(t, old, r.dev, ch1), signAttestation(t, rotated, r.dev, ch2))
	if st != http.StatusOK {
		t.Fatalf("re-attestation: %d %s", st, body)
	}
	if got := r.ids.entry(testNS, testDevice); got.AttestedHostKey != rotated.fp {
		t.Fatalf("the trusted key must win: %+v", got)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
}

func TestLiveIdentityReportsActivationAndReplacements(t *testing.T) {
	r := newRig(t)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
	r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(srv.Close)
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	if st, body := r.attestedEnroll(r.dev, dk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	activated := r.clock.Now()
	r.clock.Advance(time.Minute)
	if st, body := r.attestedEnroll(r.otherDevice(t), dk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	req, _ := http.NewRequest("GET", srv.URL+api.StatusDevicePath+testNS+"/"+testDevice, nil)
	req.Header.Set("Authorization", "Bearer "+backstageToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	id := decodeStatus(t, b).Identity
	if id == nil || id.ActivatedBy != api.ActivatedByDeviceKey || !id.ActivatedAt.Equal(activated.Add(time.Minute)) ||
		id.Replacements != 1 || !id.LastReplacedAt.Equal(activated.Add(time.Minute)) {
		t.Fatalf("identity %+v", id)
	}
}

// Entries activated before rev 3 keep their stored source and stay usable.
func TestLegacyHostKeyActivationStaysUsable(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	_, _, _, _ = r.ids.Update(t.Context(), testNS, testDevice, func(c api.IdentityEntry) *api.IdentityEntry {
		c.ActivatedBy = api.ActivatedByHostKey //nolint:staticcheck // entries from before rev 3
		return &c
	})
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
	if got := r.ids.entry(testNS, testDevice); got.ActivatedBy != api.ActivatedByHostKey { //nolint:staticcheck // entries from before rev 3
		t.Fatalf("stored source rewritten: %+v", got)
	}
}
