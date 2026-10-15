package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"k8s.io/client-go/kubernetes/fake"
)

// In activation=manual (or a generation forced to manual) the trusted device
// key still displaces a squatter's pending pin: the real device must not be
// locked out by whoever holds the enrollment key. The new pin waits for an
// admin, as everything does in that mode; a shared key displaces nothing.
func TestTrustedKeyDisplacesASquatterAlsoWithoutAutoActivation(t *testing.T) {
	modes := map[string]func(*api.PolicyEntry){
		"manual activation": func(p *api.PolicyEntry) { p.ActivationMode = "manual" },
		"forced manual":     func(p *api.PolicyEntry) { p.ForceManualGeneration = p.EnrollmentGeneration },
	}
	for name, mode := range modes {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			dk, own := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
			r.trust(dk)
			p := r.policy
			mode(&p)
			r.setPolicy(p)

			squatter := r.otherDevice(t)
			if st, body := r.attestedEnroll(squatter, own); st != http.StatusCreated {
				t.Fatalf("squatter: %d %s", st, body)
			}
			st, body := r.attestedEnroll(r.dev, dk)
			if st != http.StatusCreated {
				t.Fatalf("the real device, attested by the trusted key, is locked out: %d %s", st, body)
			}
			got := r.ids.entry(testNS, testDevice)
			if got.IdentityPublicKey != r.dev.idPubB64 || got.AttestedHostKey != dk.fp ||
				!slices.Contains(got.VoidedFingerprints, squatter.fingerprint()) || got.Conflicts != 1 {
				t.Fatalf("pin %+v", got)
			}
			// Manual mode: the displacing pin waits for an admin.
			st, body = r.deviceSessionStatus()
			wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
		})
	}
	t.Run("a shared key displaces nothing", func(t *testing.T) {
		r := newRig(t)
		dk, own := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
		r.trust(dk)
		p := r.policy
		p.DuplicateHostKey = true
		r.setPolicy(p)
		squatter := r.otherDevice(t)
		if st, body := r.attestedEnroll(squatter, own); st != http.StatusCreated {
			t.Fatalf("squatter: %d %s", st, body)
		}
		st, body := r.attestedEnroll(r.dev, dk)
		wantReason(t, st, body, http.StatusConflict, api.ReasonEnrollConflict)
	})
}

// flagged pins a device enrollment attested by k, voids it for reason and opens
// generation 2 (same trusted key, window open).
func (r *rig) flagged(t *testing.T, k testHostKey, reason string) {
	t.Helper()
	r.trust(k)
	if st, body := r.attestedEnroll(r.dev, k); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if ok, err := r.ids.Void(t.Context(), testNS, testDevice, reason, r.clock.Now()); !ok || err != nil {
		t.Fatalf("void: %v %v", ok, err)
	}
	p := r.policy
	p.EnrollmentGeneration, p.EnrollmentEpoch = 2, "epoch-2"
	p.EnrollUntil = r.clock.Now().Add(time.Minute)
	r.setPolicy(p)
}

// The distrust of a flagged pin's key is stored, not derived from the voided
// pin: no later pin, and no second attestation beside the distrusted one, brings
// the key back before the policy trusts another.
func TestDistrustOfAFlaggedKeyIsDurable(t *testing.T) {
	for _, reason := range []string{api.RevokeCompromised, api.RevokeHealthCheckFailed} {
		t.Run(reason, func(t *testing.T) {
			r := newRig(t)
			k, k2, own := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
			r.flagged(t, k, reason)
			if got := r.ids.entry(testNS, testDevice); !slices.Equal(got.DistrustedKeys, []string{k.fp}) {
				t.Fatalf("the key of the flagged pin is not recorded: %+v", got)
			}

			// A thief signs with the distrusted key beside a key of its own.
			thief := r.otherDevice(t)
			ch1, ch2 := r.challengeOK(thief), r.challengeOK(thief)
			st, body := r.enrollWith(thief, attestCaps, signAttestation(t, k, thief, ch1), signAttestation(t, own, thief, ch2))
			wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
			if got := r.ids.entry(testNS, testDevice); got.EnrollmentGeneration != 1 {
				t.Fatalf("a pin was made beside the distrusted key: %+v", got)
			}

			// With only its own key it pins (pending); the distrust moves along.
			if st, body := r.attestedEnroll(thief, own); st != http.StatusCreated {
				t.Fatalf("thief with its own key: %d %s", st, body)
			}
			if got := r.ids.entry(testNS, testDevice); got.EnrollmentGeneration != 2 || !slices.Equal(got.DistrustedKeys, []string{k.fp}) {
				t.Fatalf("the distrust was lost with the pin: %+v", got)
			}
			// The distrusted key cannot displace it and does not activate.
			genuine := r.otherDevice(t)
			st, body = r.attestedEnroll(genuine, k)
			wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
			if got := r.ids.entry(testNS, testDevice); got.IdentityPublicKey != thief.idPubB64 || got.ActivatedBy != "" {
				t.Fatalf("pin %+v", got)
			}

			// The key is rotated: an agent that still holds both signs with each.
			// The new key wins, the old one is ordinary again and the list is gone.
			p := r.policy
			p.TrustedHostKey = k2.fp
			r.setPolicy(p)
			ch1, ch2 = r.challengeOK(genuine), r.challengeOK(genuine)
			st, body = r.enrollWith(genuine, attestCaps, signAttestation(t, k, genuine, ch1), signAttestation(t, k2, genuine, ch2))
			if st != http.StatusCreated {
				t.Fatalf("enrollment with the rotated key: %d %s", st, body)
			}
			got := r.ids.entry(testNS, testDevice)
			if got.AttestedHostKey != k2.fp || got.ActivatedBy != api.ActivatedByDeviceKey || len(got.DistrustedKeys) != 0 {
				t.Fatalf("pin %+v", got)
			}
			// Trusting the old key again later is a new decision: nothing remembers it.
			p.TrustedHostKey = k.fp
			r.setPolicy(p)
			if st, _ := r.challenge(genuine); st != http.StatusOK {
				t.Fatalf("challenge after trusting the old key again: %d", st)
			}
		})
	}
}

// Voiding for anything but a flag does not distrust the key.
func TestOnlyAFlagDistrustsTheKey(t *testing.T) {
	at := time.Unix(10, 0)
	pin := api.IdentityEntry{Fingerprint: "fp", AttestedHostKey: "SHA256:k"}
	if got := VoidEntry(pin, "other", at); len(got.DistrustedKeys) != 0 {
		t.Fatalf("%+v", got)
	}
	if got := VoidEntry(api.IdentityEntry{Fingerprint: "fp"}, api.RevokeCompromised, at); len(got.DistrustedKeys) != 0 {
		t.Fatalf("an unattested pin has no key to distrust: %+v", got)
	}
	got := VoidEntry(pin, api.RevokeCompromised, at)
	if !slices.Equal(got.DistrustedKeys, []string{"SHA256:k"}) {
		t.Fatalf("%+v", got)
	}
}

// ReplacePin carries the distrusted keys over, bounded, also from a pin that
// was voided before the list existed.
func TestReplacePinCarriesDistrustedKeysOver(t *testing.T) {
	cur := api.IdentityEntry{
		Fingerprint: "fp1", EnrollmentGeneration: 1, EnrollmentEpoch: "e1", DistrustedKeys: []string{"SHA256:a"},
	}
	next, same, err := ReplacePin(&cur, api.IdentityEntry{Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e2"})
	if err != nil || same || !slices.Equal(next.DistrustedKeys, []string{"SHA256:a"}) {
		t.Fatalf("%+v %v %v", next, same, err)
	}
	legacy := api.IdentityEntry{
		Fingerprint: "fp1", EnrollmentGeneration: 1, EnrollmentEpoch: "e1",
		Voided: true, VoidedReason: api.RevokeHealthCheckFailed, AttestedHostKey: "SHA256:old",
	}
	next, _, err = ReplacePin(&legacy, api.IdentityEntry{Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e2"})
	if err != nil || !slices.Equal(next.DistrustedKeys, []string{"SHA256:old"}) {
		t.Fatalf("%+v %v", next, err)
	}
	var many []string
	for i := range 2 * api.MaxDistrustedKeys {
		many = append(many, "SHA256:"+time.Duration(i).String())
	}
	cur.DistrustedKeys = many
	next, _, _ = ReplacePin(&cur, api.IdentityEntry{Fingerprint: "fp2", EnrollmentGeneration: 2, EnrollmentEpoch: "e2"})
	if len(next.DistrustedKeys) != api.MaxDistrustedKeys || next.DistrustedKeys[len(next.DistrustedKeys)-1] != many[len(many)-1] {
		t.Fatalf("not bounded to the newest: %d", len(next.DistrustedKeys))
	}
}

// Displacing a pin keeps the distrusted keys too.
func TestDisplacementKeepsDistrustedKeys(t *testing.T) {
	r := newRig(t)
	dk, own := newTestHostKey(t, "ed25519"), newTestHostKey(t, "ed25519")
	r.trust(dk)
	squatter := r.otherDevice(t)
	if st, body := r.attestedEnroll(squatter, own); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	_, _, _, _ = r.ids.Update(t.Context(), testNS, testDevice, func(c api.IdentityEntry) *api.IdentityEntry {
		c.DistrustedKeys = []string{"SHA256:old"}
		return &c
	})
	idPub, err := identity.ParsePublicKey(r.dev.idPubB64)
	if err != nil {
		t.Fatal(err)
	}
	att := &attested{hostKey: dk.fp, keyType: "ssh-ed25519"}
	entry := newPinEntry(testNS, testDevice, idPub, r.dev.fingerprint(), r.policy, r.clock.Now(), att, nil)
	_, replaced, err := r.h.displace(t.Context(), entry, squatter.fingerprint(), r.policy, att, false)
	if err != nil || !replaced {
		t.Fatalf("displace: %v %v", replaced, err)
	}
	if got := r.ids.entry(testNS, testDevice); !slices.Equal(got.DistrustedKeys, []string{"SHA256:old"}) || got.IdentityPublicKey != r.dev.idPubB64 {
		t.Fatalf("pin %+v", got)
	}
}

func TestLiveIdentityReportsCurrentAndCapabilities(t *testing.T) {
	r := newRig(t)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
	r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(srv.Close)
	identityOf := func() *api.LiveIdentity {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+api.StatusDevicePath+testNS+"/"+testDevice, nil)
		req.Header.Set("Authorization", "Bearer "+backstageToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return decodeStatus(t, b).Identity
	}
	dk := newTestHostKey(t, "ed25519")
	r.trust(dk)
	ch := r.challengeOK(r.dev)
	caps := []string{api.CapAttest, api.CapDeviceKey}
	if st, body := r.enrollWith(r.dev, caps, signAttestation(t, dk, r.dev, ch)); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	id := identityOf()
	if id == nil || !id.Current || !slices.Equal(id.AgentCapabilities, caps) {
		t.Fatalf("identity %+v", id)
	}
	// A new generation makes the pin an old one.
	p := r.policy
	p.EnrollmentGeneration, p.EnrollmentEpoch = 2, "epoch-2"
	r.setPolicy(p)
	id = identityOf()
	if id == nil || id.Current || !slices.Equal(id.AgentCapabilities, caps) {
		t.Fatalf("identity after the generation changed %+v", id)
	}
}

// The ConfigMap store persists the distrusted key of a flagged pin and carries
// it over to the pin that replaces it.
func TestK8sIdentityStoreKeepsDistrustedKeys(t *testing.T) {
	s := NewK8sIdentityStore(fake.NewSimpleClientset(), api.HubNamespace)
	ctx := t.Context()
	e := idEntry(1, "keyA")
	e.AttestedHostKey = "SHA256:k"
	if _, _, err := s.Pin(ctx, e); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Void(ctx, "acme", "cam-1", api.RevokeCompromised, time.Unix(5, 0).UTC()); err != nil || !changed {
		t.Fatalf("void: %v %v", changed, err)
	}
	cur, _, err := s.Pin(ctx, idEntry(2, "keyB"))
	if err != nil || !slices.Equal(cur.DistrustedKeys, []string{"SHA256:k"}) {
		t.Fatalf("%+v %v", cur, err)
	}
	got, found, err := s.Get(ctx, "acme", "cam-1")
	if err != nil || !found || !slices.Equal(got.DistrustedKeys, []string{"SHA256:k"}) {
		t.Fatalf("%+v %v %v", got, found, err)
	}
}

// Where the key would activate nothing (a generation forced to manual) an admin
// decides anyway: the flagged pin's key is not refused there.
func TestDistrustedKeyIsNotRefusedWhereAnAdminDecides(t *testing.T) {
	r := newRig(t)
	k := newTestHostKey(t, "ed25519")
	r.flagged(t, k, api.RevokeCompromised)
	p := r.policy
	p.ForceManualGeneration = p.EnrollmentGeneration
	r.setPolicy(p)
	if st, body := r.attestedEnroll(r.otherDevice(t), k); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	st, body := r.deviceSessionStatus()
	_ = body
	if st == http.StatusCreated {
		t.Fatal("a forced-manual generation activated by itself")
	}
}
