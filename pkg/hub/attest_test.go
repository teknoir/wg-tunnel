package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
)

// testHostKey is an sshd host key of a test device.
type testHostKey struct {
	signer ssh.Signer
	fp     string
}

func newTestHostKey(t *testing.T, kind string) testHostKey {
	t.Helper()
	var key any
	var err error
	if kind == "rsa" {
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	} else {
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testHostKey{signer: s, fp: ssh.FingerprintSHA256(s.PublicKey())}
}

// challenge asks for an attestation nonce with a fresh enrollment token of c.
func (r *rig) challenge(c *deviceCreds) (int, []byte) {
	r.t.Helper()
	tok, _, err := identity.MintEnrollJWTAt(c.rsaPEM, c.sub(), c.idPubB64, 30*time.Second, r.clock.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	return r.post(api.AttestChallengePath, tok, struct{}{})
}

func (r *rig) challengeOK(c *deviceCreds) api.AttestChallenge {
	r.t.Helper()
	st, body := r.challenge(c)
	if st != http.StatusOK {
		r.t.Fatalf("challenge: %d %s", st, body)
	}
	var ch api.AttestChallenge
	if err := json.Unmarshal(body, &ch); err != nil {
		r.t.Fatal(err)
	}
	return ch
}

// sign is what the attestor does: sign the statement for identity c with hk.
func signAttestation(t *testing.T, hk testHostKey, c *deviceCreds, ch api.AttestChallenge) api.HostKeyAttestation {
	t.Helper()
	return signStatement(t, hk, testNS, testDevice, c.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
}

func signStatement(t *testing.T, hk testHostKey, ns, dev, fp, epoch string, gen int64, nonce string) api.HostKeyAttestation {
	t.Helper()
	blob, err := sshsig.Sign(hk.signer, api.AttestNamespace, api.AttestStatement(ns, dev, fp, epoch, gen, nonce))
	if err != nil {
		t.Fatal(err)
	}
	return api.HostKeyAttestation{Nonce: nonce, Signature: base64.StdEncoding.EncodeToString(blob)}
}

// enrollWith enrolls identity c with the given attestations and capabilities.
func (r *rig) enrollWith(c *deviceCreds, caps []string, atts ...api.HostKeyAttestation) (int, []byte) {
	r.t.Helper()
	tok, req := c.enrollRequest(r.t, r.clock.Now())
	req.Capabilities, req.HostKeyAttestations = caps, atts
	return r.enroll(tok, req)
}

// attestedEnroll runs the whole agent flow for identity c with host key hk.
func (r *rig) attestedEnroll(c *deviceCreds, hk testHostKey) (int, []byte) {
	r.t.Helper()
	ch := r.challengeOK(c)
	return r.enrollWith(c, []string{api.CapAttest}, signAttestation(r.t, hk, c, ch))
}

func (r *rig) trust(hk testHostKey) {
	p := r.policy
	p.TrustedHostKey = hk.fp
	r.setPolicy(p)
}

func (r *rig) otherDevice(t *testing.T) *deviceCreds {
	t.Helper()
	o := *r.dev
	o.newIdentity(t)
	return &o
}

var attestCaps = []string{api.CapAttest}

func TestAttestChallengeIssuesSingleUseNonces(t *testing.T) {
	r := newRig(t)
	a, b := r.challengeOK(r.dev), r.challengeOK(r.dev)
	if a.Nonce == "" || a.Nonce == b.Nonce {
		t.Fatalf("nonces %q %q", a.Nonce, b.Nonce)
	}
	if a.EnrollmentEpoch != "epoch-1" || a.EnrollmentGeneration != 1 {
		t.Fatalf("challenge %+v", a)
	}
	if want := r.clock.Now().Add(attestNonceTTL); !a.ExpiresAt.Equal(want) {
		t.Errorf("expires %v, want %v", a.ExpiresAt, want)
	}
}

func TestAttestChallengeAuth(t *testing.T) {
	r := newRig(t)
	if st, body := r.post(api.AttestChallengePath, "", struct{}{}); st != http.StatusUnauthorized {
		t.Errorf("no token: %d %s", st, body)
	}
	if st, body := r.post(api.AttestChallengePath, "garbage", struct{}{}); st != http.StatusUnauthorized {
		t.Errorf("garbage token: %d %s", st, body)
	}
	// A token for a different RSA key (an outsider) looks like any bad token.
	outsider := newDeviceCreds(t)
	st, body := r.challenge(outsider)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	// GET is refused.
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+api.AttestChallengePath, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", resp.StatusCode)
	}
}

func TestAttestChallengeReplayedTokenRefused(t *testing.T) {
	r := newRig(t)
	tok, _, err := identity.MintEnrollJWTAt(r.dev.rsaPEM, r.dev.sub(), r.dev.idPubB64, 30*time.Second, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st, body := r.post(api.AttestChallengePath, tok, struct{}{}); st != http.StatusOK {
		t.Fatalf("first: %d %s", st, body)
	}
	st, body := r.post(api.AttestChallengePath, tok, struct{}{})
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonReplay)
}

func TestAttestChallengeFollowsEnrollmentState(t *testing.T) {
	t.Run("window closed", func(t *testing.T) {
		r := newRig(t)
		r.clock.Advance(16 * time.Minute)
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	})
	t.Run("window closed but a pin exists", func(t *testing.T) {
		r := newRig(t)
		r.enrollOK()
		r.clock.Advance(time.Hour)
		if st, body := r.challenge(r.dev); st != http.StatusOK {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		r := newRig(t)
		r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceRevoked)
	})
	t.Run("voided pin", func(t *testing.T) {
		r := newRig(t)
		r.enrollOK()
		if _, err := r.ids.Void(context.Background(), testNS, testDevice, api.RevokeCompromised, r.clock.Now()); err != nil {
			t.Fatal(err)
		}
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	})
	t.Run("unknown device", func(t *testing.T) {
		r := newRig(t)
		ghost := *r.dev
		ghost.name = "ghost"
		st, body := r.challenge(&ghost)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
}

func TestAttestedEnrollRecordsHostKey(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	st, body := r.attestedEnroll(r.dev, hk)
	if st != http.StatusCreated {
		t.Fatalf("enroll: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != hk.fp || got.AttestedHostKeyType != ssh.KeyAlgoED25519 || !slices.Equal(got.AgentCapabilities, attestCaps) {
		t.Fatalf("pin %+v", got)
	}
	if got.ActivatedBy != "" {
		t.Errorf("no trusted key: must not activate (%q)", got.ActivatedBy)
	}
	// Identity fingerprint and host key fingerprint share one format.
	if len(got.AttestedHostKey) < 10 || got.AttestedHostKey[:7] != "SHA256:" || got.AttestedHostKey[len(got.AttestedHostKey)-1] == '=' {
		t.Errorf("host key fingerprint format %q", got.AttestedHostKey)
	}
}

func TestAttestedEnrollWithRSAHostKey(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "rsa")
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("enroll: %d %s", st, body)
	}
	if got := r.ids.entry(testNS, testDevice); got.AttestedHostKey != hk.fp || got.AttestedHostKeyType != ssh.KeyAlgoRSA {
		t.Fatalf("pin %+v", got)
	}
}

func TestAttestNonceIsSingleUse(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	ch := r.challengeOK(r.dev)
	att := signAttestation(t, hk, r.dev, ch)
	// The attacker intercepts an attestation and replays it for ITS identity: it
	// does not verify (statement binds the identity), and the nonce is burnt.
	attacker := r.otherDevice(t)
	if st, body := r.enrollWith(attacker, attestCaps, att); st != http.StatusForbidden {
		t.Fatalf("replay for another identity: %d %s", st, body)
	}
	st, body := r.enrollWith(r.dev, attestCaps, att)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
		t.Fatal("nothing may be pinned")
	}
	// A fresh challenge works.
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("fresh: %d %s", st, body)
	}
}

func TestAttestNonceReuseAfterSuccess(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	ch := r.challengeOK(r.dev)
	att := signAttestation(t, hk, r.dev, ch)
	if st, body := r.enrollWith(r.dev, attestCaps, att); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	st, body := r.enrollWith(r.dev, attestCaps, att)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
}

func TestAttestNonceExpires(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	ch := r.challengeOK(r.dev)
	att := signAttestation(t, hk, r.dev, ch)
	r.clock.Advance(attestNonceTTL + time.Second)
	st, body := r.enrollWith(r.dev, attestCaps, att)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
}

func TestAttestRefusedForWrongEpochOrGeneration(t *testing.T) {
	hk := newTestHostKey(t, "ed25519")
	t.Run("epoch reset after the challenge", func(t *testing.T) {
		r := newRig(t)
		ch := r.challengeOK(r.dev)
		att := signAttestation(t, hk, r.dev, ch)
		p := r.policy
		p.EnrollmentEpoch = "epoch-2"
		r.setPolicy(p)
		st, body := r.enrollWith(r.dev, attestCaps, att)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
	t.Run("generation reset after the challenge", func(t *testing.T) {
		r := newRig(t)
		ch := r.challengeOK(r.dev)
		att := signAttestation(t, hk, r.dev, ch)
		p := r.policy
		p.EnrollmentGeneration = 2
		r.setPolicy(p)
		st, body := r.enrollWith(r.dev, attestCaps, att)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
	t.Run("statement signed with a stale epoch", func(t *testing.T) {
		r := newRig(t)
		ch := r.challengeOK(r.dev)
		att := signStatement(t, hk, testNS, testDevice, r.dev.fingerprint(), "epoch-0", ch.EnrollmentGeneration, ch.Nonce)
		st, body := r.enrollWith(r.dev, attestCaps, att)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
	t.Run("statement signed with a stale generation", func(t *testing.T) {
		r := newRig(t)
		ch := r.challengeOK(r.dev)
		att := signStatement(t, hk, testNS, testDevice, r.dev.fingerprint(), ch.EnrollmentEpoch, 0, ch.Nonce)
		st, body := r.enrollWith(r.dev, attestCaps, att)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
}

func TestAttestRefusedForWrongStatement(t *testing.T) {
	hk := newTestHostKey(t, "ed25519")
	var other *deviceCreds
	var r *rig
	cases := map[string]func(ch api.AttestChallenge) api.HostKeyAttestation{
		"other namespace": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return signStatement(t, hk, "elsewhere", testDevice, r.dev.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
		},
		"other device": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return signStatement(t, hk, testNS, "cam-2", r.dev.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
		},
		"other identity": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return signStatement(t, hk, testNS, testDevice, other.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
		},
		"other nonce": func(ch api.AttestChallenge) api.HostKeyAttestation {
			a := signStatement(t, hk, testNS, testDevice, r.dev.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, "forged")
			a.Nonce = ch.Nonce
			return a
		},
		"garbage signature": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return api.HostKeyAttestation{Nonce: ch.Nonce, Signature: base64.StdEncoding.EncodeToString([]byte("SSHSIGnonsense"))}
		},
		"not base64": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return api.HostKeyAttestation{Nonce: ch.Nonce, Signature: "!!!"}
		},
		"unknown nonce": func(ch api.AttestChallenge) api.HostKeyAttestation {
			return signStatement(t, hk, testNS, testDevice, r.dev.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, "never-issued")
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r = newRig(t)
			other = r.otherDevice(t)
			ch := r.challengeOK(r.dev)
			st, body := r.enrollWith(r.dev, attestCaps, mk(ch))
			wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
			if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
				t.Fatal("must not pin")
			}
		})
	}
}

func TestAttestNonceBoundToTheAskingIdentityKey(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	// The nonce is issued against identity key A's enrollment token ...
	ch := r.challengeOK(r.dev)
	// ... and a perfectly signed attestation for identity B (same device) uses it.
	b := r.otherDevice(t)
	att := signAttestation(t, hk, b, ch)
	st, body := r.enrollWith(b, attestCaps, att)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
}

func TestAttestRefusedForSignatureInAnotherNamespace(t *testing.T) {
	// A SSHSIG made for another purpose (a git commit signature, say) over the
	// very same bytes is not an attestation. (ssh-rsa/SHA-1 and the other weak
	// forms are refused by pkg/sshsig; see its tests.)
	r := newRig(t)
	hk := newTestHostKey(t, "rsa")
	ch := r.challengeOK(r.dev)
	stmt := api.AttestStatement(testNS, testDevice, r.dev.fingerprint(), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
	blob, err := sshsig.Sign(hk.signer, "git", stmt)
	if err != nil {
		t.Fatal(err)
	}
	st, body := r.enrollWith(r.dev, attestCaps, api.HostKeyAttestation{Nonce: ch.Nonce, Signature: base64.StdEncoding.EncodeToString(blob)})
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
}

func TestAttestRequiredWhenAdvertisedWithoutAttestation(t *testing.T) {
	r := newRig(t)
	st, body := r.enrollWith(r.dev, attestCaps)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
		t.Fatal("must not pin")
	}
	// A phase-1 agent (no capability, no attestation) still enrolls.
	if st, body := r.enrollWith(r.dev, nil); st != http.StatusCreated {
		t.Fatalf("phase-1 enrollment: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != "" || len(got.AgentCapabilities) != 0 {
		t.Fatalf("pin %+v", got)
	}
}

func TestAttestRequiredAlsoForSamePinReenroll(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	st, body := r.enrollWith(r.dev, attestCaps)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
}

func TestTooManyAttestationsRefused(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	var atts []api.HostKeyAttestation
	for range maxAttestations + 1 {
		atts = append(atts, signAttestation(t, hk, r.dev, r.challengeOK(r.dev)))
	}
	st, body := r.enrollWith(r.dev, attestCaps, atts...)
	wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
}

func TestUnknownCapabilitiesAreSanitized(t *testing.T) {
	r := newRig(t)
	caps := []string{"services-v1", "services-v1", "BAD CAP", "", "x\ny", "a-very-long-capability-name-that-goes-on-and-on"}
	if st, body := r.enrollWith(r.dev, caps); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if got := r.ids.entry(testNS, testDevice); !slices.Equal(got.AgentCapabilities, []string{"services-v1"}) {
		t.Fatalf("caps %v", got.AgentCapabilities)
	}
}

// ---- activation ----

func TestAutoActivationByTrustedHostKey(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("enroll: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.ActivatedBy != api.ActivatedByDeviceKey || !got.ActivatedAt.Equal(r.clock.Now()) {
		t.Fatalf("activation not recorded at enrollment: %+v", got)
	}
	// No admin approval anywhere, yet the session is granted.
	if r.policy.ApprovedFingerprint != "" {
		t.Fatal("test setup")
	}
	st, body := r.deviceSessionStatus()
	if st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
}

func TestActivationRecordedOnceAndKeepsFirstSource(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	r.attestedEnroll(r.dev, hk)
	first := r.ids.entry(testNS, testDevice)
	r.clock.Advance(time.Minute)
	r.approve() // later approval does not rewrite the record
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if got := r.ids.entry(testNS, testDevice); got.ActivatedBy != api.ActivatedByDeviceKey || !got.ActivatedAt.Equal(first.ActivatedAt) {
		t.Fatalf("activation record changed: %+v -> %+v", first, got)
	}
}

func TestManualApprovalRecordsActivation(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	if got := r.ids.entry(testNS, testDevice); got.ActivatedBy != "" {
		t.Fatalf("pending pin is not activated: %+v", got)
	}
	r.approve()
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.ActivatedBy != api.ActivatedByApproval || got.ActivatedAt.IsZero() {
		t.Fatalf("activation: %+v", got)
	}
}

func TestNoAutoActivationWithoutTrustedKeyOrWithAnotherKey(t *testing.T) {
	hk := newTestHostKey(t, "ed25519")
	t.Run("no trusted key", func(t *testing.T) {
		r := newRig(t)
		r.attestedEnroll(r.dev, hk)
		st, body := r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	})
	t.Run("attested by another key", func(t *testing.T) {
		r := newRig(t)
		r.trust(newTestHostKey(t, "ed25519"))
		r.attestedEnroll(r.dev, hk)
		st, body := r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
		// Manual approval still works.
		r.approve()
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("after approval: %d %s", st, body)
		}
	})
	t.Run("unattested phase-1 agent with a trusted key", func(t *testing.T) {
		// Once a host key is trusted an enrollment without attestation is
		// refused outright (review finding 27): manual approval of an
		// unattested identity is not possible until the trusted key is removed.
		r := newRig(t)
		r.trust(hk)
		tok, req := r.dev.enrollRequest(t, r.clock.Now())
		st, body := r.enroll(tok, req)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
		if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); found {
			t.Fatal("an unattested identity was pinned although a host key is trusted")
		}
		// Removing the trusted key re-opens the manual path.
		p := r.policy
		p.TrustedHostKey = ""
		r.setPolicy(p)
		r.enrollOK()
		st, body = r.deviceSessionStatus()
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	})
	t.Run("a capable-looking squatter without attestation is refused too", func(t *testing.T) {
		r := newRig(t)
		r.trust(hk)
		st, body := r.enrollWith(r.dev, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	})
}

func TestForcedManualGeneration(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	p := r.policy
	p.ForceManualGeneration = p.EnrollmentGeneration // a flag was cleared in this generation
	r.setPolicy(p)
	r.attestedEnroll(r.dev, hk)
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	if got := r.ids.entry(testNS, testDevice); got.ActivatedBy != "" {
		t.Fatalf("must not record an activation: %+v", got)
	}
	// An explicit approval still activates.
	r.approve()
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("approved: %d %s", st, body)
	}

	// A later generation is automatic again.
	p = r.policy
	p.EnrollmentGeneration, p.EnrollmentEpoch, p.ApprovedFingerprint = 2, "epoch-2", ""
	p.EnrollUntil = r.clock.Now().Add(15 * time.Minute)
	r.setPolicy(p)
	r.dev.newIdentity(t)
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("re-enroll: %d %s", st, body)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("generation 2 should auto-activate: %d %s", st, body)
	}
}

func TestManualActivationMode(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	p := r.policy
	p.ActivationMode = "manual"
	r.setPolicy(p)
	r.attestedEnroll(r.dev, hk)
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	r.approve()
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("approved: %d %s", st, body)
	}
}

func TestDuplicateHostKeyRefusesAutoActivation(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	p := r.policy
	p.DuplicateHostKey = true
	r.setPolicy(p)
	r.attestedEnroll(r.dev, hk)
	st, body := r.deviceSessionStatus()
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	r.approve()
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("approved: %d %s", st, body)
	}
}

func TestReenrollWithAttestationUpgradesPin(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.enrollOK() // phase-1 style, pending
	r.trust(hk)
	if st, _ := r.deviceSessionStatus(); st != http.StatusForbidden {
		t.Fatal("pending expected")
	}
	// The same identity enrolls again, now with a valid attestation.
	st, body := r.attestedEnroll(r.dev, hk)
	if st != http.StatusOK {
		t.Fatalf("re-enroll: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.AttestedHostKey != hk.fp || got.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v", got)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
}

func TestRenewalAndEnforcementUseTheSameRule(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	r.attestedEnroll(r.dev, hk)
	tok, req, priv := r.dev.sessionRequest(t, r.clock.Now())
	st, body := r.post(api.DeviceSessionPath, tok, req)
	if st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
	var sess api.SessionResponse
	_ = json.Unmarshal(body, &sess)
	pub, _ := priv.Public()

	// Renewal works while the rule holds.
	r.clock.Advance(time.Minute)
	rt := r.dev.renewToken(t, r.clock.Now(), pub.Base64())
	if st, body := r.tunnelPost(api.RenewPath, sess.Address, rt, nil); st != http.StatusOK {
		t.Fatalf("renew: %d %s", st, body)
	}

	// The admin forces manual: the renewal that races the enforcer is refused
	// by the very same rule ...
	p := r.policy
	p.ActivationMode = "manual"
	r.pol.mu.Lock()
	r.pol.m[devKey{testNS, testDevice}] = p // no notification
	r.pol.mu.Unlock()
	r.clock.Advance(time.Minute)
	rt = r.dev.renewToken(t, r.clock.Now(), pub.Base64())
	st, body = r.tunnelPost(api.RenewPath, sess.Address, rt, nil)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonPendingApproval)
	if d, _ := r.h.sessionCounts(); d != 0 {
		t.Fatal("renewal denial must end the session")
	}
}

func TestEnforcerEndsHostKeyActivatedSessionWhenTrustChanges(t *testing.T) {
	for name, mutate := range map[string]func(*api.PolicyEntry){
		"trusted key cleared":      func(p *api.PolicyEntry) { p.TrustedHostKey = "" },
		"another key trusted":      func(p *api.PolicyEntry) { p.TrustedHostKey = "SHA256:someoneelse" },
		"manual mode":              func(p *api.PolicyEntry) { p.ActivationMode = "manual" },
		"duplicate flag":           func(p *api.PolicyEntry) { p.DuplicateHostKey = true },
		"forced manual generation": func(p *api.PolicyEntry) { p.ForceManualGeneration = p.EnrollmentGeneration },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			hk := newTestHostKey(t, "ed25519")
			r.trust(hk)
			r.attestedEnroll(r.dev, hk)
			if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
				t.Fatalf("%d %s", st, body)
			}
			p := r.policy
			mutate(&p)
			r.setPolicy(p)
			waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
		})
	}
	t.Run("approved sessions are unaffected by trust changes", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		p := r.policy
		p.ActivationMode, p.TrustedHostKey, p.DuplicateHostKey = "manual", "", true
		r.setPolicy(p)
		time.Sleep(100 * time.Millisecond)
		if d, _ := r.h.sessionCounts(); d != 1 {
			t.Fatal("approval-activated session must stay")
		}
	})
}

// ---- pin displacement ----

func TestTrustedAttestationDisplacesSquattedPin(t *testing.T) {
	r := newRig(t)
	hk := newTestHostKey(t, "ed25519")

	// An attacker with the exposed legacy RSA key enrolls first, unattested
	// (before any host key was trusted; afterwards it could not).
	squatter := r.otherDevice(t)
	if st, body := r.enrollWith(squatter, nil); st != http.StatusCreated {
		t.Fatalf("squatter: %d %s", st, body)
	}
	r.trust(hk)
	// Without an attestation the real device is turned away.
	if st, body := r.enrollWith(r.dev, nil); st != http.StatusForbidden {
		t.Fatalf("unattested real device: %d %s", st, body)
	}
	// With an attestation by the trusted key it takes the pin.
	st, body := r.attestedEnroll(r.dev, hk)
	if st != http.StatusCreated {
		t.Fatalf("attested real device: %d %s", st, body)
	}
	got := r.ids.entry(testNS, testDevice)
	if got.IdentityPublicKey != r.dev.idPubB64 || got.AttestedHostKey != hk.fp || got.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v", got)
	}
	if got.Conflicts < 2 { // the earlier unattested attempt (recorded) and the displacement
		t.Errorf("conflicts %d", got.Conflicts)
	}
	if !slices.Contains(got.VoidedFingerprints, squatter.fingerprint()) {
		t.Errorf("displaced fingerprint is not in the voided history: %v", got.VoidedFingerprints)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("session: %d %s", st, body)
	}
	// The squatter cannot get back in.
	if st, body := r.enrollWith(squatter, nil); st != http.StatusForbidden {
		t.Fatalf("squatter again: %d %s", st, body)
	}
}

func TestDisplacementNeverHappensWhen(t *testing.T) {
	hk := newTestHostKey(t, "ed25519")
	setup := func(t *testing.T, mutate func(*rig, *deviceCreds)) (*rig, *deviceCreds) {
		r := newRig(t)
		squatter := r.otherDevice(t)
		if st, body := r.enrollWith(squatter, nil); st != http.StatusCreated {
			t.Fatalf("squatter: %d %s", st, body)
		}
		r.trust(hk)
		if mutate != nil {
			mutate(r, squatter)
		}
		return r, squatter
	}
	notDisplaced := func(t *testing.T, r *rig, squatter *deviceCreds, st int) {
		t.Helper()
		if st != http.StatusConflict {
			t.Fatalf("status %d, want 409", st)
		}
		if got := r.ids.entry(testNS, testDevice); got.IdentityPublicKey != squatter.idPubB64 {
			t.Fatalf("the pin was displaced: %+v", got)
		}
	}
	t.Run("the attestation is by another key", func(t *testing.T) {
		r, squatter := setup(t, nil)
		st, _ := r.attestedEnroll(r.dev, newTestHostKey(t, "ed25519"))
		notDisplaced(t, r, squatter, st)
	})
	t.Run("no key is trusted", func(t *testing.T) {
		r, squatter := setup(t, func(r *rig, _ *deviceCreds) {
			p := r.policy
			p.TrustedHostKey = ""
			r.setPolicy(p)
		})
		st, _ := r.attestedEnroll(r.dev, hk)
		notDisplaced(t, r, squatter, st)
	})
	t.Run("the trusted key is shared with another device", func(t *testing.T) {
		r, squatter := setup(t, func(r *rig, _ *deviceCreds) {
			p := r.policy
			p.DuplicateHostKey = true
			r.setPolicy(p)
		})
		st, _ := r.attestedEnroll(r.dev, hk)
		notDisplaced(t, r, squatter, st)
	})
	t.Run("an admin approved the pin and the device is online", func(t *testing.T) {
		r, squatter := setup(t, func(r *rig, sq *deviceCreds) {
			p := r.policy
			p.ApprovedFingerprint = sq.fingerprint()
			r.setPolicy(p)
		})
		// A live session of the approved pin: it is replaced only while offline.
		real := r.dev
		r.dev = squatter
		r.deviceSessionOK()
		r.dev = real
		st, _ := r.attestedEnroll(r.dev, hk)
		notDisplaced(t, r, squatter, st)
	})
	t.Run("the pin is attested by the trusted key itself and the device is online", func(t *testing.T) {
		r := newRig(t)
		r.trust(hk)
		if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		// A clone of the device key (the image was copied) enrolls a new identity
		// while the device is online: first wins, no displacement.
		clone := r.otherDevice(t)
		st, _ := r.attestedEnroll(clone, hk)
		if st != http.StatusConflict {
			t.Fatalf("status %d", st)
		}
		if got := r.ids.entry(testNS, testDevice); got.IdentityPublicKey != r.dev.idPubB64 {
			t.Fatalf("pin displaced: %+v", got)
		}
	})
	t.Run("the pin is void", func(t *testing.T) {
		r, _ := setup(t, func(r *rig, _ *deviceCreds) {
			_, _ = r.ids.Void(context.Background(), testNS, testDevice, api.RevokeCompromised, r.clock.Now())
		})
		st, body := r.challenge(r.dev)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonEnrollClosed)
	})
}

func TestDisplacedSquatterSessionEnds(t *testing.T) {
	// A squatter whose pin an admin approved cannot be displaced, so the only
	// way it has a session is approval. Here the squatter's session is made
	// by hand in the registry to prove endStaleDeviceSession only touches
	// other identities.
	r := newRig(t)
	r.deviceSessionOK()
	r.h.endStaleDeviceSession(devKey{testNS, testDevice}, r.dev.fingerprint())
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("the live identity's session must stay")
	}
	r.h.endStaleDeviceSession(devKey{testNS, testDevice}, "SHA256:another")
	waitFor(t, "stale session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
}

// ---- nonce store ----

func TestNonceStoreBounds(t *testing.T) {
	clk := newFakeClock()
	n := newNonceStore(clk.Now)
	mk := func(dev string) nonceRec { return nonceRec{ns: "ns", device: dev, epoch: "e", generation: 1} }

	first, _, ok := n.issue(mk("d"), "")
	if !ok {
		t.Fatal("issue")
	}
	var last string
	for range attestNoncePerDev {
		clk.Advance(time.Millisecond)
		last, _, _ = n.issue(mk("d"), "")
	}
	if _, ok := n.take(first); ok {
		t.Error("the oldest nonce of a device must be dropped at the per-device cap")
	}
	if _, ok := n.take(last); !ok {
		t.Error("the newest nonce must work")
	}
	if _, ok := n.take(last); ok {
		t.Error("nonce reused")
	}

	// Expiry and sweeping.
	x, _, _ := n.issue(mk("e"), "")
	clk.Advance(attestNonceTTL + time.Second)
	if _, ok := n.take(x); ok {
		t.Error("expired nonce accepted")
	}

	// Global cap: other devices cannot push the store past it.
	n2 := newNonceStore(clk.Now)
	for i := range attestNonceMax {
		if _, _, ok := n2.issue(mk("dev-"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))), ""); !ok {
			t.Fatalf("issue %d refused below the cap", i)
		}
	}
	if n2.len() > attestNonceMax {
		t.Fatalf("store holds %d", n2.len())
	}
	if _, _, ok := n2.issue(mk("brand-new"), ""); ok {
		t.Error("issue succeeded at the global cap")
	}
	clk.Advance(attestNonceTTL + time.Second)
	if _, _, ok := n2.issue(mk("brand-new"), ""); !ok {
		t.Error("expired entries must make room")
	}
}

func TestChallengeWhenStoreFullIsRateLimited(t *testing.T) {
	r := newRig(t)
	for i := range attestNonceMax {
		r.h.nonces.mu.Lock()
		r.h.nonces.m["fill-"+string(rune(i))+"-"+time.Duration(i).String()] = nonceRec{ns: "x", device: "y" + time.Duration(i).String(), expires: r.clock.Now().Add(time.Hour), issued: r.clock.Now()}
		r.h.nonces.mu.Unlock()
	}
	st, body := r.challenge(r.dev)
	wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonRateLimited)
}

func TestIdentityEntryJSONCarriesAttestationFields(t *testing.T) {
	e := api.IdentityEntry{AttestedHostKey: "SHA256:x", AttestedHostKeyType: "ssh-ed25519", AgentCapabilities: []string{"attest-v1"}, ActivatedBy: api.ActivatedByHostKey} //nolint:staticcheck // the pre-rev-3 value must still round-trip
	b, _ := json.Marshal(e)
	var back api.IdentityEntry
	if err := json.Unmarshal(b, &back); err != nil || back.AttestedHostKey != "SHA256:x" || back.ActivatedBy != "host-key" {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}
