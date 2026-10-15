package fakehub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
)

// Host-key attestation support of the fake hub (Options.Attest): the challenge
// endpoint, single-use nonces, SSHSIG verification at enrollment. The real
// logic is in pkg/hub; this is the minimum a client test needs.

type fakeNonce struct{ ns, name, idk string }

// Attested is what the fake hub recorded for a device's last enrollment.
type Attested struct {
	// HostKey is the SHA256 fingerprint of the first key that signed ("" =
	// none), KeyType its type; Keys lists every key that signed (a device
	// holding two device keys signs with both).
	HostKey string
	KeyType string
	Keys    []string
	// Capabilities the agent advertised when it enrolled.
	Capabilities []string
	// Challenges counts the nonces issued.
	Challenges int
}

type attestState struct {
	nonces map[string]fakeNonce
	last   Attested
}

func (d *device) attestSt() *attestState {
	if d.att == nil {
		d.att = &attestState{nonces: map[string]fakeNonce{}}
	}
	return d.att
}

// Attestation returns what the device's last enrollment attested.
func (h *Hub) Attestation(ns, name string) Attested {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.devices[ns+"/"+name]
	if d == nil || d.att == nil {
		return Attested{}
	}
	return d.att.last
}

// SessionCapabilities returns the capabilities of the device's latest session request.
func (h *Hub) SessionCapabilities(ns, name string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.devCaps[ns+"/"+name])
}

func (h *Hub) epoch(d *device) string { return fmt.Sprintf("fake-epoch-%d", d.generation) }

func (h *Hub) handleAttestChallenge(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	ns, name, ok := subjectOf(tok)
	if tok == "" || !ok {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, Call{Path: api.AttestChallengePath, Kind: api.KindDevice, Bearer: tok})
	d := h.devices[ns+"/"+name]
	if d == nil {
		writeErr(w, 404, api.ReasonDeviceUnknown)
		return
	}
	if !d.spec.EnrollOpen {
		writeErr(w, 403, api.ReasonEnrollClosed)
		return
	}
	claims, err := identity.VerifyEnrollJWT(tok, d.spec.RSACertPEM, api.DeviceSubject(ns, name), time.Now())
	if err != nil || d.seenJTI[claims.ID] {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	d.seenJTI[claims.ID] = true
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	nonce := base64.RawURLEncoding.EncodeToString(raw[:])
	st := d.attestSt()
	st.nonces[nonce] = fakeNonce{ns: ns, name: name, idk: claims.IdentityKey}
	st.last.Challenges++
	writeJSON(w, 200, api.AttestChallenge{
		Nonce: nonce, EnrollmentEpoch: h.epoch(d), EnrollmentGeneration: d.generation, ExpiresAt: time.Now().Add(5 * time.Minute),
	})
}

// verifyEnrollAttest applies the attestation rules to an enrollment and
// returns "" or the refusal reason. Called with h.mu held.
func (h *Hub) verifyEnrollAttest(d *device, ns, name string, idk ed25519.PublicKey, req api.EnrollRequest) string {
	if !h.opts.Attest {
		return ""
	}
	st := d.attestSt()
	advertised := slices.Contains(req.Capabilities, api.CapAttest)
	if !advertised && len(req.HostKeyAttestations) == 0 {
		st.last = Attested{Challenges: st.last.Challenges}
		return ""
	}
	fp := identity.Fingerprint(idk)
	var got Attested
	for _, a := range req.HostKeyAttestations {
		rec, ok := st.nonces[a.Nonce]
		delete(st.nonces, a.Nonce)
		if !ok || rec.ns != ns || rec.name != name || rec.idk != req.IdentityPublicKey {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(a.Signature)
		if err != nil {
			continue
		}
		pub, err := sshsig.Verify(blob, api.AttestNamespace, api.AttestStatement(ns, name, fp, h.epoch(d), d.generation, a.Nonce))
		if err != nil {
			continue
		}
		if got.HostKey == "" {
			got.HostKey, got.KeyType = ssh.FingerprintSHA256(pub), pub.Type()
		}
		got.Keys = append(got.Keys, ssh.FingerprintSHA256(pub))
	}
	if got.HostKey == "" {
		return api.ReasonAttestRequired
	}
	got.Capabilities, got.Challenges = slices.Clone(req.Capabilities), st.last.Challenges
	st.last = got
	return ""
}
