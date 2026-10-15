package hub

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
)

// Device-key attestation (api.CapAttest, api.CapDeviceKey).
//
// The agent first asks for a single-use nonce (api.AttestChallengePath) per
// key it holds, signs api.AttestStatement with its device key (a pre-rev-3
// agent had the attestor sidecar sign with the SSH host key) and sends the
// signatures with its enrollment. The hub verifies them against the CURRENT
// epoch and generation of the policy and the enrolling identity, and records
// which key signed. Automatic activation (identityUsable) then compares that
// key with the trusted one (PolicyEntry.TrustedHostKey, the device key since
// rev 3).

const (
	attestNonceTTL     = 5 * time.Minute
	attestNonceMax     = 4096 // outstanding nonces in total
	attestNoncePerDev  = 8    // outstanding nonces per (device, identity key); the oldest is dropped
	attestNonceDevMax  = 64   // outstanding nonces per device over all identity keys
	maxAttestations    = 4
	maxAttestationSize = 8 << 10
	maxAgentCaps       = 8
	maxAgentCapLen     = 32
)

type nonceRec struct {
	ns, device  string
	epoch       string
	generation  int64
	identityKey string // base64 identity key of the enrollment token that asked
	expires     time.Time
	issued      time.Time
}

// nonceStore holds the outstanding single-use attestation nonces, bounded in
// total and per device, expiring after attestNonceTTL.
type nonceStore struct {
	mu    sync.Mutex
	m     map[string]nonceRec
	now   func() time.Time
	swept time.Time
}

func newNonceStore(now func() time.Time) *nonceStore {
	return &nonceStore{m: map[string]nonceRec{}, now: now}
}

func (n *nonceStore) sweepLocked(now time.Time) {
	if now.Sub(n.swept) < time.Second && len(n.m) < attestNonceMax {
		return
	}
	n.swept = now
	for k, r := range n.m {
		if !now.Before(r.expires) {
			delete(n.m, k)
		}
	}
}

// issue stores a new nonce for rec. It fails only when the store is full of
// unexpired nonces of other devices.
func (n *nonceStore) issue(rec nonceRec) (string, time.Time, bool) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, false
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw[:])
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.sweepLocked(now)
	// The cap is per (device, identity key): a caller holding the (legacy)
	// enrollment key can mint identity keys at will, but its nonces only
	// evict its own. The newest nonce of every key survives.
	var mine, dev []string
	for k, r := range n.m {
		if r.ns == rec.ns && r.device == rec.device {
			dev = append(dev, k)
			if r.identityKey == rec.identityKey {
				mine = append(mine, k)
			}
		}
	}
	byAge := func(keys []string) {
		slices.SortFunc(keys, func(a, b string) int { return n.m[a].issued.Compare(n.m[b].issued) })
	}
	if len(mine) >= attestNoncePerDev {
		byAge(mine)
		for _, k := range mine[:len(mine)-attestNoncePerDev+1] {
			delete(n.m, k)
		}
		dev = slices.DeleteFunc(dev, func(k string) bool { _, ok := n.m[k]; return !ok })
	}
	// Device wide: make room by dropping the oldest nonce of the identity key
	// that holds the most; when every key holds just its newest nonce, refuse.
	if len(dev) >= attestNonceDevMax {
		per := map[string][]string{}
		for _, k := range dev {
			per[n.m[k].identityKey] = append(per[n.m[k].identityKey], k)
		}
		var fattest []string
		for _, ks := range per {
			if len(ks) > len(fattest) {
				fattest = ks
			}
		}
		if len(fattest) < 2 {
			return "", time.Time{}, false
		}
		byAge(fattest)
		delete(n.m, fattest[0])
	}
	if len(n.m) >= attestNonceMax {
		return "", time.Time{}, false
	}
	rec.issued = now
	rec.expires = now.Add(attestNonceTTL)
	n.m[nonce] = rec
	return nonce, rec.expires, true
}

// take consumes a nonce: it is valid once, and only before it expires.
func (n *nonceStore) take(nonce string) (nonceRec, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	rec, ok := n.m[nonce]
	if !ok {
		return nonceRec{}, false
	}
	delete(n.m, nonce)
	if !n.now().Before(rec.expires) {
		return nonceRec{}, false
	}
	return rec, true
}

func (n *nonceStore) len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.m)
}

// handleAttestChallenge issues a single-use nonce to a device that holds the
// enrollment key. It applies the same checks as handleEnroll, including the
// enrollment window and the policy state, so a closed window or a revoked
// device does not even get a nonce.
func (h *Hub) handleAttestChallenge(ctx context.Context, r *http.Request, _ []byte, d *dctx) (int, any, *denial) {
	d.kind = api.KindDevice
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		return 0, nil, deny(api.ReasonUnauthenticated, "bearer token required")
	}
	sub, ok := unverifiedSubject(tok)
	if !ok {
		return 0, nil, unauthenticatedDenial()
	}
	ns, device, ok := splitSubject(sub)
	if !ok {
		return 0, nil, unauthenticatedDenial()
	}
	d.ns, d.device, d.subject = ns, device, sub

	pol, ok := h.deps.Policy.Get(ns, device)
	if !ok {
		return 0, nil, unauthenticatedDenial()
	}
	now := h.now()
	claims, err := identity.VerifyEnrollJWT(tok, []byte(pol.RSAPublicCert), sub, now)
	if err != nil {
		return 0, nil, unauthenticatedDenial()
	}
	if den := h.enrollDenial("attest", sub, claims.IdentityKey); den != nil {
		return 0, nil, den
	}
	if den := h.replayDenial("attest|"+sub+"|"+claims.IdentityKey, claims); den != nil {
		return 0, nil, den
	}
	eff := computeEffective(h.deps.Policy, h.deps.Flags, ns, device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
	}
	pol = eff.Policy
	cur, found, err := h.deps.Identity.Get(ctx, ns, device)
	if err != nil {
		h.log.Error("reading identity pin failed", "ns", ns, "device", device, "err", err)
		return 0, nil, denyUnavailable("identity store unavailable")
	}
	if found && sameEpoch(cur, pol) {
		if cur.Voided {
			return 0, nil, deny(api.ReasonEnrollClosed, "the pinned identity was voided; an admin must reset enrollment")
		}
		// A pin of this window exists: attesting is still useful (it can
		// upgrade the pin or displace an unattested one).
	} else if !now.Before(pol.EnrollUntil) && !deviceKeyTrusted(pol) {
		// With a device key trusted, the window does not gate attestation: only
		// an enrollment attested by that key is admitted outside it (handleEnroll).
		return 0, nil, deny(api.ReasonEnrollClosed, "enrollment window is closed")
	}
	nonce, exp, ok := h.nonces.issue(nonceRec{ns: ns, device: device, epoch: pol.EnrollmentEpoch, generation: pol.EnrollmentGeneration, identityKey: claims.IdentityKey})
	if !ok {
		return 0, nil, deny(api.ReasonRateLimited, "too many outstanding attestation challenges")
	}
	return http.StatusOK, &api.AttestChallenge{
		Nonce: nonce, EnrollmentEpoch: pol.EnrollmentEpoch, EnrollmentGeneration: pol.EnrollmentGeneration, ExpiresAt: exp,
	}, nil
}

// attested is a verified attestation: the key that signed (the device key
// since rev 3, the SSH host key before).
type attested struct {
	hostKey string // "SHA256:<b64>" (ssh.FingerprintSHA256 of the key blob)
	keyType string
}

// deviceKeyTrusted reports whether pol names a device key that can activate
// identities: one is trusted and it is not shared with another device.
func deviceKeyTrusted(pol api.PolicyEntry) bool {
	return pol.TrustedHostKey != "" && !pol.DuplicateHostKey
}

// byTrustedKey reports whether att was signed by the device key pol trusts.
func byTrustedKey(att *attested, pol api.PolicyEntry) bool {
	return att != nil && deviceKeyTrusted(pol) && att.hostKey == pol.TrustedHostKey
}

// verifyAttestations checks the attestations of an enrollment. It returns
// (nil, nil) for an enrollment that neither advertises api.CapAttest nor sends
// attestations (a phase-1 agent) while the policy trusts no device key, and
// ReasonAttestRequired when it does advertise or send them but none is valid,
// or when the policy has a TrustedHostKey and there is none at all. Every nonce presented is consumed. A valid attestation
// is a SSHSIG by an ed25519 or RSA (rsa-sha2-512) key over api.AttestStatement
// with the policy's CURRENT epoch and generation, a nonce this hub issued to
// this device for this identity key, and the enrolling identity's fingerprint.
func (h *Hub) verifyAttestations(ns, device, fingerprint string, req api.EnrollRequest, pol api.PolicyEntry) (*attested, *denial) {
	advertised := slices.Contains(req.Capabilities, api.CapAttest)
	if !advertised && len(req.HostKeyAttestations) == 0 {
		if pol.TrustedHostKey != "" {
			// A device key is trusted: identities now activate by attestation
			// alone. An enrollment that carries none (whatever it claims to
			// support) could only ever be approved by hand, which is exactly
			// what a squatter with the legacy key wants; refuse it. Removing the
			// trusted key re-opens manual approval.
			return nil, deny(api.ReasonAttestRequired, "a device key is trusted for this device; the enrollment must be attested by it")
		}
		return nil, nil
	}
	if len(req.HostKeyAttestations) > maxAttestations {
		return nil, deny(api.ReasonBadRequest, "too many attestations")
	}
	var valid []attested
	for _, a := range req.HostKeyAttestations {
		rec, ok := h.nonces.take(a.Nonce)
		if !ok || rec.ns != ns || rec.device != device ||
			rec.epoch != pol.EnrollmentEpoch || rec.generation != pol.EnrollmentGeneration ||
			!sameKey(rec.identityKey, req.IdentityPublicKey) || len(a.Signature) > maxAttestationSize {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(a.Signature)
		if err != nil {
			continue
		}
		stmt := api.AttestStatement(ns, device, fingerprint, rec.epoch, rec.generation, a.Nonce)
		pub, err := sshsig.Verify(blob, api.AttestNamespace, stmt)
		if err != nil {
			continue
		}
		valid = append(valid, attested{hostKey: ssh.FingerprintSHA256(pub), keyType: pub.Type()})
	}
	if len(valid) == 0 {
		return nil, deny(api.ReasonAttestRequired, "this agent supports attestation, but the enrollment carries no valid attestation")
	}
	// Prefer the trusted key, then ed25519.
	best := valid[0]
	for _, v := range valid {
		switch {
		case pol.TrustedHostKey != "" && v.hostKey == pol.TrustedHostKey:
			return &v, nil
		case v.keyType == ssh.KeyAlgoED25519 && best.keyType != ssh.KeyAlgoED25519:
			best = v
		}
	}
	return &best, nil
}

// withAttestation returns cur carrying the attestation and capabilities, or
// nil when cur already has them.
func withAttestation(cur api.IdentityEntry, att *attested, caps []string) *api.IdentityEntry {
	next := cur
	if att != nil {
		next.AttestedHostKey, next.AttestedHostKeyType = att.hostKey, att.keyType
	}
	if len(caps) > 0 {
		next.AgentCapabilities = slices.Clone(caps)
	}
	if next.AttestedHostKey == cur.AttestedHostKey && next.AttestedHostKeyType == cur.AttestedHostKeyType &&
		slices.Equal(next.AgentCapabilities, cur.AgentCapabilities) {
		return nil
	}
	return &next
}

// canDisplace reports whether a new enrollment attested by att may take the
// place of the pin cur of the same enrollment window: only an attestation by
// the trusted device key can, and only a pin that is not itself attested by
// that key and was not explicitly approved by an admin. A trusted key shared
// with another device (DuplicateHostKey) proves nothing and displaces nothing.
func canDisplace(cur api.IdentityEntry, att *attested, pol api.PolicyEntry) bool {
	return byTrustedKey(att, pol) &&
		!cur.Voided && sameEpoch(cur, pol) &&
		cur.AttestedHostKey != pol.TrustedHostKey &&
		(pol.ApprovedFingerprint == "" || cur.Fingerprint != pol.ApprovedFingerprint)
}

// canReplace reports whether a new enrollment attested by att may replace the
// pin cur of the same enrollment window although cur is itself trusted (it
// was attested by the device key, or an admin approved it): the device lost
// its identity file or was re-imaged, and the one thing it still holds, the
// device key, proves it is the same device. Unlike canDisplace it needs the
// device to be offline (the caller checks): a live session of the trusted pin
// stays a conflict.
func canReplace(cur api.IdentityEntry, att *attested, pol api.PolicyEntry) bool {
	return byTrustedKey(att, pol) &&
		!cur.Voided && sameEpoch(cur, pol) &&
		!canDisplace(cur, att, pol) &&
		(cur.AttestedHostKey == pol.TrustedHostKey ||
			(pol.ApprovedFingerprint != "" && cur.Fingerprint == pol.ApprovedFingerprint))
}

// displace replaces the pin whose fingerprint is displaced by entry. The
// displaced fingerprint joins the voided history (it can never be pinned
// again). A displacement counts as a conflict, a replacement (replace: the
// pin was trusted, canReplace) as a replacement. replaced is false when the
// stored pin changed meanwhile and no longer qualifies.
func (h *Hub) displace(ctx context.Context, entry api.IdentityEntry, displaced string, pol api.PolicyEntry, att *attested, replace bool) (cur api.IdentityEntry, replaced bool, err error) {
	now := h.now()
	cur, found, wrote, err := h.deps.Identity.Update(ctx, entry.Namespace, entry.Device, func(c api.IdentityEntry) *api.IdentityEntry {
		if c.Fingerprint != displaced {
			return nil
		}
		if replace && !canReplace(c, att, pol) || !replace && !canDisplace(c, att, pol) {
			return nil
		}
		next := entry
		next.VoidedFingerprints = appendVoided(c.VoidedFingerprints, c.Fingerprint)
		next.Conflicts, next.LastConflictAt = c.Conflicts, c.LastConflictAt
		next.Replacements, next.LastReplacedAt, next.LastReplacedFingerprint = c.Replacements, c.LastReplacedAt, c.LastReplacedFingerprint
		if replace {
			next.Replacements++
			next.LastReplacedAt, next.LastReplacedFingerprint = now, c.Fingerprint
		} else {
			next.Conflicts++
			next.LastConflictAt = now
		}
		return &next
	})
	return cur, found && wrote, err
}

// recordActivation stores, once, how a pin became usable (hub-owned fields
// ActivatedBy/ActivatedAt). Failures are logged; they never block a session.
func (h *Hub) recordActivation(ctx context.Context, pin api.IdentityEntry, by string) {
	if pin.ActivatedBy != "" || by == "" {
		return
	}
	pol, ok := h.deps.Policy.Get(pin.Namespace, pin.Device)
	if !ok {
		return
	}
	now := h.now()
	_, _, wrote, err := h.deps.Identity.Update(ctx, pin.Namespace, pin.Device, func(c api.IdentityEntry) *api.IdentityEntry {
		if c.ActivatedBy != "" || c.Fingerprint != pin.Fingerprint {
			return nil
		}
		okNow, byNow := identityUsable(viewOfPin(c), pol)
		if !okNow {
			return nil
		}
		c.ActivatedBy, c.ActivatedAt = byNow, now
		return &c
	})
	if err != nil {
		h.log.Warn("recording identity activation failed", "ns", pin.Namespace, "device", pin.Device, "err", err)
		return
	}
	if wrote {
		h.log.Info("device identity activated", "ns", pin.Namespace, "device", pin.Device, "fingerprint", pin.Fingerprint, "by", by)
	}
}
