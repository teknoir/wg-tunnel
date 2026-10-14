package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

const (
	maxBody       = 16 << 10
	maxHostKeys   = 16
	maxHostKeyLen = 2048
)

// handlerFunc is an endpoint implementation: it returns the success status and
// body, or a denial. It must fill d as it learns the request's identity.
type handlerFunc func(ctx context.Context, r *http.Request, body []byte, d *dctx) (int, any, *denial)

// Handler serves the outside-tunnel API (enroll, device and client session
// creation) plus /healthz and /readyz on the port reachable through the
// ingress gateways (api.HubHTTPPort). It authenticates Keycloak users and
// devices only: service-account delegation and direct sessions are refused
// here and served by InternalHandler. The caller wraps it in an http.Server
// with the hub's timeouts (see NewHTTPServer).
func (h *Hub) Handler() http.Handler { return h.apiHandler(false) }

// InternalHandler serves the same API for in-cluster callers on
// api.HubInternalPort, which no VirtualService routes to. In addition to
// everything Handler accepts it accepts service-account delegation
// (OnBehalfOf) and direct UDP sessions.
func (h *Hub) InternalHandler() http.Handler { return h.apiHandler(true) }

func (h *Hub) apiHandler(internal bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.DeviceEnrollPath, h.wrap("enroll", internal, h.handleEnroll))
	mux.HandleFunc(api.AttestChallengePath, h.wrap("attest-challenge", internal, h.handleAttestChallenge))
	mux.HandleFunc(api.DeviceSessionPath, h.wrap("session", internal, h.handleDeviceSession))
	mux.HandleFunc(api.ClientSessionPath, h.wrap("session", internal, h.handleClientSession))
	mux.HandleFunc(api.HealthzPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// NewHTTPServer returns an http.Server with the hub's limits: header timeout
// 5s, read and write timeouts 15s, small headers.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

// wrap adds the common prelude: method, rate limits (per trusted source
// address when there is one, plus a global backstop per endpoint; both before
// anything is parsed or allocated), body limit, JSON rendering and the
// decision line.
func (h *Hub) wrap(op string, internal bool, fn handlerFunc) http.HandlerFunc {
	listener := "outside|"
	if internal {
		listener = "internal|"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ip, trusted := h.clientIP(r)
		d := &dctx{op: op, remote: ip, internal: internal}
		if r.Method != http.MethodPost {
			den := deny(api.ReasonBadRequest, "POST required")
			den.status = http.StatusMethodNotAllowed
			w.Header().Set("Allow", http.MethodPost)
			h.writeDenial(w, d, den)
			return
		}
		// The per-source limiter needs a client address that a trusted proxy
		// vouches for. Without one every request would share the proxy's
		// address and one caller could exhaust the limit for everybody.
		if trusted {
			if ok, retry := h.ipLimit.Allow(ip); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
				h.writeDenial(w, d, deny(api.ReasonRateLimited, "too many requests"))
				return
			}
		}
		if ok, retry := h.globalLimit.Allow(listener + r.URL.Path); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			h.writeDenial(w, d, deny(api.ReasonRateLimited, "the hub is busy"))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			den := deny(api.ReasonBadRequest, "unreadable or oversized body")
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				den.status = http.StatusRequestEntityTooLarge
			}
			h.writeDenial(w, d, den)
			return
		}
		status, resp, den := fn(r.Context(), r, body, d)
		if den != nil {
			h.writeDenial(w, d, den)
			return
		}
		h.logDecision(d, "allow", "ok", "")
		writeJSON(w, status, resp)
	}
}

func (h *Hub) writeDenial(w http.ResponseWriter, d *dctx, den *denial) {
	if den.reason == api.ReasonRateLimited || den.reason == api.ReasonSessionLimit {
		if w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "5")
		}
	}
	h.logDecision(d, "deny", den.reason, den.msg)
	writeJSON(w, den.status, &api.Error{Reason: den.reason, Message: den.msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// unverifiedSubject reads the "sub" claim of a JWT without verifying it, only
// to learn which device's key to verify against.
func unverifiedSubject(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Sub == "" {
		return "", false
	}
	return c.Sub, true
}

// sameKey compares two base64 Ed25519 public keys by value.
func sameKey(a, b string) bool {
	ka, err1 := identity.ParsePublicKey(a)
	kb, err2 := identity.ParsePublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(ka, kb)
}

func decodeJSON(body []byte, v any) *denial {
	if len(body) == 0 {
		return deny(api.ReasonBadRequest, "empty body")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return deny(api.ReasonBadRequest, "malformed JSON")
	}
	return nil
}

func validPosture(p api.Posture, softwares ...string) *denial {
	if !slices.Contains(softwares, p.Software) {
		return deny(api.ReasonPosture, "unsupported client software")
	}
	for _, f := range []string{p.Version, p.OS, p.Arch, p.Hostname} {
		if len(f) > 128 {
			return deny(api.ReasonPosture, "posture field too long")
		}
	}
	return nil
}

// replayDenial records the jti of a verified device token in the partition of
// subjectKey. The subject limiter must run first, so a subject that is already
// over its rate cannot even add entries.
func (h *Hub) replayDenial(subjectKey string, claims *api.DeviceClaims) *denial {
	// The entry must outlive the token's last moment of validity, which is
	// exp plus the accepted clock skew, rounded up to a whole second.
	until := time.Unix(claims.ExpiresAt, 0).Add(api.MaxClockSkew + 2*time.Second)
	switch err := h.replay.Check(subjectKey, claims.ID, until); {
	case errors.Is(err, errReplay):
		return deny(api.ReasonReplay, "token already used")
	case err != nil:
		return deny(api.ReasonRateLimited, "too many tokens for this subject")
	}
	return nil
}

func (h *Hub) subjectDenial(key string) *denial {
	if ok, _ := h.subjLimit.Allow(key); !ok {
		return deny(api.ReasonRateLimited, "too many requests for this subject")
	}
	return nil
}

// errUnauthenticated is the one answer an unauthenticated caller gets for
// anything that depends on a device's existence or enrollment state.
func unauthenticatedDenial() *denial { return deny(api.ReasonUnauthenticated, "invalid token") }

func (h *Hub) handleEnroll(ctx context.Context, r *http.Request, body []byte, d *dctx) (int, any, *denial) {
	d.kind = api.KindDevice
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		return 0, nil, deny(api.ReasonUnauthenticated, "bearer token required")
	}
	var req api.EnrollRequest
	if den := decodeJSON(body, &req); den != nil {
		return 0, nil, den
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

	// Until the token is verified, every failure looks the same: a caller who
	// cannot prove the legacy key learns nothing about which devices exist.
	pol, ok := h.deps.Policy.Get(ns, device)
	if !ok {
		return 0, nil, unauthenticatedDenial()
	}
	now := h.now()
	claims, err := identity.VerifyEnrollJWT(tok, []byte(pol.RSAPublicCert), sub, now)
	if err != nil {
		return 0, nil, unauthenticatedDenial()
	}
	idPub, err := identity.ParsePublicKey(req.IdentityPublicKey)
	if err != nil {
		return 0, nil, deny(api.ReasonBadRequest, "invalid identity public key")
	}
	if !sameKey(claims.IdentityKey, req.IdentityPublicKey) {
		return 0, nil, deny(api.ReasonUnauthenticated, "token identity key does not match request")
	}
	if err := identity.VerifyEnrollProof(idPub, sub, claims.ID, req.Proof); err != nil {
		return 0, nil, unauthenticatedDenial()
	}
	// Subject limit first, then the replay cache: a subject over its rate must
	// not be able to fill its replay partition.
	if den := h.subjectDenial("enroll|" + sub); den != nil {
		return 0, nil, den
	}
	if den := h.replayDenial("enroll|"+sub, claims); den != nil {
		return 0, nil, den
	}
	if den := validPosture(req.Posture, "wg-agent"); den != nil {
		return 0, nil, den
	}
	eff := computeEffective(h.deps.Policy, h.deps.Flags, ns, device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
	}
	pol = eff.Policy
	fingerprint := identity.Fingerprint(idPub)

	// Host-key attestation (api.CapAttest). An agent that advertises it must
	// present a valid one; a phase-1 agent enrolls as before.
	att, den := h.verifyAttestations(ns, device, fingerprint, req, pol)
	if den != nil {
		return 0, nil, den
	}
	caps := sanitizeCaps(req.Capabilities)

	cur, found, err := h.deps.Identity.Get(ctx, ns, device)
	if err != nil {
		h.log.Error("reading identity pin failed", "ns", ns, "device", device, "err", err)
		return 0, nil, denyUnavailable("identity store unavailable")
	}
	if found && sameEpoch(cur, pol) {
		// First wins per enrollment epoch.
		if cur.Voided {
			return 0, nil, deny(api.ReasonEnrollClosed, "the pinned identity was voided; an admin must reset enrollment")
		}
		if sameKey(cur.IdentityPublicKey, req.IdentityPublicKey) {
			// The pinned identity enrolling again: record what it attests now.
			cur = h.updateAttestation(ctx, cur, att, caps)
			h.recordActivation(ctx, cur, activationSource(cur, pol))
			return h.enrollResult(ctx, cur, req.IdentityPublicKey, false, d)
		}
		if canDisplace(cur, att, pol) {
			// A different identity, attested by the host key the admin trusted,
			// meets a pin that is not: the pin was squatted by someone who
			// holds the enrollment key but not the device.
			if IsVoidedFingerprint(cur, fingerprint) {
				return 0, nil, h.voidedEnrollDenial(ctx, d)
			}
			entry := newPinEntry(ns, device, idPub, fingerprint, pol, h.now(), att, caps)
			got, replaced, err := h.displace(ctx, entry, cur.Fingerprint, pol, att)
			if err != nil {
				h.log.Error("displacing identity pin failed", "ns", ns, "device", device, "err", err)
				return 0, nil, denyUnavailable("identity store unavailable")
			}
			if replaced {
				h.log.Warn("identity pin displaced by an enrollment attested by the trusted host key",
					"ns", ns, "device", device, "displaced", cur.Fingerprint, "fingerprint", fingerprint)
				h.endStaleDeviceSession(devKey{ns, device}, fingerprint)
				h.recordActivation(ctx, got, activationSource(got, pol))
				return h.enrollResult(ctx, got, req.IdentityPublicKey, true, d)
			}
			cur = got
		}
		return h.enrollResult(ctx, cur, req.IdentityPublicKey, false, d)
	}
	// No pin, or a pin of another epoch or generation (void): enrollment is
	// allowed only inside the open window of this policy.
	if !now.Before(pol.EnrollUntil) {
		return 0, nil, deny(api.ReasonEnrollClosed, "enrollment window is closed")
	}
	// A voided identity is never re-admitted, whatever the epoch: a new window
	// needs a NEW key (sticky void).
	if found && IsVoidedFingerprint(cur, fingerprint) {
		return 0, nil, h.voidedEnrollDenial(ctx, d)
	}
	got, created, err := h.deps.Identity.Pin(ctx, newPinEntry(ns, device, idPub, fingerprint, pol, now, att, caps))
	if errors.Is(err, ErrFingerprintVoided) {
		return 0, nil, h.voidedEnrollDenial(ctx, d)
	}
	if err != nil {
		h.log.Error("pinning identity failed", "ns", ns, "device", device, "err", err)
		return 0, nil, denyUnavailable("identity store unavailable")
	}
	if created {
		if ok, by := identityUsable(viewOfPin(got), pol); ok {
			h.log.Info("identity pinned and activated automatically", "ns", ns, "device", device, "fingerprint", fingerprint, "by", by)
			h.recordActivation(ctx, got, by)
		} else {
			h.log.Info("identity pinned; waiting for admin approval", "ns", ns, "device", device, "fingerprint", fingerprint)
		}
	}
	return h.enrollResult(ctx, got, req.IdentityPublicKey, created, d)
}

// newPinEntry is the identity entry of a new enrollment.
func newPinEntry(ns, device string, pub ed25519.PublicKey, fingerprint string, pol api.PolicyEntry, now time.Time, att *attested, caps []string) api.IdentityEntry {
	e := api.IdentityEntry{
		Device: device, Namespace: ns,
		IdentityPublicKey:    identity.EncodePublicKey(pub),
		Fingerprint:          fingerprint,
		EnrollmentGeneration: pol.EnrollmentGeneration,
		EnrollmentEpoch:      pol.EnrollmentEpoch,
		EnrolledAt:           now,
		AgentCapabilities:    caps,
	}
	if att != nil {
		e.AttestedHostKey, e.AttestedHostKeyType = att.hostKey, att.keyType
	}
	return e
}

// updateAttestation records a later attestation (or new capabilities) on the
// pin of the identity that made it and returns the pin in effect.
func (h *Hub) updateAttestation(ctx context.Context, cur api.IdentityEntry, att *attested, caps []string) api.IdentityEntry {
	if att == nil && len(caps) == 0 {
		return cur
	}
	got, found, _, err := h.deps.Identity.Update(ctx, cur.Namespace, cur.Device, func(c api.IdentityEntry) *api.IdentityEntry {
		if c.Fingerprint != cur.Fingerprint || c.Voided {
			return nil
		}
		return withAttestation(c, att, caps)
	})
	if err != nil {
		h.log.Warn("recording host-key attestation failed", "ns", cur.Namespace, "device", cur.Device, "err", err)
		return cur
	}
	if !found {
		return cur
	}
	return got
}

// activationSource is how pin is usable under pol ("" when it is not).
func activationSource(pin api.IdentityEntry, pol api.PolicyEntry) string {
	_, by := identityUsable(viewOfPin(pin), pol)
	return by
}

// endStaleDeviceSession ends the live device session of k unless it belongs to
// the identity with the given fingerprint.
func (h *Hub) endStaleDeviceSession(k devKey, fingerprint string) {
	h.mu.Lock()
	dev := h.devices[k]
	h.mu.Unlock()
	if dev != nil && dev.fingerprint != fingerprint {
		h.endSession(dev, api.ReasonReenroll)
	}
}

// voidedEnrollDenial answers an enrollment with an identity that was voided
// before. It is recorded as a conflict, like any other rejected key.
func (h *Hub) voidedEnrollDenial(ctx context.Context, d *dctx) *denial {
	if err := h.deps.Identity.RecordConflict(ctx, d.ns, d.device, h.now()); err != nil {
		h.log.Error("recording enrollment conflict failed", "ns", d.ns, "device", d.device, "err", err)
	}
	return deny(api.ReasonEnrollConflict, "this identity was voided and cannot be enrolled again")
}

// enrollResult answers an enrollment given the pin in effect.
func (h *Hub) enrollResult(ctx context.Context, pin api.IdentityEntry, requested string, created bool, d *dctx) (int, any, *denial) {
	if !sameKey(pin.IdentityPublicKey, requested) {
		if err := h.deps.Identity.RecordConflict(ctx, d.ns, d.device, h.now()); err != nil {
			h.log.Error("recording enrollment conflict failed", "ns", d.ns, "device", d.device, "err", err)
		}
		return 0, nil, deny(api.ReasonEnrollConflict, "a different identity is pinned for this generation")
	}
	resp := &api.EnrollResponse{Fingerprint: pin.Fingerprint, EnrollmentGeneration: pin.EnrollmentGeneration, EnrolledAt: pin.EnrolledAt}
	if created {
		return http.StatusCreated, resp, nil
	}
	return http.StatusOK, resp, nil
}

// loadPin loads the identity pin of a device and its key. It does not judge
// the pin against the policy (see checkPin): a caller must authenticate with
// the pinned key first, so that the reasons below stay hidden from strangers.
func (h *Hub) loadPin(ctx context.Context, ns, device string) (api.IdentityEntry, ed25519.PublicKey, *denial) {
	pin, found, err := h.deps.Identity.Get(ctx, ns, device)
	switch {
	case err != nil:
		h.log.Error("reading identity pin failed", "ns", ns, "device", device, "err", err)
		return pin, nil, denyUnavailable("identity store unavailable")
	case !found:
		return pin, nil, deny(api.ReasonNotEnrolled, "device identity is not enrolled")
	}
	pub, err := identity.ParsePublicKey(pin.IdentityPublicKey)
	if err != nil {
		h.log.Error("pinned identity key is malformed", "ns", ns, "device", device)
		return pin, nil, deny(api.ReasonInternal, "pinned identity is invalid")
	}
	return pin, pub, nil
}

// checkPin judges an authenticated device's pin against the policy: the pin
// must belong to the current enrollment (epoch and generation, not voided) and
// satisfy the activation rule (identityUsable): its fingerprint is the one an
// admin approved, or it was enrolled with an attestation by the trusted host
// key. The first time a pin is found usable the activation is recorded on it.
func (h *Hub) checkPin(ctx context.Context, pin api.IdentityEntry, pub ed25519.PublicKey, pol api.PolicyEntry) *denial {
	if !pinCurrent(pin, pol) {
		return deny(api.ReasonReenroll, "enrollment was reset; enroll a new identity")
	}
	v := viewOfPin(pin)
	v.Fingerprint = identity.Fingerprint(pub)
	ok, by := identityUsable(v, pol)
	if !ok {
		return deny(api.ReasonPendingApproval, "the device identity is waiting for an admin to approve it in the Teknoir UI")
	}
	h.recordActivation(ctx, pin, by)
	return nil
}

// sanitizeHostKeys keeps the valid authorized_keys-format SSH host keys in a
// canonical "type base64" form (comments and options dropped).
func sanitizeHostKeys(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range in {
		if len(out) >= maxHostKeys {
			break
		}
		if len(line) > maxHostKeyLen {
			continue
		}
		pk, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(opts) > 0 {
			continue
		}
		canon := pk.Type() + " " + base64.StdEncoding.EncodeToString(pk.Marshal())
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	return out
}

func (h *Hub) handleDeviceSession(ctx context.Context, r *http.Request, body []byte, d *dctx) (int, any, *denial) {
	d.kind = api.KindDevice
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		return 0, nil, deny(api.ReasonUnauthenticated, "bearer token required")
	}
	var req api.DeviceSessionRequest
	if den := decodeJSON(body, &req); den != nil {
		return 0, nil, den
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

	// Unknown devices look like bad tokens. Only a device that has a pin can
	// be told more, and only after it proved it holds the pinned key.
	if _, ok := h.deps.Policy.Get(ns, device); !ok {
		return 0, nil, unauthenticatedDenial()
	}
	pin, pub, den := h.loadPin(ctx, ns, device)
	if den != nil {
		if den.reason == api.ReasonNotEnrolled || den.reason == api.ReasonInternal && den.status != http.StatusServiceUnavailable {
			// Nothing proves yet that the caller holds a pinned key, so the
			// enrollment state stays hidden: the agent enrolls on this answer
			// too (see pkg/agent).
			return 0, nil, unauthenticatedDenial()
		}
		return 0, nil, den
	}
	now := h.now()
	claims, err := identity.VerifyIdentityJWT(tok, pub, sub, now)
	if err != nil {
		return 0, nil, unauthenticatedDenial()
	}
	// Authenticated. A device that is revoked, disabled or unknown to the
	// policy hears that before anything about its pin.
	eff := computeEffective(h.deps.Policy, h.deps.Flags, ns, device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
	}
	if den := h.checkPin(ctx, pin, pub, eff.Policy); den != nil {
		return 0, nil, den
	}
	wgPub, err := wgkey.ParsePublic(req.WGPublicKey)
	if err != nil {
		return 0, nil, deny(api.ReasonBadRequest, "invalid WireGuard public key")
	}
	if tokKey, err := wgkey.ParsePublic(claims.WGKey); err != nil || tokKey != wgPub {
		return 0, nil, deny(api.ReasonUnauthenticated, "token is not bound to this WireGuard key")
	}
	if den := h.subjectDenial("device|" + sub); den != nil {
		return 0, nil, den
	}
	if den := h.replayDenial("device|"+sub, claims); den != nil {
		return 0, nil, den
	}
	if den := validPosture(req.Posture, "wg-agent"); den != nil {
		return 0, nil, den
	}

	id, err := newID()
	if err != nil {
		return 0, nil, deny(api.ReasonInternal, "internal error")
	}
	turn, err := h.deps.TURN.Mint(ns, id)
	if err != nil {
		h.log.Error("minting TURN credentials failed", "err", err)
		return 0, nil, denyUnavailable("TURN credentials unavailable")
	}
	ports := validPorts(eff.Policy.AllowedPorts)
	s := &session{
		id: id, kind: api.KindDevice, authKind: authDevice, ns: ns, device: device, subject: sub,
		wgKey: wgPub, wgKeyB64: wgPub.Base64(), createdAt: now,
		generation: pin.EnrollmentGeneration, epoch: pin.EnrollmentEpoch, fingerprint: identity.Fingerprint(pub), attestedKey: pin.AttestedHostKey, ports: ports,
		hostKeys: sanitizeHostKeys(req.SSHHostKeys), remote: d.remote,
		expiresAt: now.Add(h.cfg.SessionTTL), turnExpiry: turn.ExpiresAt,
	}
	d.session = id
	if den := h.admit(s); den != nil {
		return 0, nil, den
	}
	// An annotation or the policy may have changed between the checks and the
	// registration; the enforcer saw that change before s existed.
	if again := computeEffective(h.deps.Policy, h.deps.Flags, ns, device); !again.Active {
		h.endSession(s, again.Reason)
		return 0, nil, deny(again.Reason, again.Detail)
	} else if reason, detail := deviceStale(s, again.Policy); reason != "" {
		h.endSession(s, reason)
		return 0, nil, deny(staleDenialReason(reason), detail)
	}
	return http.StatusCreated, &api.SessionResponse{
		SessionID: id, Kind: api.KindDevice, Address: s.ip.String(),
		HubAddress: api.HubAddress, HubPublicKey: h.tunnel.PublicKey().Base64(), HubEndpoint: h.Endpoint(),
		TURN: turn, ExpiresAt: s.expiresAt, RenewAfterSeconds: int(h.cfg.RenewAfter.Seconds()), MTU: api.MTU,
		AllowedPorts: slices.Clone(ports),
	}, nil
}

// deviceStale reports why a live device session no longer matches pol: its
// identity belongs to an older enrollment, the admin approved another
// fingerprint, or the allowed ports changed (the agent only learns the ports
// at session creation, so it must reconnect).
func deviceStale(s *session, pol api.PolicyEntry) (reason, detail string) {
	switch {
	case pol.EnrollmentGeneration != s.generation || pol.EnrollmentEpoch != s.epoch:
		return api.ReasonReenroll, "enrollment reset"
	case !activated(s.identityView(), pol):
		return api.ReasonPendingApproval, "identity approval changed"
	case !samePorts(pol.AllowedPorts, s.ports):
		return reasonPortsChanged, "allowed ports changed"
	}
	return "", ""
}

// staleDenialReason maps an internal end reason to a wire reason.
func staleDenialReason(reason string) string {
	if reason == reasonPortsChanged {
		return api.ReasonForbidden
	}
	return reason
}

func (h *Hub) handleClientSession(ctx context.Context, r *http.Request, body []byte, d *dctx) (int, any, *denial) {
	d.kind = api.KindClient
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		return 0, nil, deny(api.ReasonUnauthenticated, "bearer token required")
	}
	var req api.ClientSessionRequest
	if den := decodeJSON(body, &req); den != nil {
		return 0, nil, den
	}
	// Service-account delegation and direct UDP are in-cluster features: the
	// outside API (reachable through the ingress gateways) refuses them, no
	// matter what credential comes with the request.
	if !d.internal && (req.OnBehalfOf != "" || req.Direct) {
		return 0, nil, deny(api.ReasonForbidden, "delegation and direct sessions are not available on this endpoint")
	}
	if !validLabel(req.Namespace) || !validLabel(req.Device) || req.Port < 1 || req.Port > 65535 {
		return 0, nil, deny(api.ReasonBadRequest, "invalid namespace, device or port")
	}
	wgPub, err := wgkey.ParsePublic(req.WGPublicKey)
	if err != nil {
		return 0, nil, deny(api.ReasonBadRequest, "invalid WireGuard public key")
	}
	ns, device := req.Namespace, req.Device
	d.ns, d.device = ns, device

	// Authenticate. TokenReview is attempted only for delegating callers.
	var (
		email, saName string
		authKind      = authKeycloak
		tokenExp      time.Time
		tokenID       string
		tokenIAT      time.Time
	)
	if req.OnBehalfOf != "" {
		if !ValidEmail(req.OnBehalfOf) {
			return 0, nil, deny(api.ReasonBadRequest, "onBehalfOf must be a lowercase email address")
		}
		if h.deps.SA == nil {
			return 0, nil, deny(api.ReasonForbidden, "delegation is not enabled")
		}
		sa, err := h.deps.SA.Verify(ctx, tok, ns, device, req.OnBehalfOf)
		if err != nil {
			return 0, nil, asDenial(err)
		}
		email, saName, authKind = req.OnBehalfOf, sa.Name, authSA
	} else {
		u, err := h.deps.Users.Authenticate(ctx, tok)
		if err != nil {
			return 0, nil, asDenial(err)
		}
		email, tokenExp, tokenID, tokenIAT = u.Email, u.ExpiresAt, u.TokenID, u.IssuedAt
	}
	d.subject = email
	if authKind == authSA {
		d.subject = email + " via sa:" + saName
	}
	probe := &session{authKind: authKind, saName: saName, subject: email}
	if den := h.subjectDenial("client|" + probe.limitKey()); den != nil {
		return 0, nil, den
	}
	if den := validPosture(req.Posture, "tnctl", "web-terminal"); den != nil {
		return 0, nil, den
	}

	// Authorize before revealing anything about the device.
	allowed, err := h.deps.Authz.CanExec(ctx, email, ns)
	if err != nil {
		h.log.Error("authorization check failed", "ns", ns, "err", err)
		return 0, nil, denyUnavailable("authorization backend unavailable")
	}
	if !allowed {
		return 0, nil, deny(api.ReasonForbidden, "no access to this teamspace")
	}
	eff := computeEffective(h.deps.Policy, h.deps.Flags, ns, device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
	}
	if !portAllowed(eff.Policy.AllowedPorts, req.Port) {
		return 0, nil, deny(api.ReasonPortNotAllowed, "port is not allowed for this device")
	}
	dev := h.deviceSession(ns, device)
	if dev == nil {
		return 0, nil, deny(api.ReasonDeviceOffline, "device has no live tunnel")
	}

	id, err := newID()
	if err != nil {
		return 0, nil, deny(api.ReasonInternal, "internal error")
	}
	var turn *api.TURNCredentials
	if !req.Direct {
		if turn, err = h.deps.TURN.Mint(ns, id); err != nil {
			h.log.Error("minting TURN credentials failed", "err", err)
			return 0, nil, denyUnavailable("TURN credentials unavailable")
		}
	}
	now := h.now()
	s := &session{
		id: id, kind: api.KindClient, authKind: authKind, ns: ns, device: device, subject: email, saName: saName,
		wgKey: wgPub, wgKeyB64: wgPub.Base64(), createdAt: now, targetPort: req.Port, direct: req.Direct,
		remote: d.remote, tokenExpiry: tokenExp, lastTokenID: tokenID, lastTokenIAT: tokenIAT,
		expiresAt: capExpiry(now.Add(h.cfg.SessionTTL), tokenExp, h.cfg.SessionTTL),
	}
	if turn != nil {
		s.turnExpiry = turn.ExpiresAt
	}
	d.session = id
	if den := h.admit(s); den != nil {
		return 0, nil, den
	}
	// Close the window between the checks above and the registration: a flag
	// flip or a device session ending in between must not leave this session up.
	if again := computeEffective(h.deps.Policy, h.deps.Flags, ns, device); !again.Active {
		h.endSession(s, again.Reason)
		return 0, nil, deny(again.Reason, again.Detail)
	}
	if h.deviceSession(ns, device) == nil {
		h.endSession(s, api.ReasonDeviceOffline)
		return 0, nil, deny(api.ReasonDeviceOffline, "device has no live tunnel")
	}
	return http.StatusCreated, &api.SessionResponse{
		SessionID: id, Kind: api.KindClient, Address: s.ip.String(),
		HubAddress: api.HubAddress, HubPublicKey: h.tunnel.PublicKey().Base64(), HubEndpoint: h.Endpoint(),
		TURN: turn, ExpiresAt: s.expiresAt, RenewAfterSeconds: int(h.cfg.RenewAfter.Seconds()), MTU: api.MTU,
		SplicePort: api.HubSplicePort, TargetPort: req.Port, SSHHostKeys: slices.Clone(dev.hostKeys),
	}, nil
}

// capExpiry limits a session expiry to tokenExp+grace (Keycloak users).
func capExpiry(exp, tokenExp time.Time, grace time.Duration) time.Time {
	if tokenExp.IsZero() {
		return exp
	}
	if lim := tokenExp.Add(grace); lim.Before(exp) {
		return lim
	}
	return exp
}
