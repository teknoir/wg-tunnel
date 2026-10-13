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
// creation) plus /healthz and /readyz. The caller wraps it in an http.Server
// with the hub's timeouts (see NewHTTPServer).
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.DeviceEnrollPath, h.wrap("enroll", h.handleEnroll))
	mux.HandleFunc(api.DeviceSessionPath, h.wrap("session", h.handleDeviceSession))
	mux.HandleFunc(api.ClientSessionPath, h.wrap("session", h.handleClientSession))
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

// wrap adds the common prelude: method, per-source rate limit (before anything
// is parsed or allocated), body limit, JSON rendering and the decision line.
func (h *Hub) wrap(op string, fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := &dctx{op: op, remote: h.clientIP(r)}
		if r.Method != http.MethodPost {
			den := deny(api.ReasonBadRequest, "POST required")
			den.status = http.StatusMethodNotAllowed
			w.Header().Set("Allow", http.MethodPost)
			h.writeDenial(w, d, den)
			return
		}
		if ok, retry := h.ipLimit.Allow(d.remote); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			h.writeDenial(w, d, deny(api.ReasonRateLimited, "too many requests"))
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

func (h *Hub) replayDenial(key string, claims *api.DeviceClaims) *denial {
	until := time.Unix(claims.ExpiresAt, 0).Add(api.MaxClockSkew)
	switch err := h.replay.Check(key+"|"+claims.ID, until); {
	case errors.Is(err, errReplay):
		return deny(api.ReasonReplay, "token already used")
	case err != nil:
		return deny(api.ReasonRateLimited, "replay cache full")
	}
	return nil
}

func (h *Hub) subjectDenial(key string) *denial {
	if ok, _ := h.subjLimit.Allow(key); !ok {
		return deny(api.ReasonRateLimited, "too many requests for this subject")
	}
	return nil
}

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
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid token")
	}
	ns, device, ok := splitSubject(sub)
	if !ok {
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid token subject")
	}
	d.ns, d.device, d.subject = ns, device, sub

	pol, ok := h.deps.Policy.Get(ns, device)
	if !ok {
		return 0, nil, deny(api.ReasonDeviceUnknown, "no policy for device")
	}
	now := h.now()
	claims, err := identity.VerifyEnrollJWT(tok, []byte(pol.RSAPublicCert), sub, now)
	if err != nil {
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid enrollment token")
	}
	idPub, err := identity.ParsePublicKey(req.IdentityPublicKey)
	if err != nil {
		return 0, nil, deny(api.ReasonBadRequest, "invalid identity public key")
	}
	if !sameKey(claims.IdentityKey, req.IdentityPublicKey) {
		return 0, nil, deny(api.ReasonUnauthenticated, "token identity key does not match request")
	}
	if err := identity.VerifyEnrollProof(idPub, sub, claims.ID, req.Proof); err != nil {
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid proof of possession")
	}
	if den := h.replayDenial("enroll|"+sub, claims); den != nil {
		return 0, nil, den
	}
	if den := h.subjectDenial("enroll|" + sub); den != nil {
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

	cur, found, err := h.deps.Identity.Get(ctx, ns, device)
	if err != nil {
		h.log.Error("reading identity pin failed", "ns", ns, "device", device, "err", err)
		return 0, nil, denyUnavailable("identity store unavailable")
	}
	if found && cur.EnrollmentGeneration >= pol.EnrollmentGeneration {
		return h.enrollResult(ctx, cur, req.IdentityPublicKey, false, d)
	}
	if !now.Before(pol.EnrollUntil) {
		return 0, nil, deny(api.ReasonEnrollClosed, "enrollment window is closed")
	}
	got, created, err := h.deps.Identity.Pin(ctx, api.IdentityEntry{
		Device: device, Namespace: ns,
		IdentityPublicKey:    identity.EncodePublicKey(idPub),
		Fingerprint:          fingerprint,
		EnrollmentGeneration: pol.EnrollmentGeneration,
		EnrolledAt:           now,
	})
	if err != nil {
		h.log.Error("pinning identity failed", "ns", ns, "device", device, "err", err)
		return 0, nil, denyUnavailable("identity store unavailable")
	}
	return h.enrollResult(ctx, got, req.IdentityPublicKey, created, d)
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

// pinnedKey loads the identity pin of a device and checks it against the
// current policy generation.
func (h *Hub) pinnedKey(ctx context.Context, ns, device string, pol api.PolicyEntry) (ed25519.PublicKey, int64, *denial) {
	pin, found, err := h.deps.Identity.Get(ctx, ns, device)
	switch {
	case err != nil:
		h.log.Error("reading identity pin failed", "ns", ns, "device", device, "err", err)
		return nil, 0, denyUnavailable("identity store unavailable")
	case !found:
		return nil, 0, deny(api.ReasonNotEnrolled, "device identity is not enrolled")
	case pin.EnrollmentGeneration < pol.EnrollmentGeneration:
		return nil, 0, deny(api.ReasonReenroll, "enrollment was reset; enroll a new identity")
	}
	pub, err := identity.ParsePublicKey(pin.IdentityPublicKey)
	if err != nil {
		h.log.Error("pinned identity key is malformed", "ns", ns, "device", device)
		return nil, 0, deny(api.ReasonInternal, "pinned identity is invalid")
	}
	return pub, pin.EnrollmentGeneration, nil
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
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid token")
	}
	ns, device, ok := splitSubject(sub)
	if !ok {
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid token subject")
	}
	d.ns, d.device, d.subject = ns, device, sub

	pol, ok := h.deps.Policy.Get(ns, device)
	if !ok {
		return 0, nil, deny(api.ReasonDeviceUnknown, "no policy for device")
	}
	pub, gen, den := h.pinnedKey(ctx, ns, device, pol)
	if den != nil {
		return 0, nil, den
	}
	now := h.now()
	claims, err := identity.VerifyIdentityJWT(tok, pub, sub, now)
	if err != nil {
		return 0, nil, deny(api.ReasonUnauthenticated, "invalid identity token")
	}
	wgPub, err := wgkey.ParsePublic(req.WGPublicKey)
	if err != nil {
		return 0, nil, deny(api.ReasonBadRequest, "invalid WireGuard public key")
	}
	if tokKey, err := wgkey.ParsePublic(claims.WGKey); err != nil || tokKey != wgPub {
		return 0, nil, deny(api.ReasonUnauthenticated, "token is not bound to this WireGuard key")
	}
	if den := h.replayDenial("device|"+sub, claims); den != nil {
		return 0, nil, den
	}
	if den := h.subjectDenial("device|" + sub); den != nil {
		return 0, nil, den
	}
	if den := validPosture(req.Posture, "wg-agent"); den != nil {
		return 0, nil, den
	}
	eff := computeEffective(h.deps.Policy, h.deps.Flags, ns, device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
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
	s := &session{
		id: id, kind: api.KindDevice, authKind: authDevice, ns: ns, device: device, subject: sub,
		wgKey: wgPub, wgKeyB64: wgPub.Base64(), createdAt: now, generation: gen,
		hostKeys: sanitizeHostKeys(req.SSHHostKeys), remote: d.remote,
		expiresAt: now.Add(h.cfg.SessionTTL), turnExpiry: turn.ExpiresAt,
	}
	d.session = id
	if den := h.admit(s); den != nil {
		return 0, nil, den
	}
	// An annotation may have flipped between the check and the registration.
	if again := computeEffective(h.deps.Policy, h.deps.Flags, ns, device); !again.Active {
		h.endSession(s, again.Reason)
		return 0, nil, deny(again.Reason, again.Detail)
	}
	return http.StatusCreated, &api.SessionResponse{
		SessionID: id, Kind: api.KindDevice, Address: s.ip.String(),
		HubAddress: api.HubAddress, HubPublicKey: h.tunnel.PublicKey().Base64(), HubEndpoint: h.Endpoint(),
		TURN: turn, ExpiresAt: s.expiresAt, RenewAfterSeconds: int(h.cfg.RenewAfter.Seconds()), MTU: api.MTU,
		AllowedPorts: slices.Clone(eff.Policy.AllowedPorts),
	}, nil
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
		email, tokenExp = u.Email, u.ExpiresAt
	}
	d.subject = email
	if authKind == authSA {
		d.subject = email + " via sa:" + saName
	}
	if req.Direct && authKind != authSA {
		return 0, nil, deny(api.ReasonForbidden, "direct UDP is only available to in-cluster clients")
	}
	if den := h.subjectDenial("client|" + email); den != nil {
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
		remote: d.remote, tokenExpiry: tokenExp,
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
