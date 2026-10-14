package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// ServeTunnel opens the in-tunnel listeners on the hub overlay address (the
// HTTP API on api.HubAPIPort and the splice listener on api.HubSplicePort) and
// serves them until ctx is done. Nothing else listens on the netstack.
func (h *Hub) ServeTunnel(ctx context.Context) error {
	apiLn, err := h.tunnel.Listen(netip.AddrPortFrom(h.hubAddr, api.HubAPIPort))
	if err != nil {
		return err
	}
	spliceLn, err := h.tunnel.Listen(netip.AddrPortFrom(h.hubAddr, api.HubSplicePort))
	if err != nil {
		_ = apiLn.Close()
		return err
	}
	srv := NewHTTPServer("", h.tunnelHandler())
	srv.ErrorLog = slog.NewLogLogger(h.log.Handler(), slog.LevelDebug)

	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(apiLn) }()
	go func() { errc <- h.serveSplice(ctx, spliceLn) }()
	h.tunnelServing.Store(true)
	defer h.tunnelServing.Store(false)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	_ = srv.Close()
	_ = spliceLn.Close()
	_ = apiLn.Close()
	if err != nil && ctx.Err() == nil && h.ctx.Err() == nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// responseGrace is how long the WireGuard peer of a session ended from inside
// its tunnel stays installed, so that the HTTP response can be delivered.
const responseGrace = 500 * time.Millisecond

// selfEndGrace is the peer grace of a session that ends from inside its own
// tunnel: long enough for the response and for the closed streams' FIN/RST.
func (h *Hub) selfEndGrace() time.Duration { return max(responseGrace, h.cfg.FlushGrace) }

func (h *Hub) tunnelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.RenewPath, h.wrapTunnel("renew", h.handleRenew))
	mux.HandleFunc(api.CloseSessionPath, h.wrapTunnel("close", h.handleClose))
	return mux
}

// tunnelFunc is an in-tunnel endpoint; the session is resolved from the
// connection's source address.
type tunnelFunc func(ctx context.Context, r *http.Request, body []byte, s *session, d *dctx) (int, any, *denial)

func (h *Hub) wrapTunnel(op string, fn tunnelFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := &dctx{op: op, remote: remoteIP(r.RemoteAddr)}
		if r.Method != http.MethodPost {
			den := deny(api.ReasonBadRequest, "POST required")
			den.status = http.StatusMethodNotAllowed
			w.Header().Set("Allow", http.MethodPost)
			h.writeDenial(w, d, den)
			return
		}
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		var s *session
		if err == nil {
			s = h.sessionByAddr(ap.Addr())
		}
		if s == nil {
			h.writeDenial(w, d, deny(api.ReasonSessionUnknown, "no session for this address"))
			return
		}
		d.kind, d.ns, d.device, d.subject, d.session = s.kind, s.ns, s.device, s.subjectLabel(), s.id
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			h.writeDenial(w, d, deny(api.ReasonBadRequest, "unreadable or oversized body"))
			return
		}
		status, resp, den := fn(r.Context(), r, body, s, d)
		if den != nil {
			if den.teardown {
				// The peer stays up for a moment so the denial reaches the client.
				if h.endSessionGrace(s, h.selfEndGrace()) {
					h.met.revocations.WithLabelValues(den.reason).Inc()
				}
			}
			h.writeDenial(w, d, den)
			return
		}
		h.logDecision(d, "allow", "ok", "")
		if resp == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, resp)
	}
}

func (h *Hub) handleClose(_ context.Context, _ *http.Request, _ []byte, s *session, _ *dctx) (int, any, *denial) {
	// The tunnel peer owns its session; ending it needs no further credential
	// (closing only ever reduces access).
	h.endSessionGrace(s, h.selfEndGrace())
	return http.StatusNoContent, nil, nil
}

func (h *Hub) handleRenew(ctx context.Context, r *http.Request, body []byte, s *session, d *dctx) (int, any, *denial) {
	if ok, _ := h.renewLimit.Allow(s.id); !ok {
		return 0, nil, deny(api.ReasonRateLimited, "renewing too often")
	}
	var req api.RenewRequest
	if len(body) > 0 {
		if den := decodeJSON(body, &req); den != nil {
			return 0, nil, den
		}
	}
	tok := bearer(r.Header.Get("Authorization"))
	if tok == "" {
		return 0, nil, deny(api.ReasonUnauthenticated, "bearer token required")
	}
	now := h.now()
	if now.Sub(s.createdAt) > h.cfg.MaxAge {
		return 0, nil, deny(api.ReasonSessionMaxAge, "session exceeded its maximum age")
	}

	// 1. A fresh credential of the kind that created the session.
	var tokenExp time.Time
	switch s.authKind {
	case authDevice:
		if den := h.reauthDevice(ctx, tok, s, now); den != nil {
			return 0, nil, den
		}
	case authKeycloak:
		u, err := h.deps.Users.Authenticate(ctx, tok)
		if err != nil {
			return 0, nil, asDenial(err)
		}
		if u.Email != s.subject {
			return 0, nil, deny(api.ReasonUnauthenticated, "credential does not belong to this session")
		}
		// A renewal needs a freshly issued token, not the one that was already
		// accepted: otherwise a disabled user would keep the tunnel until the
		// old access token expires.
		if !s.acceptToken(u.TokenID, u.IssuedAt) {
			return 0, nil, deny(api.ReasonUnauthenticated, "renewal needs a freshly issued access token")
		}
		tokenExp = u.ExpiresAt
	case authSA:
		if h.deps.SA == nil {
			return 0, nil, deny(api.ReasonForbidden, "delegation is not enabled")
		}
		sa, err := h.deps.SA.Verify(ctx, tok, s.ns, s.device, s.subject)
		if err != nil {
			return 0, nil, asDenial(err)
		}
		if sa.Name != s.saName {
			return 0, nil, deny(api.ReasonUnauthenticated, "credential does not belong to this session")
		}
	default:
		return 0, nil, deny(api.ReasonInternal, "unknown session kind")
	}

	// 2. The full policy, again.
	eff := computeEffective(h.deps.Policy, h.deps.Flags, s.ns, s.device)
	if !eff.Active {
		return 0, nil, deny(eff.Reason, eff.Detail)
	}
	if s.kind == api.KindClient {
		allowed, err := h.deps.Authz.CanExec(ctx, s.subject, s.ns)
		if err != nil {
			h.log.Error("authorization check failed", "ns", s.ns, "err", err)
			return 0, nil, denyUnavailable("authorization backend unavailable")
		}
		if !allowed {
			return 0, nil, deny(api.ReasonForbidden, "no access to this teamspace")
		}
		if den := h.serviceDenialLive(s, eff.Policy); den != nil {
			return 0, nil, den
		}
	} else if reason, detail := deviceStale(s, eff.Policy); reason != "" {
		return 0, nil, deny(staleDenialReason(reason), detail)
	}

	// 3. Extend, capped by max age and the user's token.
	exp := now.Add(h.cfg.SessionTTL)
	if lim := s.createdAt.Add(h.cfg.MaxAge); lim.Before(exp) {
		exp = lim
	}
	s.mu.Lock()
	if !tokenExp.IsZero() {
		s.tokenExpiry = tokenExp
	}
	exp = capExpiry(exp, s.tokenExpiry, h.cfg.SessionTTL)
	s.expiresAt = exp
	rotate := !s.direct && !s.turnExpiry.IsZero() && s.turnExpiry.Sub(now) < h.cfg.TURNRotateLeft
	s.mu.Unlock()

	resp := &api.RenewResponse{ExpiresAt: exp, RenewAfterSeconds: int(h.cfg.RenewAfter.Seconds())}
	if s.kind == api.KindClient {
		h.p2pRenewed(s, req.Path)
	} else if s.hasCap(api.CapP2P) && s.p2pKey != "" {
		// The backstop for a grant push that never arrived: the full set, with
		// the leases that are left (renewals of the device extend nothing).
		set := h.buildGrantSet(s)
		resp.Grants = &set
	}
	if rotate {
		turn, err := h.deps.TURN.Mint(s.ns, s.id)
		if err != nil {
			// Keep the session; the client retries the rotation at the next renewal.
			h.log.Error("rotating TURN credentials failed", "err", err)
		} else {
			s.mu.Lock()
			s.turnExpiry = turn.ExpiresAt
			s.mu.Unlock()
			resp.TURN = turn
		}
	}
	return http.StatusOK, resp, nil
}

func (h *Hub) reauthDevice(ctx context.Context, tok string, s *session, now time.Time) *denial {
	pol, ok := h.deps.Policy.Get(s.ns, s.device)
	if !ok {
		return deny(api.ReasonDeviceUnknown, "no policy for device")
	}
	pin, pub, den := h.loadPin(ctx, s.ns, s.device)
	if den != nil {
		return den
	}
	claims, err := identity.VerifyIdentityJWT(tok, pub, s.subject, now)
	if err != nil {
		return unauthenticatedDenial()
	}
	// A revoked device hears device_revoked, not a statement about its pin.
	if eff := computeEffective(h.deps.Policy, h.deps.Flags, s.ns, s.device); !eff.Active {
		return deny(eff.Reason, eff.Detail)
	}
	if den := h.checkPin(ctx, pin, pub, pol); den != nil {
		return den
	}
	if k, err := wgkey.ParsePublic(claims.WGKey); err != nil || k != s.wgKey {
		return deny(api.ReasonUnauthenticated, "token is not bound to this session's WireGuard key")
	}
	return h.replayDenial("device|"+s.subject, claims)
}
