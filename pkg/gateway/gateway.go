// Package gateway is the web gateway of a device: an HTTP reverse proxy that
// publishes the device's web services (api.ServiceSpec with Web set) to
// browsers through the platform ingress, over the ZTNA tunnel.
//
// It runs as a second container in the per-device wgt- pod. The ingress
// (Istio + oauth2-proxy) has already authenticated the user and routes each
// service host to this proxy with the header X-Ztna-Service; an
// AuthorizationPolicy admits only the ingress gateway's principal. The
// gateway holds ONE delegated hub session per service (never per user, see
// pkg/wgclient DialAs); every upstream connection names its user
// (ConnectRequest.As) and the hub authorizes that user with a
// SubjectAccessReview before the device is dialled.
//
// Nothing here logs headers, cookies, query strings or tokens.
package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
	"github.com/teknoir/wg-tunnel/pkg/version"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// Config configures a Gateway.
type Config struct {
	// HubURL is the hub's internal session API, e.g.
	// http://wg-hub.teknoir-ztna.svc.cluster.local:8081.
	HubURL string
	// Namespace and Device identify the device this gateway serves.
	Namespace, Device string
	// TokenFile holds the projected service-account token (audience api.SATokenAudience).
	TokenFile string
	// IdleTimeout closes a service's session after this long without requests
	// (default 15 min); the next request creates it again.
	IdleTimeout time.Duration
	// CreateTimeout bounds creating a session including the WireGuard
	// handshake (default 30 s).
	CreateTimeout time.Duration
	// ConnMaxAge bounds how long keep-alive connections to a device are reused
	// (default 30 s): each connection is authorized for its user when it is
	// opened, so this is the delay after which a revoked user's next request
	// is checked again.
	ConnMaxAge time.Duration
	// StripCookies lists extra cookie names (case-insensitive, exact) that are
	// never forwarded to the device nor accepted from it, on top of the built-in
	// platform rules (see platformCookie). Set from STRIP_COOKIES.
	StripCookies []string
	// SweepInterval is how often idle sessions are looked for (default 1 min).
	SweepInterval time.Duration
	// Logger receives one structured line per request (default: discard).
	Logger *slog.Logger
	// WGOptions adjusts the wgclient options of the default session factory
	// (timeouts in tests).
	WGOptions func(*wgclient.Options)
	// NewSession overrides how sessions are created (tests); the default
	// creates delegated wgclient sessions with Direct UDP to the hub.
	NewSession SessionFactory
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Gateway is an http.Handler plus the janitor that closes idle sessions.
type Gateway struct {
	cfg  Config
	log  *slog.Logger
	pool *pool

	stop    chan struct{}
	stopped sync.Once
	done    chan struct{}
}

// New creates the gateway and starts its janitor; call Close to stop it.
func New(cfg Config) (*Gateway, error) {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 15 * time.Minute
	}
	if cfg.CreateTimeout <= 0 {
		cfg.CreateTimeout = 30 * time.Second
	}
	if cfg.ConnMaxAge <= 0 {
		cfg.ConnMaxAge = 30 * time.Second
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.NewSession == nil {
		f, err := wgSessionFactory(cfg)
		if err != nil {
			return nil, err
		}
		cfg.NewSession = f
	}
	g := &Gateway{cfg: cfg, log: cfg.Logger, stop: make(chan struct{}), done: make(chan struct{})}
	g.pool = newPool(cfg.NewSession, cfg.CreateTimeout, cfg.Now)
	go g.janitor()
	return g, nil
}

func (g *Gateway) janitor() {
	defer close(g.done)
	t := time.NewTicker(g.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			g.pool.sweep(g.cfg.IdleTimeout)
		}
	}
}

// Close ends every session and stops the janitor.
func (g *Gateway) Close() {
	g.stopped.Do(func() { close(g.stop) })
	<-g.done
	g.pool.closeAll()
}

// Sessions returns the number of pooled sessions (diagnostics and tests).
func (g *Gateway) Sessions() int { return g.pool.size() }

// wgSessionFactory creates the delegated hub session of one service.
func wgSessionFactory(cfg Config) (SessionFactory, error) {
	if cfg.HubURL == "" || cfg.Namespace == "" || cfg.Device == "" || cfg.TokenFile == "" {
		return nil, errors.New("gateway: HubURL, Namespace, Device and TokenFile are required")
	}
	cred := func(context.Context, string) (string, error) {
		b, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return "", errors.New("reading the service account token failed")
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", errors.New("the service account token is empty")
		}
		return tok, nil
	}
	return func(ctx context.Context, service string) (Session, error) {
		o := wgclient.Options{
			HubURL: cfg.HubURL, Kind: api.KindClient, Direct: true, Credential: cred,
			ClientRequest: &api.ClientSessionRequest{
				Namespace: cfg.Namespace, Device: cfg.Device, Service: service,
				Posture: api.Posture{Software: "web-gateway", Version: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH},
			},
			Logger: cfg.Logger.With("component", "wgclient", "service", service),
		}
		if cfg.WGOptions != nil {
			cfg.WGOptions(&o)
		}
		return wgclient.Create(ctx, o)
	}, nil
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Probes hit the pod directly and carry no X-Ztna-Service; everything that
	// came through the ingress does (the VirtualService sets it), so a device
	// application's own /healthz is still proxied.
	if r.Header.Get(HeaderService) == "" && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
		g.health(w, r)
		return
	}
	start := g.cfg.Now()
	lw := &logWriter{ResponseWriter: w}
	var svcID, user, outcome string
	defer func() {
		status := lw.status
		if status == 0 && lw.hijacked {
			status = http.StatusSwitchingProtocols
		}
		g.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.String("service", svcID),
			slog.String("user", user), slog.Int("status", status), slog.Int64("bytes", lw.bytes),
			slog.Bool("upgrade", isUpgrade(r.Header)), slog.String("outcome", outcome),
			slog.Duration("took", g.cfg.Now().Sub(start)))
	}()

	// The user: set by oauth2-proxy behind ext_authz. The AuthorizationPolicy
	// admits only the ingress gateway, so the header is trusted here.
	user = strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderEmail)))
	if !validEmail(user) {
		user, outcome = "", "no-user"
		g.deny(lw, r, http.StatusForbidden, "Sign-in required", "This page is only available to signed-in users.")
		return
	}
	svcID = r.Header.Get(HeaderService)
	if !svc.ValidID(svcID) {
		svcID, outcome = "", "bad-service"
		g.deny(lw, r, http.StatusNotFound, "Not found", "There is no such service.")
		return
	}
	// CSRF: requests that change state, and WebSocket upgrades (which carry
	// the user's cookies cross-site), must come from this very host.
	if (unsafeMethod(r.Method) || isUpgrade(r.Header)) && !originOK(r.Header.Get("Origin"), r.Host) {
		outcome = "csrf"
		g.deny(lw, r, http.StatusForbidden, "Request blocked", "The request did not come from this page (Origin check failed).")
		return
	}

	e, err := g.pool.acquire(r.Context(), svcID)
	if err != nil {
		outcome = outcomeOf(err)
		if r.Context().Err() == nil {
			g.fail(lw, r, err)
		}
		return
	}
	defer g.pool.release(e)

	tr := e.transport(user, g.cfg.Now(), g.cfg.ConnMaxAge, func(as string) *http.Transport { return newTransport(e.sess, as) })
	invalidate := func() { g.pool.invalidate(e) }
	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			rewrite(pr, svcID, g.cfg.StripCookies)
		},
		ModifyResponse: func(resp *http.Response) error {
			sanitizeSetCookies(resp.Header, g.cfg.StripCookies)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			outcome = outcomeOf(err)
			if r.Context().Err() != nil {
				return // the browser went away
			}
			var te *tunnelError
			if errors.As(err, &te) {
				// The path through the hub is dead (peer removed, hub restarted):
				// do not keep a session that cannot reach the device.
				invalidate()
			}
			g.fail(w, r, err)
		},
	}
	rp.ServeHTTP(lw, r)
	if outcome == "" {
		outcome = "ok"
	}
}

// upstreamHost is the (meaningless, never resolved) host of the outgoing
// request; the Transport's dial goes to the session regardless of it.
func upstreamHost(svcID string) string { return svcID + ".ztna.invalid" }

// rewrite builds the outgoing request: scrubbed, pointed at the service, with
// the forwarding headers set (the client's own are never trusted: ReverseProxy
// removes X-Forwarded-* and Forwarded from Out before this runs).
func rewrite(pr *httputil.ProxyRequest, svcID string, stripCookies []string) {
	in, out := pr.In, pr.Out
	out.URL.Scheme = "http"
	out.URL.Host = upstreamHost(svcID)
	out.Host = in.Host
	stripRequestHeaders(out.Header, stripCookies)
	// The peer is the ingress gateway (nothing else is admitted); its
	// X-Forwarded-For chain is the real client path.
	ip := peerIP(in.RemoteAddr)
	if prior := in.Header.Get("X-Forwarded-For"); prior != "" && ip != "" {
		out.Header.Set("X-Forwarded-For", prior+", "+ip)
	} else if ip != "" {
		out.Header.Set("X-Forwarded-For", ip)
	} else if prior != "" {
		out.Header.Set("X-Forwarded-For", prior)
	}
	out.Header.Set("X-Forwarded-Host", in.Host)
	out.Header.Set("X-Forwarded-Proto", "https")
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	return host
}

// dialTimeout bounds one upstream dial including the hub's answer.
const dialTimeout = 15 * time.Second

// tunnelError marks a dial that failed below the hub's protocol (no answer, no
// path): the session itself is suspect, unlike a refusal.
type tunnelError struct{ err error }

func (e *tunnelError) Error() string { return "tunnel: " + e.err.Error() }
func (e *tunnelError) Unwrap() error { return e.err }

// newTransport dials every connection through the session for one user.
func newTransport(sess Session, as string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			c, err := sess.DialAs(ctx, as)
			var de *wgclient.DialError
			var he *wgclient.Error
			if err != nil && !errors.As(err, &de) && !errors.As(err, &he) && !errors.Is(err, wgclient.ErrSessionClosed) {
				err = &tunnelError{err}
			}
			return c, err
		},
		DisableCompression:  true, // pass encodings through untouched
		MaxConnsPerHost:     6,
		MaxIdleConnsPerHost: 2, // idle connections occupy the session's connection slots
		IdleConnTimeout:     10 * time.Second,
		ForceAttemptHTTP2:   false,
	}
}

func (g *Gateway) health(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/readyz" && g.cfg.TokenFile != "" {
		if _, err := os.Stat(g.cfg.TokenFile); err != nil {
			http.Error(w, "service account token missing", http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// outcomeOf names the failure class for the log line.
func outcomeOf(err error) string {
	var de *wgclient.DialError
	var he *wgclient.Error
	switch {
	case errors.As(err, &de):
		return "refused:" + de.Reason
	case errors.As(err, &he):
		return "hub:" + he.Reason
	case errors.As(err, new(*tunnelError)):
		return "tunnel-error"
	case errors.Is(err, errClosed):
		return "shutdown"
	}
	return "upstream-error"
}

// fail answers a failed upstream or session setup.
func (g *Gateway) fail(w http.ResponseWriter, r *http.Request, err error) {
	reason := ""
	var de *wgclient.DialError
	var he *wgclient.Error
	switch {
	case errors.As(err, &de):
		reason = de.Reason
	case errors.As(err, &he):
		reason = he.Reason
	}
	status, title, msg := http.StatusBadGateway, "Device unreachable", "The device did not answer. It may be busy or its web service may be down."
	switch reason {
	case api.ReasonForbidden:
		status, title, msg = http.StatusForbidden, "No access", "Your account may not open this device."
	case api.ReasonDeviceRevoked, api.ReasonDeviceDisabled, api.ReasonPendingApproval, api.ReasonNotEnrolled,
		api.ReasonReenroll, api.ReasonServiceDenied, api.ReasonPortNotAllowed:
		status, title, msg = http.StatusForbidden, "Access disabled", "Remote access to this device is switched off."
	case api.ReasonServiceUnknown:
		status, title, msg = http.StatusNotFound, "Not found", "This service is not published on the device any more."
	case api.ReasonDeviceOffline:
		status, title, msg = http.StatusServiceUnavailable, "Device offline", "The device is not connected right now. Try again when it is back online."
	case api.ReasonSessionLimit, api.ReasonRateLimited:
		status, title, msg = http.StatusServiceUnavailable, "Busy", "Too many connections to this device. Try again in a moment."
		w.Header().Set("Retry-After", "5")
	default:
		if errors.Is(err, errClosed) {
			status, title, msg = http.StatusServiceUnavailable, "Restarting", "The gateway is restarting. Try again in a moment."
		}
	}
	g.deny(w, r, status, title, msg)
}

// deny writes a short error page (HTML for browsers, text otherwise).
func (g *Gateway) deny(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, errorPage, html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg), status)
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s: %s\n", title, msg)
}

const errorPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1b1f24;--mut:#5d6672;--card:#fff;--line:#dfe3e8}
@media(prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e8eaed;--mut:#9aa3ad;--card:#1d2125;--line:#2d333a}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:30rem;margin:16px;padding:28px 32px;background:var(--card);border:1px solid var(--line);border-radius:10px}
h1{margin:0 0 8px;font-size:1.25rem}p{margin:0;color:var(--mut)}small{display:block;margin-top:16px;color:var(--mut)}
</style></head><body><main><h1>%s</h1><p>%s</p><small>HTTP %d</small></main></body></html>`

// logWriter records status and size and stays compatible with
// http.ResponseController (Flush, Hijack for WebSocket upgrades).
type logWriter struct {
	http.ResponseWriter
	status   int
	bytes    int64
	hijacked bool
}

func (l *logWriter) WriteHeader(code int) {
	if l.status == 0 {
		l.status = code
	}
	l.ResponseWriter.WriteHeader(code)
}

func (l *logWriter) Write(p []byte) (int, error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err := l.ResponseWriter.Write(p)
	l.bytes += int64(n)
	return n, err
}

func (l *logWriter) Flush() { _ = http.NewResponseController(l.ResponseWriter).Flush() }

func (l *logWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	l.hijacked = true
	return http.NewResponseController(l.ResponseWriter).Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (l *logWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }
