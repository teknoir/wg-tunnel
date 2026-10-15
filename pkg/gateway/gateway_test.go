package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const (
	alice = "alice@example.com"
	bob   = "bob@example.com"
	host  = "app.vdev-1.teknoir.test"
)

// fakeSession dials a local upstream and records who asked.
type fakeSession struct {
	svc  string
	addr string
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	dials  []string // the "as" of every dial
	dialFn func(as string) error
	closed atomic.Bool
}

func (f *fakeSession) DialAs(ctx context.Context, as string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, as)
	fn := f.dialFn
	f.mu.Unlock()
	if fn != nil {
		if err := fn(as); err != nil {
			return nil, err
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.addr)
}
func (f *fakeSession) Done() <-chan struct{} { return f.done }
func (f *fakeSession) Close() error {
	f.closed.Store(true)
	f.once.Do(func() { close(f.done) })
	return nil
}
func (f *fakeSession) dialed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

type rig struct {
	t        *testing.T
	gw       *Gateway
	srv      *httptest.Server
	upstream *httptest.Server
	logs     *syncBuf

	mu       sync.Mutex
	sessions map[string][]*fakeSession
	create   atomic.Int32
	failMu   sync.Mutex
	failErr  error
	clock    *fakeClock
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newRig(t *testing.T, upstream http.Handler) *rig {
	t.Helper()
	r := &rig{t: t, sessions: map[string][]*fakeSession{}, logs: &syncBuf{}, clock: &fakeClock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}}
	r.upstream = httptest.NewServer(upstream)
	t.Cleanup(r.upstream.Close)
	gw, err := New(Config{
		NewSession: func(_ context.Context, service string) (Session, error) {
			r.create.Add(1)
			if e := r.takeFail(); e != nil {
				return nil, e
			}
			fs := &fakeSession{svc: service, addr: r.upstream.Listener.Addr().String(), done: make(chan struct{})}
			r.mu.Lock()
			r.sessions[service] = append(r.sessions[service], fs)
			r.mu.Unlock()
			return fs, nil
		},
		Logger: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    r.clock.Now, SweepInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.gw = gw
	r.srv = httptest.NewServer(gw)
	t.Cleanup(func() { r.srv.Close(); gw.Close() })
	return r
}

func (r *rig) takeFail() error {
	r.failMu.Lock()
	defer r.failMu.Unlock()
	e := r.failErr
	r.failErr = nil
	return e
}

func (r *rig) failNext(err error) {
	r.failMu.Lock()
	r.failErr = err
	r.failMu.Unlock()
}

func (r *rig) session(service string, i int) *fakeSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.sessions[service]) {
		r.t.Fatalf("service %s: only %d sessions", service, len(r.sessions[service]))
	}
	return r.sessions[service][i]
}

// do sends a request as the ingress would: oauth2-proxy has authenticated user
// and the VirtualService has set the service header.
func (r *rig) do(method, path, user, service string, hdr map[string]string, body io.Reader) *http.Response {
	r.t.Helper()
	req, err := http.NewRequest(method, r.srv.URL+path, body)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Host = host
	if user != "" {
		req.Header.Set(HeaderEmail, user)
	}
	if service != "" {
		req.Header.Set(HeaderService, service)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// echoHeaders is an upstream that returns what it received.
func echoHeaders(w http.ResponseWriter, r *http.Request) {
	h := map[string][]string{}
	for k, v := range r.Header {
		h[k] = v
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"host": r.Host, "path": r.URL.RequestURI(), "method": r.Method, "headers": h})
}

type seen struct {
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Method  string              `json:"method"`
	Headers map[string][]string `json:"headers"`
}

func decodeSeen(t *testing.T, resp *http.Response) seen {
	t.Helper()
	var s seen
	if err := json.Unmarshal([]byte(readBody(t, resp)), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequestHeadersAndCookiesAreStripped(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	resp := r.do("GET", "/dash?x=1", alice, "web", map[string]string{
		"Cookie":                   "_oauth2_proxy=SECRETCOOKIE; app=1; _oauth2_proxy_csrf=CSRF; theme=dark; _oauth2_proxy_1=SPLIT",
		"Authorization":            "Bearer SECRETTOKEN",
		"Proxy-Authorization":      "Basic SECRET",
		"X-Forwarded-Access-Token": "SECRETACCESS",
		"X-Auth-Request-User":      "alice",
		"X-Auth-Request-Groups":    "admins",
		"X-Auth-Request-Token":     "SECRETX",
		"X-Forwarded-User":         "alice",
		"X-Forwarded-Email":        alice,
		"X-Forwarded-Host":         "evil.example",
		"X-Forwarded-Proto":        "http",
		"X-Forwarded-For":          "203.0.113.9",
		"X-Custom":                 "keep",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, readBody(t, resp))
	}
	s := decodeSeen(t, resp)
	for _, k := range []string{"Authorization", "Proxy-Authorization", "X-Forwarded-Access-Token", "X-Auth-Request-Email",
		"X-Auth-Request-User", "X-Auth-Request-Groups", "X-Auth-Request-Token", "X-Ztna-Service", "X-Forwarded-User", "X-Forwarded-Email"} {
		if v, ok := s.Headers[k]; ok {
			t.Errorf("header %s reached the device: %v", k, v)
		}
	}
	if got := s.Headers["Cookie"]; len(got) != 1 || got[0] != "app=1; theme=dark" {
		t.Errorf("cookie = %v, want only the application cookies", got)
	}
	if s.Headers["X-Custom"][0] != "keep" {
		t.Error("an ordinary header was dropped")
	}
	if s.Host != host {
		t.Errorf("upstream Host = %q, want %q", s.Host, host)
	}
	if s.Path != "/dash?x=1" {
		t.Errorf("path = %q", s.Path)
	}
	if got := s.Headers["X-Forwarded-Host"]; len(got) != 1 || got[0] != host {
		t.Errorf("X-Forwarded-Host = %v (the client's value must not survive)", got)
	}
	if got := s.Headers["X-Forwarded-Proto"]; len(got) != 1 || got[0] != "https" {
		t.Errorf("X-Forwarded-Proto = %v", got)
	}
	if got := s.Headers["X-Forwarded-For"]; len(got) != 1 || !strings.HasPrefix(got[0], "203.0.113.9, 127.0.0.1") {
		t.Errorf("X-Forwarded-For = %v", got)
	}
}

func TestCookiesOnlyOAuthIsRemovedEntirely(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	resp := r.do("GET", "/", alice, "web", map[string]string{"Cookie": "_oauth2_proxy=a; _oauth2_proxy_csrf=b"}, nil)
	s := decodeSeen(t, resp)
	if _, ok := s.Headers["Cookie"]; ok {
		t.Errorf("Cookie header survived: %v", s.Headers["Cookie"])
	}
}

func TestResponseSetCookieIsHostOnly(t *testing.T) {
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "sid=abc; Domain=.teknoir.test; Path=/; Secure; HttpOnly; SameSite=Lax")
		w.Header().Add("Set-Cookie", "pref=1; domain=teknoir.test; Max-Age=60")
		w.Header().Add("Set-Cookie", "_oauth2_proxy=EVIL; Domain=.teknoir.test; Path=/")
		w.Header().Add("Set-Cookie", "_oauth2_proxy_csrf=EVIL2; Path=/")
		w.Header().Add("Set-Cookie", "plain=2; Path=/x")
		_, _ = io.WriteString(w, "ok")
	}))
	resp := r.do("GET", "/", alice, "web", nil, nil)
	got := resp.Header.Values("Set-Cookie")
	want := []string{
		"sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
		"pref=1; Max-Age=60",
		"plain=2; Path=/x",
	}
	if len(got) != len(want) {
		t.Fatalf("Set-Cookie = %q, want %q", got, want)
	}
	for i := range want {
		if strings.TrimSpace(got[i]) != want[i] {
			t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIdentityAndServiceRequirements(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	cases := []struct {
		name          string
		user, service string
		want          int
	}{
		{"no user", "", "web", 403},
		{"garbage user", "not an email", "web", 403},
		{"uppercase user is normalised", "ALICE@example.com", "web", 200},
		{"no service", alice, "", 404},
		{"bad service id", alice, "Web_1", 404},
		{"long service id", alice, strings.Repeat("a", 21), 404},
		{"ok", alice, "web", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := r.do("GET", "/x", c.user, c.service, nil, nil)
			if resp.StatusCode != c.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, c.want)
			}
		})
	}
	if n := r.create.Load(); n != 1 {
		t.Errorf("%d sessions created; refused requests must not touch the hub", n)
	}
	// Uppercase was normalised before it went to the hub.
	if got := r.session("web", 0).dialed(); len(got) == 0 || got[0] != alice {
		t.Errorf("dialed as %v", got)
	}
}

func TestHealthEndpointsOnlyWithoutServiceHeader(t *testing.T) {
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "app "+r.URL.Path) }))
	for _, p := range []string{"/healthz", "/readyz"} {
		resp := r.do("GET", p, "", "", nil, nil)
		if resp.StatusCode != 200 || !strings.HasPrefix(readBody(t, resp), "ok") {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	// The same path through the ingress belongs to the device's app.
	resp := r.do("GET", "/healthz", alice, "web", nil, nil)
	if b := readBody(t, resp); b != "app /healthz" {
		t.Errorf("proxied /healthz = %q", b)
	}
}

func TestCSRFOriginRules(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	good := "https://" + host
	cases := []struct {
		method, origin string
		upgrade        bool
		want           int
	}{
		{"GET", "", false, 200},
		{"GET", "https://evil.example", false, 200},
		{"HEAD", "", false, 200},
		{"POST", "", false, 403},
		{"POST", "null", false, 403},
		{"POST", "https://evil.example", false, 403},
		{"POST", "http://" + host, false, 403},
		{"POST", "https://" + host + ".evil.example", false, 403},
		{"POST", good, false, 200},
		{"POST", strings.ToUpper(good), false, 200},
		{"PUT", "", false, 403},
		{"PATCH", "", false, 403},
		{"DELETE", "", false, 403},
		{"DELETE", good, false, 200},
		{"GET", "", true, 403},
		{"GET", "https://evil.example", true, 403},
	}
	for _, c := range cases {
		hdr := map[string]string{}
		if c.origin != "" {
			hdr["Origin"] = c.origin
		}
		if c.upgrade {
			hdr["Connection"], hdr["Upgrade"] = "Upgrade", "websocket"
		}
		resp := r.do(c.method, "/x", alice, "web", hdr, nil)
		if resp.StatusCode != c.want {
			t.Errorf("%s origin=%q upgrade=%v: status %d, want %d", c.method, c.origin, c.upgrade, resp.StatusCode, c.want)
		}
	}
	// A refused request never reached the device.
	for _, as := range r.session("web", 0).dialed() {
		if as != alice {
			t.Errorf("dialed as %q", as)
		}
	}
}

// wsUpstream accepts an Upgrade, answers 101 and echoes bytes.
func wsUpstream(t *testing.T, gotHeaders chan<- http.Header) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "no upgrade", 400)
			return
		}
		if gotHeaders != nil {
			gotHeaders <- r.Header.Clone()
		}
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(c, rw)
	})
}

func TestWebSocketUpgradeThroughTheGateway(t *testing.T) {
	hdrs := make(chan http.Header, 1)
	r := newRig(t, wsUpstream(t, hdrs))
	c, err := net.Dial("tcp", r.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET /socket HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://" + host + "\r\n" +
		"X-Auth-Request-Email: " + alice + "\r\nX-Ztna-Service: web\r\nCookie: _oauth2_proxy=SECRET; app=1\r\n" +
		"Authorization: Bearer SECRET\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for i, msg := range []string{"hello", strings.Repeat("x", 100_000)} {
		go func() { _, _ = io.WriteString(c, msg) }()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %d: %v", i, err)
		}
	}
	h := <-hdrs
	if h.Get("Cookie") != "app=1" || h.Get("Authorization") != "" || h.Get("X-Auth-Request-Email") != "" {
		t.Errorf("upgrade request was not scrubbed: cookie=%q auth=%q", h.Get("Cookie"), h.Get("Authorization"))
	}
	if !strings.EqualFold(h.Get("Upgrade"), "websocket") || h.Get("Sec-WebSocket-Key") == "" {
		t.Errorf("upgrade headers lost: %v", h)
	}
	if got := r.session("web", 0).dialed(); len(got) != 1 || got[0] != alice {
		t.Errorf("dialed %v", got)
	}
	// While the socket is open the session counts as in use.
	r.clock.Advance(time.Hour)
	r.gw.pool.sweep(15 * time.Minute)
	if r.session("web", 0).closed.Load() {
		t.Error("a session with an open WebSocket was closed as idle")
	}
	_ = c.Close()
}

func TestOneSessionPerServiceNotPerUser(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := alice
			if i%2 == 1 {
				user = bob
			}
			resp := r.do("GET", "/", user, "web", nil, nil)
			if resp.StatusCode != 200 {
				t.Errorf("status %d", resp.StatusCode)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
	}
	wg.Wait()
	if n := r.create.Load(); n != 1 {
		t.Fatalf("%d sessions for one service and two users, want 1", n)
	}
	if resp := r.do("GET", "/", alice, "admin", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("second service: %d", resp.StatusCode)
	}
	if n := r.create.Load(); n != 2 {
		t.Fatalf("%d sessions for two services, want 2", n)
	}
	if r.gw.Sessions() != 2 {
		t.Errorf("pool has %d sessions", r.gw.Sessions())
	}
	// Connections are carried per user: every dial names the user it serves.
	seen := map[string]bool{}
	for _, as := range r.session("web", 0).dialed() {
		seen[as] = true
	}
	if !seen[alice] || !seen[bob] || len(seen) != 2 {
		t.Errorf("dialed as %v", seen)
	}
}

func TestUpstreamConnectionsAreNeverSharedBetweenUsers(t *testing.T) {
	var conns sync.Map
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RemoteAddr)
	}))
	up.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Store(c.RemoteAddr().String(), true)
		}
	}
	up.Start()
	r := newRig(t, http.NotFoundHandler())
	r.upstream.Close()
	r.upstream = up
	t.Cleanup(up.Close)

	addr := func(resp *http.Response) string { return readBody(t, resp) }
	a1 := addr(r.do("GET", "/", alice, "web", nil, nil))
	a2 := addr(r.do("GET", "/", alice, "web", nil, nil))
	b1 := addr(r.do("GET", "/", bob, "web", nil, nil))
	b2 := addr(r.do("GET", "/", bob, "web", nil, nil))
	if a1 != a2 {
		t.Error("a user's keep-alive connection was not reused")
	}
	if b1 != b2 {
		t.Error("a second user's keep-alive connection was not reused")
	}
	if a1 == b1 {
		t.Fatal("two users shared one upstream connection")
	}
	got := r.session("web", 0).dialed()
	if len(got) != 2 {
		t.Errorf("dials = %v, want one per user", got)
	}
}

func TestSessionEndsAndIsRecreated(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	first := r.session("web", 0)
	_ = first.Close() // the hub ended it (revocation, admin end, expiry)
	deadline := time.Now().Add(5 * time.Second)
	for r.gw.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d after the session ended", resp.StatusCode)
	}
	if n := r.create.Load(); n != 2 {
		t.Errorf("%d sessions created, want a new one after the first ended", n)
	}
}

func TestIdleSessionsAreClosed(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	r.do("GET", "/", alice, "web", nil, nil)
	r.do("GET", "/", alice, "other", nil, nil)
	r.clock.Advance(10 * time.Minute)
	r.do("GET", "/", alice, "other", nil, nil) // keeps "other" alive
	r.clock.Advance(6 * time.Minute)
	r.gw.pool.sweep(15 * time.Minute)
	if !r.session("web", 0).closed.Load() {
		t.Error("the idle session was not closed after 16 minutes")
	}
	if r.session("other", 0).closed.Load() {
		t.Error("a session used 6 minutes ago was closed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.gw.Sessions() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.gw.Sessions() != 1 {
		t.Errorf("pool has %d sessions, want 1", r.gw.Sessions())
	}
	// The next request quietly creates it again.
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := r.create.Load(); n != 3 {
		t.Errorf("%d sessions created, want 3", n)
	}
}

func TestHubRefusalsBecomeHTTPStatuses(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	dial := func(reason string) {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, s := range r.sessions["web"] {
			s.mu.Lock()
			s.dialFn = func(string) error { return &wgclient.DialError{Reason: reason} }
			s.mu.Unlock()
		}
	}
	r.do("GET", "/", alice, "web", nil, nil) // create the session
	type page struct {
		status int
		title  string
	}
	for reason, want := range map[string]page{
		api.ReasonForbidden:       {403, "No access"},
		api.ReasonDeviceOffline:   {503, "Device offline"},
		api.ReasonDeviceRevoked:   {403, "Access blocked"},
		api.ReasonDeviceDisabled:  {403, "Access disabled"},
		api.ReasonPendingApproval: {503, "Device not ready"},
		api.ReasonReenroll:        {503, "Device reconnecting"},
		// A refused target is not "access switched off" (seen on staging:
		// a virtual device's agent refusing ClusterIPs outside its networks).
		api.ReasonServiceDenied:  {403, "Service refused"},
		api.ReasonPortNotAllowed: {403, "Service refused"},
		api.ReasonSessionLimit:   {503, "Busy"},
		api.ReasonInternal:       {502, "Device unreachable"},
	} {
		dial(reason)
		r.gw.pool.mu.Lock()
		for _, e := range r.gw.pool.m {
			e.mu.Lock()
			for _, u := range e.up {
				u.tr.CloseIdleConnections()
			}
			e.up = map[string]*upstream{}
			e.mu.Unlock()
		}
		r.gw.pool.mu.Unlock()
		resp := r.do("GET", "/", alice, "web", map[string]string{"Accept": "text/html"}, nil)
		if resp.StatusCode != want.status {
			t.Errorf("reason %s: status %d, want %d", reason, resp.StatusCode, want.status)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("reason %s: content type %q", reason, ct)
		}
		b := readBody(t, resp)
		if strings.Contains(b, reason) {
			t.Errorf("internal reason code leaked into the page: %q", b)
		}
		if !strings.Contains(b, want.title) {
			t.Errorf("reason %s: page does not say %q: %q", reason, want.title, b)
		}
	}
}

func TestSessionCreationFailures(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	r.failNext(&wgclient.Error{Status: 409, Reason: api.ReasonDeviceOffline})
	resp := r.do("GET", "/", alice, "web", nil, nil)
	if resp.StatusCode != 503 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// Remembered briefly: a burst of requests does not retry the hub every time.
	for range 5 {
		r.do("GET", "/", alice, "web", nil, nil)
	}
	if n := r.create.Load(); n != 1 {
		t.Errorf("%d creations during the backoff, want 1", n)
	}
	r.clock.Advance(3 * time.Second)
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d after the backoff", resp.StatusCode)
	}
	r.failNext(errors.New("boom"))
	r.clock.Advance(3 * time.Second)
	if resp := r.do("GET", "/", alice, "other", nil, nil); resp.StatusCode != 502 {
		t.Fatalf("unknown failure: status %d", resp.StatusCode)
	}
}

func TestLogsCarryNoSecrets(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	r.do("GET", "/page?token=QUERYSECRET", alice, "web", map[string]string{
		"Cookie": "_oauth2_proxy=COOKIESECRET; app=APPSECRET", "Authorization": "Bearer AUTHSECRET",
		"X-Forwarded-Access-Token": "ACCESSSECRET",
	}, nil)
	r.do("POST", "/page", alice, "web", nil, nil) // refused: csrf
	logs := r.logs.String()
	for _, s := range []string{"QUERYSECRET", "COOKIESECRET", "APPSECRET", "AUTHSECRET", "ACCESSSECRET", "Bearer", "Cookie"} {
		if strings.Contains(logs, s) {
			t.Errorf("log contains %q:\n%s", s, logs)
		}
	}
	if !strings.Contains(logs, `"outcome":"csrf"`) || !strings.Contains(logs, `"service":"web"`) || !strings.Contains(logs, alice) {
		t.Errorf("log lacks the structured fields:\n%s", logs)
	}
}

func TestStreamingResponsesAreFlushed(t *testing.T) {
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: one\n\n")
		fl.Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "data: two\n\n")
		fl.Flush()
	}))
	resp := r.do("GET", "/events", alice, "web", nil, nil)
	br := bufio.NewReader(resp.Body)
	start := time.Now()
	line, err := br.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event %q, %v", line, err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Error("the first event was held back until the response ended")
	}
}

func TestStripHelpers(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "a=1; _oauth2_proxy=x")
	h.Add("Cookie", "b=2; _oauth2_proxy_1=y;c=3")
	filterCookies(h, nil)
	if got := h.Get("Cookie"); got != "a=1; b=2; c=3" {
		t.Errorf("cookies = %q", got)
	}
	for in, want := range map[string]string{
		"a=b; Domain=x.com":                   "a=b",
		"a=b; domain=x.com; Path=/":           "a=b; Path=/",
		"a=b; Path=/; DOMAIN = x.com; Secure": "a=b; Path=/; Secure",
		"_oauth2_proxy=v; Path=/":             "",
		"a=b; Path=/domain":                   "a=b; Path=/domain",
	} {
		if got := stripCookieDomain(in, nil); got != want {
			t.Errorf("stripCookieDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// The platform's real oauth2-proxy cookie is _teknoir_oauth2_proxy (and may be
// split into _0/_1); none of the platform login cookies may cross the gateway,
// in either direction.
func TestPlatformLoginCookiesNeverCrossTheGateway(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "app=1; _teknoir_oauth2_proxy=S; _teknoir_oauth2_proxy_csrf=C")
	h.Add("Cookie", "_Teknoir_Oauth2_Proxy_0=a; _teknoir_oauth2_proxy_1=b; KEYCLOAK_IDENTITY=k; keycloak_session=s; AUTH_SESSION_ID=x; extra=9; theme=dark")
	filterCookies(h, []string{"Extra"})
	if got := h.Get("Cookie"); got != "app=1; theme=dark" {
		t.Errorf("cookies = %q, want only the application's own", got)
	}
	h = http.Header{}
	h.Set("Cookie", "_teknoir_oauth2_proxy=S")
	filterCookies(h, nil)
	if h.Get("Cookie") != "" {
		t.Errorf("Cookie header survived: %q", h.Get("Cookie"))
	}
	for _, in := range []string{
		"_teknoir_oauth2_proxy=v; Path=/; Domain=x.com",
		"_teknoir_oauth2_proxy_0=v",
		"KEYCLOAK_SESSION=v; Path=/",
		"AUTH_SESSION_ID=v",
		"mine=v; Path=/; Domain=x",
	} {
		got := stripCookieDomain(in, nil)
		if strings.HasPrefix(in, "mine") {
			if got != "mine=v; Path=/" {
				t.Errorf("stripCookieDomain(%q) = %q", in, got)
			}
		} else if got != "" {
			t.Errorf("stripCookieDomain(%q) = %q, want dropped", in, got)
		}
	}
	if stripCookieDomain("sticky=1; Path=/", []string{"STICKY"}) != "" {
		t.Error("configured STRIP_COOKIES name not dropped from Set-Cookie")
	}
	// End to end through the proxy.
	r := newRig(t, http.HandlerFunc(echoHeaders))
	resp := r.do("GET", "/", alice, "web", map[string]string{"Cookie": "_teknoir_oauth2_proxy=SECRET; app=1"}, nil)
	if body := readBody(t, resp); strings.Contains(body, "SECRET") || strings.Contains(body, "_teknoir_oauth2") {
		t.Errorf("device saw the platform session cookie: %s", body)
	}
}

func TestDeadTunnelDropsTheSession(t *testing.T) {
	r := newRig(t, http.HandlerFunc(echoHeaders))
	r.do("GET", "/", alice, "web", nil, nil)
	first := r.session("web", 0)
	// Break the path below the hub's protocol: no refusal, just an error.
	first.mu.Lock()
	first.dialFn = func(string) error { return errors.New("i/o timeout") }
	first.mu.Unlock()
	r.gw.pool.mu.Lock()
	for _, e := range r.gw.pool.m {
		e.mu.Lock()
		e.up = map[string]*upstream{}
		e.mu.Unlock()
	}
	r.gw.pool.mu.Unlock()
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !first.closed.Load() {
		t.Error("the session with a dead tunnel was kept")
	}
	// A refusal from the hub is a different thing and keeps the session.
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d after the session was rebuilt", resp.StatusCode)
	}
	second := r.session("web", 1)
	second.mu.Lock()
	second.dialFn = func(string) error { return &wgclient.DialError{Reason: api.ReasonDeviceOffline} }
	second.mu.Unlock()
	r.gw.pool.mu.Lock()
	for _, e := range r.gw.pool.m {
		e.mu.Lock()
		e.up = map[string]*upstream{}
		e.mu.Unlock()
	}
	r.gw.pool.mu.Unlock()
	if resp := r.do("GET", "/", alice, "web", nil, nil); resp.StatusCode != 503 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if second.closed.Load() {
		t.Error("a refusal closed the session")
	}
}

func TestKeepAliveConnectionsAreRecycled(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.RemoteAddr) }))
	t.Cleanup(up.Close)
	r := newRig(t, http.NotFoundHandler())
	r.upstream.Close()
	r.upstream = up
	a1 := readBody(t, r.do("GET", "/", alice, "web", nil, nil))
	r.clock.Advance(20 * time.Second)
	a2 := readBody(t, r.do("GET", "/", alice, "web", nil, nil))
	if a1 != a2 {
		t.Error("a young keep-alive connection was not reused")
	}
	r.clock.Advance(20 * time.Second) // 40 s since the transport was created: past ConnMaxAge
	a3 := readBody(t, r.do("GET", "/", alice, "web", nil, nil))
	if a3 == a2 {
		t.Error("a keep-alive connection outlived ConnMaxAge: the user would not be re-authorized")
	}
	if got := r.session("web", 0).dialed(); len(got) != 2 {
		t.Errorf("dials = %v", got)
	}
}

// One user cannot take the shared session: the per-user slots are held for the
// life of every connection (upgraded ones included) and shared by all of the
// user's transports (review finding 4).
func TestPerUserConnectionCap(t *testing.T) {
	old := semWait
	semWait = 50 * time.Millisecond
	t.Cleanup(func() { semWait = old })
	r := newRig(t, http.HandlerFunc(echoHeaders))
	r.do("GET", "/", alice, "web", nil, nil) // creates the session
	fs := r.session("web", 0)
	e := &entry{sems: map[string]chan struct{}{}}
	sem := e.sem(alice, 2)
	if e.sem(alice, 99) != sem {
		t.Fatal("the semaphore of a user is not shared")
	}
	trA, trB := newTransport(fs, alice, sem), newTransport(fs, alice, sem) // e.g. a retired and a fresh transport
	c1, err := trA.DialContext(context.Background(), "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := trB.DialContext(context.Background(), "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	_, err = trB.DialContext(context.Background(), "tcp", "x")
	var de *wgclient.DialError
	if !errors.As(err, &de) || de.Reason != api.ReasonSessionLimit {
		t.Fatalf("third dial: %v, want session_limit", err)
	}
	// Another user is unaffected.
	if c, err := newTransport(fs, bob, e.sem(bob, 2)).DialContext(context.Background(), "tcp", "x"); err != nil {
		t.Fatalf("bob: %v", err)
	} else {
		_ = c.Close()
	}
	_ = c1.Close()
	_ = c1.Close() // closing twice frees one slot only
	c3, err := trB.DialContext(context.Background(), "tcp", "x")
	if err != nil {
		t.Fatalf("after a close: %v", err)
	}
	_ = c2.Close()
	_ = c3.Close()
	if len(sem) != 0 {
		t.Errorf("%d slots leaked", len(sem))
	}
	// A failed dial gives its slot back.
	fs.mu.Lock()
	fs.dialFn = func(string) error { return errors.New("boom") }
	fs.mu.Unlock()
	if _, err := trA.DialContext(context.Background(), "tcp", "x"); err == nil || len(sem) != 0 {
		t.Errorf("failed dial: err %v, %d slots held", err, len(sem))
	}
}
