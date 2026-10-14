package wgclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

func okCred(context.Context, string) (string, error) { return "t", nil }

func validClient() Options {
	return Options{
		HubURL: "https://wg.example.com", Kind: api.KindClient, Credential: okCred,
		ClientRequest: &api.ClientSessionRequest{Namespace: "ns", Device: "d", Port: 22},
	}
}

func TestOptionsValidate(t *testing.T) {
	dev := Options{HubURL: "https://wg-device.example.com:8084", Kind: api.KindDevice, Credential: okCred, DeviceRequest: &api.DeviceSessionRequest{}}
	if err := dev.Validate(); err != nil {
		t.Fatalf("valid device options: %v", err)
	}
	if err := validClient().Validate(); err != nil {
		t.Fatalf("valid client options: %v", err)
	}
	mod := func(f func(*Options)) Options { o := validClient(); f(&o); return o }
	cases := map[string]Options{
		"no hub url":                  mod(func(o *Options) { o.HubURL = "" }),
		"plain http, public host":     mod(func(o *Options) { o.HubURL = "http://wg.teknoir.cloud" }),
		"plain http, lookalike svc":   mod(func(o *Options) { o.HubURL = "http://wg-hub.svc.evil.com:8081" }),
		"plain http, private address": mod(func(o *Options) { o.HubURL = "http://10.0.0.5:8081" }),
		"ftp scheme":                  mod(func(o *Options) { o.HubURL = "ftp://x" }),
		"no host":                     mod(func(o *Options) { o.HubURL = "https://" }),
		"userinfo":                    mod(func(o *Options) { o.HubURL = "https://u:p@wg.example.com" }),
		"query":                       mod(func(o *Options) { o.HubURL = "https://wg.example.com/?x=1" }),
		"no credential":               mod(func(o *Options) { o.Credential = nil }),
		"unknown kind":                mod(func(o *Options) { o.Kind = "robot" }),
		"client no request":           mod(func(o *Options) { o.ClientRequest = nil }),
		"client no device":            mod(func(o *Options) { o.ClientRequest.Device = "" }),
		"client no ns":                mod(func(o *Options) { o.ClientRequest.Namespace = "" }),
		"client port 0":               mod(func(o *Options) { o.ClientRequest.Port = 0 }),
		"client port big":             mod(func(o *Options) { o.ClientRequest.Port = 70000 }),
		"both requests":               mod(func(o *Options) { o.DeviceRequest = &api.DeviceSessionRequest{} }),
		"bad override":                mod(func(o *Options) { o.TURNServerOverride = "a b:3478" }),
		"device no request":           {HubURL: "https://x", Kind: api.KindDevice, Credential: okCred},
	}
	for name, o := range cases {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := Create(context.Background(), o); err == nil {
			t.Errorf("%s: Create accepted", name)
		}
	}
}

func TestDecodeError(t *testing.T) {
	cases := []struct {
		status int
		body   string
		reason string
		denial bool
	}{
		{403, `{"reason":"device_revoked","message":"flagged compromised"}`, api.ReasonDeviceRevoked, true},
		{401, `<html>login</html>`, api.ReasonUnauthenticated, true},
		{302, ``, api.ReasonUnauthenticated, true},
		{403, `nope`, api.ReasonForbidden, true},
		{429, `{"reason":"rate_limited"}`, api.ReasonRateLimited, false},
		{502, `bad gateway`, api.ReasonInternal, false},
		{500, `{"reason":"internal"}`, api.ReasonInternal, false},
		{409, `{"reason":"enroll_conflict"}`, api.ReasonEnrollConflict, true},
		{404, `{"reason":"Bad Reason!\n\u001b[31m"}`, "adeason31m", true},
	}
	for _, c := range cases {
		e := decodeError(c.status, strings.NewReader(c.body))
		if e.Status != c.status || e.Reason != c.reason || e.Denial() != c.denial {
			t.Errorf("%d %q: got %+v denial=%v", c.status, c.body, e, e.Denial())
		}
		if strings.ContainsAny(e.Error(), "\n\x1b") {
			t.Errorf("error text not sanitised: %q", e.Error())
		}
	}
	long := decodeError(400, strings.NewReader(`{"reason":"bad_request","message":"`+strings.Repeat("a", 5000)+`"}`))
	if len(long.Message) > 210 {
		t.Errorf("message not truncated: %d", len(long.Message))
	}
	multi := decodeError(400, strings.NewReader(`{"reason":"bad_request","message":"line1\nline2"}`))
	if strings.Contains(multi.Message, "\n") {
		t.Errorf("newline kept: %q", multi.Message)
	}
	wrapped := errors.Join(errors.New("x"), decodeError(403, strings.NewReader(`{"reason":"forbidden"}`)))
	if ReasonOf(wrapped) != api.ReasonForbidden || ReasonOf(errors.New("y")) != "" {
		t.Error("ReasonOf")
	}
}

func TestTURNServer(t *testing.T) {
	cases := []struct {
		urls     []string
		override string
		want     string
		bad      bool
	}{
		{[]string{"turn:turn.example.com:3478?transport=udp"}, "", "turn.example.com:3478", false},
		{[]string{"turn:turn.example.com?transport=udp"}, "", "turn.example.com:3478", false},
		{[]string{"turn:turn.example.com:4000"}, "", "turn.example.com:4000", false},
		{[]string{"turn:[2001:db8::1]:3478?transport=udp"}, "", "[2001:db8::1]:3478", false},
		{[]string{"turn:turn.example.com:3478?transport=udp"}, "127.0.0.1:5000", "127.0.0.1:5000", false},
		{[]string{"turn:turn.example.com:3478?transport=udp"}, "192.168.2.166", "192.168.2.166:3478", false},
		{[]string{"turns:turn.example.com:5349?transport=tcp", "turn:b.example.com:3478?transport=udp"}, "", "b.example.com:3478", false},
		{[]string{"turn:turn.example.com:3478?transport=tcp"}, "", "", true},
		{[]string{"stun:turn.example.com:3478"}, "", "", true},
		{[]string{"turn:host:99999"}, "", "", true},
		{[]string{"turn:"}, "", "", true},
		{nil, "", "", true},
	}
	for _, c := range cases {
		got, err := turnServer(c.urls, c.override)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("%v override %q: got %q, %v; want %q (bad=%v)", c.urls, c.override, got, err, c.want, c.bad)
		}
	}
}

func TestCreateRejectsBadResponses(t *testing.T) {
	_, hubPub, _ := wgkey.Generate()
	good := api.SessionResponse{
		SessionID: "s1", Kind: api.KindClient, Address: "100.96.0.7", HubAddress: api.HubAddress,
		HubPublicKey: hubPub.Base64(), HubEndpoint: "10.0.0.1:51820", ExpiresAt: time.Now().Add(time.Minute),
		RenewAfterSeconds: 60, MTU: 1280, SplicePort: 2222, TargetPort: 22,
		TURN: &api.TURNCredentials{URLs: []string{"turn:t.example.com:3478"}, Username: "u", Password: "p"},
	}
	mutate := map[string]func(*api.SessionResponse){
		"wrong kind":      func(r *api.SessionResponse) { r.Kind = api.KindDevice },
		"hub address":     func(r *api.SessionResponse) { r.HubAddress = "10.0.0.9" },
		"hub key":         func(r *api.SessionResponse) { r.HubPublicKey = "AAAA" },
		"outside overlay": func(r *api.SessionResponse) { r.Address = "10.1.2.3" },
		"hub as address":  func(r *api.SessionResponse) { r.Address = api.HubAddress },
		"v6 address":      func(r *api.SessionResponse) { r.Address = "fd00::1" },
		"endpoint":        func(r *api.SessionResponse) { r.HubEndpoint = "hub.example.com:51820" },
		"mtu":             func(r *api.SessionResponse) { r.MTU = 100 },
		"no renew":        func(r *api.SessionResponse) { r.RenewAfterSeconds = 0 },
		"no turn":         func(r *api.SessionResponse) { r.TURN = nil },
		"tcp turn":        func(r *api.SessionResponse) { r.TURN.URLs = []string{"turn:t:3478?transport=tcp"} },
		"turn user":       func(r *api.SessionResponse) { r.TURN.Username = "" },
		"splice port":     func(r *api.SessionResponse) { r.SplicePort = -1 },
	}
	for name, m := range mutate {
		r := good
		tc := *good.TURN
		r.TURN = &tc
		m(&r)
		if err := checkResponse(validClient(), &r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkResponse(validClient(), &good); err != nil {
		t.Fatalf("good response rejected: %v", err)
	}
}

func TestDoJSONDoesNotLeakOrFollowRedirects(t *testing.T) {
	var other int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/ok" {
			if r.Header.Get("Authorization") != "Bearer secret-token" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("headers: %v", r.Header)
			}
			_, _ = w.Write([]byte(`{"x":1}`))
			return
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	o := Options{}
	c := o.httpClient()
	var out map[string]int
	if err := doJSON(context.Background(), c, srv.URL+"/v1/ok", "secret-token", map[string]string{"a": "b"}, &out); err != nil || out["x"] != 1 {
		t.Fatalf("%v %v", err, out)
	}
	err := doJSON(context.Background(), c, srv.URL+"/redir", "secret-token", nil, nil)
	var he *Error
	if !errors.As(err, &he) || he.Reason != api.ReasonUnauthenticated || other != 0 {
		t.Fatalf("redirect: %v (followed=%d)", err, other)
	}
	// Credentials with whitespace are refused before anything is sent.
	if err := doJSON(context.Background(), c, srv.URL+"/v1/ok", "bad token", nil, nil); err == nil || strings.Contains(err.Error(), "bad token") {
		t.Fatalf("got %v", err)
	}
	// A transport error mentions neither the credential nor the body.
	srv.Close()
	err = doJSON(context.Background(), c, srv.URL+"/v1/ok", "secret-token", map[string]string{"k": "very-secret-body"}, nil)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks: %v", err)
	}
}

func TestHandshakeTimeoutOnDeadEndpoint(t *testing.T) {
	_, hubPub, _ := wgkey.Generate()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"sessionId":"s","kind":"client","address":"100.96.0.9","hubAddress":"100.96.0.1","hubPublicKey":"` +
			hubPub.Base64() + `","hubEndpoint":"127.0.0.1:9","expiresAt":"2099-01-01T00:00:00Z","renewAfterSeconds":60,"mtu":1280}`))
	}))
	defer srv.Close()
	o := validClient()
	o.HubURL, o.Direct, o.HandshakeTimeout = srv.URL, true, 300*time.Millisecond
	start := time.Now()
	_, err := Create(context.Background(), o)
	if !errors.Is(err, ErrHandshakeTimeout) || time.Since(start) > 5*time.Second {
		t.Fatalf("got %v after %s", err, time.Since(start))
	}
	// Cancelling the context aborts the wait too.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	o.HandshakeTimeout = time.Minute
	if _, err := Create(ctx, o); err == nil {
		t.Fatal("Create ignored its context")
	}
}

func TestPlainHTTPOnlyForInClusterAndLoopback(t *testing.T) {
	for _, ok := range []string{
		"http://wg-hub.teknoir-ztna.svc:8081", "http://wg-hub.teknoir-ztna.svc.cluster.local:8081", "http://WG-HUB.teknoir-ztna.svc",
		"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://wg.teknoir.cloud", "https://10.0.0.5:8443",
	} {
		o := validClient()
		o.HubURL = ok
		if err := o.Validate(); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://wg.teknoir.cloud", "http://wg-hub.svc.evil.com", "http://evilsvc", "http://svc", "http://10.0.0.5:8081",
		"http://wg.teknoir.cloud:8080/svc", "http://127.0.0.1.evil.com", "http://localhost.evil.com",
	} {
		o := validClient()
		o.HubURL = bad
		err := o.Validate()
		if err == nil {
			t.Errorf("%s accepted: the Keycloak token would travel in the clear", bad)
		} else if !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: unhelpful error %v", bad, err)
		}
	}
}

// With the product defaults a single failed renewal on an idle tunnel (the hub
// sends nothing between renewals) must not end the session.
func TestDeadTunnelToleratesOneFailedRenewalWithProductDefaults(t *testing.T) {
	now := time.Now()
	s := &Session{opts: Options{}, started: now.Add(-10 * time.Minute)}
	s.resp.RenewAfterSeconds = 60
	failure := errors.New("context deadline exceeded") // transport level

	// Renewed OK a minute ago; the next renewal just timed out: 60 s of silence
	// is more than DeadAfter (50 s) but less than a renewal cycle plus a retry.
	s.lastRenewOK = now.Add(-(60*time.Second + 15*time.Second))
	if err := s.deadTunnel(failure); err != nil {
		t.Fatalf("one blip ended an idle session: %v", err)
	}
	// Silent for far longer than that: dead.
	s.lastRenewOK = now.Add(-3 * time.Minute)
	if err := s.deadTunnel(failure); !errors.Is(err, ErrTunnelDead) {
		t.Fatalf("got %v, want ErrTunnelDead", err)
	}
	// A successful renewal counts as activity, however old the last packet is.
	s.lastRenewOK = time.Now()
	if err := s.deadTunnel(failure); err != nil {
		t.Fatalf("just renewed, yet dead: %v", err)
	}
	// Answers from the hub and credential failures say nothing about the tunnel.
	s.lastRenewOK = time.Time{}
	if err := s.deadTunnel(&Error{Status: 403, Reason: api.ReasonForbidden}); err != nil {
		t.Fatalf("hub answer: %v", err)
	}
	if err := s.deadTunnel(&credentialError{errors.New("x")}); err != nil {
		t.Fatalf("credential failure: %v", err)
	}
	// An explicit DeadAfter above the floor wins; the floor is never lower than
	// one renewal cycle.
	s.opts.DeadAfter = 10 * time.Minute
	s.started = now.Add(-5 * time.Minute)
	if err := s.deadTunnel(failure); err != nil {
		t.Fatalf("DeadAfter ignored: %v", err)
	}
	if got := (&Session{opts: Options{DeadAfter: time.Second, RenewTimeout: time.Second, RenewRetry: time.Second}, resp: api.SessionResponse{RenewAfterSeconds: 2}}).deadLimit(); got != 4*time.Second {
		t.Fatalf("deadLimit %v, want 4s (renewAfter + timeout + retry)", got)
	}
}

// A Create that fails (here: the handshake never completes) must release
// everything it built: WireGuard device, netstack, sockets and goroutines.
func TestFailedCreateLeaksNothing(t *testing.T) {
	_, hubPub, _ := wgkey.Generate()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"sessionId":"s","kind":"client","address":"100.96.0.9","hubAddress":"100.96.0.1","hubPublicKey":"` +
			hubPub.Base64() + `","hubEndpoint":"127.0.0.1:9","expiresAt":"2099-01-01T00:00:00Z","renewAfterSeconds":60,"mtu":1280}`))
	}))
	defer srv.Close()
	o := validClient()
	o.HubURL, o.Direct, o.HandshakeTimeout = srv.URL, true, 100*time.Millisecond

	attempt := func() {
		if _, err := Create(context.Background(), o); !errors.Is(err, ErrHandshakeTimeout) {
			t.Fatalf("got %v", err)
		}
	}
	attempt() // warm up lazily started runtime goroutines
	time.Sleep(300 * time.Millisecond)
	before := runtime.NumGoroutine()
	for range 5 {
		attempt()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d over 5 failed Creates", before, runtime.NumGoroutine())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPlaneBFailureBackoffAndCallerCancellation(t *testing.T) {
	pc := &p2pClient{}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	pc.fail(cancelled, time.Now())
	if pc.skipUntil.Load() != 0 || pc.failures.Load() != 0 || pc.failedHS.Load() != 0 {
		t.Fatal("a failure caused by the caller was recorded")
	}
	// Real failures back off: 30 s, 60 s, 120 s, ... capped at p2pRetryMax.
	var prev time.Duration
	for i := range 8 {
		before := time.Now()
		pc.fail(context.Background(), time.Time{})
		d := time.Unix(0, pc.skipUntil.Load()).Sub(before)
		if i == 0 && (d < p2pRetryAfter-time.Second || d > p2pRetryAfter+time.Second) {
			t.Fatalf("first skip %v, want about %v", d, p2pRetryAfter)
		}
		if d < prev-time.Second || d > p2pRetryMax+time.Second {
			t.Fatalf("skip %d: %v (previous %v, max %v)", i, d, prev, p2pRetryMax)
		}
		prev = d
	}
	if prev < p2pRetryMax-time.Second {
		t.Fatalf("the backoff stopped at %v", prev)
	}
	// A zero handshake (a refusal) leaves the marker alone; a real one sets it.
	if pc.failedHS.Load() != 0 {
		t.Fatal("a refusal marked the handshake as dead")
	}
	hs := time.Now()
	pc.fail(context.Background(), hs)
	if pc.failedHS.Load() != hs.UnixNano() {
		t.Fatal("the failed handshake was not recorded")
	}
}
