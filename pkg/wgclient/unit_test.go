package wgclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
		"no hub url":        mod(func(o *Options) { o.HubURL = "" }),
		"ftp scheme":        mod(func(o *Options) { o.HubURL = "ftp://x" }),
		"no host":           mod(func(o *Options) { o.HubURL = "https://" }),
		"userinfo":          mod(func(o *Options) { o.HubURL = "https://u:p@wg.example.com" }),
		"query":             mod(func(o *Options) { o.HubURL = "https://wg.example.com/?x=1" }),
		"no credential":     mod(func(o *Options) { o.Credential = nil }),
		"unknown kind":      mod(func(o *Options) { o.Kind = "robot" }),
		"client no request": mod(func(o *Options) { o.ClientRequest = nil }),
		"client no device":  mod(func(o *Options) { o.ClientRequest.Device = "" }),
		"client no ns":      mod(func(o *Options) { o.ClientRequest.Namespace = "" }),
		"client port 0":     mod(func(o *Options) { o.ClientRequest.Port = 0 }),
		"client port big":   mod(func(o *Options) { o.ClientRequest.Port = 70000 }),
		"both requests":     mod(func(o *Options) { o.DeviceRequest = &api.DeviceSessionRequest{} }),
		"bad override":      mod(func(o *Options) { o.TURNServerOverride = "a b:3478" }),
		"device no request": {HubURL: "https://x", Kind: api.KindDevice, Credential: okCred},
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
