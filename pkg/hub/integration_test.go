package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// wgPeer is a WireGuard client or device on its own netstack, talking to the
// hub over direct UDP on loopback.
type wgPeer struct {
	dev  *device.Device
	net  *netstack.Net
	addr netip.Addr
}

func startPeer(t *testing.T, priv wgkey.PrivateKey, addr, hubPubB64, endpoint string) *wgPeer {
	t.Helper()
	return startPeerAllowed(t, priv, addr, hubPubB64, endpoint, api.HubAddress+"/32")
}

// startPeerAllowed is startPeer with a custom AllowedIPs for the hub peer (to
// let a hostile peer try to send to other overlay addresses).
func startPeerAllowed(t *testing.T, priv wgkey.PrivateKey, addr, hubPubB64, endpoint, allowed string) *wgPeer {
	t.Helper()
	a := netip.MustParseAddr(addr)
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{a}, nil, api.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	hubHex, err := wgkey.Base64ToHex(hubPubB64)
	if err != nil {
		t.Fatal(err)
	}
	cfg := "private_key=" + priv.Hex() + "\n" +
		"public_key=" + hubHex + "\nendpoint=" + endpoint + "\n" +
		"allowed_ip=" + allowed + "\npersistent_keepalive_interval=1\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &wgPeer{dev: dev, net: tnet, addr: a}
}

func (p *wgPeer) httpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:       p.net.DialContext,
			DisableKeepAlives: true,
		},
	}
}

// wgRig is a hub with real WireGuard, the in-tunnel listeners running, and a
// device with an echo server behind its overlay address.
type wgRig struct {
	*rig
	devSess devSess
	devPeer *wgPeer
	cancel  context.CancelFunc
}

func newWGDeviceRig(t *testing.T, opts ...rigOpt) *wgRig {
	t.Helper()
	return newWGDeviceRigHook(t, nil, opts...)
}

// newWGDeviceRigHook is newWGDeviceRig with a hook that runs on the hub before
// anything is served (to wrap the tunnel).
func newWGDeviceRigHook(t *testing.T, hook func(*Hub), opts ...rigOpt) *wgRig {
	t.Helper()
	r := newWGRig(t, opts...)
	if hook != nil {
		hook(r.h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := make(chan error, 1)
	go func() { served <- r.h.ServeTunnel(ctx) }()
	waitFor(t, "hub ready", r.h.Ready)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("ServeTunnel: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ServeTunnel did not stop")
		}
	})

	ds := r.deviceSessionOK()
	endpoint := r.h.Endpoint()
	dp := startPeer(t, ds.priv, ds.Address, ds.HubPublicKey, endpoint)
	ln, err := dp.net.ListenTCPAddrPort(netip.AddrPortFrom(dp.addr, 22))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { // echo server on the device's overlay :22
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	// The hub learns the device endpoint from its first keepalive.
	hubDev := rawTunnel(r.h).dev
	waitFor(t, "device endpoint learned by hub", func() bool {
		out, _ := hubDev.IpcGet()
		return strings.Contains(out, "endpoint=")
	})
	return &wgRig{rig: r, devSess: ds, devPeer: dp, cancel: cancel}
}

// connectClient creates a client session and returns its WireGuard peer.
func (w *wgRig) connectClient(token string, mut func(*api.ClientSessionRequest)) (*wgPeer, api.SessionResponse, int, []byte) {
	w.t.Helper()
	req, priv := w.clientReq(22)
	if mut != nil {
		mut(&req)
	}
	st, body := w.clientSession(token, req)
	if st != http.StatusCreated {
		return nil, api.SessionResponse{}, st, body
	}
	var resp api.SessionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		w.t.Fatal(err)
	}
	return startPeer(w.t, priv, resp.Address, resp.HubPublicKey, w.h.Endpoint()), resp, st, body
}

func dialSplice(p *wgPeer) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.net.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, "2222"))
}

func echo(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo %q != %q", buf, msg)
	}
	_ = c.SetDeadline(time.Time{})
}

func hubPeerCount(r *rig) int {
	out, _ := rawTunnel(r.h).dev.IpcGet()
	return strings.Count(out, "public_key=")
}

func TestIntegrationClientToDeviceAndRevocation(t *testing.T) {
	w := newWGDeviceRig(t)
	client, cs, _, _ := w.connectClient(aliceToken, nil)
	if client == nil {
		t.Fatal("client session refused")
	}

	c, err := dialSplice(client)
	if err != nil {
		t.Fatalf("dial splice: %v", err)
	}
	defer func() { _ = c.Close() }()
	echo(t, c, "hello through the hub")
	echo(t, c, strings.Repeat("0123456789", 500)) // multi-segment

	// A second, concurrent connection on the same session.
	c2, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	echo(t, c2, "second")

	// Half-close: the device echo server sees EOF and closes after the client
	// shut down its write side; the client still reads what was in flight.
	if hubPeerCount(w.rig) != 2 {
		t.Fatalf("hub peers %d, want 2", hubPeerCount(w.rig))
	}

	// ---- Operator marks the device compromised (hub path only). ----
	readErr := make(chan error, 2)
	for _, conn := range []net.Conn{c, c2} {
		go func() {
			_, err := conn.Read(make([]byte, 1))
			readErr <- err
		}()
	}
	t0 := time.Now()
	w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	for range 2 {
		select {
		case err := <-readErr:
			if err == nil {
				t.Fatal("unexpected data on a revoked connection")
			}
		case <-time.After(time.Second):
			t.Fatal("spliced connection still open 1s after the device was flagged")
		}
	}
	t.Logf("spliced connections closed %v after the flag change", time.Since(t0))

	// Peers are gone from the data plane, synchronously with the sessions.
	waitFor(t, "peers removed", func() bool { return hubPeerCount(w.rig) == 0 })
	if d, n := w.h.sessionCounts(); d != 0 || n != 0 {
		t.Fatalf("sessions left: %d/%d", d, n)
	}

	// New sessions are refused with device_revoked, for the client and the device.
	req, _ := w.clientReq(22)
	st, body := w.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceRevoked)
	tok, dreq, _ := w.dev.sessionRequest(t, w.clock.Now())
	st, body = w.post(api.DeviceSessionPath, tok, dreq)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceRevoked)

	// The old client peer can no longer reach the hub.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := client.net.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, "2222")); err == nil {
		_ = conn.Close()
		t.Fatal("revoked client could still open a connection")
	}
	_ = cs
}

func TestIntegrationRevocationViaControllerPathAlone(t *testing.T) {
	w := newWGDeviceRig(t)
	client, _, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	echo(t, c, "x")
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	p := w.policy
	p.State = api.StateRevoked
	p.Reasons = []string{api.RevokeHealthCheckFailed}
	w.setPolicy(p)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection survived a policy revocation")
	}
}

func TestIntegrationHealthCheckFlagAndClear(t *testing.T) {
	w := newWGDeviceRig(t)
	client, _, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	echo(t, c, "x")
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection survived a failed health check")
	}
	// Clearing the flag alone does not bring the old tunnel back: the device
	// session is gone, so clients see device_offline until the agent returns
	// (after re-enrollment when the controller bumped the generation).
	w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
	req, _ := w.clientReq(22)
	st, body := w.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusConflict, api.ReasonDeviceOffline)
}

func TestIntegrationRenewWithMismatchedCredential(t *testing.T) {
	w := newWGDeviceRig(t)
	client, cs, _, _ := w.connectClient(aliceToken, nil)
	hc := client.httpClient()
	renew := func(tok string) (int, []byte) {
		w.addSecret(tok)
		req, _ := http.NewRequest(http.MethodPost, "http://"+api.HubAddress+"/v1/renew", strings.NewReader("{}"))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("renew over the tunnel: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// Valid renewal with the session's own credential.
	st, body := renew(aliceToken)
	if st != http.StatusOK {
		t.Fatalf("renew: %d %s", st, body)
	}
	var rr api.RenewResponse
	_ = json.Unmarshal(body, &rr)
	if rr.ExpiresAt.IsZero() {
		t.Fatalf("renew response %s", body)
	}

	// Another valid user's token is refused, and the session is torn down.
	w.users.set("bob-token", "bob@example.com", w.clock.Now().Add(time.Minute))
	w.authz.set("bob@example.com", testNS, true)
	w.h.renewLimit.Forget(cs.SessionID)
	st, body = renew("bob-token")
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	waitFor(t, "client session torn down", func() bool { _, n := w.h.sessionCounts(); return n == 0 })
	// The device session is unaffected.
	if d, _ := w.h.sessionCounts(); d != 1 {
		t.Fatal("device session must survive a bad client renewal")
	}
}

func TestIntegrationDeviceSessionCannotUseSplice(t *testing.T) {
	w := newWGDeviceRig(t)
	// The device (a device-kind session) dials the splice port.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := w.devPeer.net.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, "2222"))
	if err != nil {
		// The TCP handshake itself may be refused; either way there is no path.
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("SSH-2.0-evil\r\n"))
	n, err := c.Read(make([]byte, 64))
	if n != 0 || err == nil {
		t.Fatalf("device-kind session got %d bytes from the splice port (err %v)", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("hub left the connection open instead of closing it")
	}
	waitFor(t, "denial logged", func() bool { return strings.Contains(w.logs.String(), "only client sessions may connect") })
}

func TestIntegrationSplicePortUnknownSource(t *testing.T) {
	// A WireGuard peer that is not a session cannot exist (the hub only knows
	// session peers); an established session whose peer was removed loses its
	// path. Verify the latter: end the session, then try to connect.
	w := newWGDeviceRig(t)
	client, cs, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "x")
	_ = c.Close()
	hc := client.httpClient()
	resp, err := hc.Post("http://"+api.HubAddress+"/v1/close", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("close -> %d", resp.StatusCode)
	}
	waitFor(t, "session closed", func() bool { _, n := w.h.sessionCounts(); return n == 0 })
	waitFor(t, "peer removed after the grace period", func() bool { return hubPeerCount(w.rig) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := client.net.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, "2222")); err == nil {
		_ = conn.Close()
		t.Fatal("closed session could still connect")
	}
	_ = cs
}

func TestIntegrationDelegatedDirectSessionAndConnLimit(t *testing.T) {
	w := newWGDeviceRig(t, func(c *Config) { c.MaxConnsPerSession = 2 })
	w.sa.add("sa-token-SECRET", "term-cam-1", testNS, testDevice)
	client, _, st, body := w.connectClient("sa-token-SECRET", func(q *api.ClientSessionRequest) {
		q.OnBehalfOf, q.Direct, q.Posture.Software = aliceEmail, true, "web-terminal"
	})
	if client == nil {
		t.Fatalf("delegated session: %d %s", st, body)
	}
	c1, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c1.Close() }()
	echo(t, c1, "one")
	c2, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	echo(t, c2, "two")

	// The third concurrent connection exceeds the per-session cap.
	c3, err := dialSplice(client)
	if err == nil {
		defer func() { _ = c3.Close() }()
		_ = c3.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c3.Write([]byte("three"))
		if n, rerr := c3.Read(make([]byte, 8)); n != 0 || rerr == nil {
			t.Fatalf("connection over the cap was spliced (%d bytes, %v)", n, rerr)
		}
	}
	// Losing the user's access closes the next connection at once (SAR per connection).
	c1b, c2b := c1, c2
	_ = c1b.Close()
	_ = c2b.Close()
	waitFor(t, "slots freed", func() bool { return w.rig.h.sessionByAddr(client.addr).connCount() == 0 })
	w.authz.set(aliceEmail, testNS, false)
	c4, err := dialSplice(client)
	if err == nil {
		defer func() { _ = c4.Close() }()
		_ = c4.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c4.Write([]byte("four"))
		if n, rerr := c4.Read(make([]byte, 8)); n != 0 || rerr == nil {
			t.Fatalf("connection of a user without access was spliced (%d bytes, %v)", n, rerr)
		}
	}
}

func TestIntegrationDeviceReplacementClosesOldStreams(t *testing.T) {
	w := newWGDeviceRig(t)
	client, _, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	echo(t, c, "x")
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	// The agent restarts: a new session from the same pinned identity.
	_ = w.deviceSessionOK()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("streams to the replaced device session stayed open")
	}
}

func TestLogsNeverContainCredentials(t *testing.T) {
	w := newWGDeviceRig(t)
	client, cs, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "payload-that-must-not-be-logged-XYZ")
	_ = c.Close()

	// Exercise success and failure paths with distinctive credentials.
	w.addSecret(aliceToken)
	hc := client.httpClient()
	for _, tok := range []string{aliceToken, "wrong-bearer-token-SECRET"} {
		w.addSecret(tok)
		w.h.renewLimit.Forget(cs.SessionID)
		req, _ := http.NewRequest(http.MethodPost, "http://"+api.HubAddress+"/v1/renew", strings.NewReader(`{"posture":{"software":"tnctl","hostname":"body-secret-host"}}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		if resp, err := hc.Do(req); err == nil {
			b, _ := io.ReadAll(resp.Body)
			w.noteTURN(b)
			_ = resp.Body.Close()
		}
	}
	// A rejected outside request with a garbage token and a body.
	w.post(api.ClientSessionPath, "garbage-token-SECRET-123", map[string]any{"namespace": testNS, "device": "body-secret-device", "port": 22, "wgPublicKey": "body-secret-key"})
	w.post(api.DeviceEnrollPath, "garbage-enroll-SECRET-456", []byte(`{"proof":"body-secret-proof"}`))
	w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationCompromised: "true"})
	waitFor(t, "revocation logged", func() bool { return strings.Contains(w.logs.String(), `"op":"revoke"`) })
	w.h.deps.TURN.(*turnMinter).secret = func() (string, error) { return turnSecret, nil }
	_ = w.h.Close()

	logs := w.logs.String()
	if logs == "" {
		t.Fatal("no logs captured")
	}
	w.smu.Lock()
	secrets := append([]string{turnSecret, "payload-that-must-not-be-logged-XYZ", "body-secret-host", "body-secret-proof", "body-secret-key", "garbage-token-SECRET-123", "garbage-enroll-SECRET-456"}, w.secrets...)
	w.smu.Unlock()
	// Every bearer token and TURN password seen in the run.
	if len(secrets) < 10 {
		t.Fatalf("only %d secrets collected; the test is not exercising enough", len(secrets))
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("log output contains the secret %q...", s[:min(len(s), 12)])
		}
	}
	for _, needle := range []string{"Authorization", "Bearer "} {
		if strings.Contains(logs, needle) {
			t.Errorf("log output mentions %q", needle)
		}
	}
	// Every log line is JSON and the decision lines carry the documented fields.
	var decisions int
	for line := range strings.SplitSeq(strings.TrimSpace(logs), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["msg"] == "decision" {
			decisions++
			for _, f := range []string{"op", "decision", "reason", "kind", "ns", "device", "subject", "session", "remote"} {
				if _, ok := rec[f]; !ok {
					t.Errorf("decision line lacks %q: %s", f, line)
				}
			}
		}
	}
	if decisions < 8 {
		t.Fatalf("only %d decision lines", decisions)
	}
}

// Clients and devices must have no L3 path to each other through the hub: the
// netstack does not forward, whatever the sender puts in the destination.
func TestIntegrationNoLateralMovement(t *testing.T) {
	w := newWGDeviceRig(t)

	// A hostile client lets its own WireGuard route the whole overlay to the
	// hub, then tries to reach the device directly and another client.
	req, priv := w.clientReq(22)
	st, body := w.clientSession(aliceToken, req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var cs api.SessionResponse
	_ = json.Unmarshal(body, &cs)
	evil := startPeerAllowed(t, priv, cs.Address, cs.HubPublicKey, w.h.Endpoint(), api.OverlayPrefix)

	victimReq, victimPriv := w.clientReq(22)
	w.users.set("victim", "victim@example.com", w.clock.Now().Add(time.Minute))
	w.authz.set("victim@example.com", testNS, true)
	st, body = w.clientSession("victim", victimReq)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var vs api.SessionResponse
	_ = json.Unmarshal(body, &vs)
	victim := startPeer(t, victimPriv, vs.Address, vs.HubPublicKey, w.h.Endpoint())
	vln, err := victim.net.ListenTCPAddrPort(netip.AddrPortFrom(victim.addr, 7777))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vln.Close() }()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := vln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	// Make sure the hub knows both endpoints before probing.
	if c, err := dialSplice(victim); err == nil {
		_ = c.Close()
	}
	for _, target := range []string{
		net.JoinHostPort(vs.Address, "7777"),      // another client
		net.JoinHostPort(w.devSess.Address, "22"), // the device, bypassing the splice
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		c, err := evil.net.DialContext(ctx, "tcp", target)
		cancel()
		if err == nil {
			_ = c.Close()
			t.Fatalf("direct path to %s exists", target)
		}
	}
	select {
	case <-accepted:
		t.Fatal("the victim saw a connection from another client")
	default:
	}
}

func TestMetrics(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.clientSessionOK()
	req, _ := r.clientReq(8080)
	r.clientSession(aliceToken, req) // port_not_allowed
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationCompromised: "true"})
	waitFor(t, "revocation", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })

	srv := httptest.NewServer(r.h.MetricsHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	text := string(b)
	for _, want := range []string{
		`wghub_sessions_active{kind="device"} 0`,
		`wghub_sessions_active{kind="client"} 0`,
		`wghub_session_creates_total{kind="device"} 1`,
		`wghub_session_creates_total{kind="client"} 1`,
		`wghub_decisions_total{decision="deny",op="session",reason="port_not_allowed"} 1`,
		`wghub_revocations_total{reason="device_revoked"} 1`,
		`wghub_spliced_connections 0`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	for _, leak := range []string{aliceToken, aliceEmail, testDevice} {
		if strings.Contains(text, leak) {
			t.Errorf("metrics carry high-cardinality or sensitive label value %q", leak)
		}
	}
}
