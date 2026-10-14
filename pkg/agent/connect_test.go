package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// echoServer is a TCP echo server on 127.0.0.1 standing in for a service.
type echoServer struct {
	ln net.Listener
	mu sync.Mutex
	n  int
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoServer{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.n++
			e.mu.Unlock()
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return e
}

func (e *echoServer) port() int { return e.ln.Addr().(*net.TCPAddr).Port }
func (e *echoServer) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}

// remoteConn reports a chosen remote address (the hub's overlay address).
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

type connectRig struct {
	t    *testing.T
	srv  *connectServer
	logs *syncBuffer
	ctx  context.Context
	wg   sync.WaitGroup
}

// newConnectRig builds a connect server whose external targets may be
// loopback listeners (the AllowTarget test hook).
func newConnectRig(t *testing.T, perService, global int, allow func(netip.AddrPort) bool) *connectRig {
	t.Helper()
	logs := &syncBuffer{}
	p := testPolicy(&fakeResolver{ips: map[string][]net.IP{"web.apps.svc.cluster.local.": {ip4("10.43.0.77")}}}, "192.168.1.10")
	p.AllowTarget = allow
	ctx, cancel := context.WithCancel(context.Background())
	r := &connectRig{
		t: t, logs: logs, ctx: ctx,
		srv: newConnectServer(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), p, time.Second, perService, global),
	}
	t.Cleanup(func() { cancel(); r.srv.Close(); r.wg.Wait() })
	return r
}

// dial connects to the connect server as the hub (or as remote, if given).
func (r *connectRig) dial(remote string) net.Conn {
	r.t.Helper()
	if remote == "" {
		remote = api.HubAddress + ":40000"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = cli.Close() })
	srvSide, err := ln.Accept()
	if err != nil {
		r.t.Fatal(err)
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.srv.handle(r.ctx, remoteConn{Conn: srvSide, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote))})
	}()
	return cli
}

// connect performs the preamble and returns the answer plus the conn to relay on.
func (r *connectRig) connect(req api.ConnectRequest) (*connectproto.Conn, api.ConnectResponse) {
	r.t.Helper()
	c := r.dial("")
	cc, resp, err := connectproto.Handshake(c, req, 5*time.Second)
	if err != nil {
		r.t.Fatalf("handshake: %v", err)
	}
	return cc, resp
}

func externalSpec(id string, port int) api.ServiceSpec {
	return api.ServiceSpec{ID: id, Kind: api.ServiceKindExternal, Target: "127.0.0.1", Port: port, Protocol: api.ProtocolTCP}
}

func allowPorts(ports ...int) func(netip.AddrPort) bool {
	return func(ap netip.AddrPort) bool { return slices.Contains(ports, int(ap.Port())) }
}

func TestConnectRelaysToAnExternalService(t *testing.T) {
	echo := startEchoServer(t)
	r := newConnectRig(t, 4, 8, allowPorts(echo.port()))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("echo", echo.port())})

	c, resp := r.connect(api.ConnectRequest{Service: "echo", As: "alice@example.com"})
	if !resp.OK {
		t.Fatalf("refused: %+v", resp)
	}
	for _, m := range []string{"hello", strings.Repeat("0123456789", 20_000)} {
		if err := roundTrip(c, m); err != nil {
			t.Fatalf("round trip %d bytes: %v", len(m), err)
		}
	}
	// Half-close: the echo server sees EOF and closes; we read EOF after our CloseWrite.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	eventually(t, 5*time.Second, "relay to end", func() bool { return r.srv.Active() == 0 })
	if !strings.Contains(r.logs.String(), `"as":"alice@example.com"`) {
		t.Fatal("the delegated user is not logged")
	}
}

func TestConnectKeepsBytesSentBehindThePreamble(t *testing.T) {
	echo := startEchoServer(t)
	r := newConnectRig(t, 4, 8, allowPorts(echo.port()))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("echo", echo.port())})
	c := r.dial("")
	// A dialer that does not wait for the answer: preamble and payload in one write.
	if _, err := io.WriteString(c, `{"service":"echo"}`+"\nearly bytes"); err != nil {
		t.Fatal(err)
	}
	br := connectproto.NewReader(c)
	resp, err := connectproto.ReadResponse(br)
	if err != nil || !resp.OK {
		t.Fatalf("%+v %v", resp, err)
	}
	buf := make([]byte, len("early bytes"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "early bytes" {
		t.Fatalf("echoed %q, %v", buf, err)
	}
}

func TestConnectRefusals(t *testing.T) {
	echo := startEchoServer(t)
	r := newConnectRig(t, 4, 8, allowPorts(echo.port()))
	r.srv.SetServices([]api.ServiceSpec{
		externalSpec("echo", echo.port()),
		{ID: "loop", Kind: api.ServiceKindExternal, Target: "127.0.0.1", Port: 9, Protocol: api.ProtocolTCP},        // loopback, not whitelisted
		{ID: "meta", Kind: api.ServiceKindExternal, Target: "169.254.169.254", Port: 80, Protocol: api.ProtocolTCP}, // link-local
		{ID: "api", Kind: api.ServiceKindExternal, Target: "192.168.1.10", Port: 6443, Protocol: api.ProtocolTCP},   // node control plane
		{ID: "dead", Kind: api.ServiceKindExternal, Target: "127.0.0.1", Port: 1, Protocol: api.ProtocolTCP},
		{ID: "bad id!", Kind: api.ServiceKindExternal, Target: "10.0.0.1", Port: 80, Protocol: api.ProtocolTCP}, // invalid: dropped
	})
	cases := []struct {
		service string
		want    string
	}{
		{"nope", api.ReasonServiceUnknown},
		{"", api.ReasonServiceUnknown},
		{"bad id!", api.ReasonServiceUnknown},
		{"loop", api.ReasonServiceDenied},
		{"meta", api.ReasonServiceDenied},
		{"api", api.ReasonServiceDenied},
	}
	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			c, resp := r.connect(api.ConnectRequest{Service: tc.service})
			if resp.OK || resp.Reason != tc.want {
				t.Fatalf("got %+v, want reason %s", resp, tc.want)
			}
			// The agent closes after a refusal.
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("connection stayed open after a refusal")
			}
		})
	}
	// A target that denies nothing but is not there: internal (not a policy denial).
	r.srv.SetServices([]api.ServiceSpec{
		{ID: "dead", Kind: api.ServiceKindExternal, Target: "127.0.0.1", Port: 1, Protocol: api.ProtocolTCP},
	})
	r.srv.policy.AllowTarget = allowPorts(1)
	if _, resp := r.connect(api.ConnectRequest{Service: "dead"}); resp.OK || resp.Reason != api.ReasonInternal {
		t.Fatalf("unreachable target: %+v", resp)
	}
	if echo.count() != 0 {
		t.Fatal("a refused connection reached a target")
	}
}

func TestConnectInternalServiceNeedsTheServiceCIDR(t *testing.T) {
	r := newConnectRig(t, 4, 8, nil)
	r.srv.SetServices([]api.ServiceSpec{
		{ID: "web", Kind: api.ServiceKindInternal, Target: "web.apps", Port: 80, Protocol: api.ProtocolHTTP, Web: true},
		{ID: "dns", Kind: api.ServiceKindInternal, Target: "kube-dns.kube-system", Port: 53, Protocol: api.ProtocolTCP}, // dropped on receipt
	})
	got := r.srv.Services()
	if len(got) != 2 { // ssh + web
		t.Fatalf("services %+v", got)
	}
	// web resolves to 10.43.0.77 (in the CIDR) but nothing listens there: unreachable,
	// not denied, proving the target passed validation.
	if _, resp := r.connect(api.ConnectRequest{Service: "web"}); resp.OK || resp.Reason != api.ReasonInternal {
		t.Fatalf("web: %+v", resp)
	}
	if _, resp := r.connect(api.ConnectRequest{Service: "dns"}); resp.Reason != api.ReasonServiceUnknown {
		t.Fatalf("dns: %+v", resp)
	}
}

func TestConnectPreambleErrors(t *testing.T) {
	r := newConnectRig(t, 4, 8, nil)
	r.srv.preambleTO = 300 * time.Millisecond
	readAnswer := func(c net.Conn) (api.ConnectResponse, error) {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		return connectproto.ReadResponse(connectproto.NewReader(c))
	}

	t.Run("malformed", func(t *testing.T) {
		c := r.dial("")
		_, _ = io.WriteString(c, "this is not json\n")
		resp, err := readAnswer(c)
		if err != nil || resp.OK || resp.Reason != api.ReasonBadRequest {
			t.Fatalf("%+v %v", resp, err)
		}
	})
	t.Run("oversized line", func(t *testing.T) {
		c := r.dial("")
		_, _ = c.Write(append(bytes.Repeat([]byte("x"), connectproto.MaxLine+100), '\n'))
		// No answer, just a close.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(make([]byte, 64)); err == nil || n != 0 {
			t.Fatalf("read %d bytes, err %v", n, err)
		}
	})
	t.Run("no newline, then silence", func(t *testing.T) {
		c := r.dial("")
		_, _ = io.WriteString(c, `{"service":"ssh"}`)
		start := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 64)); err == nil {
			t.Fatal("answered an unfinished preamble")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("preamble timeout took %v", d)
		}
	})
	t.Run("close without sending", func(t *testing.T) {
		c := r.dial("")
		_ = c.Close()
	})
	t.Run("not the hub", func(t *testing.T) {
		c := r.dial("100.96.0.9:40000")
		_, _ = io.WriteString(c, `{"service":"ssh"}`+"\n")
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(make([]byte, 64)); err == nil || n != 0 {
			t.Fatalf("a stranger got %d bytes (%v)", n, err)
		}
	})
	if r.srv.Active() != 0 {
		t.Fatalf("%d relays after preamble errors", r.srv.Active())
	}
}

func TestConnectCaps(t *testing.T) {
	echo := startEchoServer(t)
	r := newConnectRig(t, 2, 3, allowPorts(echo.port()))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("one", echo.port()), externalSpec("two", echo.port())})
	var open []*connectproto.Conn
	for range 2 {
		c, resp := r.connect(api.ConnectRequest{Service: "one"})
		if !resp.OK {
			t.Fatalf("%+v", resp)
		}
		open = append(open, c)
	}
	// The per-service cap of 2 is reached; another service still has room.
	if _, resp := r.connect(api.ConnectRequest{Service: "one"}); resp.OK || resp.Reason != api.ReasonSessionLimit {
		t.Fatalf("per-service cap: %+v", resp)
	}
	c2, resp := r.connect(api.ConnectRequest{Service: "two"})
	if !resp.OK {
		t.Fatalf("other service: %+v", resp)
	}
	open = append(open, c2)
	// Three in total is the global cap.
	if _, resp := r.connect(api.ConnectRequest{Service: "two"}); resp.OK || resp.Reason != api.ReasonSessionLimit {
		t.Fatalf("global cap: %+v", resp)
	}
	// A slot frees up when a connection ends.
	_ = open[0].Close()
	eventually(t, 5*time.Second, "a slot to free", func() bool {
		_, resp := r.connect(api.ConnectRequest{Service: "one"})
		return resp.OK
	})
}

func TestServicesUpdateClosesRelaysOfRemovedOrChangedServices(t *testing.T) {
	a, b := startEchoServer(t), startEchoServer(t)
	r := newConnectRig(t, 4, 8, allowPorts(a.port(), b.port()))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("keep", a.port()), externalSpec("gone", a.port()), externalSpec("moves", a.port())})
	open := map[string]*connectproto.Conn{}
	for _, id := range []string{"keep", "gone", "moves"} {
		c, resp := r.connect(api.ConnectRequest{Service: id})
		if !resp.OK {
			t.Fatalf("%s: %+v", id, resp)
		}
		if err := roundTrip(c, id); err != nil {
			t.Fatal(err)
		}
		open[id] = c
	}
	// "gone" removed, "moves" now reaches another port, "keep" only gets a new description.
	keep := externalSpec("keep", a.port())
	keep.Description = "renamed"
	r.srv.SetServices([]api.ServiceSpec{keep, externalSpec("moves", b.port())})
	for _, id := range []string{"gone", "moves"} {
		_ = open[id].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := open[id].Read(make([]byte, 1)); err == nil {
			t.Fatalf("%s: relay survived the update", id)
		}
	}
	if err := roundTrip(open["keep"], "still here"); err != nil {
		t.Fatalf("an unchanged service lost its relay: %v", err)
	}
	if _, resp := r.connect(api.ConnectRequest{Service: "gone"}); resp.Reason != api.ReasonServiceUnknown {
		t.Fatalf("removed service: %+v", resp)
	}
	// ssh is implicit and survives any update.
	r.srv.SetServices(nil)
	if got := r.srv.Services(); len(got) != 1 || got[0].ID != api.ServiceSSHID {
		t.Fatalf("services after an empty update: %+v", got)
	}
}

func TestSSHServiceIgnoresTheSpecTarget(t *testing.T) {
	sshd := startEchoServer(t)
	r := newConnectRig(t, 4, 8, nil)
	r.srv.policy.SSHPort = sshd.port() // sshd on a non-standard port
	// The policy tries to point ssh somewhere else; it is ignored.
	r.srv.SetServices([]api.ServiceSpec{{ID: "ssh", Kind: api.ServiceKindSSH, Protocol: api.ProtocolTCP, Port: 22}})
	c, resp := r.connect(api.ConnectRequest{Service: "ssh"})
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if err := roundTrip(c, "SSH-2.0-test\r\n"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionEndClosesRelays(t *testing.T) {
	echo := startEchoServer(t)
	r := newConnectRig(t, 4, 8, allowPorts(echo.port()))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("echo", echo.port())})
	c, resp := r.connect(api.ConnectRequest{Service: "echo"})
	if !resp.OK {
		t.Fatal(resp)
	}
	r.srv.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay survived Close")
	}
	if _, resp := r.connect(api.ConnectRequest{Service: "echo"}); resp.OK {
		t.Fatal("a closed server accepted a connection")
	}
}

// ---- control RPC ----

func controlRig(t *testing.T) (*controlServer, *connectServer, *GrantStore) {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	connect := newConnectServer(log, testPolicy(&fakeResolver{}), time.Second, 4, 8)
	grants := NewGrantStore(GrantStoreOptions{})
	return newControlServer(log, connect, grants), connect, grants
}

func post(t *testing.T, c *controlServer, path, remote string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, path, rd)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	c.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func TestControlServicesUpdate(t *testing.T) {
	c, connect, _ := controlRig(t)
	hub := api.HubAddress + ":51000"
	spec := externalSpec("cam", 554)
	spec.Target = "192.168.7.7"
	rec := post(t, c, api.ControlServicesPath, hub, api.ServicesUpdate{Services: []api.ServiceSpec{spec}})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if _, ok := lookupService(connect, "cam"); !ok {
		t.Fatal("service not applied")
	}
	// Not the hub: nothing happens.
	rec = post(t, c, api.ControlServicesPath, "100.96.0.9:51000", api.ServicesUpdate{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stranger got %d", rec.Code)
	}
	if _, ok := lookupService(connect, "cam"); !ok {
		t.Fatal("a stranger changed the services")
	}
	if rec := post(t, c, api.ControlServicesPath, hub, "{not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", rec.Code)
	}
	if rec := post(t, c, api.ControlServicesPath, hub, strings.Repeat("x", maxControlBody+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, api.ControlServicesPath, nil)
	req.RemoteAddr = hub
	rr := httptest.NewRecorder()
	c.srv.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rr.Code)
	}
}

func lookupService(s *connectServer, id string) (api.ServiceSpec, bool) {
	for _, sp := range s.Services() {
		if sp.ID == id {
			return sp, true
		}
	}
	return api.ServiceSpec{}, false
}

func TestControlGrants(t *testing.T) {
	c, _, grants := controlRig(t)
	hub := api.HubAddress + ":51000"
	g := testGrant(t, "pa", 1)
	rec := post(t, c, api.ControlGrantsPath, hub, api.GrantSet{HubInstance: "hub-1", Seq: 3, Grants: []api.Grant{g}})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var ack api.GrantAck
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	// Valid grants are accepted; until plane B exists the device parameters are empty.
	if !slices.Equal(ack.Accepted, []string{"pa"}) || ack.DeviceWGPublicKey != "" || ack.DeviceAddress != "" || len(ack.DeviceCandidates) != 0 {
		t.Fatalf("ack %+v", ack)
	}
	if !strings.Contains(rec.Body.String(), `"deviceCandidates":[]`) {
		t.Fatalf("deviceCandidates must be an empty array: %s", rec.Body)
	}
	if !grants.Allows("pa", "ssh") {
		t.Fatal("grant not stored")
	}
	if rec := post(t, c, api.ControlGrantsPath, hub, api.GrantSet{HubInstance: "hub-1", Seq: 2}); rec.Code != http.StatusConflict {
		t.Fatalf("stale: %d", rec.Code)
	}
	if rec := post(t, c, api.ControlGrantsPath, "100.96.0.9:1", api.GrantSet{HubInstance: "hub-1", Seq: 9}); rec.Code != http.StatusForbidden {
		t.Fatalf("stranger: %d", rec.Code)
	}
	if rec := post(t, c, api.ControlGrantsPath, hub, api.GrantSet{Seq: 9}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no instance: %d", rec.Code)
	}
	// An empty set answers with an empty (not null) accepted list.
	rec = post(t, c, api.ControlGrantsPath, hub, api.GrantSet{HubInstance: "hub-1", Seq: 4})
	if !strings.Contains(rec.Body.String(), `"accepted":[]`) || grants.Allows("pa", "ssh") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
