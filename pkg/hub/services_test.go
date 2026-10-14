package hub

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
)

var (
	webSvc = api.ServiceSpec{ID: "web", Kind: api.ServiceKindExternal, Target: "192.168.1.5", Port: 8080, Protocol: api.ProtocolHTTP, Web: true, Description: "camera UI"}
	camSvc = api.ServiceSpec{ID: "cam", Kind: api.ServiceKindExternal, Target: "192.168.1.6", Port: 554, Protocol: api.ProtocolTCP}
	k3sSvc = api.ServiceSpec{ID: "grafana", Kind: api.ServiceKindInternal, Target: "grafana.monitoring", Port: 3000, Protocol: api.ProtocolHTTP, Web: true}

	capsFull    = []string{api.CapServices, api.CapControl}
	capsNoCtl   = []string{api.CapServices}
	capsUnknown = []string{"p2p-v9", api.CapServices, api.CapServices, strings.Repeat("x", 100), api.CapControl}
)

func withServices(r *rig, specs ...api.ServiceSpec) {
	p := r.policy
	p.Services = specs
	r.setPolicy(p)
}

// ---- session creation ----

func TestSanitizeCaps(t *testing.T) {
	got := sanitizeCaps(capsUnknown)
	if !slices.Equal(got, []string{api.CapServices, api.CapControl}) {
		t.Fatalf("caps %v", got)
	}
	if sanitizeCaps(nil) != nil {
		t.Fatal("nil in, non-nil out")
	}
}

func TestDeviceSessionServicesOnlyForServicesV1Agents(t *testing.T) {
	bad := api.ServiceSpec{ID: "BAD", Kind: api.ServiceKindExternal}
	ssh := api.ServiceSpec{ID: "ssh", Kind: api.ServiceKindSSH, Protocol: api.ProtocolTCP}
	for _, tc := range []struct {
		name string
		caps []string
		want []api.ServiceSpec
	}{
		{"phase-1 agent", nil, nil},
		{"control only", []string{api.CapControl}, nil},
		{"services-v1", capsNoCtl, []api.ServiceSpec{webSvc, camSvc}},
		{"services-v1 and control", capsFull, []api.ServiceSpec{webSvc, camSvc}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			withServices(r, webSvc, bad, ssh, camSvc, webSvc) // invalid, implicit-ssh and duplicate entries are dropped
			r.devCaps = tc.caps
			ds := r.deviceSessionOK()
			if !svc.Same(ds.Services, tc.want) || (tc.want == nil && ds.Services != nil) {
				t.Fatalf("services %+v, want %+v", ds.Services, tc.want)
			}
			// AllowedPorts stays the phase-1 list either way.
			if !slices.Equal(ds.AllowedPorts, []int{22}) {
				t.Fatalf("allowed ports %v", ds.AllowedPorts)
			}
			dev := r.h.deviceSession(testNS, testDevice)
			if got := dev.hasCap(api.CapServices); got != slices.Contains(tc.caps, api.CapServices) {
				t.Fatalf("recorded caps %v", dev.caps)
			}
		})
	}
}

func TestClientSessionServiceSelection(t *testing.T) {
	type want struct {
		status  int
		reason  string
		service string
		target  int
	}
	tests := []struct {
		name     string
		caps     []string
		ports    []int
		mut      func(*api.ClientSessionRequest)
		want     want
		services []api.ServiceSpec
	}{
		{"empty service, port 22 is ssh", capsFull, []int{22}, nil, want{201, "", "ssh", 22}, nil},
		{"explicit ssh", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 0 }, want{201, "", "ssh", 22}, nil},
		{"explicit ssh with port 22", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service = "ssh" }, want{201, "", "ssh", 22}, nil},
		{"ssh is implicit even with no allowed ports", capsFull, nil, func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 0 }, want{201, "", "ssh", 22}, nil},
		{"ssh on another port", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 2222 }, want{400, api.ReasonBadRequest, "", 0}, nil},
		{"defined service", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "web", 0 }, want{201, "", "web", 0}, []api.ServiceSpec{webSvc}},
		{"service with a port", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "web", 80 }, want{400, api.ReasonBadRequest, "", 0}, []api.ServiceSpec{webSvc}},
		{"unknown service", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "nope", 0 }, want{404, api.ReasonServiceUnknown, "", 0}, []api.ServiceSpec{webSvc}},
		{"invalid service id", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "Not A Label", 0 }, want{400, api.ReasonBadRequest, "", 0}, nil},
		{"invalid service in the policy is not reachable", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "bad", 0 },
			want{404, api.ReasonServiceUnknown, "", 0}, []api.ServiceSpec{{ID: "bad", Kind: api.ServiceKindExternal, Target: "example.com", Port: 80, Protocol: api.ProtocolTCP}}},
		{"service on a phase-1 agent", nil, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "web", 0 }, want{404, api.ReasonServiceUnknown, "", 0}, []api.ServiceSpec{webSvc}},
		{"ssh on a phase-1 agent", nil, []int{22}, func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 0 }, want{201, "", "ssh", 22}, nil},
		{"ssh on a phase-1 agent needs port 22 allowed", nil, nil, func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 0 }, want{403, api.ReasonPortNotAllowed, "", 0}, nil},
		{"legacy raw port", capsFull, []int{22, 2200}, func(q *api.ClientSessionRequest) { q.Port = 2200 }, want{201, "", "", 2200}, nil},
		{"legacy raw port not allowed", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Port = 2200 }, want{403, api.ReasonPortNotAllowed, "", 0}, nil},
		{"no service and no port", capsFull, []int{22}, func(q *api.ClientSessionRequest) { q.Port = 0 }, want{400, api.ReasonBadRequest, "", 0}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			p := r.policy
			p.AllowedPorts, p.Services = tc.ports, tc.services
			r.setPolicy(p)
			r.devCaps = tc.caps
			r.deviceSessionOK()
			req, _ := r.clientReq(22)
			if tc.mut != nil {
				tc.mut(&req)
			}
			st, body := r.clientSession(aliceToken, req)
			if tc.want.status != 201 {
				wantReason(t, st, body, tc.want.status, tc.want.reason)
				return
			}
			if st != http.StatusCreated {
				t.Fatalf("%d %s", st, body)
			}
			var resp api.SessionResponse
			_ = json.Unmarshal(body, &resp)
			if resp.Service != tc.want.service || resp.TargetPort != tc.want.target || resp.SplicePort != api.HubSplicePort {
				t.Fatalf("service %q target %d splice %d", resp.Service, resp.TargetPort, resp.SplicePort)
			}
		})
	}
}

// ---- a services-v1 agent on a real tunnel ----

// svcAgent is the device side of the services protocol on a WireGuard peer: a
// connect listener (echoing) and a control listener (recording).
type svcAgent struct {
	mu        sync.Mutex
	reqs      []api.ConnectRequest
	updates   [][]api.ServiceSpec
	refuse    string // answer every connect with this refusal
	garbage   bool   // answer every connect with junk
	ctlStatus int    // control answer (default 204)
	// grants, when set, serves ControlGrantsPath.
	grants  func(w http.ResponseWriter, body []byte)
	rawEcho int // also echo on this overlay port (legacy listener)
}

func (a *svcAgent) connects() []api.ConnectRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reqs)
}

func (a *svcAgent) lastUpdate() []api.ServiceSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.updates) == 0 {
		return nil
	}
	return a.updates[len(a.updates)-1]
}

func (a *svcAgent) updateCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.updates)
}

func (a *svcAgent) setRefuse(reason string, garbage bool) {
	a.mu.Lock()
	a.refuse, a.garbage = reason, garbage
	a.mu.Unlock()
}

func (a *svcAgent) setCtl(status int) { a.mu.Lock(); a.ctlStatus = status; a.mu.Unlock() }

func (a *svcAgent) serve(t *testing.T, p *wgPeer) {
	t.Helper()
	ln, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(p.addr, api.AgentConnectPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.handleConnect(c)
		}
	}()
	cln, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(p.addr, api.AgentControlPort))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(a.handleControl), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(cln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if a.rawEcho != 0 {
		rln, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(p.addr, uint16(a.rawEcho)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rln.Close() })
		go func() {
			for {
				c, err := rln.Accept()
				if err != nil {
					return
				}
				go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
			}
		}()
	}
}

func (a *svcAgent) handleConnect(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := connectproto.NewReader(c)
	req, err := connectproto.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	refuse, garbage := a.refuse, a.garbage
	a.mu.Unlock()
	switch {
	case garbage:
		_, _ = io.WriteString(c, "this is not a response\n")
		return
	case refuse != "":
		_ = connectproto.WriteResponse(c, api.ConnectResponse{Reason: refuse})
		return
	}
	_ = connectproto.WriteResponse(c, api.ConnectResponse{OK: true})
	cc := connectproto.Wrap(c, br)
	_, _ = io.Copy(cc, cc)
}

func (a *svcAgent) handleControl(w http.ResponseWriter, r *http.Request) {
	var upd api.ServicesUpdate
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.URL.Path == api.ControlGrantsPath && a.grants != nil {
		a.grants(w, body)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != api.ControlServicesPath || json.Unmarshal(body, &upd) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	status := a.ctlStatus
	if status == 0 {
		status = http.StatusNoContent
	}
	if status < 300 {
		a.updates = append(a.updates, upd.Services)
	}
	a.mu.Unlock()
	w.WriteHeader(status)
}

// newSvcRig is a hub with real WireGuard and a services-v1 agent behind the
// device session. services is the initial policy.
func newSvcRig(t *testing.T, caps []string, services []api.ServiceSpec, agent *svcAgent, opts ...rigOpt) *wgRig {
	t.Helper()
	r := newWGRig(t, opts...)
	r.devCaps = caps
	p := r.policy
	p.Services = services
	p.AllowedPorts = []int{22, 2200}
	r.setPolicy(p)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := make(chan error, 1)
	go func() { served <- r.h.ServeTunnel(ctx) }()
	waitFor(t, "hub ready", r.h.Ready)
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("ServeTunnel did not stop")
		}
	})
	ds := r.deviceSessionOK()
	dp := startPeer(t, ds.priv, ds.Address, ds.HubPublicKey, r.h.Endpoint())
	agent.serve(t, dp)
	hubDev := rawTunnel(r.h).dev
	waitFor(t, "device endpoint learned by hub", func() bool {
		out, _ := hubDev.IpcGet()
		return strings.Contains(out, "endpoint=")
	})
	return &wgRig{rig: r, devSess: ds, devPeer: dp, cancel: cancel}
}

func (w *wgRig) serviceClient(token, service string, mut ...func(*api.ClientSessionRequest)) (*wgPeer, api.SessionResponse) {
	w.t.Helper()
	c, resp, st, body := w.connectClient(token, func(q *api.ClientSessionRequest) {
		q.Service, q.Port = service, 0
		for _, m := range mut {
			m(q)
		}
	})
	if c == nil {
		w.t.Fatalf("client session for %q: %d %s", service, st, body)
	}
	return c, resp
}

func TestSpliceSpeaksThePreambleToAServicesAgent(t *testing.T) {
	agent := &svcAgent{rawEcho: 2200}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add("sa-token", "wgt-cam-1", testNS, testDevice)

	// A named service.
	cli, resp := w.serviceClient(aliceToken, "web")
	if resp.Service != "web" {
		t.Fatalf("response service %q", resp.Service)
	}
	c, err := dialSplice(cli)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "to the web service")
	echo(t, c, strings.Repeat("0123456789", 500))
	_ = c.Close()

	// ssh, by the empty service with port 22 (phase-1 clients) and explicitly.
	for _, mut := range []func(*api.ClientSessionRequest){
		func(q *api.ClientSessionRequest) { q.Service, q.Port = "", 22 },
		func(q *api.ClientSessionRequest) { q.Service, q.Port = "ssh", 0 },
	} {
		cli, _, _, _ := w.connectClient(aliceToken, mut)
		if cli == nil {
			t.Fatal("ssh client refused")
		}
		c, err := dialSplice(cli)
		if err != nil {
			t.Fatal(err)
		}
		echo(t, c, "ssh banner")
		_ = c.Close()
	}

	// A delegated session carries the end user as As, a user session does not.
	sa, _ := w.serviceClient("sa-token", "web", func(q *api.ClientSessionRequest) {
		q.OnBehalfOf, q.Posture.Software, q.Direct = aliceEmail, "web-terminal", true
	})
	c, err = dialSplice(sa)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "delegated")
	_ = c.Close()

	got := agent.connects()
	want := []api.ConnectRequest{{Service: "web"}, {Service: "ssh"}, {Service: "ssh"}, {Service: "web", As: aliceEmail}}
	if !slices.Equal(got, want) {
		t.Fatalf("agent saw %+v, want %+v", got, want)
	}

	// A legacy raw port still goes to the agent's per-port listener, with no preamble.
	raw, _, _, _ := w.connectClient(aliceToken, func(q *api.ClientSessionRequest) { q.Service, q.Port = "", 2200 })
	if raw == nil {
		t.Fatal("legacy port client refused")
	}
	c, err = dialSplice(raw)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "raw port")
	_ = c.Close()
	if n := len(agent.connects()); n != len(want) {
		t.Fatalf("legacy port used the connect listener (%d preambles)", n)
	}
}

func TestSplicePerConnectionChecksOnTheServicePath(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add("sa-token", "wgt-cam-1", testNS, testDevice)
	sa, _ := w.serviceClient("sa-token", "web", func(q *api.ClientSessionRequest) {
		q.OnBehalfOf, q.Posture.Software, q.Direct = aliceEmail, "web-terminal", true
	})
	c, err := dialSplice(sa)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "first")
	// Alice loses access to the teamspace: the next connection is refused at
	// the hub, before the agent hears of it (the SAR runs per connection).
	w.authz.set(aliceEmail, testNS, false)
	before := len(agent.connects())
	c2, err := dialSplice(sa)
	if err == nil {
		_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, rerr := c2.Read(make([]byte, 1)); rerr == nil || n != 0 {
			t.Fatalf("connection of a user without access was spliced (%d bytes, %v)", n, rerr)
		}
		_ = c2.Close()
	}
	if after := len(agent.connects()); after != before {
		t.Fatalf("the agent was contacted for a denied user (%d -> %d)", before, after)
	}
	if !strings.Contains(w.logs.String(), `"reason":"forbidden"`) {
		t.Fatalf("no forbidden decision logged:\n%s", w.logs.String())
	}
	_ = c.Close()
}

func TestSpliceAgentRefusalsCloseTheConnection(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	cli, _ := w.serviceClient(aliceToken, "web")
	for _, tc := range []struct {
		name, refuse string
		garbage      bool
		wantReason   string
	}{
		{"service_denied", api.ReasonServiceDenied, false, "service_denied"},
		{"service_unknown", api.ReasonServiceUnknown, false, "service_unknown"},
		{"an arbitrary string never becomes a label", "x-" + strings.Repeat("a", 50), false, "internal"},
		{"junk instead of an answer", "", true, "device_offline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent.setRefuse(tc.refuse, tc.garbage)
			c, err := dialSplice(cli)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
				t.Fatalf("got %d bytes (%v) from a refused connection", n, err)
			}
			waitFor(t, "the decision", func() bool {
				return strings.Contains(w.logs.String(), `"decision":"deny","reason":"`+tc.wantReason+`"`)
			})
		})
	}
	if strings.Contains(w.logs.String(), "x-aaaa") {
		t.Fatal("an agent-chosen string reached the logs")
	}
	// And the service works again once the agent answers properly.
	agent.setRefuse("", false)
	c, err := dialSplice(cli)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "recovered")
	_ = c.Close()
}

// ---- policy changes ----

func TestServicesPushOnPolicyChange(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	dev := w.h.deviceSession(testNS, testDevice)
	if agent.updateCount() != 0 {
		t.Fatal("pushed at creation: the response already carries the set")
	}

	// Adding a service pushes the full new set to the agent.
	p := w.policy
	p.Services = []api.ServiceSpec{webSvc, camSvc, k3sSvc}
	w.setPolicy(p)
	waitFor(t, "services push", func() bool { return svc.Same(agent.lastUpdate(), p.Services) })
	waitFor(t, "hub to record the push", func() bool { return svc.Same(dev.servicesOf(), p.Services) })
	if d, _ := w.h.sessionCounts(); d != 1 {
		t.Fatal("the device session ended")
	}
	n := agent.updateCount()

	// A change that does not touch the services pushes nothing.
	p.Note = "just a note"
	w.setPolicy(p)
	time.Sleep(100 * time.Millisecond)
	if agent.updateCount() != n {
		t.Fatalf("%d pushes after an unrelated change", agent.updateCount()-n)
	}

	// Several quick changes end in the final state.
	for i := range 5 {
		q := p
		q.Services = []api.ServiceSpec{webSvc, {ID: "n" + string(rune('a'+i)), Kind: api.ServiceKindExternal, Target: "10.0.0.9", Port: 1000 + i, Protocol: api.ProtocolTCP}}
		w.setPolicy(q)
		p = q
	}
	waitFor(t, "final state pushed", func() bool { return svc.Same(agent.lastUpdate(), p.Services) && svc.Same(dev.servicesOf(), p.Services) })

	// Emptying the set pushes an empty list (not null).
	p.Services = nil
	w.setPolicy(p)
	waitFor(t, "empty set pushed", func() bool {
		agent.mu.Lock()
		defer agent.mu.Unlock()
		l := agent.updates[len(agent.updates)-1]
		return l != nil && len(l) == 0
	})
}

func TestRemovedServiceClosesItsConnectionsAndEndsItsSessions(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc, camSvc}, agent)
	webCli, _ := w.serviceClient(aliceToken, "web")
	camCli, _ := w.serviceClient(aliceToken, "cam")
	sshCli, _, _, _ := w.connectClient(aliceToken, nil)
	webConn, err := dialSplice(webCli)
	if err != nil {
		t.Fatal(err)
	}
	camConn, err := dialSplice(camCli)
	if err != nil {
		t.Fatal(err)
	}
	sshConn, err := dialSplice(sshCli)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, webConn, "w")
	echo(t, camConn, "c")
	echo(t, sshConn, "s")
	if _, c := w.h.sessionCounts(); c != 3 {
		t.Fatalf("%d client sessions", c)
	}

	readErr := func(c net.Conn) <-chan error {
		ch := make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 1)); ch <- err }()
		return ch
	}
	webEnd := readErr(webConn)
	t0 := time.Now()
	p := w.policy
	p.Services = []api.ServiceSpec{camSvc} // web removed
	w.setPolicy(p)
	select {
	case err := <-webEnd:
		if err == nil {
			t.Fatal("data on a removed service's connection")
		}
	case <-time.After(time.Second):
		t.Fatal("connection of the removed service still open 1s after the policy change")
	}
	t.Logf("removed service's connection closed %v after the policy change", time.Since(t0))
	waitFor(t, "web client session to end", func() bool { _, c := w.h.sessionCounts(); return c == 2 })
	// The others are untouched.
	echo(t, camConn, "still")
	echo(t, sshConn, "ok")
	// New sessions for the removed service are refused.
	req, _ := w.clientReq(22)
	req.Service, req.Port = "web", 0
	st, body := w.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonServiceUnknown)
	waitFor(t, "the revoke line", func() bool { return strings.Contains(w.logs.String(), `"op":"revoke"`) })

	// Redefining a service (another target) also ends the sessions that use it.
	moved := camSvc
	moved.Port = 8554
	p.Services = []api.ServiceSpec{moved}
	w.setPolicy(p)
	waitFor(t, "cam client session to end", func() bool { _, c := w.h.sessionCounts(); return c == 1 })
	camEnd := readErr(camConn)
	select {
	case err := <-camEnd:
		if err == nil {
			t.Fatal("data on a redefined service's connection")
		}
	case <-time.After(time.Second):
		t.Fatal("connection of the redefined service still open")
	}
	echo(t, sshConn, "ssh survives every services change")
}

func TestServicesPushFailureEndsTheDeviceSession(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	agent.setCtl(http.StatusInternalServerError)
	p := w.policy
	p.Services = []api.ServiceSpec{webSvc, camSvc}
	w.setPolicy(p)
	// The agent never takes the set, so the session ends: its replacement gets the
	// set in the session response.
	waitFor(t, "device session to end", func() bool { d, _ := w.h.sessionCounts(); return d == 0 })
	ds := w.deviceSessionOK()
	if !svc.Same(ds.Services, p.Services) {
		t.Fatalf("new session carries %+v", ds.Services)
	}
}

func TestServicesAgentWithoutControlReconnects(t *testing.T) {
	r := newRig(t)
	withServices(r, webSvc)
	r.devCaps = capsNoCtl
	r.deviceSessionOK()
	cs := r.clientSessionOK() // ssh
	_ = cs
	withServices(r, webSvc, camSvc)
	waitFor(t, "device session to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
	ds := r.deviceSessionOK()
	if !svc.Same(ds.Services, []api.ServiceSpec{webSvc, camSvc}) {
		t.Fatalf("%+v", ds.Services)
	}
	if !strings.Contains(r.logs.String(), `"reason":"services_changed"`) {
		t.Fatal("no services_changed revoke line")
	}
}

func TestPhase1AgentIsNotTouchedByServicesChanges(t *testing.T) {
	r := newRig(t)
	var dials int
	var mu sync.Mutex
	r.tun.dial = func(context.Context, netip.AddrPort) (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		return nil, io.EOF
	}
	r.deviceSessionOK() // no capabilities
	withServices(r, webSvc)
	withServices(r, webSvc, camSvc)
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if dials != 0 {
		t.Fatalf("%d dials to a phase-1 agent", dials)
	}
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("the phase-1 device session ended")
	}
}

func TestRenewDeniedWhenTheServiceIsGone(t *testing.T) {
	r := newRig(t)
	withServices(r, webSvc)
	r.devCaps = capsFull
	r.tun.dial = func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, io.EOF }
	r.deviceSessionOK()
	req, _ := r.clientReq(22)
	req.Service, req.Port = "web", 0
	st, body := r.clientSession(aliceToken, req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var resp api.SessionResponse
	_ = json.Unmarshal(body, &resp)
	// The enforcer ends the session at once; a renewal racing with it is denied too.
	withServices(r)
	waitFor(t, "client session to end", func() bool { _, c := r.h.sessionCounts(); return c == 0 })
	st, body = r.tunnelPost(api.RenewPath, resp.Address, aliceToken, api.RenewRequest{})
	wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
}
