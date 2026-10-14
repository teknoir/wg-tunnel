package e2e_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

func dialService(t *testing.T, sess interface {
	Dial(context.Context) (net.Conn, error)
}) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := sess.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// expectClosed asserts that c is closed by the other side without data.
func expectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(make([]byte, 16))
	if err == nil || n != 0 {
		t.Fatalf("%s: got %d bytes, err %v; want the connection closed", what, n, err)
	}
}

// Named services through the hub: the external "web" service reaches its own
// echo server, the implicit ssh service reaches the fake sshd, and the legacy
// raw port still works in the same device session.
func TestServicesThroughTheHub(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.SetServices(r.WebService("web"))
	r.StartAgent()
	r.WaitDeviceUp(1)

	web := r.MustServiceClient(e2erig.AliceEmail, "web")
	if resp := web.Response(); resp.Service != "web" || resp.TargetPort != 0 {
		t.Fatalf("response service %q target %d", resp.Service, resp.TargetPort)
	}
	c := dialService(t, web)
	for _, msg := range []string{"GET / HTTP/1.1\r\n\r\n", strings.Repeat("web", 50_000)} {
		if err := e2erig.RoundTrip(c, msg); err != nil {
			t.Fatalf("web echo of %d bytes: %v", len(msg), err)
		}
	}
	if r.Web.Total() != 1 || r.Echo.Total() != 0 {
		t.Fatalf("web echo saw %d connections, sshd %d", r.Web.Total(), r.Echo.Total())
	}
	// Half-close travels through hub and agent to the service.
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadAll(c); err != nil {
			t.Fatalf("read after half-close: %v", err)
		}
	}
	e2erig.Eventually(t, 5*time.Second, "the web echo to see the close", func() bool { return r.Web.Active() == 0 })

	// ssh is implicit: it is not in the policy, and goes to the (fake) sshd.
	ssh := r.MustServiceClient(e2erig.BobEmail, "ssh")
	if resp := ssh.Response(); resp.Service != "ssh" || resp.TargetPort != 22 || len(resp.SSHHostKeys) != 1 {
		t.Fatalf("ssh response %+v", resp)
	}
	if err := e2erig.EchoVia(ssh, "SSH-2.0-OpenSSH_9.6\r\n", 20*time.Second); err != nil {
		t.Fatalf("ssh echo: %v", err)
	}
	if r.Echo.Total() != 1 {
		t.Fatalf("sshd saw %d connections", r.Echo.Total())
	}

	// The raw port of phase 1 is unchanged.
	raw := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(raw, "legacy", 20*time.Second); err != nil {
		t.Fatalf("legacy port echo: %v", err)
	}
	if r.Echo.Total() != 2 || r.Web.Total() != 1 {
		t.Fatalf("sshd saw %d, web %d", r.Echo.Total(), r.Web.Total())
	}
	r.AssertLogHygiene()
}

// Whatever the policy says, the agent refuses targets it must never reach.
func TestAgentRefusesForbiddenTargetsEvenWhenThePolicyAllowsThem(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	ext := func(id, target string, port int) api.ServiceSpec {
		return api.ServiceSpec{ID: id, Kind: api.ServiceKindExternal, Target: target, Port: port, Protocol: api.ProtocolTCP}
	}
	r.SetServices(
		ext("meta", "169.254.169.254", 80),
		ext("loop", "127.0.0.1", r.Echo.Port), // the sshd's own port: loopback is not an external target
		ext("kube", "127.0.0.1", 6443),
		api.ServiceSpec{ID: "dns", Kind: api.ServiceKindInternal, Target: "kube-dns.kube-system", Port: 53, Protocol: api.ProtocolTCP},
		api.ServiceSpec{ID: "bogus", Kind: api.ServiceKindInternal, Target: "no-such.apps", Port: 80, Protocol: api.ProtocolTCP},
	)
	r.StartAgent()
	r.WaitDeviceUp(1)

	for _, id := range []string{"meta", "loop", "kube"} {
		sess := r.MustServiceClient(e2erig.AliceEmail, id)
		expectClosed(t, dialService(t, sess), id)
	}
	if r.Echo.Total() != 0 {
		t.Fatal("a refused service reached the sshd")
	}
	e2erig.Eventually(t, 5*time.Second, "the refusals in the hub log", func() bool {
		return r.HubLogs.Count(`"reason":"service_denied"`) >= 3
	})
	if n := r.AgentLogs.Count(`"msg":"service target refused or unreachable"`); n < 3 {
		t.Fatalf("agent logged %d refusals", n)
	}
	// kube-system never leaves the hub: an invalid service is not part of the
	// device's services (and the agent would drop it, too: see its unit tests).
	if _, err := newServiceSession(r, "dns"); err == nil || !strings.Contains(err.Error(), api.ReasonServiceUnknown) {
		t.Fatalf("kube-system service: %v", err)
	}
	// An unresolvable internal target is unreachable, not a policy denial.
	expectClosed(t, dialService(t, r.MustServiceClient(e2erig.AliceEmail, "bogus")), "bogus")
}

type fakeResolver map[string]string

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if ip, ok := f[host]; ok {
		return []net.IP{net.ParseIP(ip).To4()}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) { return host, nil }

// An internal service resolves through the agent's resolver and must land in
// the service CIDR. The rig stands in for the cluster: its "service network" is
// 127.0.0.0/8 and the one Service address is the web echo server.
func TestInternalServiceThroughTheHub(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{Agent: func(c *agent.Config) {
		c.Resolver = fakeResolver{"echo.apps.svc.cluster.local.": "127.0.0.1"}
		c.ServiceCIDRs = mustCIDRs(t, "127.0.0.0/8")
	}})
	r.SetServices(api.ServiceSpec{ID: "echo", Kind: api.ServiceKindInternal, Target: "echo.apps", Port: r.Web.Port, Protocol: api.ProtocolHTTP, Web: true})
	r.StartAgent()
	r.WaitDeviceUp(1)
	c := dialService(t, r.MustServiceClient(e2erig.AliceEmail, "echo"))
	if err := e2erig.RoundTrip(c, "via cluster dns"); err != nil {
		t.Fatal(err)
	}
	if r.Web.Total() != 1 {
		t.Fatalf("web echo saw %d connections", r.Web.Total())
	}
}

func mustCIDRs(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := agent.ParseServiceCIDRs(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A policy change reaches the live agent over the control port: new services
// work without a reconnect, removed ones are closed within a second.
func TestServicesUpdateWithoutReconnect(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.SetServices(r.WebService("web"))
	r.StartAgent()
	r.WaitDeviceUp(1)

	web := r.MustServiceClient(e2erig.AliceEmail, "web")
	webConn := dialService(t, web)
	if err := e2erig.RoundTrip(webConn, "before"); err != nil {
		t.Fatal(err)
	}
	// "docs" does not exist yet.
	if _, err := newServiceSession(r, "docs"); err == nil {
		t.Fatal("a session for an undefined service was created")
	}

	r.SetServices(r.WebService("web"), r.WebService("docs"))
	e2erig.Eventually(t, 10*time.Second, "the agent to take the update", func() bool {
		return r.AgentLogs.Count(`"msg":"services updated by the hub"`) >= 1
	})
	docs := r.MustServiceClient(e2erig.AliceEmail, "docs")
	if err := e2erig.EchoVia(docs, "after", 20*time.Second); err != nil {
		t.Fatalf("new service: %v", err)
	}
	if err := e2erig.RoundTrip(webConn, "unchanged service keeps its connection"); err != nil {
		t.Fatal(err)
	}

	// Remove "web": its connection closes within a second, "docs" is untouched.
	gone := readErrAfter(webConn)
	select { // the read must really be blocked on a live connection
	case err := <-gone:
		t.Fatalf("the connection died before the policy change: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	t0 := time.Now()
	r.SetServices(r.WebService("docs"))
	select {
	case <-gone:
	case <-time.After(time.Second):
		t.Fatal("the removed service's connection was still open a second later")
	}
	t.Logf("removed service's connection closed %v after the policy change", time.Since(t0))
	if err := e2erig.EchoVia(docs, "docs lives", 20*time.Second); err != nil {
		t.Fatalf("docs after the removal of web: %v", err)
	}
	if _, err := newServiceSession(r, "web"); err == nil {
		t.Fatal("a session for a removed service was created")
	}
	// No reconnect happened anywhere.
	if n := r.AgentLogs.Count(`"msg":"exposing port"`); n != 1 {
		t.Fatalf("the agent reconnected: %d sessions", n)
	}
}

// newServiceSession tries to create a client session for a service without the
// test failing on a refusal.
func newServiceSession(r *e2erig.Rig, service string) (interface{ Close() error }, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := wgclient.Create(ctx, r.ServiceClientOptions(e2erig.AliceEmail, service))
	if err != nil {
		return nil, err
	}
	r.T.Cleanup(func() { _ = s.Close() })
	return s, nil
}
