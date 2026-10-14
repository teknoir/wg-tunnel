package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// fakeResolver answers from tables and counts lookups.
type fakeResolver struct {
	ips     map[string][]net.IP
	cnames  map[string]string
	ipErr   error
	cnameEr error
	lookups atomic.Int32
	network string
}

func (f *fakeResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	f.lookups.Add(1)
	f.network = network
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	ips, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if f.cnameEr != nil {
		return "", f.cnameEr
	}
	if c, ok := f.cnames[host]; ok {
		return c, nil
	}
	return host, nil // plain Service: the canonical name is the name itself
}

func ip4(s string) net.IP { return net.ParseIP(s).To4() }

func testPolicy(res Resolver, nodeIPs ...string) *TargetPolicy {
	p := &TargetPolicy{Resolver: res, NodeIPs: func() []netip.Addr {
		var out []netip.Addr
		for _, s := range nodeIPs {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}}
	p.applyDefaults()
	return p
}

func ext(target string, port int) api.ServiceSpec {
	return api.ServiceSpec{ID: "t", Kind: api.ServiceKindExternal, Target: target, Port: port, Protocol: api.ProtocolTCP}
}

func internal(target string, port int) api.ServiceSpec {
	return api.ServiceSpec{ID: "t", Kind: api.ServiceKindInternal, Target: target, Port: port, Protocol: api.ProtocolTCP}
}

func TestExternalTargetRules(t *testing.T) {
	p := testPolicy(&fakeResolver{}, "192.168.1.10", "fd00::10")
	tests := []struct {
		name   string
		spec   api.ServiceSpec
		denied string // substring; empty = allowed
	}{
		{"lan host", ext("192.168.1.50", 554), ""},
		{"lan host on a protected port of ANOTHER host", ext("192.168.1.50", 6443), ""},
		{"public address", ext("203.0.113.7", 443), ""},
		{"node ssh port is fine", ext("192.168.1.10", 22), ""},
		{"loopback", ext("127.0.0.1", 8080), "loopback"},
		{"loopback other", ext("127.0.0.2", 8080), "loopback"},
		{"loopback v6", ext("::1", 8080), "loopback"},
		{"v4-mapped loopback", ext("::ffff:127.0.0.1", 8080), "loopback"},
		{"link-local v4 metadata", ext("169.254.169.254", 80), "link-local"},
		{"link-local v4", ext("169.254.1.1", 80), "link-local"},
		{"link-local v6", ext("fe80::1", 80), "link-local"},
		{"v4-mapped link-local", ext("::ffff:169.254.169.254", 80), "link-local"},
		{"multicast", ext("224.0.0.251", 5353), "multicast"},
		{"multicast v6", ext("ff02::fb", 5353), "multicast"},
		{"unspecified", ext("0.0.0.0", 80), "unspecified"},
		{"unspecified v6", ext("::", 80), "unspecified"},
		{"this network", ext("0.1.2.3", 80), "unspecified"},
		{"broadcast", ext("255.255.255.255", 80), "unspecified"},
		{"node apiserver", ext("192.168.1.10", 6443), "control-plane"},
		{"node kubelet", ext("192.168.1.10", 10250), "control-plane"},
		{"node kubelet ro", ext("192.168.1.10", 10255), "control-plane"},
		{"node etcd client", ext("192.168.1.10", 2379), "control-plane"},
		{"node etcd peer", ext("192.168.1.10", 2380), "control-plane"},
		{"node controller manager", ext("192.168.1.10", 10257), "control-plane"},
		{"node scheduler", ext("192.168.1.10", 10259), "control-plane"},
		{"node v6 apiserver", ext("fd00::10", 6443), "control-plane"},
		{"node apiserver via mapped v6", ext("::ffff:192.168.1.10", 6443), "control-plane"},
		{"inside the service CIDR", ext("10.43.0.1", 443), "service network"},
		{"hostname", ext("example.com", 80), "IP address literal"},
		{"zone", ext("fe80::1%eth0", 80), "IP address literal"},
		{"port 0", ext("192.168.1.50", 0), "port"},
		{"port too big", ext("192.168.1.50", 65536), "port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ap, err := p.Resolve(context.Background(), tc.spec)
			if tc.denied == "" {
				if err != nil {
					t.Fatalf("denied: %v", err)
				}
				if ap.Port() != uint16(tc.spec.Port) {
					t.Fatalf("resolved to %v", ap)
				}
				return
			}
			if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tc.denied) {
				t.Fatalf("err = %v, want ErrDenied containing %q", err, tc.denied)
			}
		})
	}
}

func TestSSHServiceIsFixedAndTheOnlyLoopbackByDefault(t *testing.T) {
	p := testPolicy(&fakeResolver{})
	// Whatever the spec says, ssh goes to 127.0.0.1:22.
	spec := api.ServiceSpec{ID: "ssh", Kind: api.ServiceKindSSH, Target: "10.9.9.9", Port: 2222, Protocol: api.ProtocolTCP}
	ap, err := p.Resolve(context.Background(), spec)
	if err != nil || ap != netip.MustParseAddrPort("127.0.0.1:22") {
		t.Fatalf("ssh resolved to %v, %v", ap, err)
	}
	// An external service to the same address is a plain loopback refusal.
	if _, err := p.Resolve(context.Background(), ext("127.0.0.1", 22)); !errors.Is(err, ErrDenied) {
		t.Fatalf("external 127.0.0.1:22 = %v", err)
	}
	// The configured sshd port (test hook / non-standard sshd) is honored.
	p.SSHPort = 2200
	if ap, err := p.Resolve(context.Background(), spec); err != nil || ap.Port() != 2200 {
		t.Fatalf("custom ssh port: %v, %v", ap, err)
	}
}

func TestAllowTargetHookOnlyLiftsTheLoopbackRefusal(t *testing.T) {
	echo := netip.MustParseAddrPort("127.0.0.1:40000")
	p := testPolicy(&fakeResolver{}, "127.0.0.1")
	p.AllowTarget = func(ap netip.AddrPort) bool { return ap == echo }
	if _, err := p.Resolve(context.Background(), ext("127.0.0.1", 40000)); err != nil {
		t.Fatalf("whitelisted loopback target: %v", err)
	}
	for _, spec := range []api.ServiceSpec{
		ext("127.0.0.1", 40001),    // not whitelisted
		ext("127.0.0.1", 6443),     // never the control plane
		ext("169.254.169.254", 80), // link-local is never lifted
		ext("10.43.0.1", 443),      // service network is never lifted
	} {
		if _, err := p.Resolve(context.Background(), spec); !errors.Is(err, ErrDenied) {
			t.Errorf("%v: %v", spec, err)
		}
	}
	p.AllowTarget = func(netip.AddrPort) bool { return true }
	if _, err := p.Resolve(context.Background(), ext("127.0.0.1", 6443)); !errors.Is(err, ErrDenied) {
		t.Errorf("hook allowed a control-plane port: %v", err)
	}
	if _, err := p.Resolve(context.Background(), ext("169.254.169.254", 80)); !errors.Is(err, ErrDenied) {
		t.Errorf("hook allowed link-local: %v", err)
	}
}

func TestInternalTargetRules(t *testing.T) {
	const fq = "grafana.monitoring.svc.cluster.local."
	cases := []struct {
		name    string
		res     *fakeResolver
		spec    api.ServiceSpec
		denied  string // ErrDenied containing; "" = allowed
		unreach bool   // ErrUnreachable
		want    string
	}{
		{"cluster ip", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5")}}}, internal("grafana.monitoring", 3000), "", false, "10.43.12.5:3000"},
		{"extra AAAA-looking v6 is ignored", &fakeResolver{ips: map[string][]net.IP{fq: {net.ParseIP("fd00::5"), ip4("10.43.12.5")}}}, internal("grafana.monitoring", 3000), "", false, "10.43.12.5:3000"},
		{"CNAME (ExternalName)", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5")}}, cnames: map[string]string{fq: "evil.example.com."}}, internal("grafana.monitoring", 3000), "CNAME", false, ""},
		{"CNAME to another cluster name", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5")}}, cnames: map[string]string{fq: "other.default.svc.cluster.local."}}, internal("grafana.monitoring", 3000), "CNAME", false, ""},
		{"CNAME case and dot differences are the same name", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5")}}, cnames: map[string]string{fq: "Grafana.Monitoring.SVC.cluster.local"}}, internal("grafana.monitoring", 3000), "", false, "10.43.12.5:3000"},
		{"pod ip (headless)", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.42.0.17")}}}, internal("grafana.monitoring", 3000), "outside the service network", false, ""},
		{"one pod ip among cluster ips", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5"), ip4("10.42.0.17")}}}, internal("grafana.monitoring", 3000), "outside the service network", false, ""},
		{"loopback answer", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("127.0.0.1")}}}, internal("grafana.monitoring", 3000), "outside the service network", false, ""},
		{"metadata answer", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("169.254.169.254")}}}, internal("grafana.monitoring", 3000), "outside the service network", false, ""},
		{"no A record", &fakeResolver{ips: map[string][]net.IP{fq: {net.ParseIP("fd00::5")}}}, internal("grafana.monitoring", 3000), "", true, ""},
		{"nxdomain", &fakeResolver{}, internal("grafana.monitoring", 3000), "", true, ""},
		{"resolver failure", &fakeResolver{ipErr: errors.New("servfail")}, internal("grafana.monitoring", 3000), "", true, ""},
		{"cname lookup failure fails closed", &fakeResolver{ips: map[string][]net.IP{fq: {ip4("10.43.12.5")}}, cnameEr: errors.New("timeout")}, internal("grafana.monitoring", 3000), "", true, ""},
		{"kube-system", &fakeResolver{ips: map[string][]net.IP{"kube-dns.kube-system.svc.cluster.local.": {ip4("10.43.0.10")}}}, internal("kube-dns.kube-system", 53), "kube-system", false, ""},
		{"kubernetes api", &fakeResolver{ips: map[string][]net.IP{"kubernetes.default.svc.cluster.local.": {ip4("10.43.0.1")}}}, internal("kubernetes.default", 443), "kubernetes API", false, ""},
		{"other default service is fine", &fakeResolver{ips: map[string][]net.IP{"web.default.svc.cluster.local.": {ip4("10.43.0.50")}}}, internal("web.default", 80), "", false, "10.43.0.50:80"},
		{"fqdn target refused", &fakeResolver{}, internal("grafana.monitoring.svc.cluster.local", 3000), "must be", false, ""},
		{"no namespace", &fakeResolver{}, internal("grafana", 3000), "must be", false, ""},
		{"bad port", &fakeResolver{}, internal("grafana.monitoring", 0), "port", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(tc.res)
			ap, err := p.Resolve(context.Background(), tc.spec)
			switch {
			case tc.unreach:
				if !errors.Is(err, ErrUnreachable) {
					t.Fatalf("err = %v, want ErrUnreachable", err)
				}
			case tc.denied != "":
				if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tc.denied) {
					t.Fatalf("err = %v, want ErrDenied containing %q", err, tc.denied)
				}
			default:
				if err != nil || ap.String() != tc.want {
					t.Fatalf("got %v, %v; want %s", ap, err, tc.want)
				}
			}
		})
	}
}

func TestInternalLooksUpAandOnlyA(t *testing.T) {
	res := &fakeResolver{ips: map[string][]net.IP{"a.b.svc.cluster.local.": {ip4("10.43.0.9")}}}
	p := testPolicy(res)
	if _, err := p.Resolve(context.Background(), internal("a.b", 80)); err != nil {
		t.Fatal(err)
	}
	if res.network != "ip4" {
		t.Fatalf("lookup network %q, want ip4 (A records only)", res.network)
	}
	// A custom cluster domain and a custom service CIDR.
	res = &fakeResolver{ips: map[string][]net.IP{"a.b.svc.k8s.example.": {ip4("172.20.1.1")}}}
	p = testPolicy(res)
	p.ClusterDomain = "k8s.example"
	p.ServiceCIDRs, _ = ParseServiceCIDRs("172.20.0.0/16, 10.96.0.0/12")
	if ap, err := p.Resolve(context.Background(), internal("a.b", 80)); err != nil || ap.String() != "172.20.1.1:80" {
		t.Fatalf("%v %v", ap, err)
	}
}

func TestEveryDialResolvesAgain(t *testing.T) {
	res := &fakeResolver{ips: map[string][]net.IP{"a.b.svc.cluster.local.": {ip4("10.43.0.9")}}}
	p := testPolicy(res)
	for range 3 {
		if _, err := p.Resolve(context.Background(), internal("a.b", 80)); err != nil {
			t.Fatal(err)
		}
	}
	if n := res.lookups.Load(); n != 3 {
		t.Fatalf("%d lookups for 3 dials", n)
	}
	// The service moves out of the CIDR (e.g. recreated headless): the next dial refuses.
	res.ips["a.b.svc.cluster.local."] = []net.IP{ip4("10.42.1.1")}
	if _, err := p.Resolve(context.Background(), internal("a.b", 80)); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseServiceCIDRs(t *testing.T) {
	got, err := ParseServiceCIDRs("10.43.0.0/16,fd00:43::/108")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "10.43.0.0", "nope"} {
		if _, err := ParseServiceCIDRs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDialServiceConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	p := testPolicy(&fakeResolver{})
	spec := ext("127.0.0.1", port)
	if _, err := p.DialService(context.Background(), spec, time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("loopback dial = %v", err)
	}
	p.AllowTarget = func(ap netip.AddrPort) bool { return int(ap.Port()) == port }
	c, err := p.DialService(context.Background(), spec, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = ln.Close()
	if _, err := p.DialService(context.Background(), spec, time.Second); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("closed port = %v", err)
	}
}
