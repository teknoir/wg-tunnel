package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS is a UDP DNS server with a table of names to A records or a CNAME,
// so that the internal-service rules are tested against the REAL net.Resolver
// (pure Go): plain Service answers, ExternalName answers (CNAME + A) and
// headless answers.
type fakeDNS struct {
	pc    net.PacketConn
	a     map[string][4]byte
	cname map[string]string // name -> target; the target's A record comes from a
}

func startFakeDNS(t *testing.T, a map[string][4]byte, cname map[string]string) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDNS{pc: pc, a: a, cname: cname}
	t.Cleanup(func() { _ = pc.Close() })
	go d.serve()
	return d
}

func (d *fakeDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
			continue
		}
		qs := q.Questions[0]
		name := qs.Name.String()
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionAvailable: true},
			Questions: q.Questions,
		}
		target := name
		if c, ok := d.cname[name]; ok {
			target = c
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: qs.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 5},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(c)},
			})
		}
		if ip, ok := d.a[target]; ok {
			if qs.Type == dnsmessage.TypeA || qs.Type == dnsmessage.TypeALL {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5},
					Body:   &dnsmessage.AResource{A: ip},
				})
			}
		} else if len(resp.Answers) == 0 {
			resp.Header.RCode = dnsmessage.RCodeNameError
		}
		out, err := resp.Pack()
		if err == nil {
			_, _ = d.pc.WriteTo(out, addr)
		}
	}
}

func (d *fakeDNS) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "udp", d.pc.LocalAddr().String())
	}}
}

func TestInternalRulesAgainstTheRealResolver(t *testing.T) {
	dns := startFakeDNS(t,
		map[string][4]byte{
			"grafana.monitoring.svc.cluster.local.": {10, 43, 12, 5},
			"podip.apps.svc.cluster.local.":         {10, 42, 0, 17},
			"evil.example.com.":                     {10, 43, 99, 99}, // an ExternalName target that happens to be in the CIDR
		},
		map[string]string{
			"extname.apps.svc.cluster.local.": "evil.example.com.",
		})
	p := testPolicy(dns.resolver())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ap, err := p.Resolve(ctx, internal("grafana.monitoring", 3000))
	if err != nil || ap != netip.MustParseAddrPort("10.43.12.5:3000") {
		t.Fatalf("plain service: %v %v", ap, err)
	}
	// ExternalName: the answer comes through a CNAME. The plain-Service path
	// must see the canonical name equal to the queried one, an ExternalName
	// service must not.
	if _, err := p.Resolve(ctx, internal("extname.apps", 80)); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("externalname: %v", err)
	}
	if _, err := p.Resolve(ctx, internal("podip.apps", 80)); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "service network") {
		t.Fatalf("pod ip: %v", err)
	}
	if _, err := p.Resolve(ctx, internal("missing.apps", 80)); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("nxdomain: %v", err)
	}
}
