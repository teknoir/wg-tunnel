package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/turntest"
	"github.com/teknoir/wg-tunnel/pkg/turncred"
)

const secret = "test-shared-secret"

func newUDP(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func udpAP(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func creds(server string, peer netip.AddrPort, id string) Config {
	u, p, _ := turncred.Generate(secret, "teknoir-demo/"+id, 30*time.Minute, time.Now())
	return Config{Server: server, Username: u, Password: p, Peer: peer}
}

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAllocateRoundTripAndPermission(t *testing.T) {
	srv := turntest.Start(t, secret)
	peer := newUDP(t)
	r, err := Allocate(context.Background(), creds(srv.Addr, udpAP(peer), "a"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Peer() != udpAP(peer) || r.Config().Realm != DefaultRealm {
		t.Fatalf("peer/config: %v %+v", r.Peer(), r.Config())
	}
	if !r.RelayedAddr().IsValid() || r.RelayedAddr().Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("RelayedAddr = %v", r.RelayedAddr())
	}
	if srv.Allocations() != 1 {
		t.Fatalf("allocations = %d", srv.Allocations())
	}

	// Peer -> relay BEFORE the relay has sent anything: only works because the
	// permission was created up front.
	if _, err := peer.WriteTo([]byte("hello relay"), net.UDPAddrFromAddrPort(r.RelayedAddr())); err != nil {
		t.Fatal(err)
	}
	_ = r.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := r.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello relay" || from.String() != peer.LocalAddr().String() {
		t.Fatalf("relay read: %q %v %v", buf[:n], from, err)
	}
	// relay -> peer
	if _, err := r.WriteTo([]byte("hello peer"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err = peer.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello peer" || from.String() != r.RelayedAddr().String() {
		t.Fatalf("peer read: %q %v %v", buf[:n], from, err)
	}
	// Large-ish datagram near the WireGuard MTU.
	big := bytes.Repeat([]byte{0xab}, 1280)
	if _, err := r.WriteTo(big, peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], big) {
		t.Fatalf("big datagram: %d %v", n, err)
	}
}

func TestCloseReleasesEverything(t *testing.T) {
	srv := turntest.Start(t, secret)
	peer := newUDP(t)
	r, err := Allocate(context.Background(), creds(srv.Addr, udpAP(peer), "a"))
	if err != nil {
		t.Fatal(err)
	}
	local := r.sock.LocalAddr().String()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	eventually(t, 15*time.Second, "server to drop the allocation", func() bool { return srv.Allocations() == 0 })
	// The UDP socket is closed: its port can be bound again.
	c, err := net.ListenPacket("udp4", local)
	if err != nil {
		t.Fatalf("local socket still bound: %v", err)
	}
	_ = c.Close()
	if _, _, err := r.ReadFrom(make([]byte, 16)); err == nil {
		t.Fatal("ReadFrom on a closed relay succeeded")
	}
}

func TestAllocateErrors(t *testing.T) {
	srv := turntest.Start(t, secret)
	peer := newUDP(t)
	good := creds(srv.Addr, udpAP(peer), "a")

	for name, mut := range map[string]func(*Config){
		"no server":   func(c *Config) { c.Server = "" },
		"no username": func(c *Config) { c.Username = "" },
		"no peer":     func(c *Config) { c.Peer = netip.AddrPort{} },
		"bad server":  func(c *Config) { c.Server = "nonsense" },
	} {
		c := good
		mut(&c)
		if r, err := Allocate(context.Background(), c); err == nil {
			_ = r.Close()
			t.Errorf("%s: no error", name)
		}
	}

	bad := good
	bad.Password = "wrong"
	if r, err := Allocate(context.Background(), bad); err == nil {
		_ = r.Close()
		t.Error("wrong password accepted")
	}
	expired := creds(srv.Addr, udpAP(peer), "x")
	u, p, _ := turncred.Generate(secret, "ns/x", time.Minute, time.Now().Add(-time.Hour))
	expired.Username, expired.Password = u, p
	if r, err := Allocate(context.Background(), expired); err == nil {
		_ = r.Close()
		t.Error("expired credentials accepted")
	}
	if srv.Allocations() != 0 {
		t.Fatalf("leaked allocations: %d", srv.Allocations())
	}
}

func TestAllocateHonoursContext(t *testing.T) {
	// A server that never answers.
	black := newUDP(t)
	peer := newUDP(t)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r, err := Allocate(ctx, creds(black.LocalAddr().String(), udpAP(peer), "a"))
	if err == nil {
		_ = r.Close()
		t.Fatal("allocation against a black hole succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestAllocateResolvesHostnames(t *testing.T) {
	srv := turntest.Start(t, secret)
	peer := newUDP(t)
	_, port, _ := net.SplitHostPort(srv.Addr)
	r, err := Allocate(context.Background(), creds("localhost:"+port, udpAP(peer), "a"))
	if err != nil {
		if strings.Contains(err.Error(), "resolving") {
			t.Skipf("localhost does not resolve here: %v", err)
		}
		t.Fatal(err)
	}
	_ = r.Close()
}

// pion only logs refresh failures; the Relay must surface them.
func TestFailedSignalsRefreshError(t *testing.T) {
	t.Parallel()
	srv := turntest.Start(t, secret, turntest.WithAllocationLifetime(2*time.Second))
	peer := newUDP(t)
	r, err := Allocate(context.Background(), creds(srv.Addr, udpAP(peer), "a"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	select {
	case <-r.Failed():
		t.Fatal("Failed() closed on a healthy relay")
	case <-time.After(2500 * time.Millisecond): // survives at least two refresh cycles
	}
	if r.Err() != nil {
		t.Fatalf("Err = %v", r.Err())
	}
	t0 := time.Now()
	srv.Restart() // allocation vanishes; the next refresh is rejected
	select {
	case <-r.Failed():
		t.Logf("failure surfaced after %v: %v", time.Since(t0), r.Err())
	case <-time.After(15 * time.Second):
		t.Fatal("refresh failure not surfaced")
	}
	if r.Err() == nil || !strings.Contains(strings.ToLower(r.Err().Error()), "refresh") {
		t.Fatalf("Err = %v", r.Err())
	}
}
