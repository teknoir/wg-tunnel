package hub

import (
	"net/netip"
	"testing"
	"time"
)

func testIPAM(t *testing.T, prefix string, hub string, q time.Duration, clock *fakeClock) *ipam {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	m, err := newIPAM(p.Addr(), netip.MustParseAddr(hub), p.Bits(), q, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIPAMExcludesNetworkHubBroadcast(t *testing.T) {
	clock := newFakeClock()
	m := testIPAM(t, "100.96.0.0/29", "100.96.0.1", time.Minute, clock)
	seen := map[netip.Addr]bool{}
	for {
		ip, err := m.Alloc()
		if err != nil {
			if err != ErrPoolExhausted {
				t.Fatal(err)
			}
			break
		}
		if seen[ip] {
			t.Fatalf("%s allocated twice", ip)
		}
		seen[ip] = true
	}
	// /29: 8 addresses, minus network, hub and broadcast = 5.
	if len(seen) != 5 {
		t.Fatalf("allocated %d addresses (%v), want 5", len(seen), seen)
	}
	for _, bad := range []string{"100.96.0.0", "100.96.0.1", "100.96.0.7"} {
		if seen[netip.MustParseAddr(bad)] {
			t.Fatalf("handed out reserved address %s", bad)
		}
	}
}

func TestIPAMQuarantine(t *testing.T) {
	clock := newFakeClock()
	m := testIPAM(t, "100.96.0.0/29", "100.96.0.1", 5*time.Minute, clock)
	var ips []netip.Addr
	for range 5 {
		ip, err := m.Alloc()
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, ip)
	}
	m.Release(ips[2])
	if _, err := m.Alloc(); err != ErrPoolExhausted {
		t.Fatalf("released address reused during quarantine: %v", err)
	}
	clock.Advance(4*time.Minute + 59*time.Second)
	if _, err := m.Alloc(); err != ErrPoolExhausted {
		t.Fatal("quarantine ended early")
	}
	clock.Advance(2 * time.Second)
	ip, err := m.Alloc()
	if err != nil || ip != ips[2] {
		t.Fatalf("after quarantine got %v, %v; want %v", ip, err, ips[2])
	}
}

func TestIPAMFreeSkipsQuarantine(t *testing.T) {
	clock := newFakeClock()
	m := testIPAM(t, "100.96.0.0/30", "100.96.0.1", time.Hour, clock)
	ip, err := m.Alloc() // /30: only .2 is usable
	if err != nil {
		t.Fatal(err)
	}
	m.Free(ip)
	if again, err := m.Alloc(); err != nil || again != ip {
		t.Fatalf("Free should return the address immediately: %v %v", again, err)
	}
}

func TestIPAMRoundRobinAvoidsImmediateReuse(t *testing.T) {
	clock := newFakeClock()
	m := testIPAM(t, "100.96.0.0/24", "100.96.0.1", 0, clock)
	a, _ := m.Alloc()
	m.Release(a)
	b, _ := m.Alloc()
	if a == b {
		t.Fatalf("freshly released %s was handed out again at once", a)
	}
	if m.Sweep() != 0 && m.InUse() != 1 {
		t.Fatalf("unexpected state: inUse=%d", m.InUse())
	}
}

func TestIPAMProductionPrefix(t *testing.T) {
	clock := newFakeClock()
	m := testIPAM(t, "100.96.0.0/16", "100.96.0.1", time.Minute, clock)
	ip, err := m.Alloc()
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("100.96.0.0/16").Contains(ip) || ip == netip.MustParseAddr("100.96.0.1") || ip == netip.MustParseAddr("100.96.0.0") {
		t.Fatalf("bad address %s", ip)
	}
}
