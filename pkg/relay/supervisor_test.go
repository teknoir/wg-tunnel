package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/teknoir/wg-tunnel/internal/turntest"
	"github.com/teknoir/wg-tunnel/internal/wgtest"
	"github.com/teknoir/wg-tunnel/pkg/turnbind"
)

type swapEvents struct {
	mu      sync.Mutex
	reasons []string
}

func (e *swapEvents) add(r string) {
	e.mu.Lock()
	e.reasons = append(e.reasons, r)
	e.mu.Unlock()
}

func (e *swapEvents) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.reasons...)
}

func (e *swapEvents) has(r string) bool {
	for _, x := range e.list() {
		if x == r {
			return true
		}
	}
	return false
}

// pusher makes the peer send "tick" to the supervisor's current relayed
// address every interval, like a hub that talks to a client.
func pusher(t *testing.T, peer *net.UDPConn, sup *Supervisor, every time.Duration) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		tk := time.NewTicker(every)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				if r := sup.Current(); r != nil {
					_, _ = peer.WriteTo([]byte("tick"), net.UDPAddrFromAddrPort(r.RelayedAddr()))
				}
			}
		}
	}()
}

func drain(b *turnbind.Bind) (count *atomic.Int64) {
	count = new(atomic.Int64)
	fns, _, err := b.Open(0)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
			if _, err := fns[0](pk, sizes, eps); err != nil {
				return
			}
			count.Add(1)
		}
	}()
	return count
}

func fastCfg(b *turnbind.Bind, creds func(context.Context) (Config, error), ev *swapEvents) SupervisorConfig {
	return SupervisorConfig{
		Bind: b, Creds: creds,
		// Generous: under a loaded machine the pusher may be late by hundreds
		// of milliseconds, which must not look like a dead relay.
		StaleAfter: time.Second, CheckInterval: 25 * time.Millisecond,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		AllocateTimeout: 5 * time.Second,
		OnSwap:          ev.add,
	}
}

func TestSupervisorConfigValidation(t *testing.T) {
	if _, err := NewSupervisor(SupervisorConfig{}); err == nil {
		t.Error("accepted empty config")
	}
	if _, err := NewSupervisor(SupervisorConfig{Bind: turnbind.New(nil)}); err == nil {
		t.Error("accepted config without credentials")
	}
	s, err := NewSupervisor(SupervisorConfig{Bind: turnbind.New(nil), Creds: func(context.Context) (Config, error) { return Config{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.StaleAfter != 75*time.Second || s.cfg.AllocateTimeout != DefaultAllocateTimeout || s.cfg.CheckInterval != 5*time.Second {
		t.Fatalf("defaults: %+v", s.cfg)
	}
	if err := s.Rotate(Config{}); err == nil {
		t.Error("Rotate accepted an invalid config")
	}
	if err := s.Rotate(Config{Server: "a:1", Username: "u", Peer: netip.MustParseAddrPort("1.2.3.4:5")}); err == nil {
		t.Error("Rotate before Start succeeded")
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

func TestSupervisorStartFailsFast(t *testing.T) {
	srv := turntest.Start(t, secret)
	peer := newUDP(t)
	bad := creds(srv.Addr, udpAP(peer), "a")
	bad.Password = "nope"
	b := turnbind.New(nil)
	ev := &swapEvents{}
	sup, _ := NewSupervisor(fastCfg(b, func(context.Context) (Config, error) { return bad, nil }, ev))
	if err := sup.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded with bad credentials")
	}
	sup2, _ := NewSupervisor(fastCfg(b, func(context.Context) (Config, error) { return Config{}, errors.New("no creds") }, ev))
	if err := sup2.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded without credentials")
	}
	if len(ev.list()) != 0 || srv.Allocations() != 0 {
		t.Fatalf("events %v allocations %d", ev.list(), srv.Allocations())
	}
	_ = sup.Close()
	_ = sup2.Close()
}

func TestSupervisorStaleOnServerRestart(t *testing.T) {
	srv := turntest.Start(t, secret)
	hub := newUDP(t)
	b := turnbind.New(nil)
	count := drain(b)
	ev := &swapEvents{}
	var ncreds atomic.Int32
	sup, err := NewSupervisor(fastCfg(b, func(context.Context) (Config, error) {
		ncreds.Add(1)
		return creds(srv.Addr, udpAP(hub), "dev"), nil
	}, ev))
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Close()
	pusher(t, hub, sup, 20*time.Millisecond)

	eventually(t, 15*time.Second, "traffic", func() bool { return count.Load() > 5 })
	first := sup.Current()
	time.Sleep(1300 * time.Millisecond) // longer than StaleAfter: traffic keeps it healthy
	if sup.Current() != first || b.Swaps() != 1 {
		t.Fatalf("healthy relay was replaced: swaps=%d events=%v", b.Swaps(), ev.list())
	}

	srv.Restart() // all allocations lost
	before := count.Load()
	// OnSwap runs just after the new relay is installed, so wait for the event
	// itself, not only for the relay to change.
	eventually(t, 30*time.Second, "supervisor recovery", func() bool {
		return sup.Current() != first && count.Load() > before+5 && (ev.has(ReasonStale) || ev.has(ReasonRefreshFailed))
	})
	// Old relay is closed, exactly one allocation is live.
	if _, _, err := first.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("old relay still readable")
	}
	eventually(t, 15*time.Second, "single allocation", func() bool { return srv.Allocations() == 1 })
	if ncreds.Load() < 2 {
		t.Fatalf("Creds called %d times", ncreds.Load())
	}
}

func TestSupervisorRotate(t *testing.T) {
	srv := turntest.Start(t, secret)
	hub := newUDP(t)
	b := turnbind.New(nil)
	count := drain(b)
	ev := &swapEvents{}
	initial := creds(srv.Addr, udpAP(hub), "dev-1")
	sup, err := NewSupervisor(SupervisorConfig{
		Bind: b, Initial: &initial, StaleAfter: 500 * time.Millisecond, CheckInterval: 25 * time.Millisecond,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, OnSwap: ev.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Close()
	if sup.Start(context.Background()) == nil {
		t.Fatal("second Start succeeded")
	}
	pusher(t, hub, sup, 20*time.Millisecond)
	eventually(t, 15*time.Second, "traffic", func() bool { return count.Load() > 3 })
	first := sup.Current()

	next := creds(srv.Addr, udpAP(hub), "dev-2")
	if err := sup.Rotate(next); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "rotation", func() bool { return sup.Current() != first && b.Swaps() == 2 && ev.has(ReasonRotate) })
	if got := sup.Current().Config().Username; got != next.Username {
		t.Fatalf("rotated relay uses username %q", got)
	}
	eventually(t, 15*time.Second, "old allocation released", func() bool { return srv.Allocations() == 1 })
	before := count.Load()
	eventually(t, 15*time.Second, "traffic after rotation", func() bool { return count.Load() > before+3 })

	// Without Creds the last (rotated) configuration is reused on staleness.
	srv.Restart()
	eventually(t, 30*time.Second, "recovery with reused config", func() bool {
		r := sup.Current()
		return r != nil && r.Config().Username == next.Username && b.Swaps() >= 3
	})
}

func TestSupervisorRefreshFailureSwapsWithoutStaleness(t *testing.T) {
	t.Parallel()
	srv := turntest.Start(t, secret, turntest.WithAllocationLifetime(2*time.Second))
	hub := newUDP(t)
	b := turnbind.New(nil)
	ev := &swapEvents{}
	sup, err := NewSupervisor(SupervisorConfig{
		Bind: b,
		Creds: func(context.Context) (Config, error) {
			return creds(srv.Addr, udpAP(hub), "dev"), nil
		},
		// Liveness always looks fresh, so only the refresh signal can trigger.
		LastReceive: time.Now,
		StaleAfter:  time.Hour, CheckInterval: 25 * time.Millisecond,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 100 * time.Millisecond, OnSwap: ev.add,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Close()
	first := sup.Current()
	srv.Restart()
	// Current() changes just before OnSwap reports the reason, so wait for the
	// event, and only then check the relay.
	eventually(t, 60*time.Second, "refresh-failure swap event", func() bool { return ev.has(ReasonRefreshFailed) })
	if sup.Current() == first {
		t.Fatalf("relay not replaced; events %v", ev.list())
	}
}

func TestSupervisorRetriesWithBackoffKeepingOldRelay(t *testing.T) {
	srv := turntest.Start(t, secret)
	hub := newUDP(t)
	b := turnbind.New(nil)
	ev := &swapEvents{}
	var fail atomic.Bool
	var calls atomic.Int32
	sup, _ := NewSupervisor(SupervisorConfig{
		Bind: b,
		Creds: func(context.Context) (Config, error) {
			calls.Add(1)
			if fail.Load() {
				return Config{}, errors.New("token service down")
			}
			return creds(srv.Addr, udpAP(hub), "dev"), nil
		},
		LastReceive: func() time.Time { return time.Time{} }, // never receives: always stale
		StaleAfter:  200 * time.Millisecond, CheckInterval: 20 * time.Millisecond,
		MinBackoff: 100 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, OnSwap: ev.add,
	})
	// Healthy start, then the credential source breaks.
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Close()
	first := sup.Current()
	fail.Store(true)
	callsBefore := calls.Load()
	time.Sleep(1200 * time.Millisecond)
	if sup.Current() != first {
		t.Fatal("old relay dropped although re-allocation never succeeded")
	}
	n := calls.Load() - callsBefore
	if n < 2 || n > 8 {
		t.Fatalf("expected bounded retries with backoff, got %d attempts in 1.2s", n)
	}
	if srv.Allocations() != 1 {
		t.Fatalf("allocations = %d", srv.Allocations())
	}
	fail.Store(false)
	eventually(t, 20*time.Second, "recovery after credentials return", func() bool { return sup.Current() != first })
	eventually(t, 15*time.Second, "single allocation", func() bool { return srv.Allocations() == 1 })
}

func TestSupervisorClose(t *testing.T) {
	srv := turntest.Start(t, secret)
	hub := newUDP(t)
	b := turnbind.New(nil)
	ev := &swapEvents{}
	cfg := creds(srv.Addr, udpAP(hub), "dev")
	sup, _ := NewSupervisor(SupervisorConfig{Bind: b, Initial: &cfg, StaleAfter: time.Minute, OnSwap: ev.add})
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.Allocations() != 1 {
		t.Fatalf("allocations = %d", srv.Allocations())
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
	if sup.Current() != nil {
		t.Fatal("Current after Close")
	}
	eventually(t, 15*time.Second, "allocation released", func() bool { return srv.Allocations() == 0 })
	_, _, _ = b.Open(0)
	if err := b.Send([][]byte{{1}}, turnbind.NewEndpoint(netip.MustParseAddrPort("127.0.0.1:9"))); !errors.Is(err, turnbind.ErrNoConn) {
		t.Fatalf("Send after Close = %v", err)
	}
	if err := sup.Rotate(cfg); err == nil {
		t.Fatal("Rotate after Close succeeded")
	}
}

func TestSupervisorStopsWithContext(t *testing.T) {
	srv := turntest.Start(t, secret)
	hub := newUDP(t)
	b := turnbind.New(nil)
	cfg := creds(srv.Addr, udpAP(hub), "dev")
	sup, _ := NewSupervisor(SupervisorConfig{Bind: b, Initial: &cfg, StaleAfter: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-sup.done:
	case <-time.After(3 * time.Second):
		t.Fatal("loop did not stop with its context")
	}
	if err := sup.Close(); err != nil {
		t.Fatal(err)
	}
}

// End to end: a WireGuard "client" device whose transport is Bind+Supervisor
// over TURN talks to a "hub" device on plain UDP. The TURN server restarts in
// the middle of a TCP echo stream; the supervisor re-allocates, the keepalive
// nudge lets the hub re-learn the endpoint, and the stream completes intact.
func TestWireGuardOverTURNSurvivesServerRestart(t *testing.T) {
	srv := turntest.Start(t, secret)

	hubSock := newUDP(t)
	hubAddr, clientAddr := netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("100.96.0.2")
	hubBind := turnbind.New(hubSock)
	hub := wgtest.NewNode(t, hubBind, hubAddr)

	clientBind := turnbind.New(nil)
	client := wgtest.NewNode(t, clientBind, clientAddr)
	hub.AddPeer(t, client.Pub, clientAddr, "", 0)
	client.AddPeer(t, hub.Pub, hubAddr, udpAP(hubSock).String(), 1)

	ev := &swapEvents{}
	sup, err := NewSupervisor(SupervisorConfig{
		Bind: clientBind,
		Creds: func(context.Context) (Config, error) {
			return creds(srv.Addr, udpAP(hubSock), "dev"), nil
		},
		StaleAfter: time.Second, CheckInterval: 50 * time.Millisecond,
		MinBackoff: 100 * time.Millisecond, MaxBackoff: 500 * time.Millisecond,
		OnSwap: func(reason string) {
			ev.add(reason)
			_ = turnbind.Nudge(client.Dev, hub.Pub.Hex(), 1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Close()

	ln, err := hub.Net.ListenTCPAddrPort(netip.AddrPortFrom(hubAddr, 22))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	c, err := client.Net.DialTCPAddrPort(netip.AddrPortFrom(hubAddr, 22))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const chunks, size = 120, 300
	want := make([]byte, 0, chunks*size)
	for i := 0; i < chunks; i++ {
		want = append(want, bytes.Repeat([]byte{byte(i)}, size)...)
	}
	got := make(chan []byte, 1)
	rerr := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		_, err := io.ReadFull(c, buf)
		rerr <- err
		got <- buf
	}()
	for i := 0; i < chunks; i++ {
		if _, err := c.Write(want[i*size : (i+1)*size]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if i == 40 {
			srv.Restart()
		}
		time.Sleep(30 * time.Millisecond)
	}
	select {
	case err := <-rerr:
		if err != nil {
			t.Fatalf("stream broke: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("stream stalled; swap events %v", ev.list())
	}
	if !bytes.Equal(<-got, want) {
		t.Fatal("echoed bytes differ")
	}
	if len(ev.list()) < 2 {
		t.Fatalf("expected a re-allocation, events %v", ev.list())
	}
	eventually(t, 15*time.Second, "single allocation", func() bool { return srv.Allocations() == 1 })
}
