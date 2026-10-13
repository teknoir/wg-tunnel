package turnbind

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/teknoir/wg-tunnel/internal/wgtest"
)

func udp(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestParseEndpoint(t *testing.T) {
	e, err := ParseEndpoint("10.1.2.3:51820")
	if err != nil {
		t.Fatal(err)
	}
	if e.DstToString() != "10.1.2.3:51820" || e.DstIP() != netip.MustParseAddr("10.1.2.3") || e.SrcIP().IsValid() || e.SrcToString() != "" {
		t.Fatalf("endpoint %#v", e)
	}
	e.ClearSrc()
	if got, _ := netip.AddrFromSlice(e.DstToBytes()[:4]); got != e.DstIP() {
		t.Fatalf("DstToBytes = %x", e.DstToBytes())
	}
	v6, err := ParseEndpoint("[2001:db8::1]:9")
	if err != nil || v6.DstIP() != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6: %v %v", v6, err)
	}
	mapped, err := ParseEndpoint("[::ffff:1.2.3.4]:9")
	if err != nil || mapped.DstIP() != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("mapped: %v %v", mapped, err)
	}
	for _, bad := range []string{"", "host:80", "1.2.3.4", "1.2.3.4:99999", ":80"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) accepted", bad)
		}
	}
	b := New(nil)
	if _, err := b.ParseEndpoint("bad"); err == nil {
		t.Error("Bind.ParseEndpoint accepted junk")
	}
	if ep, err := b.ParseEndpoint("1.2.3.4:5"); err != nil || ep.DstToString() != "1.2.3.4:5" {
		t.Errorf("Bind.ParseEndpoint = %v, %v", ep, err)
	}
}

func TestBindBasics(t *testing.T) {
	pc := udp(t)
	b := New(pc)
	if b.BatchSize() != 1 || b.SetMark(7) != nil {
		t.Fatal("BatchSize/SetMark")
	}
	if !b.LastReceive().IsZero() {
		t.Fatal("LastReceive must start zero")
	}
	if err := b.Send([][]byte{{1}}, Endpoint{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send before Open = %v", err)
	}
	fns, port, err := b.Open(0)
	if err != nil || len(fns) != 1 {
		t.Fatalf("Open: %v %d", err, len(fns))
	}
	if int(port) != pc.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("port = %d", port)
	}
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open = %v", err)
	}
	if err := b.Send([][]byte{{1}}, fakeEndpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("wrong endpoint type = %v", err)
	}

	// Send and receive through real sockets.
	peer := udp(t)
	dst := NewEndpoint(peer.LocalAddr().(*net.UDPAddr).AddrPort())
	if err := b.Send([][]byte{[]byte("hi"), []byte("there")}, dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, want := range []string{"hi", "there"} {
		n, from, err := peer.ReadFrom(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("peer read %q: %q %v", want, buf[:n], err)
		}
		if from.String() != pc.LocalAddr().String() {
			t.Fatalf("from %v", from)
		}
	}
	if _, err := peer.WriteTo([]byte("pong"), pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
	n, err := fns[0](pk, sizes, eps)
	if err != nil || n != 1 || string(pk[0][:sizes[0]]) != "pong" {
		t.Fatalf("recv: %d %v %q", n, err, pk[0][:sizes[0]])
	}
	if eps[0].DstToString() != peer.LocalAddr().String() {
		t.Fatalf("endpoint %s", eps[0].DstToString())
	}
	if time.Since(b.LastReceive()) > 5*time.Second || b.LastReceive().IsZero() {
		t.Fatalf("LastReceive = %v", b.LastReceive())
	}
	if b.LocalAddr().String() != pc.LocalAddr().String() {
		t.Fatal("LocalAddr")
	}
}

type fakeEndpoint struct{ Endpoint }

func TestCloseAndReopen(t *testing.T) {
	pc := udp(t)
	b := New(pc)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
		res <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-res:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked receive not woken by Close")
	}
	// The old receive function stays closed forever.
	if _, err := fns[0]([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old fn after Close = %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := b.Send([][]byte{{1}}, NewEndpoint(netip.MustParseAddrPort("127.0.0.1:9"))); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	// The conn is still usable: BindUpdate reopens.
	fns2, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	peer := udp(t)
	if _, err := peer.WriteTo([]byte("again"), pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
	if _, err := fns2[0](pk, sizes, eps); err != nil || string(pk[0][:sizes[0]]) != "again" {
		t.Fatalf("receive after reopen: %v %q", err, pk[0][:sizes[0]])
	}
}

func TestSwapKeepsReceiveRunning(t *testing.T) {
	a, c := udp(t), udp(t)
	b := New(a)
	fns, _, _ := b.Open(0)

	got := make(chan string, 4)
	errc := make(chan error, 1)
	go func() {
		for {
			pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
			if _, err := fns[0](pk, sizes, eps); err != nil {
				errc <- err
				return
			}
			got <- string(pk[0][:sizes[0]])
		}
	}()
	peer := udp(t)
	if _, err := peer.WriteTo([]byte("one"), a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "one")

	old := b.Swap(c)
	if old != net.PacketConn(a) {
		t.Fatalf("Swap returned %v", old)
	}
	if b.Swaps() != 1 {
		t.Fatal("Swaps")
	}
	_ = old.Close()
	if _, err := peer.WriteTo([]byte("two"), c.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "two")
	select {
	case err := <-errc:
		t.Fatalf("receive returned during swap: %v", err)
	default:
	}
	// Sending now leaves from the new socket.
	if err := b.Send([][]byte{[]byte("out")}, NewEndpoint(peer.LocalAddr().(*net.UDPAddr).AddrPort())); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, from, err := peer.ReadFrom(buf)
	if err != nil || from.String() != c.LocalAddr().String() {
		t.Fatalf("send source %v %v", from, err)
	}
	if b.Swap(c) != nil {
		t.Fatal("swapping in the installed conn must be a no-op")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}

func expect(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case s := <-ch:
		if s != want {
			t.Fatalf("got %q want %q", s, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %q", want)
	}
}

// A conn that was closed under the Bind must not end the receive function:
// wireguard-go would give up on it. It recovers when a new conn is swapped in.
func TestReceiveSurvivesDeadConn(t *testing.T) {
	a, c := udp(t), udp(t)
	b := New(a)
	fns, _, _ := b.Open(0)
	got := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		for {
			pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
			if _, err := fns[0](pk, sizes, eps); err != nil {
				errc <- err
				return
			}
			got <- string(pk[0][:sizes[0]])
		}
	}()
	_ = a.Close() // dies without a swap
	select {
	case err := <-errc:
		t.Fatalf("receive returned on dead conn: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	b.Swap(c)
	if _, err := udp(t).WriteTo([]byte("alive"), c.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "alive")
	_ = b.Close()
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestNilConnThenSwap(t *testing.T) {
	b := New(nil)
	fns, port, err := b.Open(0)
	if err != nil || port != 0 {
		t.Fatalf("Open: %v %d", err, port)
	}
	if err := b.Send([][]byte{{1}}, NewEndpoint(netip.MustParseAddrPort("127.0.0.1:9"))); !errors.Is(err, ErrNoConn) {
		t.Fatalf("Send without conn = %v", err)
	}
	if b.LocalAddr() != nil {
		t.Fatal("LocalAddr should be nil")
	}
	got := make(chan string, 1)
	go func() {
		pk, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)
		if _, err := fns[0](pk, sizes, eps); err == nil {
			got <- string(pk[0][:sizes[0]])
		}
	}()
	pc := udp(t)
	time.Sleep(50 * time.Millisecond)
	b.Swap(pc)
	if _, err := udp(t).WriteTo([]byte("late"), pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "late")
}

func TestNudgeValidation(t *testing.T) {
	if err := Nudge(nil, "00", 0); err == nil {
		t.Fatal("Nudge must reject a zero interval")
	}
}

// Two wireguard-go devices exchange a TCP stream through Binds; one side swaps
// its socket mid-stream (new source port, like a new TURN allocation). The TCP
// connection must survive and the stream must arrive complete and in order.
func TestWireGuardSurvivesSwapMidStream(t *testing.T) {
	cA, cB := udp(t), udp(t)
	bindA, bindB := New(cA), New(cB)
	addrA, addrB := netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("100.96.0.2")
	nodeA := wgtest.NewNode(t, bindA, addrA)
	nodeB := wgtest.NewNode(t, bindB, addrB)
	// B (the client) knows A's endpoint; A learns B's by roaming.
	nodeA.AddPeer(t, nodeB.Pub, addrB, "", 1)
	nodeB.AddPeer(t, nodeA.Pub, addrA, cA.LocalAddr().String(), 1)

	ln, err := nodeA.Net.ListenTCPAddrPort(netip.AddrPortFrom(addrA, 7))
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

	client, err := nodeB.Net.DialTCPAddrPort(netip.AddrPortFrom(addrA, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const chunks, chunkSize = 60, 400
	want := make([]byte, 0, chunks*chunkSize)
	for i := 0; i < chunks; i++ {
		chunk := bytes.Repeat([]byte{byte(i)}, chunkSize)
		want = append(want, chunk...)
	}
	readErr := make(chan error, 1)
	gotAll := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(client, got)
		readErr <- err
		gotAll <- got
	}()

	swapSide := func(b *Bind, node, other *wgtest.Node) {
		fresh := udp(t)
		old := b.Swap(fresh)
		if old != nil {
			_ = old.Close()
		}
		if err := Nudge(node.Dev, other.Pub.Hex(), 1); err != nil {
			t.Error(err)
		}
	}
	for i := 0; i < chunks; i++ {
		if _, err := client.Write(want[i*chunkSize : (i+1)*chunkSize]); err != nil {
			t.Fatalf("write chunk %d: %v", i, err)
		}
		switch i {
		case 20:
			swapSide(bindA, nodeA, nodeB)
		case 40:
			swapSide(bindB, nodeB, nodeA)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-readErr:
		if err != nil {
			t.Fatalf("echo stream broke: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("echo stream stalled after swap")
	}
	if !bytes.Equal(<-gotAll, want) {
		t.Fatal("echoed bytes differ")
	}
	if bindA.Swaps() != 1 || bindB.Swaps() != 1 {
		t.Fatalf("swaps = %d, %d", bindA.Swaps(), bindB.Swaps())
	}
	if time.Since(bindA.LastReceive()) > 5*time.Second || time.Since(bindB.LastReceive()) > 5*time.Second {
		t.Fatal("LastReceive not advancing")
	}
}
