package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

func mustAP(t testing.TB, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// wgPacket fabricates the first bytes of a WireGuard message of the given
// type and size with a random index at bytes 4..8.
func wgPacket(typ byte, size int) []byte {
	p := make([]byte, size)
	_, _ = rand.Read(p)
	p[0], p[1], p[2], p[3] = typ, 0, 0, 0
	return p
}

func TestClassify(t *testing.T) {
	t.Parallel()
	req, _, err := newBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	var id txID
	resp := encodeBindingResponse(id, mustAP(t, "203.0.113.7:4242"))
	key, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.Public()
	pr, err := buildProbe([32]byte{1}, idOf(pub), probePing, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
		want Kind
	}{
		{"STUN request", req, KindSTUN},
		{"STUN response", resp, KindSTUN},
		{"probe", pr, KindProbe},
		{"WG initiation", wgPacket(1, 148), KindWireGuard},
		{"WG response", wgPacket(2, 92), KindWireGuard},
		{"WG cookie", wgPacket(3, 64), KindWireGuard},
		{"WG keepalive", wgPacket(4, 32), KindWireGuard},
		{"WG data", wgPacket(4, 1280), KindWireGuard},
		{"empty", nil, KindWireGuard},
		{"short", []byte{0, 1, 0, 0}, KindWireGuard},
	}
	for _, c := range cases {
		if got := Classify(c.pkt); got != c.want {
			t.Errorf("%s: classified as %d, want %d", c.name, got, c.want)
		}
	}

	// A WireGuard datagram whose bytes 4..8 happen to equal the STUN cookie is
	// still WireGuard: its length field (bytes 2..4) is zero, which would make
	// it a 20-byte STUN message, and no WireGuard message is that short.
	for _, size := range []int{32, 64, 92, 148, 1280} {
		p := wgPacket(1, size)
		binary.BigEndian.PutUint32(p[4:8], stunMagic)
		if Classify(p) != KindWireGuard {
			t.Errorf("WireGuard-shaped %d-byte packet with the STUN cookie was taken for STUN", size)
		}
	}
	// And the first two bits must be 00.
	bad := append([]byte(nil), req...)
	bad[0] |= 0x40
	if Classify(bad) == KindSTUN {
		t.Error("a message whose first bits are not 00 was taken for STUN")
	}
	// A STUN message with an inconsistent length is not STUN.
	bad = append([]byte(nil), resp...)
	bad = bad[:len(bad)-4]
	if Classify(bad) == KindSTUN {
		t.Error("a truncated STUN message was accepted")
	}
}

func TestSTUNEncodeParse(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"203.0.113.7:4242", "[2001:db8::1]:55555", "10.0.0.1:1"} {
		id := txID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		want := mustAP(t, s)
		gotID, got, err := parseBindingResponse(encodeBindingResponse(id, want))
		if err != nil || gotID != id || got != want {
			t.Fatalf("%s: got %v %v err %v", s, got, gotID, err)
		}
	}
	// Plain MAPPED-ADDRESS is accepted when there is no XOR-MAPPED-ADDRESS.
	b := make([]byte, stunHeaderLen, 40)
	binary.BigEndian.PutUint16(b[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	attr := []byte{0, 1, 0, 8, 0, 1, 0x30, 0x39, 192, 0, 2, 9}
	b = append(b, attr...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(attr)))
	_, got, err := parseBindingResponse(b)
	if err != nil || got != mustAP(t, "192.0.2.9:12345") {
		t.Fatalf("MAPPED-ADDRESS: %v %v", got, err)
	}
	if _, _, err := parseBindingResponse(b[:10]); err == nil {
		t.Fatal("garbage parsed")
	}
}

func listenUDP(t testing.TB) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestBindingThroughDemux(t *testing.T) {
	t.Parallel()
	srv := listenUDP(t)
	go ServeSTUN(srv)
	defer srv.Close()

	s, err := OpenSocket(SocketConfig{Conn: listenUDP(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := s.Conn().Binding(ctx, mustAP(t, srv.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if got != mustAP(t, s.Conn().LocalAddr().String()) {
		t.Fatalf("reflexive address %v, local %v", got, s.Conn().LocalAddr())
	}

	// WireGuard datagrams still reach ReadFrom while STUN is consumed.
	peer := listenUDP(t)
	defer peer.Close()
	wg := wgPacket(4, 100)
	if _, err := peer.WriteTo(wg, s.Conn().LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = s.Conn().SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := s.Conn().ReadFrom(buf)
	if err != nil || n != len(wg) || from.String() != peer.LocalAddr().String() {
		t.Fatalf("ReadFrom: %d %v %v", n, from, err)
	}
	// A deadline in the past times out; clearing it blocks again.
	_ = s.Conn().SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := s.Conn().ReadFrom(buf); err == nil {
		t.Fatal("expired deadline did not fail the read")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("deadline error %v is not a timeout", err)
	}
}

func TestBindingTimeoutAndWrongSource(t *testing.T) {
	t.Parallel()
	// A silent "server": the Binding must give up at the context deadline.
	silent := listenUDP(t)
	defer silent.Close()
	s, err := OpenSocket(SocketConfig{Conn: listenUDP(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := s.Conn().Binding(ctx, mustAP(t, silent.LocalAddr().String())); err == nil {
		t.Fatal("Binding to a silent server succeeded")
	}

	// A response from a source other than the server is ignored: a spoofer
	// answers every request it can see, the real server never does.
	spoof := listenUDP(t)
	defer spoof.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := silent.ReadFrom(buf)
			if err != nil {
				return
			}
			var id txID
			copy(id[:], buf[8:20])
			_ = n
			_, _ = spoof.WriteTo(encodeBindingResponse(id, mustAP(t, "198.51.100.1:1")), s.Conn().LocalAddr())
		}
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel2()
	if ap, err := s.Conn().Binding(ctx2, mustAP(t, silent.LocalAddr().String())); err == nil {
		t.Fatalf("accepted a response from the wrong source: %v", ap)
	}
}

func TestBuildCandidates(t *testing.T) {
	t.Parallel()
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	hosts := []netip.Addr{
		addr("192.168.1.10"), addr("203.0.113.5"), addr("10.0.0.2"), addr("fe80::1"), addr("169.254.3.4"),
		addr("fd00::5"), addr("2001:db8::7"), addr("192.168.1.10"), addr("0.0.0.0"), addr("224.0.0.1"), addr("::ffff:10.9.9.9"),
	}
	srflx := []netip.AddrPort{mustAP(t, "198.51.100.9:7000"), mustAP(t, "198.51.100.9:7000")}
	got := Strings(BuildCandidates(hosts, 5000, srflx, api.MaxP2PCandidates))
	want := []string{
		// private hosts first (in listing order), then server-reflexive, then public hosts
		"192.168.1.10:5000", "10.0.0.2:5000", "[fd00::5]:5000", "10.9.9.9:5000",
		"198.51.100.9:7000",
		"203.0.113.5:5000", "[2001:db8::7]:5000",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates\n got  %v\n want %v", got, want)
	}
	// The cap keeps the reflexive candidate and prefers private hosts to public ones.
	got = Strings(BuildCandidates(hosts, 5000, srflx, 3))
	if len(got) != 3 || !strings.Contains(strings.Join(got, ","), "198.51.100.9:7000") {
		t.Fatalf("capped candidates %v", got)
	}
	if strings.Contains(strings.Join(got, ","), "203.0.113.5") {
		t.Fatalf("a public host beat a private one under the cap: %v", got)
	}
	if n := len(BuildCandidates(nil, 1, nil, 8)); n != 0 {
		t.Fatalf("empty input produced %d candidates", n)
	}
	// Never more than the contract maximum, however many addresses there are.
	var many []netip.Addr
	for i := 1; i <= 40; i++ {
		many = append(many, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
	}
	if n := len(BuildCandidates(many, 1, srflx, 0)); n != api.MaxP2PCandidates {
		t.Fatalf("%d candidates, want the cap %d", n, api.MaxP2PCandidates)
	}
}

func TestSocketGatherWithFakeInterfaces(t *testing.T) {
	t.Parallel()
	srv := listenUDP(t)
	go ServeSTUN(srv)
	defer srv.Close()
	s, err := OpenSocket(SocketConfig{
		Conn: listenUDP(t),
		Interfaces: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.168.7.7"), netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := Strings(s.Gather(ctx, srv.LocalAddr().String()))
	port := s.Port()
	if len(got) != 2 || got[0] != netip.AddrPortFrom(netip.MustParseAddr("192.168.7.7"), uint16(port)).String() {
		t.Fatalf("candidates %v", got)
	}
	// The reflexive address (what the loopback STUN server saw) equals the
	// loopback host candidate and is not listed twice.
	if got[1] != s.Conn().LocalAddr().String() {
		t.Fatalf("candidates %v: want the reflexive/loopback address once", got)
	}
	// A failing STUN server still yields host candidates.
	s2, _ := OpenSocket(SocketConfig{Conn: listenUDP(t), Interfaces: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.1.1.1")}, nil }})
	defer s2.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if got := s2.Gather(ctx2, "127.0.0.1:1"); len(got) != 1 {
		t.Fatalf("host-only gather: %v", got)
	}
}

func TestParseCandidates(t *testing.T) {
	t.Parallel()
	ok, err := ParseCandidates([]string{"1.2.3.4:5", "[2001:db8::1]:6", "1.2.3.4:5", "127.0.0.1:9"})
	if err != nil || len(ok) != 3 {
		t.Fatalf("valid list: %v %v", ok, err)
	}
	for _, bad := range []string{"", "1.2.3.4", "1.2.3.4:0", "0.0.0.0:5", "[::]:5", "224.0.0.1:5", "[ff02::1]:5", "255.255.255.255:5", "host:5", "1.2.3.4:99999"} {
		if _, err := ParseCandidates([]string{bad}); err == nil {
			t.Errorf("candidate %q accepted", bad)
		}
	}
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, byte(i + 1)}), 5).String()
	}
	if _, err := ParseCandidates(nine); err == nil {
		t.Fatal("more than the maximum accepted")
	}
}

func TestAddrFor(t *testing.T) {
	t.Parallel()
	got, err := AddrFor(netip.MustParseAddr("100.96.3.77"))
	if err != nil || got != netip.MustParseAddr("100.97.3.77") {
		t.Fatalf("AddrFor: %v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.1", "100.97.0.5", "::1"} {
		if _, err := AddrFor(netip.MustParseAddr(bad)); err == nil {
			t.Errorf("AddrFor(%s) accepted", bad)
		}
	}
	if !ValidPlaneBAddr(got) || ValidPlaneBAddr(netip.MustParseAddr("100.96.1.1")) {
		t.Fatal("ValidPlaneBAddr")
	}
}

func TestSTUNServerSelection(t *testing.T) {
	t.Parallel()
	got, err := STUNServer([]string{"turn:turn.teknoir.cloud:3478?transport=udp"}, "")
	if err != nil || got != "turn.teknoir.cloud:3478" {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := STUNServer([]string{"turn:turn.example"}, ""); got != "turn.example:3478" {
		t.Fatalf("default port: %q", got)
	}
	if got, _ := STUNServer([]string{"turn:x:1?transport=tcp", "turn:y:2?transport=udp"}, ""); got != "y:2" {
		t.Fatalf("transport filter: %q", got)
	}
	if got, _ := STUNServer([]string{"turn:x:1"}, "10.0.0.1:19302"); got != "10.0.0.1:19302" {
		t.Fatalf("override: %q", got)
	}
	if _, err := STUNServer(nil, ""); err == nil {
		t.Fatal("no server accepted")
	}
	if got, ok := STUNServerFromHub("https://wg.teknoir.cloud"); !ok || got != "turn.teknoir.cloud:3478" {
		t.Fatalf("from hub: %q %v", got, ok)
	}
	for _, u := range []string{"http://127.0.0.1:8080", "https://hub.example.com", "http://wg-hub.teknoir-ztna.svc:8080", "https://wg.local"} {
		if got, ok := STUNServerFromHub(u); ok {
			t.Errorf("%s derived %q", u, got)
		}
	}
}

func TestProbeAuthentication(t *testing.T) {
	t.Parallel()
	a, _, _ := wgkey.Generate()
	b, _, _ := wgkey.Generate()
	c, _, _ := wgkey.Generate()
	pa, _ := a.Public()
	pb, _ := b.Public()
	pc, _ := c.Public()
	kab, err := pairKey(a, pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	kba, err := pairKey(b, pb, pa)
	if err != nil {
		t.Fatal(err)
	}
	if kab != kba {
		t.Fatal("the two ends derive different probe keys")
	}
	kac, _ := pairKey(a, pa, pc)
	if kab == kac {
		t.Fatal("different pairs share a probe key")
	}
	pkt, err := buildProbe(kab, idOf(pa), probePing, probeNoSession, nil)
	if err != nil {
		t.Fatal(err)
	}
	hdr, ok := parseProbeHeader(pkt)
	if !ok || hdr.typ != probePing || hdr.flags != probeNoSession || hdr.sender != idOf(pa) {
		t.Fatalf("header %+v ok=%v", hdr, ok)
	}
	if !verifyProbe(kab, pkt) {
		t.Fatal("valid probe failed verification")
	}
	if verifyProbe(kac, pkt) {
		t.Fatal("a probe verified under another pair's key")
	}
	for i := range pkt {
		m := append([]byte(nil), pkt...)
		m[i] ^= 0x80
		if _, ok := parseProbeHeader(m); ok && verifyProbe(kab, m) {
			t.Fatalf("a probe with byte %d flipped verified", i)
		}
	}
}

// pair builds two planes on loopback sockets, each gathering only its
// loopback host candidate.
type testPlane struct {
	*Plane
	key   wgkey.PrivateKey
	addr  netip.Addr
	cands []netip.AddrPort
	conn  *lossy
}

// lossy drops packets while blocked (it wraps the raw socket).
type lossy struct {
	net.PacketConn
	blocked atomic.Bool
}

func (l *lossy) WriteTo(p []byte, a net.Addr) (int, error) {
	if l.blocked.Load() && !isSTUN(p) {
		return len(p), nil
	}
	return l.PacketConn.WriteTo(p, a)
}

func newTestPlane(t testing.TB, addr string, interval time.Duration) *testPlane {
	t.Helper()
	raw := listenUDP(t)
	l := &lossy{PacketConn: raw}
	sock, err := OpenSocket(SocketConfig{
		Conn: l, Interfaces: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pl, err := NewPlane(PlaneConfig{Socket: sock, PrivateKey: priv, Address: netip.MustParseAddr(addr), ProbeInterval: interval})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pl.Close)
	return &testPlane{Plane: pl, key: priv, addr: pl.Address(), cands: sock.Candidates(), conn: l}
}

func TestPunchBetweenTwoSockets(t *testing.T) {
	t.Parallel()
	a := newTestPlane(t, "100.97.0.10", 50*time.Millisecond)
	b := newTestPlane(t, "100.97.0.20", 50*time.Millisecond)
	if len(a.cands) != 1 || len(b.cands) != 1 {
		t.Fatalf("candidates %v %v", a.cands, b.cands)
	}
	ln, err := b.Listen(2224)
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

	if err := b.AddPeer(a.PublicKey(), a.addr, PeerOptions{Candidates: a.cands}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{Initiator: true, Candidates: b.cands}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !a.WaitEstablished(ctx, b.PublicKey()) || !b.WaitEstablished(ctx, a.PublicKey()) {
		t.Fatal("no direct path between two sockets on loopback")
	}
	st := a.Status(b.PublicKey())
	if st.Path != api.PathDirectLAN || st.Endpoint != b.cands[0] {
		t.Fatalf("status %+v, want direct-lan via %v", st, b.cands[0])
	}
	// TCP over the plane works end to end.
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	c, err := a.DialContext(dctx, "tcp", netip.AddrPortFrom(b.addr, 2224).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := strings.Repeat("plane-b ", 20000)
	go func() { _, _ = c.Write([]byte(msg)) }()
	buf := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo over plane B: %v", err)
	}
}

func TestPunchOneSideOnly(t *testing.T) {
	t.Parallel()
	// Only A knows B's candidates (B has none for A): B learns A's address from
	// A's authenticated ping, so the path still comes up.
	a := newTestPlane(t, "100.97.1.10", 50*time.Millisecond)
	b := newTestPlane(t, "100.97.1.20", 50*time.Millisecond)
	if err := b.AddPeer(a.PublicKey(), a.addr, PeerOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{Initiator: true, Candidates: b.cands}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !a.WaitEstablished(ctx, b.PublicKey()) || !b.WaitEstablished(ctx, a.PublicKey()) {
		t.Fatal("no path when only one side knew the other's candidates")
	}
}

func TestPunchBlockedGivesUpAndRecovers(t *testing.T) {
	t.Parallel()
	a := newTestPlane(t, "100.97.2.10", 30*time.Millisecond)
	b := newTestPlane(t, "100.97.2.20", 30*time.Millisecond)
	a.conn.blocked.Store(true)
	b.conn.blocked.Store(true)
	if err := b.AddPeer(a.PublicKey(), a.addr, PeerOptions{Candidates: a.cands, Budget: 600 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{Initiator: true, Candidates: b.cands, Budget: 600 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if a.WaitEstablished(ctx, b.PublicKey()) {
		t.Fatal("a path came up although every packet was dropped")
	}
	// Unblock and punch again.
	a.conn.blocked.Store(false)
	b.conn.blocked.Store(false)
	a.Punch(b.PublicKey(), 5*time.Second)
	b.Punch(a.PublicKey(), 5*time.Second)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if !a.WaitEstablished(ctx2, b.PublicKey()) {
		t.Fatal("no path after the block was lifted and the punch restarted")
	}
}

func TestProbeFromStrangerIsIgnored(t *testing.T) {
	t.Parallel()
	a := newTestPlane(t, "100.97.3.10", 50*time.Millisecond)
	b := newTestPlane(t, "100.97.3.20", 50*time.Millisecond)
	// A knows B but B's key is not what the attacker has: the attacker (key c)
	// sends a ping naming B's key ID with a MAC under the wrong key.
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{}); err != nil {
		t.Fatal(err)
	}
	evil := listenUDP(t)
	defer evil.Close()
	var junk [32]byte
	pkt, _ := buildProbe(junk, idOf(b.PublicKey()), probePing, probeNoSession, nil)
	for range 5 {
		_, _ = evil.WriteTo(pkt, a.sock.Conn().LocalAddr())
	}
	// A real peer would be answered with a pong; the forged ping must not be.
	_ = evil.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := evil.ReadFrom(make([]byte, 100)); err == nil {
		t.Fatalf("answered a forged probe (%d bytes)", n)
	}
	if st := a.Status(b.PublicKey()); st.Endpoint.IsValid() {
		t.Fatalf("a forged probe moved the endpoint to %v", st.Endpoint)
	}
}

func TestRemovePeerGraceAndReAdd(t *testing.T) {
	t.Parallel()
	a := newTestPlane(t, "100.97.4.10", 50*time.Millisecond)
	b := newTestPlane(t, "100.97.4.20", 50*time.Millisecond)
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{}); err != nil {
		t.Fatal(err)
	}
	if !a.HasPeer(b.PublicKey()) || a.PeerCount() != 1 {
		t.Fatal("peer not installed")
	}
	a.RemovePeer(b.PublicKey(), 150*time.Millisecond)
	if a.HasPeer(b.PublicKey()) {
		t.Fatal("peer still reported present while being removed")
	}
	if a.PeerCount() != 1 {
		t.Fatal("peer vanished before the grace period")
	}
	// Re-adding within the grace period cancels the removal.
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if !a.HasPeer(b.PublicKey()) {
		t.Fatal("re-added peer was removed by the old timer")
	}
	a.RemovePeer(b.PublicKey(), 0)
	if a.PeerCount() != 0 || a.HasPeer(b.PublicKey()) {
		t.Fatal("peer not removed")
	}
	// Peer validation.
	if err := a.AddPeer(a.PublicKey(), b.addr, PeerOptions{}); err == nil {
		t.Fatal("own key accepted as a peer")
	}
	if err := a.AddPeer(b.PublicKey(), netip.MustParseAddr("100.96.1.1"), PeerOptions{}); err == nil {
		t.Fatal("a plane-A address accepted as a peer address")
	}
	if err := a.AddPeer(b.PublicKey(), a.addr, PeerOptions{}); err == nil {
		t.Fatal("own address accepted as a peer address")
	}
}

func TestParsePeer(t *testing.T) {
	t.Parallel()
	dump := "private_key=aa\nlisten_port=1\npublic_key=11\nendpoint=127.0.0.1:5\nrx_bytes=7\ntx_bytes=9\nlast_handshake_time_sec=" +
		itoa(time.Now().Unix()) + "\nlast_handshake_time_nsec=5\npublic_key=22\nendpoint=10.0.0.1:6\nlast_handshake_time_sec=0\n"
	st := parsePeer(dump, "11")
	if !st.Established || st.Endpoint != mustAP(t, "127.0.0.1:5") || st.RxBytes != 7 || st.TxBytes != 9 || st.Path != api.PathDirectLAN {
		t.Fatalf("peer 11: %+v", st)
	}
	st = parsePeer(dump, "22")
	if st.Established || st.Path != "" || st.Endpoint != mustAP(t, "10.0.0.1:6") {
		t.Fatalf("peer 22: %+v", st)
	}
	old := "public_key=33\nlast_handshake_time_sec=" + itoa(time.Now().Add(-10*time.Minute).Unix()) + "\nendpoint=8.8.8.8:1\n"
	if st := parsePeer(old, "33"); st.Established {
		t.Fatal("a ten-minute-old handshake counts as established")
	}
	if PathOf(mustAP(t, "8.8.8.8:1")) != api.PathDirect || PathOf(mustAP(t, "[fd00::1]:1")) != api.PathDirectLAN || PathOf(mustAP(t, "192.168.0.4:1")) != api.PathDirectLAN {
		t.Fatal("PathOf")
	}
}

func itoa(n int64) string { return strings.TrimSpace(strings.Join([]string{formatInt(n)}, "")) }

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A responder that loses its peer (removed and added again, as when a lost
// grant set is restored) reports "no session" in its probes; the initiator
// then starts over instead of waiting for WireGuard's 15 s timers.
func TestInitiatorRecoversWhenResponderLosesSession(t *testing.T) {
	t.Parallel()
	a := newTestPlane(t, "100.97.5.10", 40*time.Millisecond)
	b := newTestPlane(t, "100.97.5.20", 40*time.Millisecond)
	if err := b.AddPeer(a.PublicKey(), a.addr, PeerOptions{Candidates: a.cands}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPeer(b.PublicKey(), b.addr, PeerOptions{Initiator: true, Candidates: b.cands}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !a.WaitEstablished(ctx, b.PublicKey()) || !b.WaitEstablished(ctx, a.PublicKey()) {
		t.Fatal("no initial path")
	}
	first := b.Status(a.PublicKey()).LastHandshake

	b.RemovePeer(a.PublicKey(), 0)
	if err := b.AddPeer(a.PublicKey(), a.addr, PeerOptions{Candidates: a.cands}); err != nil {
		t.Fatal(err)
	}
	if b.Status(a.PublicKey()).Established {
		t.Fatal("a re-added peer must not have a session")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()
	if !b.WaitEstablished(ctx2, a.PublicKey()) {
		t.Fatal("the initiator did not re-establish the session after the responder lost it")
	}
	if !b.Status(a.PublicKey()).LastHandshake.After(first) {
		t.Fatal("no new handshake")
	}
}

func TestProbeTargets(t *testing.T) {
	t.Parallel()
	in := []netip.AddrPort{
		mustAP(t, "127.0.0.1:5000"), mustAP(t, "[::1]:5000"), mustAP(t, "169.254.169.254:80"), mustAP(t, "[fe80::1]:5000"),
		mustAP(t, "0.0.0.0:5"), mustAP(t, "192.168.1.9:5000"), mustAP(t, "203.0.113.4:5000"), mustAP(t, "[fd00::1]:5000"),
	}
	got := Strings(ProbeTargets(in, false))
	if strings.Join(got, ",") != "192.168.1.9:5000,203.0.113.4:5000,[fd00::1]:5000" {
		t.Fatalf("targets %v", got)
	}
	if got := ProbeTargets(in, true); len(got) != 5 {
		t.Fatalf("with loopback allowed: %v", got)
	}
}
