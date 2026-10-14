package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// bRig is the plane-B connect handler with a grant store, fed with in-memory
// connections whose remote address is the plane-B source.
type bRig struct {
	*connectRig
	grants *GrantStore
	seq    uint64
}

func newBRig(t *testing.T, echoPort int) *bRig {
	t.Helper()
	r := newConnectRig(t, 4, 8, allowPorts(echoPort))
	r.srv.SetServices([]api.ServiceSpec{externalSpec("web", echoPort), externalSpec("cam", echoPort)})
	return &bRig{connectRig: r, grants: NewGrantStore(GrantStoreOptions{})}
}

// dialB connects as the plane-B source `remote`.
func (r *bRig) dialB(remote string) net.Conn {
	r.t.Helper()
	cli, srv := net.Pipe()
	r.t.Cleanup(func() { _ = cli.Close() })
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.srv.handleB(r.ctx, remoteConn{Conn: srv, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote))}, r.grants)
	}()
	return cli
}

func (r *bRig) grant(pair string, n int, services ...string) api.Grant {
	r.t.Helper()
	g := testGrant(r.t, pair, n, services...)
	r.seq++
	if _, err := r.grants.Apply(set("hub-1", r.seq, append(r.grants.Snapshot(), g)...)); err != nil {
		r.t.Fatal(err)
	}
	return g
}

func connectB(t *testing.T, c net.Conn, service string) (*connectproto.Conn, api.ConnectResponse, error) {
	t.Helper()
	return connectproto.Handshake(c, api.ConnectRequest{Service: service}, 3*time.Second)
}

func TestPlaneBRefusesSourcesWithoutAGrant(t *testing.T) {
	echo := startEchoServer(t)
	r := newBRig(t, echo.port())
	r.grant("pa", 1, "web")

	// A source that is not a granted client address is closed without an answer.
	for _, remote := range []string{"100.97.0.9:40000", api.HubAddress + ":40000", "100.96.0.1:1", "10.0.0.1:5"} {
		c := r.dialB(remote)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_ = connectproto.WriteRequest(c, api.ConnectRequest{Service: "web"})
		if n, err := c.Read(make([]byte, 64)); err == nil || n != 0 {
			t.Fatalf("source %s got %d bytes (%v); it must be closed unanswered", remote, n, err)
		}
	}
	if echo.count() != 0 {
		t.Fatal("a service was dialled for an ungranted source")
	}
	if !strings.Contains(r.logs.String(), "without a grant") {
		t.Fatalf("no refusal logged:\n%s", r.logs.String())
	}
}

func TestPlaneBOnlyServesTheGrantedServices(t *testing.T) {
	echo := startEchoServer(t)
	r := newBRig(t, echo.port())
	r.grant("pa", 1, "web")

	// "cam" exists on the device but is not in this pair's grant.
	c := r.dialB("100.97.0.1:40000")
	_, resp, err := connectB(t, c, "cam")
	if err != nil || resp.OK || resp.Reason != api.ReasonServiceDenied {
		t.Fatalf("ungranted service: resp %+v err %v", resp, err)
	}
	// ssh is implicit on the device, and still not granted.
	c = r.dialB("100.97.0.1:40000")
	if _, resp, err = connectB(t, c, "ssh"); err != nil || resp.OK {
		t.Fatalf("ssh without a grant for it: %+v %v", resp, err)
	}
	// The granted one works.
	c = r.dialB("100.97.0.1:40000")
	cc, resp, err := connectB(t, c, "web")
	if err != nil || !resp.OK {
		t.Fatalf("granted service: %+v %v", resp, err)
	}
	_ = cc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if echo.count() != 1 {
		t.Fatalf("service dialled %d times, want 1", echo.count())
	}
	// The target is the policy's: a made-up service id is unknown.
	c = r.dialB("100.97.0.1:40000")
	if _, resp, _ = connectB(t, c, "nope"); resp.OK {
		t.Fatal("unknown service accepted")
	}
}

func TestPlaneBRemovalClosesTheRelayAtOnce(t *testing.T) {
	echo := startEchoServer(t)
	r := newBRig(t, echo.port())
	closed := make(chan string, 4)
	r.grants = NewGrantStore(GrantStoreOptions{Hooks: GrantHooks{
		Add: func(api.Grant) error { return nil },
		Remove: func(g api.Grant) {
			closed <- g.PairID
			r.srv.ClosePair(g.PairID)
		},
	}})
	ga := r.grant("pa", 1, "web")
	r.grant("pb", 2, "web")

	ca := r.dialB("100.97.0.1:40000")
	cca, resp, err := connectB(t, ca, "web")
	if err != nil || !resp.OK {
		t.Fatal(resp, err)
	}
	cb := r.dialB("100.97.0.2:40000")
	ccb, resp, err := connectB(t, cb, "web")
	if err != nil || !resp.OK {
		t.Fatal(resp, err)
	}
	waitUntil(t, "two relays", func() bool { return r.srv.Active() == 2 })

	// The hub's next set lists only pair pb: pa's relay closes, pb's stays.
	r.seq++
	if _, err := r.grants.Apply(set("hub-1", r.seq, r.grants.Snapshot()[1])); err != nil {
		t.Fatal(err)
	}
	if got := <-closed; got != ga.PairID {
		t.Fatalf("removed %s", got)
	}
	_ = cca.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cca.Read(make([]byte, 1)); err == nil {
		t.Fatal("the relay of the removed pair survived")
	}
	if _, err := ccb.Write([]byte("x")); err != nil {
		t.Fatal("the other pair's relay was closed")
	}
	// The removed pair cannot come back (tombstone) and gets nothing new.
	c := r.dialB("100.97.0.1:40000")
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = connectproto.WriteRequest(c, api.ConnectRequest{Service: "web"})
	if n, err := c.Read(make([]byte, 8)); err == nil || n != 0 {
		t.Fatalf("a connection for the removed pair got an answer (%d)", n)
	}
}

func TestPlaneBPerPairLimit(t *testing.T) {
	echo := startEchoServer(t)
	r := newBRig(t, echo.port())
	r.srv.perPair = 2
	r.grant("pa", 1, "web")
	var keep []*connectproto.Conn
	for range 2 {
		cc, resp, err := connectB(t, r.dialB("100.97.0.1:40000"), "web")
		if err != nil || !resp.OK {
			t.Fatal(resp, err)
		}
		keep = append(keep, cc)
	}
	_, resp, err := connectB(t, r.dialB("100.97.0.1:40000"), "web")
	if err != nil || resp.OK || resp.Reason != api.ReasonSessionLimit {
		t.Fatalf("third connection of one pair: %+v %v", resp, err)
	}
	_ = keep
}

// Plane A does not take plane-B sources and plane B does not take the hub: the
// two handlers are separate on purpose.
func TestPlanesAreSeparate(t *testing.T) {
	echo := startEchoServer(t)
	r := newBRig(t, echo.port())
	r.grant("pa", 1, "web")
	// handle() (plane A) refuses a plane-B source ...
	c := r.dial("100.97.0.1:40000")
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = connectproto.WriteRequest(c, api.ConnectRequest{Service: "web"})
	if n, err := c.Read(make([]byte, 8)); err == nil || n != 0 {
		t.Fatal("plane A accepted a plane-B source")
	}
	// ... and handleB() refuses the hub's overlay address.
	c2 := r.dialB(api.HubAddress + ":40000")
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	_ = connectproto.WriteRequest(c2, api.ConnectRequest{Service: "web"})
	if n, err := c2.Read(make([]byte, 8)); err == nil || n != 0 {
		t.Fatal("plane B accepted the hub address")
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- the grant hooks on a real plane ----

type hookRig struct {
	pl      *p2p.Plane
	pb      *planeB
	connect *connectServer
	grants  *GrantStore
	log     *syncBuffer
}

func newHookRig(t *testing.T) *hookRig {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sock, err := p2p.OpenSocket(p2p.SocketConfig{Conn: pc, Interfaces: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pl, err := p2p.NewPlane(p2p.PlaneConfig{Socket: sock, PrivateKey: priv, Address: netip.MustParseAddr("100.97.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pl.Close)
	logs := &syncBuffer{}
	connect := newConnectServer(newTestLogger(logs), testPolicy(&fakeResolver{}), time.Second, 4, 8)
	pb := &planeB{log: newTestLogger(logs), pl: pl, connect: connect, pub: pl.PublicKey(), addr: pl.Address(), grace: 20 * time.Millisecond}
	return &hookRig{pl: pl, pb: pb, connect: connect, log: logs, grants: NewGrantStore(GrantStoreOptions{Hooks: pb.hooks()})}
}

func TestGrantHooksInstallAndRemovePeers(t *testing.T) {
	r := newHookRig(t)
	g := testGrant(t, "pa", 7, "ssh")
	g.ClientCandidates = []string{"192.0.2.10:5000"}
	res, err := r.grants.Apply(set("hub-1", 1, g))
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	pub, _ := wgkey.ParsePublic(g.ClientWGPublicKey)
	if !r.pl.HasPeer(pub) {
		t.Fatal("peer not installed")
	}
	// The next set drops it: the peer goes after the (short) grace.
	if _, err := r.grants.Apply(set("hub-1", 2)); err != nil {
		t.Fatal(err)
	}
	if r.pl.HasPeer(pub) {
		t.Fatal("peer still present right after removal")
	}
	waitUntil(t, "the peer to be removed", func() bool { return r.pl.PeerCount() == 0 })

	// Invalid grants are refused by the hook and never acknowledged.
	bad := testGrant(t, "pb", 8, "ssh")
	bad.ClientCandidates = []string{"0.0.0.0:99"}
	res, err = r.grants.Apply(set("hub-1", 3, bad))
	if err != nil || len(res.Accepted) != 0 || res.Rejected["pb"] == "" {
		t.Fatalf("grant with a bad candidate: %+v %v", res, err)
	}
	if r.pl.PeerCount() != 0 {
		t.Fatal("peer installed for a refused grant")
	}
	// Dropping everything (the A session ended) removes the peers too.
	if _, err := r.grants.Apply(set("hub-1", 4, testGrant(t, "pc", 9, "ssh"))); err != nil {
		t.Fatal(err)
	}
	r.grants.DropAll()
	waitUntil(t, "peers to go on DropAll", func() bool { return r.pl.PeerCount() == 0 })
}

func TestGrantAckCarriesThePlaneBParameters(t *testing.T) {
	r := newHookRig(t)
	logs := &syncBuffer{}
	ctl := newControlServer(newTestLogger(logs), r.connect, r.grants, r.pb)
	rec := post(t, ctl, api.ControlGrantsPath, api.HubAddress+":51000", set("hub-1", 1, testGrant(t, "pa", 3, "ssh")))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`"deviceWgPublicKey":"` + r.pl.PublicKey().Base64() + `"`, `"deviceAddress":"100.97.0.2"`, `"accepted":["pa"]`, `127.0.0.1:`} {
		if !strings.Contains(body, want) {
			t.Fatalf("ack lacks %s: %s", want, body)
		}
	}
	// A refused pair is not accepted, but the parameters are still there.
	bad := testGrant(t, "pb", 4, "ssh")
	bad.ClientCandidates = []string{"224.0.0.1:1"}
	rec = post(t, ctl, api.ControlGrantsPath, api.HubAddress+":51000", set("hub-1", 2, bad))
	if !strings.Contains(rec.Body.String(), `"accepted":[]`) {
		t.Fatalf("%s", rec.Body)
	}
}

func TestUnavailablePlaneBRefusesGrants(t *testing.T) {
	grants := NewGrantStore(GrantStoreOptions{Hooks: unavailableHooks()})
	res, err := grants.Apply(set("hub-1", 1, testGrant(t, "pa", 3, "ssh")))
	if err != nil || len(res.Accepted) != 0 || !strings.Contains(res.Rejected["pa"], "not available") {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGrantHolderAppliesTheRenewalBackstop(t *testing.T) {
	logs := &syncBuffer{}
	h := &grantHolder{log: newTestLogger(logs)}
	h.applyBackstop(set("hub-1", 1, testGrant(t, "pa", 3, "ssh"))) // no store yet: ignored
	var added, removed []string
	var mu sync.Mutex
	g := NewGrantStore(GrantStoreOptions{Hooks: GrantHooks{
		Add:    func(g api.Grant) error { mu.Lock(); added = append(added, g.PairID); mu.Unlock(); return nil },
		Remove: func(g api.Grant) { mu.Lock(); removed = append(removed, g.PairID); mu.Unlock() },
	}})
	h.set(g)
	h.applyBackstop(set("hub-1", 1, testGrant(t, "pa", 3, "ssh")))
	if !g.Allows("pa", "ssh") {
		t.Fatal("backstop set not applied")
	}
	// A restored set after the store was emptied (a lost push) brings it back.
	g.DropAll()
	if g.Allows("pa", "ssh") {
		t.Fatal("DropAll")
	}
	h.applyBackstop(set("hub-1", 5, testGrant(t, "pa", 3, "ssh")))
	if !g.Allows("pa", "ssh") {
		t.Fatal("the backstop did not restore the grant")
	}
	// An older set is ignored.
	h.applyBackstop(set("hub-1", 2))
	if !g.Allows("pa", "ssh") {
		t.Fatal("a stale backstop removed a grant")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(added) != 2 || len(removed) != 1 {
		t.Fatalf("hooks: added %v removed %v", added, removed)
	}
}

func TestConfigFromEnvP2P(t *testing.T) {
	base := map[string]string{"DEVICE_ID": "d", "NAMESPACE": "ns", "DOMAIN": "example.com"}
	env := func(extra map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return base[k]
		}
	}
	for _, tc := range []struct {
		name  string
		extra map[string]string
		on    bool
		port  int
		stun  string
		err   bool
	}{
		{"default is on", nil, true, 0, "", false},
		{"explicit on", map[string]string{"P2P": "on", "P2P_PORT": "51999"}, true, 51999, "", false},
		{"off", map[string]string{"P2P": "off"}, false, 0, "", false},
		{"false", map[string]string{"P2P": "False"}, false, 0, "", false},
		{"stun override", map[string]string{"P2P_STUN": "stun.example.com:3478"}, true, 0, "stun.example.com:3478", false},
		{"bad value", map[string]string{"P2P": "maybe"}, false, 0, "", true},
		{"bad port", map[string]string{"P2P_PORT": "99999"}, false, 0, "", true},
		{"bad stun", map[string]string{"P2P_STUN": "no-port"}, false, 0, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ConfigFromEnv(env(tc.extra))
			if (err != nil) != tc.err {
				t.Fatalf("err %v", err)
			}
			if err == nil && (c.P2P != tc.on || c.P2PPort != tc.port || c.P2PSTUN != tc.stun) {
				t.Fatalf("config %+v", c)
			}
		})
	}
}

func TestCapabilitiesFollowP2PConfig(t *testing.T) {
	a, err := New(Config{DeviceID: "d", Namespace: "n", HubURL: "https://hub.example.com", P2P: true})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(a.capabilities(), api.CapP2P) {
		t.Fatalf("caps %v", a.capabilities())
	}
	a2, _ := New(Config{DeviceID: "d", Namespace: "n", HubURL: "https://hub.example.com"})
	if contains(a2.capabilities(), api.CapP2P) {
		t.Fatalf("caps %v advertise p2p although it is off", a2.capabilities())
	}
	if st := a.P2PStatus(); st.Up || st.Peers != 0 {
		t.Fatalf("status of an idle agent: %+v", st)
	}
	_ = errors.New
	_ = context.Background
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// The client's candidates are its word: a grant that points the device's
// probes at the device itself is installed, but without those targets.
func TestGrantHookDoesNotProbeLoopbackOrLinkLocal(t *testing.T) {
	r := newHookRig(t)
	g := testGrant(t, "pa", 7, "ssh")
	g.ClientCandidates = []string{"127.0.0.1:41000", "169.254.169.254:80", "192.0.2.10:5000"}
	if res, err := r.grants.Apply(set("hub-1", 1, g)); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	pub, _ := wgkey.ParsePublic(g.ClientWGPublicKey)
	if !r.pl.HasPeer(pub) {
		t.Fatal("peer not installed")
	}
	// Observe what the plane sends: a socket listening on the loopback candidate
	// must stay silent.
	ln, err := net.ListenPacket("udp4", "127.0.0.1:41000")
	if err != nil {
		t.Skip("cannot listen on 127.0.0.1:41000:", err)
	}
	defer ln.Close()
	_ = ln.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, _, err := ln.ReadFrom(make([]byte, 100)); err == nil {
		t.Fatalf("the device sent %d bytes to a loopback candidate", n)
	}
}
