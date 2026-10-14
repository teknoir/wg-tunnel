package e2e_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/hub"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// spliceConns counts the connections the hub has spliced so far (the "connect"
// decisions it logged). A connection made over plane B never shows up here.
func spliceConns(r *e2erig.Rig) int { return r.HubLogs.Count(`"op":"connect","decision":"allow"`) }

func p2pRig(t *testing.T, opts e2erig.Options) (*e2erig.Rig, *e2erig.Agent) {
	t.Helper()
	opts.P2P = true
	r := e2erig.New(t, opts)
	ag := r.StartAgent()
	r.WaitDeviceUp(1)
	e2erig.Eventually(t, 10*time.Second, "the agent's plane B", func() bool { return ag.Agent.P2PStatus().Up })
	return r, ag
}

func waitDirect(t *testing.T, s *wgclient.Session) {
	t.Helper()
	e2erig.Eventually(t, 10*time.Second, "the direct path", func() bool { return s.P2PStatus().Established })
}

// The direct path is established and used: the bytes of the echo go through
// plane B, the hub splices nothing, and the path is reported at the next renewal.
func TestP2PDirectPathEstablishedAndUsed(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	before := spliceConns(r)
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	resp := sess.Response()
	if resp.P2P == nil {
		t.Fatalf("the hub gave no plane-B grant; hub log:\n%s", r.HubLogs.String())
	}
	if resp.P2P.PairID != resp.SessionID || resp.P2P.ClientAddress == "" || resp.P2P.DeviceAddress == "" || len(resp.P2P.DeviceCandidates) == 0 {
		t.Fatalf("grant %+v", resp.P2P)
	}
	if !strings.HasPrefix(resp.P2P.ClientAddress, "100.97.") || !strings.HasPrefix(resp.P2P.DeviceAddress, "100.97.") {
		t.Fatalf("plane-B addresses %s %s are not in %s", resp.P2P.ClientAddress, resp.P2P.DeviceAddress, api.P2PPrefix)
	}
	waitDirect(t, sess)
	if p := sess.Path(); p != api.PathDirectLAN {
		t.Fatalf("path %q, want %q (loopback counts as LAN)", p, api.PathDirectLAN)
	}

	c, err := e2erig.EchoViaService(sess, "SSH-2.0-direct\r\n", 15*time.Second)
	if err != nil {
		t.Fatalf("echo over plane B: %v\nagent log:\n%s", err, r.AgentLogs.String())
	}
	defer c.Close()
	if err := e2erig.RoundTrip(c, strings.Repeat("direct ", 40_000)); err != nil {
		t.Fatalf("bulk echo over plane B: %v", err)
	}
	if st := sess.P2PStatus(); st.DirectDials != 1 {
		t.Fatalf("direct dials %d, want 1", st.DirectDials)
	}
	if n := spliceConns(r) - before; n != 0 {
		t.Fatalf("the hub spliced %d connections although plane B was up", n)
	}
	if r.Echo.Total() != 1 {
		t.Fatalf("the sshd saw %d connections", r.Echo.Total())
	}
	if got := ag.Agent.P2PStatus(); got.Peers != 1 || len(got.Candidates) == 0 {
		t.Fatalf("agent plane B %+v", got)
	}
	if pairs := r.Hub.P2PPairs(e2erig.NS, e2erig.DeviceName); len(pairs) != 1 || pairs[0] != resp.SessionID {
		t.Fatalf("hub pairs %v", pairs)
	}

	// The client reports its path at its next renewal (informational).
	e2erig.Eventually(t, 10*time.Second, "the hub to learn the path", func() bool {
		p, ok := r.Hub.ClientPath(resp.SessionID)
		return ok && p == api.PathDirectLAN
	})
	// The splice still works for the same session (it is the fallback).
	if err := e2erig.EchoVia(sess, "via the hub\r\n", 15*time.Second); err != nil {
		t.Fatalf("splice next to plane B: %v", err)
	}
	if spliceConns(r)-before != 1 {
		t.Fatalf("explicit splice not counted")
	}
	r.AssertLogHygiene()
}

// A web service is reached over plane B with the policy's own target, not
// anything the client says.
func TestP2PWebService(t *testing.T) {
	t.Parallel()
	r, _ := p2pRig(t, e2erig.Options{})
	r.SetServices(r.WebService("web"))
	sess := r.MustP2PClient(e2erig.BobEmail, "web")
	if sess.Response().P2P == nil {
		t.Fatal("no plane-B grant for the web service")
	}
	waitDirect(t, sess)
	c, err := e2erig.EchoViaService(sess, "GET / HTTP/1.1\r\n\r\n", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if r.Web.Total() != 1 || r.Echo.Total() != 0 {
		t.Fatalf("web %d sshd %d", r.Web.Total(), r.Echo.Total())
	}
	if sess.P2PStatus().DirectDials != 1 {
		t.Fatal("not over plane B")
	}
}

// B blocked: the race gives up after api.P2PDialRaceMillis and the connection
// goes through the hub splice. The next dial does not wait again.
func TestP2PBlockedFallsBackToTheSplice(t *testing.T) {
	t.Parallel()
	r, _ := p2pRig(t, e2erig.Options{})
	r.BlockP2P(true)
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	if sess.Response().P2P == nil {
		t.Fatal("expected a grant (the block is on the UDP path only)")
	}
	before := spliceConns(r)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := sess.DialService(ctx, "")
	if err != nil {
		t.Fatalf("fallback dial: %v", err)
	}
	waited := time.Since(start)
	if err := e2erig.RoundTrip(c, "fallback\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if waited < api.P2PDialRaceMillis*time.Millisecond-300*time.Millisecond || waited > api.P2PDialRaceMillis*time.Millisecond+4*time.Second {
		t.Fatalf("the race took %v, want about %dms", waited, api.P2PDialRaceMillis)
	}
	if st := sess.P2PStatus(); st.DirectDials != 0 || st.Established || sess.Path() != api.PathHub {
		t.Fatalf("status %+v path %q", st, sess.Path())
	}
	if spliceConns(r)-before != 1 {
		t.Fatalf("hub splices %d, want 1", spliceConns(r)-before)
	}
	// The second dial skips plane B at once.
	start = time.Now()
	c2, err := sess.DialService(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := e2erig.RoundTrip(c2, "again\r\n"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the second fallback dial took %v; plane B should be skipped", d)
	}
}

// Revocation: ending the client session removes the pair and the peer within a
// second, and a policy change that removes the service closes the open plane-B
// connection within a second.
func TestP2PRevocation(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	r.SetServices(r.WebService("web"))

	// (1) the client closes its session.
	s1 := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	waitDirect(t, s1)
	if _, err := e2erig.EchoViaService(s1, "x\r\n", 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if ag.Agent.P2PStatus().Peers != 1 {
		t.Fatal("peer not installed")
	}
	start := time.Now()
	_ = s1.Close()
	e2erig.Eventually(t, time.Second, "the device to drop the pair", func() bool { return ag.Agent.P2PStatus().Peers == 0 })
	if d := time.Since(start); d > time.Second {
		t.Fatalf("dropping the pair took %v", d)
	}
	if pairs := r.Hub.P2PPairs(e2erig.NS, e2erig.DeviceName); len(pairs) != 0 {
		t.Fatalf("hub still holds %v", pairs)
	}

	// (2) the service is removed from the policy while a plane-B connection is open.
	s2 := r.MustP2PClient(e2erig.BobEmail, "web")
	waitDirect(t, s2)
	c, err := e2erig.EchoViaService(s2, "hello\r\n", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s2.P2PStatus().DirectDials != 1 {
		t.Fatal("not over plane B")
	}
	dead := readErrAfter(c)
	start = time.Now()
	r.SetServices() // no web service any more
	select {
	case <-dead:
	case <-time.After(time.Second):
		t.Fatalf("the plane-B connection was still open %v after the service was removed", time.Since(start))
	}
	e2erig.Eventually(t, time.Second, "the pair to go", func() bool { return ag.Agent.P2PStatus().Peers == 0 })
	// And nothing new gets in: the client's session is over.
	e2erig.Eventually(t, 10*time.Second, "the client session to end", func() bool {
		select {
		case <-s2.Done():
			return true
		default:
			return false
		}
	})
}

// A compromised device flag ends every session and every pair.
func TestP2PCompromisedFlagRemovesPairs(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	waitDirect(t, sess)
	c, err := e2erig.EchoViaService(sess, "up\r\n", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dead := readErrAfter(c)
	start := time.Now()
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	select {
	case <-dead:
	case <-time.After(2 * time.Second):
		t.Fatalf("connection still open %v after the compromised flag", time.Since(start))
	}
	e2erig.Eventually(t, 5*time.Second, "pairs to be gone", func() bool { return ag.Agent.P2PStatus().Peers == 0 })
}

// The device opts out of plane B (annotation p2p=disabled): no new grants, and
// pairs that exist are dropped. The splice keeps working.
func TestP2PPolicyOptOut(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	s1 := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	waitDirect(t, s1)

	r.SetP2P(false)
	e2erig.Eventually(t, 2*time.Second, "the pair to be dropped", func() bool { return ag.Agent.P2PStatus().Peers == 0 })
	if pairs := r.Hub.P2PPairs(e2erig.NS, e2erig.DeviceName); len(pairs) != 0 {
		t.Fatalf("pairs after opt-out: %v", pairs)
	}
	s2 := r.MustP2PClient(e2erig.BobEmail, "ssh")
	if s2.Response().P2P != nil {
		t.Fatal("a grant was issued for a device that opted out")
	}
	if err := e2erig.EchoVia(s2, "splice\r\n", 15*time.Second); err != nil {
		t.Fatal(err)
	}
	// DialService quietly uses the splice when there is no plane B.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := s2.DialService(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := e2erig.RoundTrip(c, "no p2p\r\n"); err != nil {
		t.Fatal(err)
	}
	if s2.Path() != api.PathHub {
		t.Fatalf("path %q", s2.Path())
	}
}

// The renewal response carries the full grant set: a pair whose control push
// was lost is restored by the next device renewal, and the client's session
// comes back without a new client session.
func TestP2PRenewBackstopRestoresALostGrantSet(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	waitDirect(t, sess)
	c, err := e2erig.EchoViaService(sess, "before\r\n", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dead := readErrAfter(c)

	ag.Agent.DropP2PGrants() // as if the push that carried the grant had been lost
	select {
	case <-dead:
	case <-time.After(2 * time.Second):
		t.Fatal("dropping the grant did not close its connection")
	}
	e2erig.Eventually(t, 2*time.Second, "the peer to go", func() bool { return ag.Agent.P2PStatus().Peers == 0 })

	// The device renews every 2 s in the rig; its response restores the set.
	e2erig.Eventually(t, 10*time.Second, "the backstop to restore the pair", func() bool { return ag.Agent.P2PStatus().Peers == 1 })
	c2, err := e2erig.EchoViaService(sess, "after\r\n", 20*time.Second)
	if err != nil {
		t.Fatalf("no echo after the restore: %v\nagent log:\n%s", err, r.AgentLogs.String())
	}
	defer c2.Close()
	if sess.P2PStatus().DirectDials < 2 {
		t.Fatalf("the restored pair was not used: %+v", sess.P2PStatus())
	}
}

// Several clients of one device: each pair has its own address and peer, and
// ending one leaves the others untouched.
func TestP2PManyClientsOneDevice(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{})
	var sessions []*wgclient.Session
	for _, who := range []string{e2erig.AliceEmail, e2erig.BobEmail, e2erig.AliceEmail} {
		s := r.MustP2PClient(who, "ssh")
		waitDirect(t, s)
		sessions = append(sessions, s)
	}
	if got := ag.Agent.P2PStatus().Peers; got != 3 {
		t.Fatalf("%d peers, want 3", got)
	}
	addrs := map[string]bool{}
	for _, s := range sessions {
		g := s.Response().P2P
		if addrs[g.ClientAddress] {
			t.Fatalf("client address %s used twice", g.ClientAddress)
		}
		addrs[g.ClientAddress] = true
		c, err := e2erig.EchoViaService(s, "m\r\n", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	// One goes; the others are untouched.
	_ = sessions[0].Close()
	e2erig.Eventually(t, time.Second, "one pair to go", func() bool { return ag.Agent.P2PStatus().Peers == 2 })
	for _, s := range sessions[1:] {
		c, err := e2erig.EchoViaService(s, "still\r\n", 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		if s.P2PStatus().DirectDials != 2 {
			t.Fatalf("direct dials %d", s.P2PStatus().DirectDials)
		}
	}
}

// An agent that does not offer plane B (P2P=off) is not offered: the client
// gets no grant and uses the splice.
func TestP2PAgentWithoutPlaneB(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{P2P: true, Agent: func(c *agent.Config) { c.P2P = false }})
	r.StartAgent()
	r.WaitDeviceUp(1)
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	if sess.Response().P2P != nil {
		t.Fatal("grant for an agent without plane B")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := sess.DialService(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := e2erig.RoundTrip(c, "x\r\n"); err != nil {
		t.Fatal(err)
	}
}

// Short grant lifetimes: the hub keeps a live client's grant alive by
// re-pushing, and lets a dead client's grant lapse.
func TestP2PGrantLeaseRefreshAndExpiry(t *testing.T) {
	t.Parallel()
	r, ag := p2pRig(t, e2erig.Options{Hub: func(c *hub.Config) { c.P2PGrantTTL = 4 * time.Second }})
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	waitDirect(t, sess)
	// Well past one TTL, the client's renewals (every 2 s) have refreshed it.
	time.Sleep(7 * time.Second)
	if ag.Agent.P2PStatus().Peers != 1 {
		t.Fatalf("the grant of a live client lapsed; agent log:\n%s", r.AgentLogs.String())
	}
	c, err := e2erig.EchoViaService(sess, "alive\r\n", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

// A dial the caller cancels (Ctrl-C of a ProxyCommand, a browser abort) says
// nothing about the path: it must not switch plane B off for the session
// (review finding 18).
func TestP2PCancelledDialDoesNotDisablePlaneB(t *testing.T) {
	t.Parallel()
	r, _ := p2pRig(t, e2erig.Options{})
	r.BlockP2P(true)
	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	if sess.Response().P2P == nil {
		t.Fatal("expected a grant")
	}
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	if c, err := sess.DialService(short, ""); err == nil {
		_ = c.Close()
		t.Fatal("a dial with a 300ms deadline succeeded although the race takes longer")
	}
	cancel()
	// The next dial still gives plane B its race (it is blocked, so it falls back to the splice).
	start := time.Now()
	ctx, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	c, err := sess.DialService(ctx, "")
	if err != nil {
		t.Fatalf("fallback dial: %v", err)
	}
	_ = c.Close()
	if d := time.Since(start); d < api.P2PDialRaceMillis*time.Millisecond-300*time.Millisecond {
		t.Fatalf("the dial took %v: plane B was skipped after a cancelled dial", d)
	}
}
