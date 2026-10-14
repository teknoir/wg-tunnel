package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

var capsP2P = []string{api.CapServices, api.CapControl, api.CapP2P}

// grantLog is a fake agent's view of the grant pushes.
type grantLog struct {
	mu      sync.Mutex
	sets    []api.GrantSet
	devKey  string
	devAddr string
	cands   []string
	status  int                    // non-zero: answer with this status (and no ack)
	refuse  func(g api.Grant) bool // pairs to leave out of Accepted
	delay   time.Duration          // slow agent
	onSet   func(set api.GrantSet) // called under no lock after recording
	maxSeq  uint64                 // answer 409 for sets older than this
}

func (l *grantLog) handler(w http.ResponseWriter, body []byte) {
	var set api.GrantSet
	if err := json.Unmarshal(body, &set); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	l.mu.Lock()
	delay, status, refuse := l.delay, l.status, l.refuse
	stale := set.Seq < l.maxSeq
	l.sets = append(l.sets, set)
	if set.Seq > l.maxSeq {
		l.maxSeq = set.Seq
	}
	ack := api.GrantAck{DeviceWGPublicKey: l.devKey, DeviceAddress: l.devAddr, DeviceCandidates: slices.Clone(l.cands)}
	cb := l.onSet
	l.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if cb != nil {
		cb(set)
	}
	switch {
	case status != 0:
		w.WriteHeader(status)
		return
	case stale:
		w.WriteHeader(http.StatusConflict)
		return
	}
	ack.Accepted = []string{}
	for _, g := range set.Grants {
		if refuse == nil || !refuse(g) {
			ack.Accepted = append(ack.Accepted, g.PairID)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ack)
}

func (l *grantLog) last() api.GrantSet {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sets) == 0 {
		return api.GrantSet{}
	}
	return l.sets[len(l.sets)-1]
}

func (l *grantLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sets)
}

func (l *grantLog) pairs() []string {
	var ids []string
	for _, g := range l.last().Grants {
		ids = append(ids, g.PairID)
	}
	slices.Sort(ids)
	return ids
}

// p2pRig is a hub with a real tunnel, a device agent that speaks services and
// the control RPC, and plane B enabled for the device.
type p2pRig struct {
	*wgRig
	log *grantLog
}

func newP2PRig(t *testing.T, caps []string, opts ...rigOpt) *p2pRig {
	t.Helper()
	return newP2PRigPorts(t, caps, []int{22}, opts...)
}

func newP2PRigPorts(t *testing.T, caps []string, ports []int, opts ...rigOpt) *p2pRig {
	t.Helper()
	gl := &grantLog{}
	agent := &svcAgent{grants: gl.handler}
	r := newWGRig(t, opts...)
	r.devCaps = caps
	_, devPub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	r.devP2PKey = devPub.Base64()
	p := r.policy
	p.AllowedPorts = ports
	p.P2P = true
	r.setPolicy(p)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := make(chan error, 1)
	go func() { served <- r.h.ServeTunnel(ctx) }()
	waitFor(t, "hub ready", r.h.Ready)
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("ServeTunnel did not stop")
		}
	})
	ds := r.deviceSessionOK()
	dp := startPeer(t, ds.priv, ds.Address, ds.HubPublicKey, r.h.Endpoint())
	agent.serve(t, dp)
	hubDev := rawTunnel(r.h).dev
	waitFor(t, "device endpoint learned by hub", func() bool {
		out, _ := hubDev.IpcGet()
		return strings.Contains(out, "endpoint=")
	})
	devB, err := p2p.AddrFor(netip.MustParseAddr(ds.Address))
	if err != nil {
		t.Fatal(err)
	}
	gl.devKey, gl.devAddr, gl.cands = r.devP2PKey, devB.String(), []string{"10.9.9.9:41000", "203.0.113.9:41000"}
	return &p2pRig{wgRig: &wgRig{rig: r, devSess: ds, devPeer: dp, cancel: cancel}, log: gl}
}

// offer returns a plane-B offer with a fresh key.
func offer(t *testing.T, cands ...string) (*api.P2POffer, wgkey.PublicKey) {
	t.Helper()
	_, pub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if cands == nil {
		cands = []string{"192.168.1.20:50000", "198.51.100.4:50000"}
	}
	return &api.P2POffer{WGPublicKey: pub.Base64(), Candidates: cands}, pub
}

func (p *p2pRig) p2pClient(token, service string, o *api.P2POffer, mut ...func(*api.ClientSessionRequest)) (api.SessionResponse, int, []byte) {
	p.t.Helper()
	req, _ := p.clientReq(22)
	req.Service, req.Port, req.P2P = service, 0, o
	for _, m := range mut {
		m(&req)
	}
	st, body := p.clientSession(token, req)
	var resp api.SessionResponse
	if st == http.StatusCreated {
		if err := json.Unmarshal(body, &resp); err != nil {
			p.t.Fatal(err)
		}
	}
	return resp, st, body
}

func (p *p2pRig) mustClient(token, service string) (api.SessionResponse, *api.P2POffer) {
	p.t.Helper()
	o, _ := offer(p.t)
	resp, st, body := p.p2pClient(token, service, o)
	if st != http.StatusCreated {
		p.t.Fatalf("client session: %d %s", st, body)
	}
	return resp, o
}

func (p *p2pRig) session(id string) *session {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.byID[id]
}

// ---- the grant flow ----

func TestP2PGrantPushedAndReturned(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	resp, o := p.mustClient(aliceToken, "ssh")
	g := resp.P2P
	if g == nil {
		t.Fatalf("no plane-B grant; hub log:\n%s", p.logs.String())
	}
	clientB, _ := p2p.AddrFor(netip.MustParseAddr(resp.Address))
	devB, _ := p2p.AddrFor(netip.MustParseAddr(p.devSess.Address))
	if g.PairID != resp.SessionID || g.ClientAddress != clientB.String() || g.DeviceAddress != devB.String() ||
		g.DeviceWGPublicKey != p.devP2PKey || g.TTLSeconds != api.DefaultGrantTTL {
		t.Fatalf("grant %+v (client B %s, device B %s)", g, clientB, devB)
	}
	if !slices.Equal(g.DeviceCandidates, []string{"10.9.9.9:41000", "203.0.113.9:41000"}) {
		t.Fatalf("device candidates %v", g.DeviceCandidates)
	}
	set := p.log.last()
	if set.HubInstance == "" || set.HubInstance != p.h.instance || set.Seq != 1 || len(set.Grants) != 1 {
		t.Fatalf("pushed set %+v", set)
	}
	got := set.Grants[0]
	if got.PairID != resp.SessionID || got.ClientWGPublicKey != o.WGPublicKey || got.ClientAddress != clientB.String() ||
		!slices.Equal(got.Services, []string{"ssh"}) || got.TTLSeconds < 1 || got.TTLSeconds > api.DefaultGrantTTL ||
		!slices.Equal(got.ClientCandidates, o.Candidates) {
		t.Fatalf("pushed grant %+v", got)
	}
	if strings.Contains(p.logs.String(), o.WGPublicKey) || strings.Contains(p.logs.String(), p.devP2PKey) {
		t.Fatal("a plane-B key was logged")
	}
}

func TestP2PSetsAreFullAndNumbered(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	r1, _ := p.mustClient(aliceToken, "ssh")
	r2, _ := p.mustClient(aliceToken, "ssh")
	set := p.log.last()
	if set.Seq != 2 || len(set.Grants) != 2 {
		t.Fatalf("second push %+v", set)
	}
	ids := p.log.pairs()
	want := []string{r1.SessionID, r2.SessionID}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("pairs %v want %v", ids, want)
	}
	a1, a2 := set.Grants[0].ClientAddress, set.Grants[1].ClientAddress
	if a1 == a2 {
		t.Fatal("two pairs share a client address")
	}
	// Removal pushes the full set without the pair, immediately.
	p.h.endSession(p.session(r1.SessionID), "test")
	waitFor(t, "the removal push", func() bool { return len(p.log.last().Grants) == 1 })
	set = p.log.last()
	if set.Seq != 3 || set.Grants[0].PairID != r2.SessionID {
		t.Fatalf("after removal %+v", set)
	}
	if pairs := p.h.P2PPairs(testNS, testDevice); !slices.Equal(pairs, []string{r2.SessionID}) {
		t.Fatalf("hub pairs %v", pairs)
	}
}

func TestP2PQuarantinedAddressesAreNotReused(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	r1, _ := p.mustClient(aliceToken, "ssh")
	b1 := p.log.last().Grants[0].ClientAddress
	p.h.endSession(p.session(r1.SessionID), "test")
	waitFor(t, "removal", func() bool { return len(p.log.last().Grants) == 0 })
	// The plane-A address is quarantined, so its plane-B twin is too.
	r2, _ := p.mustClient(aliceToken, "ssh")
	if b2 := p.log.last().Grants[0].ClientAddress; b2 == b1 || r2.Address == r1.Address {
		t.Fatalf("plane-B address %s reused right after its session ended", b1)
	}
	// After the quarantine the plane-A allocator may hand the address out again.
	// Both planes use the same host part, so the pair stays consistent.
	devB, _ := p2p.AddrFor(netip.MustParseAddr(p.devSess.Address))
	if devB.String() != p.log.devAddr {
		t.Fatalf("device plane-B address %s != %s", devB, p.log.devAddr)
	}
}

func TestP2PTTLIsRelativeAndRefreshedByClientRenewals(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	resp, _ := p.mustClient(aliceToken, "ssh")
	s := p.session(resp.SessionID)
	n := p.log.count()
	// Within the first half of the TTL a renewal restarts the lease but pushes nothing.
	p.clock.Advance(20 * time.Second)
	p.h.p2pRenewed(s, api.PathDirect)
	time.Sleep(100 * time.Millisecond)
	if p.log.count() != n {
		t.Fatalf("a renewal before half the TTL pushed (%d -> %d)", n, p.log.count())
	}
	if path, _ := p.h.ClientPath(resp.SessionID); path != api.PathDirect {
		t.Fatalf("path %q", path)
	}
	// After half the TTL a renewal pushes the set with the full TTL again.
	p.clock.Advance(30 * time.Second)
	p.h.p2pRenewed(s, api.PathHub)
	waitFor(t, "the refresh push", func() bool { return p.log.count() > n })
	if g := p.log.last().Grants[0]; g.TTLSeconds != api.DefaultGrantTTL {
		t.Fatalf("refreshed TTL %d", g.TTLSeconds)
	}
	// Nonsense paths are ignored.
	p.h.p2pRenewed(s, "carrier-pigeon")
	if path, _ := p.h.ClientPath(resp.SessionID); path != api.PathHub {
		t.Fatalf("path %q after a bogus report", path)
	}
	// Without renewals the lease runs out: the pair is not in the next set.
	p.clock.Advance(api.DefaultGrantTTL*time.Second + time.Second)
	if set := p.h.buildGrantSet(p.h.deviceSession(testNS, testDevice)); len(set.Grants) != 0 {
		t.Fatalf("an expired lease is still in the set: %+v", set.Grants)
	}
	// And a set built for the device's renewal carries what is left, not a full TTL.
	p.h.p2pRenewed(s, api.PathHub) // renewed again: full lease
	p.clock.Advance(60 * time.Second)
	set := p.h.buildGrantSet(p.h.deviceSession(testNS, testDevice))
	if len(set.Grants) != 1 || set.Grants[0].TTLSeconds < 29 || set.Grants[0].TTLSeconds > 31 {
		t.Fatalf("remaining TTL in the backstop set: %+v", set.Grants)
	}
}

func TestP2PDeviceRenewalCarriesTheFullSet(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	r1, _ := p.mustClient(aliceToken, "ssh")
	tok := p.dev.renewToken(t, p.clock.Now(), p.devSess.pub.Base64())
	st, body := p.tunnelPost(api.RenewPath, p.devSess.Address, tok, api.RenewRequest{})
	if st != http.StatusOK {
		t.Fatalf("device renewal: %d %s", st, body)
	}
	var rr api.RenewResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.Grants == nil || rr.Grants.HubInstance != p.h.instance || len(rr.Grants.Grants) != 1 || rr.Grants.Grants[0].PairID != r1.SessionID {
		t.Fatalf("renewal grants %+v", rr.Grants)
	}
	if rr.Grants.Seq <= p.log.last().Seq {
		t.Fatalf("the backstop set (seq %d) is not newer than the last push (seq %d)", rr.Grants.Seq, p.log.last().Seq)
	}
	// A device without plane B gets no Grants field.
	q := newP2PRig(t, capsFull)
	tok = q.dev.renewToken(t, q.clock.Now(), q.devSess.pub.Base64())
	st, body = q.tunnelPost(api.RenewPath, q.devSess.Address, tok, api.RenewRequest{})
	if st != http.StatusOK || strings.Contains(string(body), `"grants"`) {
		t.Fatalf("plain device renewal: %d %s", st, body)
	}
}

// ---- when no grant is issued (and the session still works) ----

func TestP2PNotOffered(t *testing.T) {
	type tc struct {
		name string
		caps []string
		pol  func(*api.PolicyEntry)
		mut  func(*api.ClientSessionRequest)
	}
	for _, c := range []tc{
		{name: "agent without plane B", caps: capsFull},
		{name: "device opted out", caps: capsP2P, pol: func(p *api.PolicyEntry) { p.P2P = false }},
		{name: "raw port session", caps: capsP2P, mut: func(q *api.ClientSessionRequest) { q.Service, q.Port = "", 2200 }},
		{name: "direct session", caps: capsP2P, mut: func(q *api.ClientSessionRequest) {
			q.Direct = true
			q.OnBehalfOf = aliceEmail
			q.Posture.Software = "web-terminal"
		}},
		{name: "delegated session", caps: capsP2P, mut: func(q *api.ClientSessionRequest) { q.OnBehalfOf = aliceEmail; q.Posture.Software = "web-terminal" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newP2PRigPorts(t, c.caps, []int{22, 2200})
			p.sa.add("sa-token", "wgt-cam-1", testNS, testDevice)
			if c.pol != nil {
				pol := p.policy
				c.pol(&pol)
				p.setPolicy(pol)
			}
			token := aliceToken
			if c.mut != nil {
				req0, _ := p.clientReq(22)
				c.mut(&req0)
				if req0.OnBehalfOf != "" {
					token = "sa-token"
				}
			}
			o, _ := offer(t)
			resp, st, body := p.p2pClient(token, "ssh", o, func(q *api.ClientSessionRequest) {
				if c.mut != nil {
					c.mut(q)
				}
			})
			if st != http.StatusCreated {
				t.Fatalf("session refused: %d %s", st, body)
			}
			if resp.P2P != nil {
				t.Fatalf("grant issued: %+v", resp.P2P)
			}
			if n := p.log.count(); n != 0 {
				t.Fatalf("%d grant pushes for a session that gets no plane B", n)
			}
		})
	}
}

func TestP2PAgentDoesNotAccept(t *testing.T) {
	nine := []string{"1.1.1.1:1", "1.1.1.2:1", "1.1.1.3:1", "1.1.1.4:1", "1.1.1.5:1", "1.1.1.6:1", "1.1.1.7:1", "1.1.1.8:1", "1.1.1.9:1"}
	// cleanup: the device may hold the pair, so the hub must push it away again.
	for name, tc := range map[string]struct {
		set     func(l *grantLog)
		cleanup bool
	}{
		"pair refused":       {func(l *grantLog) { l.refuse = func(api.Grant) bool { return true } }, false},
		"push fails":         {func(l *grantLog) { l.status = http.StatusInternalServerError }, true},
		"wrong device key":   {func(l *grantLog) { l.devKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }, true},
		"wrong device addr":  {func(l *grantLog) { l.devAddr = "100.97.200.200" }, true},
		"no device key":      {func(l *grantLog) { l.devKey = "" }, true},
		"bad candidates":     {func(l *grantLog) { l.cands = []string{"0.0.0.0:1"} }, true},
		"too many candidate": {func(l *grantLog) { l.cands = nine }, true},
	} {
		t.Run(name, func(t *testing.T) {
			p := newP2PRig(t, capsP2P)
			tc.set(p.log)
			resp, st, body := p.p2pClient(aliceToken, "ssh", func() *api.P2POffer { o, _ := offer(t); return o }())
			if st != http.StatusCreated {
				t.Fatalf("the splice session must not depend on plane B: %d %s", st, body)
			}
			if resp.P2P != nil {
				t.Fatalf("grant returned: %+v", resp.P2P)
			}
			if pairs := p.h.P2PPairs(testNS, testDevice); len(pairs) != 0 {
				t.Fatalf("hub kept pairs %v", pairs)
			}
			// The hub takes the pair out of the device's set again (it may have been applied).
			p.log.mu.Lock()
			p.log.status, p.log.refuse = 0, nil
			p.log.mu.Unlock()
			if tc.cleanup {
				waitFor(t, "cleanup push", func() bool { return len(p.log.last().Grants) == 0 && p.log.count() >= 2 })
			}
		})
	}
}

func TestP2PRejectsBadOffers(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	_, pub := offer(t)
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, byte(i + 1)}), 5000).String()
	}
	for name, o := range map[string]*api.P2POffer{
		"bad key":        {WGPublicKey: "not-a-key", Candidates: []string{"1.2.3.4:5"}},
		"empty key":      {Candidates: []string{"1.2.3.4:5"}},
		"too many":       {WGPublicKey: pub.Base64(), Candidates: nine},
		"unspecified":    {WGPublicKey: pub.Base64(), Candidates: []string{"0.0.0.0:5000"}},
		"multicast":      {WGPublicKey: pub.Base64(), Candidates: []string{"224.0.0.251:5353"}},
		"v6 multicast":   {WGPublicKey: pub.Base64(), Candidates: []string{"[ff02::1]:5000"}},
		"port zero":      {WGPublicKey: pub.Base64(), Candidates: []string{"1.2.3.4:0"}},
		"not an address": {WGPublicKey: pub.Base64(), Candidates: []string{"cam.local:5000"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, st, body := p.p2pClient(aliceToken, "ssh", o)
			wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
		})
	}
	if p.log.count() != 0 {
		t.Fatal("a bad offer reached the agent")
	}
	// A valid offer with no candidates at all is fine (the device may still reach out).
	o := &api.P2POffer{WGPublicKey: pub.Base64()}
	resp, st, body := p.p2pClient(aliceToken, "ssh", o)
	if st != http.StatusCreated || resp.P2P == nil {
		t.Fatalf("offer without candidates: %d %s", st, body)
	}
}

func TestP2PInvalidDeviceKeyDropsTheCapability(t *testing.T) {
	r := newWGRig(t)
	r.devCaps = capsP2P
	r.devP2PKey = "garbage"
	p := r.policy
	p.P2P = true
	r.setPolicy(p)
	r.deviceSessionOK()
	dev := r.h.deviceSession(testNS, testDevice)
	if dev.hasCap(api.CapP2P) || dev.p2pKey != "" {
		t.Fatalf("caps %v key %q", dev.caps, dev.p2pKey)
	}
	if !dev.hasCap(api.CapServices) {
		t.Fatal("other capabilities must survive")
	}
}

// ---- revocation ----

func TestP2PPolicyOptOutDropsPairs(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	p.mustClient(aliceToken, "ssh")
	pol := p.policy
	pol.P2P = false
	p.setPolicy(pol)
	waitFor(t, "the pair to be pushed away", func() bool { return len(p.log.last().Grants) == 0 && p.log.count() >= 2 })
	if pairs := p.h.P2PPairs(testNS, testDevice); len(pairs) != 0 {
		t.Fatalf("pairs %v", pairs)
	}
}

func TestP2PServiceRemovalAndRevocationPushAtOnce(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	pol := p.policy
	pol.Services = []api.ServiceSpec{webSvc}
	p.setPolicy(pol)
	r1, _ := p.mustClient(aliceToken, "web")
	r2, _ := p.mustClient(aliceToken, "ssh")
	if len(p.log.last().Grants) != 2 {
		t.Fatal("two pairs expected")
	}
	// Removing the web service ends that client session and pushes the set without its pair.
	pol.Services = nil
	p.setPolicy(pol)
	waitFor(t, "the web pair to go", func() bool { return slices.Equal(p.log.pairs(), []string{r2.SessionID}) })
	_ = r1
	// A compromised flag ends everything and the last push is empty.
	p.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	waitFor(t, "the empty set", func() bool { return len(p.log.last().Grants) == 0 && p.log.last().Seq >= 4 })
}

// ---- ordering ----

func TestP2PStalePushIsRebuilt(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	// The agent already holds a much newer set (a backstop overtook this push):
	// the hub rebuilds with a new sequence number and the pair is accepted.
	p.log.mu.Lock()
	p.log.maxSeq = 3
	p.log.mu.Unlock()
	resp, _ := p.mustClient(aliceToken, "ssh")
	if resp.P2P == nil {
		t.Fatalf("a stale-rejected push was not retried; log:\n%s", p.logs.String())
	}
	if last := p.log.last(); last.Seq != 3 {
		t.Fatalf("final seq %d, want 3 (two stale answers, then accepted)", last.Seq)
	}
}

func TestP2PSlowAgentDoesNotHangTheSession(t *testing.T) {
	p := newP2PRig(t, capsP2P, func(c *Config) { c.P2PPushTimeout = 300 * time.Millisecond })
	p.log.mu.Lock()
	p.log.delay = 2 * time.Second
	p.log.mu.Unlock()
	start := time.Now()
	o, _ := offer(t)
	resp, st, _ := p.p2pClient(aliceToken, "ssh", o)
	if st != http.StatusCreated || resp.P2P != nil {
		t.Fatalf("status %d grant %v", st, resp.P2P)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("session creation took %v with a slow agent", d)
	}
}

func TestHubInstancesDiffer(t *testing.T) {
	a, b := newRig(t), newRig(t)
	if a.h.instance == "" || a.h.instance == b.h.instance {
		t.Fatalf("instances %q %q", a.h.instance, b.h.instance)
	}
	if a.h.cfg.P2PGrantTTL != api.DefaultGrantTTL*time.Second {
		t.Fatalf("default TTL %v", a.h.cfg.P2PGrantTTL)
	}
}
