package hub

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// A gateway (perConn) session is shared by every user of the web service, so
// it gets its own, larger cap than a one-user session (review finding 4).
func TestGatewaySessionHasItsOwnConnectionCap(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent, func(c *Config) {
		c.MaxConnsPerSession, c.MaxConnsPerConnSession = 2, 5
	})
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	w.authz.set(bobEmail, testNS, true)
	cli, _ := gwSession(w, "web")
	var open []net.Conn
	t.Cleanup(func() {
		for _, c := range open {
			_ = c.Close()
		}
	})
	for i := range 5 { // well past the plain cap of 2
		user := aliceEmail
		if i%2 == 1 {
			user = bobEmail
		}
		c, ans, err := dialAs(cli, "web", user)
		if err != nil || !ans.OK {
			t.Fatalf("connection %d: %v %+v", i, err, ans)
		}
		open = append(open, c)
	}
	_, ans, err := dialAs(cli, "web", aliceEmail)
	if err != nil || ans.OK || ans.Reason != api.ReasonSessionLimit {
		t.Fatalf("connection 6: %v %+v, want session_limit", err, ans)
	}
}

// A user who loses access keeps no open WebSocket or stream: the next renewal
// of the gateway session authorizes every user with an open connection again
// (review finding 17).
func TestGatewayRenewalClosesConnectionsOfRevokedUsers(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	w.authz.set(bobEmail, testNS, true)
	cli, resp := gwSession(w, "web")
	ca, ans, err := dialAs(cli, "web", aliceEmail)
	if err != nil || !ans.OK {
		t.Fatalf("alice: %v %+v", err, ans)
	}
	cb, ans, err := dialAs(cli, "web", bobEmail)
	if err != nil || !ans.OK {
		t.Fatalf("bob: %v %+v", err, ans)
	}
	echo(t, ca, "a")
	echo(t, cb, "b")

	w.authz.set(bobEmail, testNS, false)
	code, out := w.tunnelPost(api.RenewPath, resp.Address, gwToken, api.RenewRequest{Posture: api.Posture{Software: "web-gateway"}})
	if code != 200 {
		t.Fatalf("renew: %d %s", code, out)
	}
	waitFor(t, "bob's connection to close", func() bool {
		_ = cb.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := cb.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && !(errors.As(err, &ne) && ne.Timeout())
	})
	// Alice, still authorized, is untouched, and so is the session.
	echo(t, ca, "still here")
	if w.h.sessionByAddr(cli.addr) == nil {
		t.Fatal("the gateway session ended")
	}
}

// ---- attestation budgets (review finding 5) ----

// A squatter holding the enrollment key drains its own bucket; the real
// device's identity key keeps its budget.
func TestAttestChallengeBudgetIsPerIdentityKey(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SubjectRate, c.SubjectBurst = 0.01, 3 })
	squatter := r.otherDevice(t)
	limited := 0
	for range 10 {
		if st, _ := r.challenge(squatter); st == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the squatter was never rate limited")
	}
	// The genuine device is not affected.
	for i := range 3 {
		if st, body := r.challenge(r.dev); st != http.StatusOK {
			t.Fatalf("real device challenge %d: %d %s", i, st, body)
		}
	}
	// ... and its replay partition is its own, too.
	if st, _ := r.challenge(r.dev); st != http.StatusTooManyRequests {
		t.Error("the real device's own bucket is not limited at all")
	}
}

func TestNoncesOfOneIdentityKeyNeverEvictAnothers(t *testing.T) {
	clk := newFakeClock()
	n := newNonceStore(clk.Now)
	mk := func(key string) nonceRec {
		return nonceRec{ns: "ns", device: "d", epoch: "e", generation: 1, identityKey: key}
	}
	real, _, _ := n.issue(mk("real"))
	for range 50 { // a squatter minting nonces under one key, and under many
		clk.Advance(time.Millisecond)
		n.issue(mk("squat"))
	}
	for i := range 100 {
		clk.Advance(time.Millisecond)
		n.issue(mk("squat-" + time.Duration(i).String()))
	}
	if _, ok := n.take(real); !ok {
		t.Fatal("the real device's nonce was evicted by a squatter")
	}
}

// An unattested enrollment of another identity is a conflict on the console,
// even when it is turned away for the missing attestation.
func TestForeignEnrollWithoutAttestationIsRecordedAsConflict(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	squatter := r.otherDevice(t)
	st, body := r.enrollWith(squatter, attestCaps)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonAttestRequired)
	if got := r.ids.entry(testNS, testDevice).Conflicts; got != 1 {
		t.Fatalf("conflicts = %d, want 1", got)
	}
	// The pinned identity itself is no conflict.
	r.enrollWith(r.dev, attestCaps)
	if got := r.ids.entry(testNS, testDevice).Conflicts; got != 1 {
		t.Fatalf("conflicts = %d after the pinned identity, want 1", got)
	}
}

// A plane-B pair does not outlive the device session it lives on: when the
// agent reconnects, the clients' pairs are dropped on the hub at once and a
// renewal does not try to refresh them on the dead session (review finding 16).
func TestP2PPairsAreDroppedWhenTheDeviceSessionIsReplaced(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	resp, _ := p.mustClient(aliceToken, "ssh")
	if pairs := p.h.P2PPairs(testNS, testDevice); len(pairs) != 1 {
		t.Fatalf("pairs %v", pairs)
	}
	before := p.log.count()
	p.deviceSessionOK() // the agent reconnects: a new device session replaces the old one
	waitFor(t, "the pair to be dropped", func() bool { return len(p.h.P2PPairs(testNS, testDevice)) == 0 })

	// Renewing after half the grant TTL would have refreshed the old pair.
	p.clock.Advance(p.h.cfg.P2PGrantTTL)
	p.users.set(aliceToken, aliceEmail, p.clock.Now().Add(5*time.Minute)) // a refreshed token
	code, out := p.tunnelPost(api.RenewPath, resp.Address, aliceToken, api.RenewRequest{})
	if code != http.StatusOK {
		t.Fatalf("renew: %d %s", code, out)
	}
	time.Sleep(100 * time.Millisecond)
	if n := p.log.count(); n != before {
		t.Errorf("%d grant sets were pushed to the replaced device session", n-before)
	}
	if pairs := p.h.P2PPairs(testNS, testDevice); len(pairs) != 0 {
		t.Errorf("the renewal resurrected pairs %v", pairs)
	}
}

// While the agent has not applied a redefined service, a connection to it is
// refused (retryable) instead of reaching the old target (review finding 21).
func TestSpliceRefusesAServiceTheAgentHasNotApplied(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	// Fresh agent, same definition: works.
	cli, _ := w.serviceClient(aliceToken, "web")
	c, err := dialSplice(cli)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "before")
	_ = c.Close()

	agent.setCtl(http.StatusInternalServerError) // the control push will not land
	moved := webSvc
	moved.Target = "192.168.1.99"
	withServices(w.rig, moved)
	waitFor(t, "the old client session to end", func() bool { return w.h.sessionByAddr(cli.addr) == nil })
	cli2, _ := w.serviceClient(aliceToken, "web") // resolved from the NEW policy
	before := len(agent.connects())
	c2, err := dialSplice(cli2)
	if err == nil {
		_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, rerr := c2.Read(make([]byte, 1)); rerr == nil || n != 0 {
			t.Fatalf("a connection reached the agent with the old definition (%d, %v)", n, rerr)
		}
		_ = c2.Close()
	}
	if after := len(agent.connects()); after != before {
		t.Fatalf("the agent was dialled for an unapplied definition (%d -> %d)", before, after)
	}
	if !strings.Contains(w.logs.String(), "has not applied this service definition") {
		t.Errorf("no decision logged:\n%s", w.logs.String())
	}
}

// A client session whose service was redefined between the policy lookup and
// the registration is not given a plane-B grant (review finding 22): the
// post-admit check runs the service check again.
func TestClientSessionRechecksTheServiceAfterAdmission(t *testing.T) {
	p := newP2PRig(t, capsP2P)
	pol := p.policy
	pol.Services = []api.ServiceSpec{webSvc}
	p.setPolicy(pol)
	moved := webSvc
	moved.Port = 9999
	// Change the policy at the moment the session is admitted (after the
	// resolution of the service, before the grant is made).
	p.h.testHookAfterAdmit = func() {
		pol2 := p.policy
		pol2.Services = []api.ServiceSpec{moved}
		p.setPolicy(pol2)
	}
	o, _ := offer(t)
	_, st, body := p.p2pClient(aliceToken, "web", o)
	p.h.testHookAfterAdmit = nil
	if st == http.StatusCreated {
		t.Fatalf("a session for a redefined service was created: %s", body)
	}
	if pairs := p.h.P2PPairs(testNS, testDevice); len(pairs) != 0 {
		t.Fatalf("a pair was granted for the stale service: %v", pairs)
	}
}

// The agent's reserved overlay ports are never advertised to the agent as raw
// ports nor allowed on the client path (review finding 23).
func TestReservedAgentPortsAreNeverRawPorts(t *testing.T) {
	got := validPorts([]int{22, api.AgentConnectPort, 2200, api.AgentControlPort, 22})
	if len(got) != 2 || got[0] != 22 || got[1] != 2200 {
		t.Fatalf("validPorts = %v", got)
	}
	for _, p := range []int{api.AgentConnectPort, api.AgentControlPort} {
		if portAllowed([]int{p, 22}, p) {
			t.Errorf("port %d allowed", p)
		}
	}
	if !samePorts([]int{22, api.AgentControlPort}, []int{22}) {
		t.Error("a reserved port counts as a difference in the allowed-port set")
	}
}
