package e2e_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

func compromised() map[string]string {
	return map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"}
}

func enabled() map[string]string { return map[string]string{api.AnnotationWireGuard: "enabled"} }

// readErrAfter starts a blocking read on c and returns a channel that yields
// its error. The read happens on the client side of the tunnel.
func readErrAfter(c interface{ Read([]byte) (int, error) }) <-chan error {
	ch := make(chan error, 1)
	go func() {
		n, err := c.Read(make([]byte, 1))
		if err == nil {
			err = errors.New("unexpected data on a connection that should be dead")
			_ = n
		}
		ch <- err
	}()
	return ch
}

// (a) Enroll, device session, and a client echo through TURN on both legs.
func TestEnrollSessionAndEchoThroughTURN(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)

	// The identity was pinned by trust on first use.
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.Fingerprint == "" || pin.Fingerprint != r.AgentFingerprint() || pin.EnrollmentGeneration != 1 {
		t.Fatalf("pin %+v, agent fingerprint %s", pin, r.AgentFingerprint())
	}

	cli := r.MustClient(e2erig.AliceEmail)
	resp := cli.Response()
	if resp.TURN == nil || cli.RelaySwaps() != 1 {
		t.Fatalf("client is not on TURN: turn=%v swaps=%d", resp.TURN != nil, cli.RelaySwaps())
	}
	if len(resp.SSHHostKeys) != 1 || resp.SSHHostKeys[0] != r.HostKey {
		t.Fatalf("host keys reported to the client: %v, want [%s]", resp.SSHHostKeys, r.HostKey)
	}
	if resp.TargetPort != r.Echo.Port {
		t.Fatalf("target port %d", resp.TargetPort)
	}
	// Both legs use a TURN allocation.
	if n := r.TURN.Allocations(); n != 2 {
		t.Fatalf("TURN allocations = %d, want 2 (agent and client)", n)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := cli.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"hello through wireguard and turn", strings.Repeat("0123456789", 20_000)} {
		if err := e2erig.RoundTrip(c, msg); err != nil {
			t.Fatalf("echo of %d bytes: %v", len(msg), err)
		}
	}
	if r.Echo.Total() != 1 || r.Echo.Active() != 1 {
		t.Fatalf("fake sshd saw %d connections, %d active", r.Echo.Total(), r.Echo.Active())
	}
	_ = c.Close()
	e2erig.Eventually(t, 5*time.Second, "the fake sshd to see the close", func() bool { return r.Echo.Active() == 0 })
}

// (b) Marking the device compromised: the client's conn errors within 1s, new
// sessions are refused, the device session ends, the agent backs off.
func TestCompromisedDeviceIsCutOff(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	cli := r.MustClient(e2erig.AliceEmail)
	c, err := cli.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := e2erig.RoundTrip(c, "before"); err != nil {
		t.Fatal(err)
	}

	readErr := readErrAfter(c)
	t0 := time.Now()
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	select {
	case err := <-readErr:
		t.Logf("client-side read failed %v after the flag: %v", time.Since(t0).Round(time.Millisecond), err)
	case <-time.After(time.Second):
		t.Fatal("the client's Dial'ed connection was still open 1s after the device was marked compromised")
	}

	// The agent tore its side down too: the fake sshd sees the close.
	e2erig.Eventually(t, 5*time.Second, "the agent to close its local connection", func() bool { return r.Echo.Active() == 0 })

	// New client sessions are refused with device_revoked.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = r.NewClient(ctx, e2erig.AliceEmail)
	var we *wgclient.Error
	if !errors.As(err, &we) || we.Reason != api.ReasonDeviceRevoked || we.Status != 403 {
		t.Fatalf("new client session: %v, want 403 %s", err, api.ReasonDeviceRevoked)
	}

	// The device session ends (the hub closed it) and the agent is refused and
	// backs off instead of hammering the hub.
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool {
		d, _ := r.Hub.SessionCounts()
		return d == 0
	})
	e2erig.Eventually(t, 10*time.Second, "the agent to be refused with device_revoked", func() bool {
		return r.AgentLogs.Count(`"reason":"device_revoked"`) > 0
	})
	before := r.AgentLogs.Count(`"msg":"no session"`)
	time.Sleep(2 * time.Second)
	attempts := r.AgentLogs.Count(`"msg":"no session"`) - before
	if attempts > 40 {
		t.Fatalf("agent made %d attempts in 2s; it must back off", attempts)
	}
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("a revoked device got a session")
	}
	if !strings.Contains(r.AgentLogs.String(), `"retry_in"`) {
		t.Fatal("agent did not log its retry delay")
	}
}

// (c) Clearing the flag together with an enrollment reset: the agent gets
// reenroll, rotates its identity, enrolls again, and access returns.
func TestClearedDeviceReenrollsAndWorksAgain(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	fp0 := r.AgentFingerprint()
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "first life", 20*time.Second); err != nil {
		t.Fatal(err)
	}

	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })

	// The controller bumps the generation and opens a new window; while the
	// flag is still set the device stays out.
	p, _ := r.Policy.Get(e2erig.NS, e2erig.DeviceName)
	p.EnrollmentGeneration = 2
	p.EnrollmentEpoch = e2erig.Epoch2
	p.EnrollUntil = time.Now().Add(time.Hour)
	r.Policy.Set(p)
	e2erig.Eventually(t, 10*time.Second, "the agent to be refused while flagged", func() bool {
		return r.AgentLogs.Count(`"reason":"device_revoked"`) > 0
	})
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("flagged device has a session")
	}

	// Clear the flag.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, enabled())
	r.WaitDeviceUp(2)

	fp1 := r.AgentFingerprint()
	if fp1 == fp0 {
		t.Fatalf("identity fingerprint did not change after re-enrollment (%s)", fp1)
	}
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.Fingerprint != fp1 || pin.EnrollmentGeneration != 2 {
		t.Fatalf("pin after re-enrollment: %+v (agent %s)", pin, fp1)
	}
	if !strings.Contains(r.AgentLogs.String(), "enrollment was reset") {
		t.Fatal("agent log does not show the re-enrollment")
	}

	cli2 := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli2, "second life", 20*time.Second); err != nil {
		t.Fatalf("client after re-enrollment: %v", err)
	}
}

// (d) A user who loses the SubjectAccessReview is refused on the next
// connection at once, and the renewal is denied.
func TestUserLosingAccessIsRefused(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	cli := r.MustClient(e2erig.AliceEmail)
	c1, err := cli.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if err := e2erig.RoundTrip(c1, "while allowed"); err != nil {
		t.Fatal(err)
	}

	r.Authz.Set(e2erig.AliceEmail, e2erig.NS, false)

	// The next connection is refused immediately: no byte is echoed. (The
	// renewal can end the session first; then Dial fails, which is a refusal
	// too.)
	t0 := time.Now()
	if c2, err := cli.Dial(context.Background()); err == nil {
		_ = c2.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c2.Write([]byte("should not reach the device"))
		n, rerr := c2.Read(make([]byte, 64))
		_ = c2.Close()
		if n != 0 || rerr == nil {
			t.Fatalf("a connection of a user without access was spliced (%d bytes, %v)", n, rerr)
		}
	}
	if d := time.Since(t0); d > 2500*time.Millisecond {
		t.Fatalf("refusal took %v", d)
	}

	// The renewal is denied: the session ends with the hub's reason and the
	// established connection is closed.
	select {
	case <-cli.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("the client session survived the loss of access")
	}
	if got := wgclient.ReasonOf(cli.Err()); got != api.ReasonForbidden {
		t.Fatalf("session ended with %v (reason %q), want %s", cli.Err(), got, api.ReasonForbidden)
	}
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("established connection stayed open")
	}

	// A new session is refused at creation; another user still gets in; the
	// device session was never touched.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := r.NewClient(ctx, e2erig.AliceEmail); wgclient.ReasonOf(err) != api.ReasonForbidden {
		t.Fatalf("new session for the user without access: %v", err)
	}
	bob := r.MustClient(e2erig.BobEmail)
	if err := e2erig.EchoVia(bob, "bob", 20*time.Second); err != nil {
		t.Fatalf("a user with access was affected: %v", err)
	}
	if d, _ := r.Hub.SessionCounts(); d != 1 {
		t.Fatal("device session must survive a client losing access")
	}
}

// (e) The TURN server restarts and loses every allocation; the relay
// supervisors of agent and client recover and a new connection works.
func TestTURNRestartRecovers(t *testing.T) {
	t.Parallel()
	// Renewals every 2s keep the tunnel receiving; 5s without anything means a
	// dead relay.
	r := e2erig.New(t, e2erig.Options{StaleAfter: 5 * time.Second})
	r.StartAgent()
	r.WaitDeviceUp(1)
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "before the restart", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := r.TURN.Allocations(); n != 2 {
		t.Fatalf("allocations before restart: %d", n)
	}

	t0 := time.Now()
	r.TURN.Restart() // every allocation is lost, exactly like a STUNner pod restart
	if err := e2erig.EchoVia(cli, "after the restart", 80*time.Second); err != nil {
		t.Fatalf("no working connection %v after the TURN restart: %v\nclient log: %s", time.Since(t0).Round(time.Second), err, tail(r.ClientLogs.String()))
	}
	t.Logf("a new connection worked %v after the TURN restart", time.Since(t0).Round(time.Millisecond))
	e2erig.Eventually(t, 30*time.Second, "both legs to hold a new allocation", func() bool { return r.TURN.Allocations() == 2 })
	if !strings.Contains(r.ClientLogs.String(), `"msg":"relay swapped"`) {
		t.Fatal("the client did not re-allocate its relay")
	}
	select {
	case <-cli.Done():
		t.Fatalf("client session ended: %v", cli.Err())
	default:
	}
	if d, _ := r.Hub.SessionCounts(); d != 1 {
		t.Fatalf("device sessions = %d, want 1 (the same session recovered)", d)
	}
}

func tail(s string) string {
	if len(s) > 1500 {
		return "..." + s[len(s)-1500:]
	}
	return s
}

// (f) No credential, token, password or key ever reaches a log, through
// enrollment, sessions, renewals, denials and revocation.
func TestLogHygiene(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "log me not", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	// Several renewals on both sessions (debug-level lines).
	e2erig.Eventually(t, 20*time.Second, "renewals", func() bool {
		return r.ClientLogs.Count(`"msg":"session renewed"`) >= 2 && r.AgentLogs.Count(`"msg":"session renewed"`) >= 2
	})

	// A client with a bad token, and one that is refused.
	bad := r.ClientOptions(e2erig.AliceEmail)
	bad.Credential = func(context.Context, string) (string, error) { return "garbage-token-for-the-log-check-12345", nil }
	r.AddSecret("garbage-token-for-the-log-check-12345")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := wgclient.Create(ctx, bad); err == nil {
		t.Fatal("a garbage token was accepted")
	}
	r.Authz.Set(e2erig.BobEmail, e2erig.NS, false)
	if _, err := r.NewClient(ctx, e2erig.BobEmail); err == nil {
		t.Fatal("a user without access got a session")
	}

	// Revocation and the agent's reaction.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	e2erig.Eventually(t, 10*time.Second, "the agent to be refused", func() bool {
		return r.AgentLogs.Count(`"reason":"device_revoked"`) > 0
	})

	for name, l := range map[string]*e2erig.LogBuf{"hub": r.HubLogs, "agent": r.AgentLogs, "client": r.ClientLogs} {
		t.Logf("%s log: %d bytes, %d lines", name, len(l.String()), strings.Count(l.String(), "\n"))
	}
	if r.HubLogs.Count(`"decision":"revoke"`) == 0 {
		t.Fatal("the hub logged no revocation; the check would not have seen the interesting paths")
	}
	r.AssertLogHygiene()
}

// failRecorder turns test failures into a count, to prove that the hygiene
// check really catches a leak.
type failRecorder struct {
	testing.TB
	failures int
}

func (f *failRecorder) Errorf(string, ...any) { f.failures++ }
func (f *failRecorder) Helper()               {}

func TestLogHygieneCheckDetectsLeaks(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "x", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	rec := &failRecorder{TB: t}
	real := r.T
	r.T = rec
	r.AssertLogHygiene()
	if rec.failures != 0 {
		t.Fatalf("clean logs were reported as leaking (%d findings)", rec.failures)
	}
	// Each kind of leak is caught.
	tok := r.UserToken(e2erig.AliceEmail)
	for name, leak := range map[string]func(){
		"hub":    func() { _, _ = r.HubLogs.Write([]byte(`{"msg":"oops ` + tok + `"}` + "\n")) },
		"agent":  func() { _, _ = r.AgentLogs.Write([]byte(`{"msg":"oops ` + e2erig.TURNSecret + `"}` + "\n")) },
		"client": func() { _, _ = r.ClientLogs.Write([]byte(`{"msg":"Authorization: Bearer abc"}` + "\n")) },
	} {
		before := rec.failures
		leak()
		r.AssertLogHygiene()
		if rec.failures == before {
			t.Errorf("a leak into the %s log was not detected", name)
		}
	}
	r.T = real
}
