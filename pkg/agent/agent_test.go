package agent

import (
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
)

func TestEnrollsThenForwardsThroughTURN(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	// A malformed file must be skipped, not sent to the hub.
	hkDir := filepath.Dir(r.hkGlob)
	if err := os.WriteFile(filepath.Join(hkDir, "ssh_host_rsa_key.pub"), []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want, err := readHostKey(filepath.Join(hkDir, "ssh_host_ed25519_key.pub"))
	if err != nil {
		t.Fatal(err)
	}

	_, stop := r.start(r.config())
	eventually(t, 15*time.Second, "enrolled device session", func() bool {
		return r.hub.PinnedKey(testNS, testDevice) != nil && len(r.hub.SessionIDs(api.KindDevice)) == 1
	})
	if got := r.hub.HostKeys(testNS, testDevice); len(got) != 1 || got[0] != want || strings.Contains(got[0], "root@host") {
		t.Fatalf("host keys at hub = %v, want [%s]", got, want)
	}
	if n := r.hub.Enrollments(testNS, testDevice); n != 1 {
		t.Fatalf("enrollments = %d", n)
	}
	priv, err := identity.LoadOrCreate(r.idDir)
	if err != nil {
		t.Fatal(err)
	}
	if !r.hub.PinnedKey(testNS, testDevice).Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("hub pinned a different key than the one on disk")
	}
	if n := strings.Count(r.logs.String(), identity.Fingerprint(priv.Public().(ed25519.PublicKey))); n < 1 {
		t.Fatal("fingerprint not logged")
	}

	// A user session reaches the local echo server through hub and device.
	cli := r.clientSession(t)
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range []string{"SSH-2.0-test\r\n", strings.Repeat("y", 200_000)} {
		if err := roundTrip(c, m); err != nil {
			t.Fatalf("round trip (%d bytes): %v", len(m), err)
		}
	}

	// Graceful shutdown closes the session at the hub and the forwarded conn.
	if err := stop(); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	eventually(t, 20*time.Second, "device session closed at the hub", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 0 })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("forwarded connection survived shutdown")
	}
}

func TestReenrollsWithNewIdentityAfterReset(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	_, stop := r.start(r.config())
	eventually(t, 15*time.Second, "first enrollment", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	first := append(ed25519.PublicKey(nil), r.hub.PinnedKey(testNS, testDevice)...)
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// An admin resets enrollment (also what clearing a compromised flag does).
	r.hub.ResetEnrollment(testNS, testDevice)
	r.hub.SetEnrollOpen(testNS, testDevice, true)
	_, stop2 := r.start(r.config())
	defer func() { _ = stop2() }()
	eventually(t, 15*time.Second, "re-enrollment", func() bool {
		return r.hub.Enrollments(testNS, testDevice) == 2 && len(r.hub.SessionIDs(api.KindDevice)) == 1
	})
	second := r.hub.PinnedKey(testNS, testDevice)
	if second.Equal(first) {
		t.Fatal("agent re-enrolled with the SAME identity key")
	}
	if _, err := os.Stat(filepath.Join(r.idDir, identity.PrevKeyFile)); err != nil {
		t.Fatalf("previous identity not kept: %v", err)
	}
	if !strings.Contains(r.logs.String(), "enrollment was reset") {
		t.Fatal("no log line explaining the re-enrollment")
	}
}

func TestBackoffOnRefusalsAndRecovery(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	r.hub.SetEnrollOpen(testNS, testDevice, false) // window closed
	cfg := r.config()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		delays []time.Duration
	)
	a.rnd = func() float64 { return 1 } // no jitter: delay == full step
	a.sleep = func(ctx context.Context, d time.Duration) {
		mu.Lock()
		delays = append(delays, d)
		n := len(delays)
		mu.Unlock()
		if n == 3 { // stop being refused after a few attempts
			r.hub.SetEnrollOpen(testNS, testDevice, true)
		}
		time.Sleep(time.Millisecond)
	}
	a.cfg.Backoff = Backoff{Min: 2 * time.Second, Max: 5 * time.Minute, Stable: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); <-done }()

	eventually(t, 15*time.Second, "enrollment after the window opened", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	mu.Lock()
	got := append([]time.Duration(nil), delays...)
	mu.Unlock()
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
	if len(got) < 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("delays = %v, want prefix %v", got, want)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"reason":"enroll_closed"`) || !strings.Contains(logs, "admin must reset enrollment") {
		t.Fatalf("refusal was not explained in the logs:\n%s", logs)
	}
	if n := r.hub.Enrollments(testNS, testDevice); n != 1 {
		t.Fatalf("enrollments = %d", n)
	}
}

func TestRefusalReasonsBackOffAndKeepTrying(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*rig)
		code  string
		hint  string
	}{
		{"revoked", func(r *rig) { r.hub.SetState(testNS, testDevice, api.StateRevoked) }, api.ReasonDeviceRevoked, "flagged compromised"},
		{"disabled", func(r *rig) { r.hub.SetState(testNS, testDevice, api.StateDisabled) }, api.ReasonDeviceDisabled, "not enabled"},
		{"unknown", func(r *rig) {
			r.hub.SetOnCreate(func(fakehub.Call) *fakehub.Denial {
				return &fakehub.Denial{Status: 404, Reason: api.ReasonDeviceUnknown}
			})
		}, api.ReasonDeviceUnknown, "no policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, fakehub.Options{})
			tc.setup(r)
			r.start(r.config())
			eventually(t, 10*time.Second, "repeated refusals", func() bool {
				return strings.Count(r.logs.String(), `"reason":"`+tc.code+`"`) >= 3
			})
			if !strings.Contains(r.logs.String(), tc.hint) {
				t.Fatalf("missing hint %q in:\n%s", tc.hint, r.logs.String())
			}
			if len(r.hub.SessionIDs(api.KindDevice)) != 0 {
				t.Fatal("a session exists while refused")
			}
			// Once the refusal is lifted the agent comes back by itself.
			r.hub.SetState(testNS, testDevice, api.StateActive)
			r.hub.SetOnCreate(nil)
			eventually(t, 15*time.Second, "recovery", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
		})
	}
}

func TestBackoffResetsAfterStableSession(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second, TTL: 2 * time.Second})
	var deny atomic.Int32
	deny.Store(2)
	r.hub.SetOnCreate(func(fakehub.Call) *fakehub.Denial {
		if deny.Add(-1) >= 0 {
			return &fakehub.Denial{Status: 403, Reason: api.ReasonForbidden}
		}
		return nil
	})
	cfg := r.config()
	cfg.Backoff = Backoff{Min: 10 * time.Millisecond, Max: time.Second, Stable: 200 * time.Millisecond}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.rnd = func() float64 { return 1 }
	var (
		mu     sync.Mutex
		delays []time.Duration
	)
	a.sleep = func(ctx context.Context, d time.Duration) {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		sleepCtx(ctx, d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); <-done }()

	// Wait for the session, then drop it at the hub so renewals fail until expiry.
	eventually(t, 15*time.Second, "session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	time.Sleep(300 * time.Millisecond) // longer than Stable
	for _, id := range r.hub.SessionIDs(api.KindDevice) {
		r.hub.KillSession(id)
	}
	eventually(t, 20*time.Second, "delay after the stable session", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(delays) >= 3
	})
	mu.Lock()
	defer mu.Unlock()
	if delays[0] != 10*time.Millisecond || delays[1] != 20*time.Millisecond || delays[2] != 10*time.Millisecond {
		t.Fatalf("delays = %v, want 10ms,20ms then reset to 10ms", delays)
	}
}

func TestConnectionCap(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	cfg := r.config()
	cfg.MaxConns = 2
	r.start(cfg)
	eventually(t, 15*time.Second, "device session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	cli := r.clientSession(t)

	var open []io.Closer
	for i := 0; i < 2; i++ {
		c, err := cli.Dial(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
		if err := roundTrip(c, "hi"); err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
	}
	third, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	_ = third.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = third.Write([]byte("x"))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection was served beyond the cap")
	}
	if !strings.Contains(r.logs.String(), "too many concurrent connections") {
		t.Fatal("cap not logged")
	}
	// Freeing a slot admits new connections again.
	_ = open[0].Close()
	eventually(t, 20*time.Second, "slot freed", func() bool {
		c, err := cli.Dial(ctxT(t))
		if err != nil {
			return false
		}
		defer c.Close()
		return roundTrip(c, "again") == nil
	})
}

func TestLocalServiceDownClosesConnectionOnly(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	r.start(r.config())
	eventually(t, 15*time.Second, "device session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	cli := r.clientSession(t)
	_ = r.echo.Close() // nothing listens on the forwarded port any more
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the connection to be closed")
	}
	if len(r.hub.SessionIDs(api.KindDevice)) != 1 {
		t.Fatal("device session ended because of a refused local connection")
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second, RotateTURNOnRenew: true})
	r.start(r.config())
	eventually(t, 15*time.Second, "session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	cli := r.clientSession(t)
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(c, "secret payload 12345"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "renewals", func() bool {
		n := 0
		for _, call := range r.hub.Calls() {
			if call.Path == api.RenewPath && call.Kind == api.KindDevice {
				n++
			}
		}
		return n >= 3
	})
	_ = c.Close()

	logs := r.logs.String()
	rsaPriv, _ := deviceRSA(t)
	secrets := []string{"eyJ", "BEGIN", "PRIVATE KEY", string(rsaPriv[40:80]), "secret payload", "Authorization", "Bearer", turnSecret}
	for _, call := range r.hub.Calls() {
		secrets = append(secrets, call.Bearer)
	}
	secrets = append(secrets, r.hub.TURNPasswords()...)
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("agent log contains a secret (%d bytes starting %.4q)", len(s), s)
		}
	}
	if !strings.Contains(logs, "device identity enrolled") {
		t.Fatalf("expected log lines missing:\n%s", logs)
	}
}

// A pinned identity that nobody approved yet: the agent says so loudly, with
// its fingerprint for the admin to compare, backs off, stays enrolled (same
// identity, no re-enrollment) and comes up by itself once approved.
func TestPendingApprovalIsLoggedAndTheAgentStaysEnrolled(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	var pending atomic.Bool
	pending.Store(true)
	r.hub.SetOnCreate(func(fakehub.Call) *fakehub.Denial {
		switch {
		case r.hub.PinnedKey(testNS, testDevice) == nil:
			return &fakehub.Denial{Status: 401, Reason: api.ReasonUnauthenticated} // what the hub says before a pin exists
		case pending.Load():
			return &fakehub.Denial{Status: 403, Reason: api.ReasonPendingApproval}
		}
		return nil
	})
	r.start(r.config())
	eventually(t, 15*time.Second, "repeated pending_approval", func() bool {
		return strings.Count(r.logs.String(), "waiting for admin approval of this device identity") >= 3
	})
	priv, err := identity.LoadOrCreate(r.idDir)
	if err != nil {
		t.Fatal(err)
	}
	fp := identity.Fingerprint(priv.Public().(ed25519.PublicKey))
	logs := r.logs.String()
	if !strings.Contains(logs, `"fingerprint":"`+fp+`"`) || !strings.Contains(logs, `"retry_in"`) || !strings.Contains(logs, "approve this device identity") {
		t.Fatalf("the log must show the fingerprint, the retry delay and what to do:\n%s", logs)
	}
	if len(r.hub.SessionIDs(api.KindDevice)) != 0 {
		t.Fatal("a session exists while approval is pending")
	}
	if n := r.hub.Enrollments(testNS, testDevice); n != 1 {
		t.Fatalf("enrollments = %d; the agent must stay enrolled, not enroll again", n)
	}
	if _, err := os.Stat(filepath.Join(r.idDir, identity.PrevKeyFile)); err == nil {
		t.Fatal("the agent rotated its identity while waiting for approval")
	}

	pending.Store(false) // the admin approves
	eventually(t, 15*time.Second, "session after approval", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	if again, _ := identity.LoadOrCreate(r.idDir); !again.Equal(priv) {
		t.Fatal("identity changed")
	}
}

// The hub no longer says "not_enrolled" to a caller that has not proven a
// pinned key (the enrollment state would leak): a first start gets the same
// bare "unauthenticated" as a stranger, and must enroll on it, once, then come
// up.
func TestFirstStartEnrollsOnTheUniformUnauthenticatedAnswer(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	r.start(r.config())
	eventually(t, 15*time.Second, "session after first enrollment", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	if n := r.hub.Enrollments(testNS, testDevice); n != 1 {
		t.Fatalf("enrollments = %d, want exactly 1", n)
	}
	if !strings.Contains(r.logs.String(), "trying to enroll it") {
		t.Fatalf("the agent must enroll because of the unauthenticated answer:\n%s", r.logs.String())
	}
	if strings.Contains(r.logs.String(), "not_enrolled") {
		t.Fatal("the hub must not answer not_enrolled to an unverified caller")
	}
}

// An identity the hub does not know (the key file was lost or replaced) is
// answered with a bare "unauthenticated", the same as for a stranger: the agent
// must try to enroll it rather than retry a session forever.
func TestAgentWithLostIdentityEnrollsWhenTheWindowOpens(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	_, stop := r.start(r.config())
	eventually(t, 15*time.Second, "first enrollment", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	first := append(ed25519.PublicKey(nil), r.hub.PinnedKey(testNS, testDevice)...)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "the first session to close", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 0 })
	if err := os.RemoveAll(r.idDir); err != nil {
		t.Fatal(err)
	}
	r.hub.SetEnrollOpen(testNS, testDevice, false)

	_, stop2 := r.start(r.config())
	defer func() { _ = stop2() }()
	eventually(t, 15*time.Second, "refusals while the window is closed", func() bool {
		return strings.Count(r.logs.String(), `"reason":"enroll_closed"`) >= 2
	})
	if !strings.Contains(r.logs.String(), "trying to enroll it") {
		t.Fatalf("the agent did not react to the unauthenticated answer:\n%s", r.logs.String())
	}
	if len(r.hub.SessionIDs(api.KindDevice)) != 0 {
		t.Fatal("session without enrollment")
	}
	r.hub.ResetEnrollment(testNS, testDevice) // an admin opens a new window
	eventually(t, 15*time.Second, "enrollment of the new key", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	if r.hub.PinnedKey(testNS, testDevice).Equal(first) {
		t.Fatal("the old key is still pinned")
	}
}
