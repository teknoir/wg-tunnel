package agent

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

func revokeRig(t *testing.T) (*controlServer, chan error) {
	t.Helper()
	c, _, _ := controlRig(t)
	c.revokeGrace = time.Millisecond // httptest requests never see a client close
	ended := make(chan error, 4)
	c.revoke = &revokeTarget{sessionID: "s7", end: func(err error) { ended <- err }}
	return c, ended
}

func TestControlRevoke(t *testing.T) {
	hub := api.HubAddress + ":51000"
	c, ended := revokeRig(t)

	for _, tc := range []struct {
		name   string
		remote string
		body   any
		want   int
	}{
		{"not the hub", "100.96.0.9:1", api.RevokeNotice{Reason: api.ReasonReenroll, SessionID: "s7"}, http.StatusForbidden},
		{"another session", hub, api.RevokeNotice{Reason: api.ReasonReenroll, SessionID: "s8"}, http.StatusConflict},
		{"no session", hub, api.RevokeNotice{Reason: api.ReasonReenroll}, http.StatusConflict},
		{"unknown reason", hub, api.RevokeNotice{Reason: "rate_limited", SessionID: "s7"}, http.StatusBadRequest},
		{"no reason", hub, api.RevokeNotice{SessionID: "s7"}, http.StatusBadRequest},
		{"malformed", hub, "{", http.StatusBadRequest},
	} {
		if rec := post(t, c, api.ControlRevokePath, tc.remote, tc.body); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	select {
	case err := <-ended:
		t.Fatalf("a refused notice ended the session: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	req := post(t, c, api.ControlRevokePath, hub, api.RevokeNotice{Reason: api.ReasonDeviceRevoked, SessionID: "s7", Detail: "flagged\nforged line"})
	if req.Code != http.StatusNoContent {
		t.Fatalf("valid notice: %d %s", req.Code, req.Body)
	}
	select {
	case err := <-ended:
		if wgclient.ReasonOf(err) != api.ReasonDeviceRevoked {
			t.Fatalf("session ended with %v, want reason %s", err, api.ReasonDeviceRevoked)
		}
		var he *wgclient.Error
		if !errors.As(err, &he) || !he.Denial() || strings.ContainsAny(he.Message, "\n\r") {
			t.Fatalf("not a clean denial: %#v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a valid notice did not end the session")
	}

	// A control server without a session (not serving yet) answers 409.
	c2, _, _ := controlRig(t)
	if rec := post(t, c2, api.ControlRevokePath, hub, api.RevokeNotice{Reason: api.ReasonReenroll, SessionID: "s7"}); rec.Code != http.StatusConflict {
		t.Fatalf("no session to end: %d", rec.Code)
	}
}

// A notice records its reason on the session before the grace wait, so that
// a renewal failing inside the window (which ends the session first) cannot
// hide the reenroll reason from skipBackoff.
func TestRevokeNoticeRecordsItsCauseBeforeTheGraceWait(t *testing.T) {
	c, _ := revokeRig(t)
	c.revokeGrace = 300 * time.Millisecond
	cause := make(chan error, 1)
	c.revoke.setCause = func(err error) { cause <- err }
	hub := api.HubAddress + ":1"
	done := make(chan struct{})
	go func() {
		defer close(done)
		post(t, c, api.ControlRevokePath, hub, api.RevokeNotice{Reason: api.ReasonReenroll, SessionID: "s7"})
	}()
	select {
	case err := <-cause:
		select {
		case <-done:
			t.Fatal("the cause was recorded only after the grace wait")
		default:
		}
		if wgclient.ReasonOf(err) != api.ReasonReenroll {
			t.Fatalf("cause %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no cause recorded")
	}
	<-done
}

func TestSkipBackoffOnlyOnceForAReenrollNotice(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	a, err := New(r.config())
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		slept []time.Duration
	)
	a.sleep = func(_ context.Context, d time.Duration) { mu.Lock(); slept = append(slept, d); mu.Unlock() }
	a.rnd = func() float64 { return 1 }
	ctx := ctxT(t)
	notice := func(reason string) error {
		return fmt.Errorf("serve: %w", &noticeError{err: wgclient.Revoked(reason, "")})
	}

	if a.skipBackoff(ctx, errors.New("plain failure")) || a.skipBackoff(ctx, nil) {
		t.Fatal("an ordinary failure skipped the back-off")
	}
	if a.skipBackoff(ctx, notice(api.ReasonDeviceRevoked)) {
		t.Fatal("a flag notice skipped the back-off")
	}
	if !a.skipBackoff(ctx, notice(api.ReasonReenroll)) {
		t.Fatal("a reenroll notice did not skip the back-off")
	}
	mu.Lock()
	if len(slept) != 1 || slept[0] < 100*time.Millisecond || slept[0] > 300*time.Millisecond {
		t.Fatalf("pause before the immediate attempt = %v, want 100-300 ms", slept)
	}
	mu.Unlock()
	// A hub that keeps sending notices gets the normal back-off.
	if a.skipBackoff(ctx, notice(api.ReasonReenroll)) {
		t.Fatal("a second notice within the cooldown skipped the back-off again")
	}
	a.mu.Lock()
	a.lastImmediate = time.Now().Add(-noticeCooldown - time.Second)
	a.mu.Unlock()
	if !a.skipBackoff(ctx, notice(api.ReasonReenroll)) {
		t.Fatal("a notice after the cooldown was ignored")
	}
}

// The session must not be torn down before the hub has the answer to the
// notice: the answer travels through the very tunnel being closed, and a hub
// that never gets it reports the notice as failed after its timeout.
func TestRevokeNoticeEndsSessionOnlyAfterTheHubTookTheAnswer(t *testing.T) {
	c, ended := revokeRig(t)
	c.revokeGrace = 10 * time.Second // the client closing must be what ends the wait
	c.hubAddr = netip.MustParseAddr("127.0.0.1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	c.Serve(ctx, ln, &wg)
	defer func() { cancel(); wg.Wait() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := `{"reason":"reenroll","sessionId":"s7"}`
	_, _ = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", api.ControlRevokePath, len(body), body)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", resp.StatusCode)
	}
	select {
	case err := <-ended:
		t.Fatalf("the session was ended while the hub still held the connection open: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	_ = conn.Close() // the hub has the answer
	select {
	case err := <-ended:
		if wgclient.ReasonOf(err) != api.ReasonReenroll {
			t.Fatalf("ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not ended after the hub closed the connection")
	}
}

// TestRevokeNoticeReenrollsWithinASecond is the zero-touch requirement: the
// hub resets enrollment and tells the agent; the agent drops the session,
// generates a new identity and enrolls again at once, instead of waiting for a
// renewal to fail.
func TestRevokeNoticeReenrollsWithinASecond(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Hour, TTL: 2 * time.Hour})
	cfg := r.config()
	cfg.Backoff = Backoff{Min: time.Minute, Max: time.Minute, Stable: time.Hour} // a back-off would show
	_, stop := r.start(cfg)
	defer func() { _ = stop() }()
	eventually(t, 15*time.Second, "first session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	r.waitTunnelUp(t, 1)
	// The control listener comes up right after the tunnel.
	eventually(t, 5*time.Second, "control listener", func() bool {
		return strings.Contains(r.logs.String(), `"serving services"`)
	})
	first := append(ed25519.PublicKey(nil), r.hub.PinnedKey(testNS, testDevice)...)
	old := r.hub.SessionIDs(api.KindDevice)[0]

	r.hub.ResetEnrollment(testNS, testDevice)
	t0 := time.Now()
	if err := r.hub.RevokeDevice(testNS, testDevice, api.ReasonReenroll); err != nil {
		t.Fatalf("notice: %v", err)
	}
	eventually(t, time.Second, "a new identity enrolled and a new session within 1 s", func() bool {
		ids := r.hub.SessionIDs(api.KindDevice)
		return r.hub.Enrollments(testNS, testDevice) == 2 && len(ids) == 1 && ids[0] != old
	})
	t.Logf("re-enrolled and re-activated %v after the notice", time.Since(t0).Round(time.Millisecond))
	if r.hub.PinnedKey(testNS, testDevice).Equal(first) {
		t.Fatal("the agent enrolled the SAME identity again")
	}
	if !strings.Contains(r.logs.String(), "the hub is ending this session") {
		t.Fatal("no log line for the notice")
	}
}

// A notice for another session, or for a reason the agent does not know, must
// leave the session alone.
func TestRevokeNoticeForAnotherSessionIsIgnored(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Hour, TTL: 2 * time.Hour})
	_, stop := r.start(r.config())
	defer func() { _ = stop() }()
	eventually(t, 15*time.Second, "first session", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	r.waitTunnelUp(t, 1)
	id := r.hub.SessionIDs(api.KindDevice)[0]
	var status int
	eventually(t, 5*time.Second, "control listener", func() bool {
		var err error
		status, err = r.hub.SendRevokeNotice(testNS, testDevice, api.RevokeNotice{Reason: api.ReasonReenroll, SessionID: "not-" + id})
		return err == nil
	})
	if status != http.StatusConflict {
		t.Fatalf("status %d, want 409", status)
	}
	if st, err := r.hub.SendRevokeNotice(testNS, testDevice, api.RevokeNotice{Reason: "made_up", SessionID: id}); err != nil || st != http.StatusBadRequest {
		t.Fatalf("unknown reason: %d %v", st, err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := r.hub.SessionIDs(api.KindDevice); len(got) != 1 || got[0] != id {
		t.Fatalf("sessions %v, want [%s]", got, id)
	}
	if r.hub.Enrollments(testNS, testDevice) != 1 {
		t.Fatal("the agent enrolled again")
	}
}
