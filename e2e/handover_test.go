package e2e_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// handoverRig is a rig in which only the hub's handover notice can make the
// agent move quickly: renewals and the dead-tunnel limit are a minute away. The
// agent's back-off is 1-2 s after the notice (Min 1 s; its start-up attempt that
// waited for the approval counts as one failure, so the delay is Min*2 with jitter).
func handoverRig(t *testing.T) *e2erig.Rig {
	t.Helper()
	return e2erig.New(t, e2erig.Options{
		RenewAfter:   time.Minute,
		DeadAfter:    time.Minute,
		AgentBackoff: agent.Backoff{Min: time.Second, Max: 4 * time.Second, Stable: time.Minute},
	})
}

// A planned handover from hub A to hub B (the Service already points at B):
// the agent is told, connects again and is on B within a few seconds although
// its renewals and its dead-tunnel limit are a minute away. A client session on
// B reaches the device afterwards, and the old hub holds nothing.
func TestHandoverBringsTheAgentBackOnTheNewHub(t *testing.T) {
	t.Parallel()
	r := handoverRig(t)
	r.StartAgent()
	r.WaitDeviceUp(1)
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "before the handover", 20*time.Second); err != nil {
		t.Fatal(err)
	}

	a := r.ReplaceHub(nil) // the old hub, now a standby; r.Hub is the new one
	newHub := r.Hub

	t0 := time.Now()
	if err := a.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			t.Logf("agent log:\n%s\nhub log:\n%s", r.AgentLogs.String(), r.HubLogs.String())
		}
	}()
	e2erig.Eventually(t, 5*time.Second, "the agent to be on the new hub", func() bool {
		d, _ := newHub.SessionCounts()
		return d == 1 && r.AgentLogs.Count(`"msg":"exposing port"`) >= 2
	})
	took := time.Since(t0)
	t.Logf("the agent was on hub B %v after the handover began", took.Round(time.Millisecond))
	if d, c := a.SessionCounts(); d != 0 || c != 0 {
		t.Fatalf("the old hub still holds %d device and %d client sessions", d, c)
	}
	if n := r.AgentLogs.Count("the hub is ending this session"); n != 1 {
		t.Fatalf("%d notices logged by the agent, want 1", n)
	}
	if n := r.AgentLogs.Count(`"reason":"hub_handover"`); n == 0 {
		t.Fatal("the agent did not see the hub_handover reason")
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "after the handover", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// The standby hub never creates a session, even for a caller that still finds
// it (a split brain): while A is the standby, a device session request that
// reaches A is refused with 503, and the agent that reaches B is unaffected.
func TestStandbyHubRefusesSessionsInTheRig(t *testing.T) {
	t.Parallel()
	r := handoverRig(t)
	a := r.Hub
	r.ReplaceHub(nil)
	if a.Leading() {
		t.Fatal("ReplaceHub left the old hub leading")
	}
	srv := a.Handler()
	for _, path := range []string{api.DeviceSessionPath, api.ClientSessionPath, api.DeviceEnrollPath} {
		rec := &recorder{header: http.Header{}}
		req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		srv.ServeHTTP(rec, req)
		if rec.code != http.StatusServiceUnavailable {
			t.Errorf("standby POST %s: %d, want 503", path, rec.code)
		}
	}
	r.StartAgent() // goes through the rig's URL, that is to hub B
	r.WaitDeviceUp(1)
	if d, _ := a.SessionCounts(); d != 0 {
		t.Fatalf("the standby holds %d device sessions", d)
	}
	if d, _ := r.Hub.SessionCounts(); d != 1 {
		t.Fatalf("hub B holds %d device sessions, want 1", d)
	}
}

type recorder struct {
	header http.Header
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }
