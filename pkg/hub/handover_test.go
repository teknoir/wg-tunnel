package hub

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// TestHandoverNoticeBeforePeerRemoval: Handover tells the control-v1 device
// first (hub_handover, for its session) and removes its peer only after the
// agent answered; the hub is closed afterwards.
func TestHandoverNoticeBeforePeerRemoval(t *testing.T) {
	// The agent holds the request for 300 ms: the peer must outlive that
	// although the flush grace is only 20 ms.
	agent := &svcAgent{revokeHang: 300 * time.Millisecond}
	w, rec := noticeRig(t, capsFull, agent, 20*time.Millisecond)
	w.h.SetLeading(false)

	if err := w.h.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := agent.revokes()
	if len(got) != 1 || got[0].Reason != api.ReasonHubHandover || got[0].SessionID != w.devSess.SessionID {
		t.Fatalf("notices = %+v, want one %q for session %s", got, api.ReasonHubHandover, w.devSess.SessionID)
	}
	removed, ok := rec.firstRemoval()
	if !ok {
		t.Fatal("the peer was never removed")
	}
	if !got[0].at.Before(removed) {
		t.Fatalf("peer removed (%v) before the notice arrived (%v)", removed, got[0].at)
	}
	if d := removed.Sub(got[0].at); d < 250*time.Millisecond {
		t.Fatalf("the peer was removed %v after the notice, before the agent answered it", d)
	}
	if w.h.DeviceOnline(testNS, testDevice) {
		t.Fatal("device session still registered after Handover")
	}
}

// TestHandoverOnlyTellsControlAgents: a phase-1 agent has no control listener
// and gets no notice (it finds out by itself); the hub still closes.
func TestHandoverOnlyTellsControlAgents(t *testing.T) {
	agent := &svcAgent{}
	w, rec := noticeRig(t, []string{api.CapServices}, agent, 20*time.Millisecond)
	if err := w.h.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(agent.revokes()); n != 0 {
		t.Fatalf("%d notices to an agent without control", n)
	}
	if _, ok := rec.firstRemoval(); !ok {
		t.Fatal("the peer was not removed")
	}
}

// TestHandoverIsBounded: an agent that never answers delays the handover by
// the one second notice timeout and no more; a context that ends earlier
// ends it earlier. Either way the hub is closed.
func TestHandoverIsBounded(t *testing.T) {
	t.Run("stuck agent", func(t *testing.T) {
		agent := &svcAgent{revokeHang: time.Minute}
		w, rec := noticeRig(t, capsFull, agent, 20*time.Millisecond)
		t0 := time.Now()
		if err := w.h.Handover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(t0); d > revokeNoticeTimeout+2*time.Second {
			t.Fatalf("handover took %v with a stuck agent", d)
		}
		if _, ok := rec.firstRemoval(); !ok || w.h.DeviceOnline(testNS, testDevice) {
			t.Fatal("hub not closed")
		}
	})
	t.Run("context ends", func(t *testing.T) {
		agent := &svcAgent{revokeHang: time.Minute}
		w, _ := noticeRig(t, capsFull, agent, 20*time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		t0 := time.Now()
		if err := w.h.Handover(ctx); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(t0); d > 1500*time.Millisecond {
			t.Fatalf("handover took %v with a 200ms budget", d)
		}
		if w.h.DeviceOnline(testNS, testDevice) {
			t.Fatal("hub not closed")
		}
	})
}

// TestHandoverNoticesAreCounted: delivered and failed notices show in the metric.
func TestHandoverNoticesAreCounted(t *testing.T) {
	agent := &svcAgent{revokeStatus: 500}
	w, _ := noticeRig(t, capsFull, agent, 20*time.Millisecond)
	if err := w.h.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := counterValue(t, w.h.met.handoverNotices, "failed"); got != 1 {
		t.Fatalf("failed notices = %v, want 1", got)
	}
	if got := counterValue(t, w.h.met.handoverNotices, "delivered"); got != 0 {
		t.Fatalf("delivered notices = %v, want 0", got)
	}
}

// legacyAgent is an agent built before hub_handover existed: it answers that
// reason with 400, as the wg-agent pinned on staging does.
func legacyAgent() *svcAgent {
	return &svcAgent{revokeRefuse: map[string]bool{api.ReasonHubHandover: true}}
}

// TestHandoverFallsBackForAnAgentThatRefusesHubHandover: the agent answers 400
// to hub_handover, so the hub sends a second notice with a reason the agent
// accepts, before the peer is removed, and counts it as delivered_legacy.
func TestHandoverFallsBackForAnAgentThatRefusesHubHandover(t *testing.T) {
	agent := legacyAgent()
	w, rec := noticeRig(t, capsFull, agent, 20*time.Millisecond)
	w.h.SetLeading(false)
	if err := w.h.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := agent.revokes()
	if len(got) != 2 || got[0].Reason != api.ReasonHubHandover || got[1].Reason != handoverFallbackReason {
		t.Fatalf("notices = %+v, want hub_handover then %q", got, handoverFallbackReason)
	}
	for _, n := range got {
		if n.SessionID != w.devSess.SessionID {
			t.Fatalf("notice for session %q, want %q", n.SessionID, w.devSess.SessionID)
		}
	}
	removed, ok := rec.firstRemoval()
	if !ok || !got[1].at.Before(removed) {
		t.Fatalf("the peer was removed (%v, %v) before the fallback notice (%v)", removed, ok, got[1].at)
	}
	if v := counterValue(t, w.h.met.handoverNotices, "delivered_legacy"); v != 1 {
		t.Fatalf("delivered_legacy = %v, want 1", v)
	}
	if v := counterValue(t, w.h.met.handoverNotices, "failed") + counterValue(t, w.h.met.handoverNotices, "delivered"); v != 0 {
		t.Fatalf("failed+delivered = %v, want 0", v)
	}
}

// TestHandoverFallbackThatFailsIsCounted: an agent that refuses both reasons
// counts as failed, and only one fallback is tried.
func TestHandoverFallbackThatFailsIsCounted(t *testing.T) {
	agent := &svcAgent{revokeRefuse: map[string]bool{api.ReasonHubHandover: true, handoverFallbackReason: true}}
	w, _ := noticeRig(t, capsFull, agent, 20*time.Millisecond)
	if err := w.h.Handover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(agent.revokes()); n != 2 {
		t.Fatalf("%d notices, want 2", n)
	}
	if v := counterValue(t, w.h.met.handoverNotices, "failed"); v != 1 {
		t.Fatalf("failed = %v, want 1", v)
	}
}

// TestHandoverNoFallbackForOtherFailures: a 500 or 409 is not a legacy agent;
// no second notice goes out.
func TestHandoverNoFallbackForOtherFailures(t *testing.T) {
	for _, st := range []int{http.StatusInternalServerError, http.StatusConflict} {
		agent := &svcAgent{revokeStatus: st}
		w, _ := noticeRig(t, capsFull, agent, 20*time.Millisecond)
		if err := w.h.Handover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if n := len(agent.revokes()); n != 1 {
			t.Fatalf("status %d: %d notices, want 1", st, n)
		}
	}
}
