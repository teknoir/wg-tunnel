package hub

import (
	"net/http"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// noticeRig is a hub with a services-v1 agent that takes the control RPC and a
// tunnel that records when the device peer is removed.
func noticeRig(t *testing.T, caps []string, agent *svcAgent, grace time.Duration) (*wgRig, *recTunnel) {
	t.Helper()
	var rec *recTunnel
	w := newSvcRigHook(t, caps, nil, agent, func(h *Hub) {
		rec = &recTunnel{Tunnel: h.tunnel}
		h.tunnel = rec
	}, func(c *Config) { c.FlushGrace = grace })
	return w, rec
}

func resetEnrollment(w *wgRig) {
	p := w.policy
	p.EnrollmentGeneration++
	w.setPolicy(p)
}

func flagCompromised(w *wgRig) {
	w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
}

// TestRevokeNoticeBeforePeerRemoval: every revocation of a device session that
// has a control listener sends the notice first, with the right reason and
// session, and the peer goes only after the notice was answered.
func TestRevokeNoticeBeforePeerRemoval(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		fire   func(*wgRig)
	}{
		{"enrollment reset", api.ReasonReenroll, resetEnrollment},
		{"flagged compromised", api.ReasonDeviceRevoked, flagCompromised},
		{"health check failed", api.ReasonDeviceRevoked, func(w *wgRig) {
			w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
		}},
		{"wireguard disabled", api.ReasonDeviceDisabled, func(w *wgRig) {
			w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "disabled"})
		}},
		{"identity approval withdrawn", api.ReasonPendingApproval, func(w *wgRig) {
			p := w.policy
			p.ApprovedFingerprint = ""
			w.setPolicy(p)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The agent holds the request for 300 ms: the peer must outlive that
			// although the flush grace is only 20 ms.
			agent := &svcAgent{revokeHang: 300 * time.Millisecond}
			w, rec := noticeRig(t, capsFull, agent, 20*time.Millisecond)
			t0 := time.Now()
			tc.fire(w)

			waitFor(t, "the revoke notice", func() bool { return len(agent.revokes()) > 0 })
			waitFor(t, "peer removal", func() bool { _, ok := rec.firstRemoval(); return ok })
			got := agent.revokes()
			if len(got) != 1 || got[0].Reason != tc.reason || got[0].SessionID != w.devSess.SessionID {
				t.Fatalf("notices = %+v, want one %q for session %s", got, tc.reason, w.devSess.SessionID)
			}
			removed, _ := rec.firstRemoval()
			if !got[0].at.Before(removed) {
				t.Fatalf("the peer was removed (%v) before the notice arrived (%v)", removed.Sub(t0), got[0].at.Sub(t0))
			}
			if d := removed.Sub(got[0].at); d < 250*time.Millisecond {
				t.Fatalf("the peer was removed %v after the notice arrived, before the agent answered it", d)
			}
			if w.h.DeviceOnline(testNS, testDevice) {
				t.Fatal("device session still registered")
			}
		})
	}
}

// TestRevokeNoticeFailureDoesNotBlockRevocation: a control listener that
// refuses, errs or never answers changes nothing about the revocation: the
// session is gone at once and the peer follows after at most the notice
// timeout.
func TestRevokeNoticeFailureDoesNotBlockRevocation(t *testing.T) {
	cases := []struct {
		name  string
		agent *svcAgent
	}{
		{"agent answers 500", &svcAgent{revokeStatus: http.StatusInternalServerError}},
		{"agent answers 409", &svcAgent{revokeStatus: http.StatusConflict}},
		{"agent never answers", &svcAgent{revokeHang: time.Minute}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, rec := noticeRig(t, capsFull, tc.agent, 20*time.Millisecond)
			t0 := time.Now()
			flagCompromised(w)
			waitFor(t, "device session ended", func() bool { return !w.h.DeviceOnline(testNS, testDevice) })
			if d := time.Since(t0); d > 500*time.Millisecond {
				t.Fatalf("revocation took %v", d)
			}
			waitFor(t, "peer removal", func() bool { _, ok := rec.firstRemoval(); return ok })
			removed, _ := rec.firstRemoval()
			if d := removed.Sub(t0); d > revokeNoticeTimeout+2*time.Second {
				t.Fatalf("peer removed only %v after the revocation", d)
			}
			if n := len(tc.agent.revokes()); n != 1 {
				t.Fatalf("%d notices, want 1", n)
			}
		})
	}
}

// TestNoRevokeNoticeWithoutControlOrForInternalReasons: a phase-1 agent (no
// control listener) and the log-only reasons end the session without a notice.
func TestNoRevokeNoticeWithoutControlOrForInternalReasons(t *testing.T) {
	t.Run("agent without control", func(t *testing.T) {
		agent := &svcAgent{}
		w, rec := noticeRig(t, []string{api.CapServices}, agent, 20*time.Millisecond)
		resetEnrollment(w)
		waitFor(t, "peer removal", func() bool { _, ok := rec.firstRemoval(); return ok })
		if n := len(agent.revokes()); n != 0 {
			t.Fatalf("%d notices to an agent without control", n)
		}
	})
	t.Run("ports changed", func(t *testing.T) {
		agent := &svcAgent{}
		w, rec := noticeRig(t, capsFull, agent, 20*time.Millisecond)
		p := w.policy
		p.AllowedPorts = []int{22}
		w.setPolicy(p)
		waitFor(t, "peer removal", func() bool { _, ok := rec.firstRemoval(); return ok })
		if n := len(agent.revokes()); n != 0 {
			t.Fatalf("%d notices for a ports change", n)
		}
	})
}
