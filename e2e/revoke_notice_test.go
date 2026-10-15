package e2e_test

import (
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// slowRig is a rig in which only the hub's revoke notice can make the agent
// react quickly: renewals and the dead-tunnel limit are a minute away and the
// agent's back-off is 30 s. Without the notice every test below takes
// a minute (or fails).
func slowRig(t *testing.T) *e2erig.Rig {
	t.Helper()
	return e2erig.New(t, e2erig.Options{
		ManualApproval: true, // nobody approves: the trusted device key activates the identity
		RenewAfter:     time.Minute,
		DeadAfter:      time.Minute,
		AgentBackoff:   agent.Backoff{Min: 30 * time.Second, Max: 30 * time.Second, Stable: time.Hour},
	})
}

// Zero touch: an admin presses "Reset enrollment" (new epoch and generation, a
// fresh window, the approval gone). The device holds the trusted device key,
// so it must come back by itself, within seconds, with a new identity.
func TestResetEnrollmentReactivatesWithinAFewSeconds(t *testing.T) {
	t.Parallel()
	r := slowRig(t)
	fp := r.DeliverDeviceKey("serial-1")
	r.TrustDeviceKey(fp)
	r.CloseEnrollmentWindow()
	r.StartAgent()
	r.WaitDeviceUp(1)
	fp0 := r.AgentFingerprint()
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("test setup: pin %+v", pin)
	}

	t0 := time.Now()
	r.Policy.Update(e2erig.NS, e2erig.DeviceName, func(e *api.PolicyEntry) {
		e.EnrollmentGeneration, e.EnrollmentEpoch, e.ApprovedFingerprint = 2, e2erig.Epoch2, ""
		e.EnrollUntil = time.Now().Add(time.Hour)
	})
	e2erig.Eventually(t, 8*time.Second, "the device to be active again with a new identity", func() bool {
		d, _ := r.Hub.SessionCounts()
		pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
		return d == 1 && r.AgentLogs.Count(`"msg":"exposing port"`) >= 2 && pin.EnrollmentGeneration == 2 && pin.ActivatedBy == api.ActivatedByDeviceKey
	})
	took := time.Since(t0)
	t.Logf("re-activated %v after the reset", took.Round(time.Millisecond))
	if took > 5*time.Second {
		t.Fatalf("re-activation took %v, want a few seconds", took)
	}
	if r.AgentFingerprint() == fp0 {
		t.Fatal("the agent kept its old identity")
	}
	if n := r.AgentLogs.Count("the hub is ending this session"); n != 1 {
		t.Fatalf("%d notices logged by the agent, want 1", n)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "after the reset", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// Marking the device compromised: the agent learns of it at once (the hub's
// notice), not when its renewal fails a minute later, and goes to its normal
// denial path.
func TestMarkCompromisedEndsTheDeviceSessionAtOnce(t *testing.T) {
	t.Parallel()
	r := slowRig(t)
	fp := r.DeliverDeviceKey("serial-1")
	r.TrustDeviceKey(fp)
	r.StartAgent()
	r.WaitDeviceUp(1)
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "before the flag", 20*time.Second); err != nil {
		t.Fatal(err)
	}

	t0 := time.Now()
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	e2erig.Eventually(t, 3*time.Second, "the agent to end its session on the hub's notice", func() bool {
		return r.AgentLogs.Count("the hub is ending this session") == 1 && r.AgentLogs.Count(`"reason":"device_revoked"`) > 0
	})
	t.Logf("the agent ended its session %v after the flag", time.Since(t0).Round(time.Millisecond))
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatalf("%d device sessions left at the hub", d)
	}
	// The denial path, not a re-enrollment: no new identity, no new session.
	if strings.Contains(r.AgentLogs.String(), "enrollment was reset") {
		t.Fatal("the agent rotated its identity on a compromised flag")
	}
	r.AssertLogHygiene()
}
