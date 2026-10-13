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

// A pinned identity gets no session until an admin approves its fingerprint.
// The agent says so, stays enrolled, and comes up by itself once approved; the
// approval is revocable.
func TestUnapprovedIdentityGetsNoSessionUntilApproved(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	r.StartAgent()
	e2erig.Eventually(t, 20*time.Second, "the agent to wait for approval", func() bool {
		return r.AgentLogs.Count("waiting for admin approval of this device identity") >= 2
	})
	fp := r.AgentFingerprint()
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.Fingerprint != fp {
		t.Fatalf("pin %+v, agent fingerprint %s", pin, fp)
	}
	if !strings.Contains(r.AgentLogs.String(), `"fingerprint":"`+fp+`"`) {
		t.Fatal("the agent log does not show the fingerprint the admin must compare")
	}
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("an unapproved device has a session")
	}
	// Users see a device that is simply not there.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.NewClient(ctx, e2erig.AliceEmail)
	var we *wgclient.Error
	if !errors.As(err, &we) || we.Reason != api.ReasonDeviceOffline {
		t.Fatalf("client: %v", err)
	}

	// The admin approves the fingerprint the agent logged.
	r.Policy.Approve(e2erig.NS, e2erig.DeviceName, fp)
	r.WaitDeviceUp(1)
	if got := r.AgentFingerprint(); got != fp {
		t.Fatalf("the agent changed identity while waiting: %s -> %s", fp, got)
	}
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "approved", 20*time.Second); err != nil {
		t.Fatal(err)
	}

	// Withdrawing the approval cuts the device off at once.
	r.Policy.Approve(e2erig.NS, e2erig.DeviceName, "")
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })
	e2erig.Eventually(t, 10*time.Second, "the agent to wait again", func() bool {
		return r.AgentLogs.Count("waiting for admin approval of this device identity") >= 3
	})
}

// The hub path alone (device-controller down, never saw the flag) still makes
// a flagged device's identity void for good.
func TestFlagVoidsTheIdentityEvenIfTheControllerNeverSawIt(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)
	fp0 := r.AgentFingerprint()

	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })
	e2erig.Eventually(t, 5*time.Second, "the pin to be voided", func() bool { return r.Identity.Entry(e2erig.NS, e2erig.DeviceName).Voided })

	// The flag is cleared; the policy (epoch, generation, approval) never changed.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, enabled())
	e2erig.Eventually(t, 15*time.Second, "the agent to rotate its identity and be refused", func() bool {
		return r.AgentLogs.Count("enrollment was reset") > 0 && r.AgentLogs.Count(`"reason":"enroll_closed"`) > 0
	})
	time.Sleep(time.Second)
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("a flagged device came back without a new enrollment window")
	}

	// device-controller finally opens one: new epoch, new generation.
	p, _ := r.Policy.Get(e2erig.NS, e2erig.DeviceName)
	p.EnrollmentGeneration, p.EnrollmentEpoch, p.ApprovedFingerprint = 2, e2erig.Epoch2, ""
	p.EnrollUntil = time.Now().Add(time.Hour)
	r.Policy.Set(p)
	r.WaitDeviceUp(2)
	if r.AgentFingerprint() == fp0 {
		t.Fatal("the old identity came back")
	}
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.Voided || pin.EnrollmentEpoch != e2erig.Epoch2 {
		t.Fatalf("pin %+v", pin)
	}
}

// The production path of the flags: Device annotations -> flags watcher ->
// flags ConfigMap -> hub. Marking the device compromised still cuts it off
// within a second, and the hub needed no access to the Device at all.
func TestAnnotationReachesTheHubThroughTheFlagsWatcher(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{FlagsViaWatcher: true})
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
	r.SetDeviceAnnotations(map[string]string{api.AnnotationCompromised: "true"})
	select {
	case err := <-readErr:
		t.Logf("connection cut %v after the annotation: %v", time.Since(t0).Round(time.Millisecond), err)
	case <-time.After(2 * time.Second):
		t.Fatal("the connection survived 2s after the Device was annotated compromised")
	}
	e2erig.Eventually(t, 5*time.Second, "the pin to be voided", func() bool { return r.Identity.Entry(e2erig.NS, e2erig.DeviceName).Voided })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = r.NewClient(ctx, e2erig.AliceEmail)
	var we *wgclient.Error
	if !errors.As(err, &we) || we.Reason != api.ReasonDeviceRevoked {
		t.Fatalf("new client session: %v, want %s", err, api.ReasonDeviceRevoked)
	}
}
