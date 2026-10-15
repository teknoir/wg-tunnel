package e2e_test

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Zero touch (rev 3): a device that received a sealed device key over its MQTT
// config activates by itself, with the enrollment window long closed and
// nobody approving anything.
func TestZeroTouchActivationWithADeliveredDeviceKey(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	fp := r.DeliverDeviceKey("serial-1")
	r.TrustDeviceKey(fp)
	r.CloseEnrollmentWindow()
	r.StartAgent()
	r.WaitDeviceUp(1)

	pol, _ := r.Policy.Get(e2erig.NS, e2erig.DeviceName)
	if pol.ApprovedFingerprint != "" {
		t.Fatal("test setup: nobody approved the identity")
	}
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.AttestedHostKey != fp || pin.ActivatedBy != api.ActivatedByDeviceKey || pin.ActivatedAt.IsZero() ||
		pin.Fingerprint != r.AgentFingerprint() {
		t.Fatalf("pin %+v, device key %s", pin, fp)
	}
	if want := []string{api.CapAttest, api.CapDeviceKey}; !slices.Equal(pin.AgentCapabilities, want) {
		t.Fatalf("capabilities %v, want %v", pin.AgentCapabilities, want)
	}
	// The agent stored the key it opened; the envelope can go.
	if fi, err := os.Stat(r.IdentityDir + "/" + api.DeliveredDeviceKeyFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("delivered key: %v %v", fi, err)
	}
	r.RemoveEnvelope()
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "zero-touch", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// The bootstrap-installed key works the same, without any envelope.
func TestZeroTouchActivationWithABootstrapDeviceKey(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	fp := r.InstallBootstrapDeviceKey()
	r.TrustDeviceKey(fp)
	r.StartAgent()
	r.WaitDeviceUp(1)
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.AttestedHostKey != fp || pin.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v", pin)
	}
	if _, err := os.Stat(r.IdentityDir + "/" + api.DeliveredDeviceKeyFile); err == nil {
		t.Fatal("a bootstrap key must not be copied")
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "bootstrap key", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// The vd-wg-1 case: a pin that was attested by the SSH host key and waits for
// approval, with the enrollment window closed, activates when the agent
// attests the same identity with the device key.
func TestPendingHostKeyPinActivatesAfterReattestingWithTheDeviceKey(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true, Attest: true})
	r.StartAgent()
	e2erig.Eventually(t, 20*time.Second, "the pin to wait for approval", func() bool {
		pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
		return pin.AttestedHostKey == r.HostKeyFingerprint && r.AgentLogs.Count("waiting for admin approval of this device identity") >= 1
	})
	first := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	r.CloseEnrollmentWindow()

	// device-controller delivers a device key and trusts it.
	fp := r.DeliverDeviceKey("serial-1")
	r.TrustDeviceKey(fp)
	r.WaitDeviceUp(1)
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.AttestedHostKey != fp || pin.ActivatedBy != api.ActivatedByDeviceKey || pin.Fingerprint != first.Fingerprint || pin.Replacements != 0 {
		t.Fatalf("pin %+v, first %+v", pin, first)
	}
	if want := []string{api.CapAttest, api.CapDeviceKey}; !slices.Equal(pin.AgentCapabilities, want) {
		t.Fatalf("capabilities %v", pin.AgentCapabilities)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "re-attested", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// The rtx2000 case: an approved, connected device gets its first device key.
// The session stays up, the identity stays approved, and the hub records the
// key once the agent attested the same identity with it.
func TestApprovedPinStaysActiveWhenADeviceKeyIsFirstSet(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	r.StartAgent()
	r.ApproveAgent()
	r.WaitDeviceUp(1)
	before := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if before.ActivatedBy != api.ActivatedByApproval {
		t.Fatalf("pin %+v", before)
	}

	fp := r.DeliverDeviceKey("serial-1")
	r.TrustDeviceKey(fp)
	e2erig.Eventually(t, 20*time.Second, "the hub to record the device key", func() bool {
		return r.Identity.Entry(e2erig.NS, e2erig.DeviceName).AttestedHostKey == fp
	})
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.ActivatedBy != api.ActivatedByApproval || pin.Fingerprint != before.Fingerprint || !pin.ActivatedAt.Equal(before.ActivatedAt) {
		t.Fatalf("pin %+v, before %+v", pin, before)
	}
	// Never interrupted: still one session and the agent exposed its ports once.
	time.Sleep(time.Second)
	if d, _ := r.Hub.SessionCounts(); d != 1 {
		t.Fatalf("%d device sessions", d)
	}
	if n := r.AgentLogs.Count(`"msg":"exposing port"`); n != 1 {
		t.Fatalf("the agent exposed its ports %d times", n)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "approved and attested", 20*time.Second); err != nil {
		t.Fatal(err)
	}
}

// A device that lost its identity while it was offline (re-image) gets a new
// identity pinned when the device key proves it is the same device; the old
// fingerprint is voided and counted as a replacement.
func TestOfflineDeviceReplacesItsPinWithTheDeviceKey(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	fp := r.InstallBootstrapDeviceKey()
	r.TrustDeviceKey(fp)
	ag := r.StartAgent()
	r.WaitDeviceUp(1)
	old := r.AgentFingerprint()
	if err := ag.Stop(); err != nil {
		t.Fatal(err)
	}
	e2erig.Eventually(t, 10*time.Second, "the device to go offline", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })

	// Lost state: the identity directory is gone, the bootstrap key is not.
	if err := os.RemoveAll(r.IdentityDir); err != nil {
		t.Fatal(err)
	}
	r.CloseEnrollmentWindow()
	r.StartAgent()
	r.WaitDeviceUp(2)

	now := r.AgentFingerprint()
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if now == old || pin.Fingerprint != now || pin.Replacements != 1 || pin.LastReplacedFingerprint != old ||
		pin.LastReplacedAt.IsZero() || !slices.Contains(pin.VoidedFingerprints, old) ||
		pin.ActivatedBy != api.ActivatedByDeviceKey || pin.AttestedHostKey != fp {
		t.Fatalf("pin %+v, old %s, new %s", pin, old, now)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "replaced", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// Rotation: a new device key is delivered and trusted; the agent attests the
// same identity with it and is active again, in either order of events.
func TestRotatedDeviceKeyActivatesTheIdentityAgain(t *testing.T) {
	t.Parallel()
	for _, trustFirst := range []bool{true, false} {
		name := "key delivered, then trusted"
		if trustFirst {
			name = "key trusted, then delivered"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := e2erig.New(t, e2erig.Options{ManualApproval: true})
			first := r.DeliverDeviceKey("serial-1")
			r.TrustDeviceKey(first)
			r.StartAgent()
			r.WaitDeviceUp(1)
			identityFP := r.AgentFingerprint()

			var second string
			if trustFirst {
				second = r.DeliverDeviceKey("serial-2")
				// The policy changes before the envelope reaches the device.
				r.TrustDeviceKey(second)
			} else {
				second = r.DeliverDeviceKey("serial-2")
				time.Sleep(500 * time.Millisecond)
				r.TrustDeviceKey(second)
			}
			e2erig.Eventually(t, 30*time.Second, "the identity to be active by the new key", func() bool {
				pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
				d, _ := r.Hub.SessionCounts()
				return pin.AttestedHostKey == second && d == 1
			})
			pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
			if pin.Fingerprint != identityFP || r.AgentFingerprint() != identityFP || pin.Replacements != 0 {
				t.Fatalf("the identity changed: %+v", pin)
			}
			e2erig.Eventually(t, 20*time.Second, "a user to reach the device again", func() bool {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cli, err := r.NewClient(ctx, e2erig.AliceEmail)
				if err != nil {
					return false
				}
				defer func() { _ = cli.Close() }()
				return e2erig.EchoVia(cli, "rotated", 3*time.Second) == nil
			})
			r.AssertLogHygiene()
		})
	}
}

// The device holds the bootstrap key and a delivered one. The hub records the
// key it trusts when the delivered key arrives; then trust moves to the other
// key. The session ends, the identity is pending and the agent attests it
// again (the hub keeps one attestation per pin) until the new key is recorded.
func TestTrustMovingToAnotherHeldKeyActivatesTheIdentityAgain(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	boot := r.InstallBootstrapDeviceKey()
	r.TrustDeviceKey(boot)
	r.StartAgent()
	r.WaitDeviceUp(1)
	identityFP := r.AgentFingerprint()

	delivered := r.DeliverDeviceKey("serial-2")
	// The agent attests with both keys; the hub still trusts, and records, the bootstrap key.
	time.Sleep(time.Second)
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.AttestedHostKey != boot {
		t.Fatalf("pin %+v, want the trusted bootstrap key %s", pin, boot)
	}
	r.TrustDeviceKey(delivered)
	e2erig.Eventually(t, 30*time.Second, "the identity to be active by the delivered key", func() bool {
		pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
		d, _ := r.Hub.SessionCounts()
		return pin.AttestedHostKey == delivered && d == 1
	})
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.Fingerprint != identityFP || pin.Replacements != 0 {
		t.Fatalf("the identity changed: %+v", pin)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "moved", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}

// A device whose pin was replaced while it was away (another node, a re-image)
// comes back with its old identity. The hub voided that identity; the device,
// which proves itself with the device key, starts over with a new one instead
// of retrying a refused enrollment for ever, and is no squatter on the console.
func TestReplacedIdentityComesBackAndStartsOver(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true})
	fp := r.InstallBootstrapDeviceKey()
	r.TrustDeviceKey(fp)
	offline := func(ag *e2erig.Agent) {
		t.Helper()
		if err := ag.Stop(); err != nil {
			t.Fatal(err)
		}
		e2erig.Eventually(t, 10*time.Second, "the device to go offline", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })
	}
	ag := r.StartAgent()
	r.WaitDeviceUp(1)
	first, firstDir := r.AgentFingerprint(), r.IdentityDir
	offline(ag)

	// The pod runs on another node with state of its own and replaces the pin.
	r.IdentityDir = t.TempDir() + "/node-b"
	r.CloseEnrollmentWindow()
	ag = r.StartAgent()
	r.WaitDeviceUp(2)
	second := r.AgentFingerprint()
	offline(ag)

	// ... and moves back to the first node.
	r.IdentityDir = firstDir
	r.StartAgent()
	r.WaitDeviceUp(3)
	third := r.AgentFingerprint()
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if third == first || third == second || pin.Fingerprint != third || pin.Replacements != 2 || pin.Conflicts != 0 ||
		!slices.Contains(pin.VoidedFingerprints, first) || !slices.Contains(pin.VoidedFingerprints, second) ||
		pin.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("pin %+v, identities %s %s %s", pin, first, second, third)
	}
	if err := e2erig.EchoVia(r.MustClient(e2erig.AliceEmail), "back", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	r.AssertLogHygiene()
}
