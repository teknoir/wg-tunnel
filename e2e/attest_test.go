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

// These tests drive the deprecated attestor sidecar (the SSH host key as the
// trusted key); devicekey_test.go covers the device key itself. The hub does not
// care which key signed: the trusted one activates (api.ActivatedByDeviceKey).
//
// With the device's SSH host key trusted, an enrollment attested by that key
// activates by itself: no admin approval, a user reaches the device, and the
// hub recorded how the identity was activated. Clearing the anchor cuts the
// session off, and the agent waits for an admin.
func TestAutoActivationByTrustedHostKey(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true, Attest: true})
	r.TrustHostKey()
	r.StartAgent()
	r.WaitDeviceUp(1)

	pol, _ := r.Policy.Get(e2erig.NS, e2erig.DeviceName)
	if pol.ApprovedFingerprint != "" {
		t.Fatal("test setup: nobody approved the identity")
	}
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.AttestedHostKey != r.HostKeyFingerprint || pin.ActivatedBy != api.ActivatedByDeviceKey || pin.ActivatedAt.IsZero() ||
		pin.Fingerprint != r.AgentFingerprint() {
		t.Fatalf("pin %+v, host key %s", pin, r.HostKeyFingerprint)
	}
	if len(pin.AgentCapabilities) != 1 || pin.AgentCapabilities[0] != api.CapAttest {
		t.Fatalf("capabilities %v", pin.AgentCapabilities)
	}
	cli := r.MustClient(e2erig.AliceEmail)
	if err := e2erig.EchoVia(cli, "auto-activated", 20*time.Second); err != nil {
		t.Fatal(err)
	}

	// The admin removes the anchor: the device loses its session at once and
	// waits for manual approval.
	r.Policy.Update(e2erig.NS, e2erig.DeviceName, func(e *api.PolicyEntry) { e.TrustedHostKey = "" })
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })
	e2erig.Eventually(t, 15*time.Second, "the agent to wait for approval", func() bool {
		return r.AgentLogs.Count("waiting for admin approval of this device identity") >= 1
	})

	// A manual approval still brings it back.
	r.Policy.Approve(e2erig.NS, e2erig.DeviceName, r.AgentFingerprint())
	r.WaitDeviceUp(2)
	r.AssertLogHygiene()
}

// Clearing a compromised flag forces manual activation for that generation:
// the very same trusted host key does not activate the new identity, and an
// admin approval does. The next enrollment generation is automatic again.
func TestClearedFlagForcesManualActivation(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true, Attest: true})
	r.TrustHostKey()
	r.StartAgent()
	r.WaitDeviceUp(1)
	fp0 := r.AgentFingerprint()

	// compromised: sticky void; the agent rotates its identity and is refused
	// until device-controller opens a new window.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, compromised())
	e2erig.Eventually(t, 5*time.Second, "the device session to end", func() bool { d, _ := r.Hub.SessionCounts(); return d == 0 })
	e2erig.Eventually(t, 5*time.Second, "the pin to be voided", func() bool { return r.Identity.Entry(e2erig.NS, e2erig.DeviceName).Voided })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.NewClient(ctx, e2erig.AliceEmail)
	var we *wgclient.Error
	if !errors.As(err, &we) || we.Reason != api.ReasonDeviceRevoked {
		t.Fatalf("client: %v", err)
	}

	// The flag is cleared: device-controller opens generation 2 and forces
	// manual activation for it.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, enabled())
	r.Policy.Update(e2erig.NS, e2erig.DeviceName, func(e *api.PolicyEntry) {
		e.EnrollmentGeneration, e.EnrollmentEpoch, e.ApprovedFingerprint = 2, e2erig.Epoch2, ""
		e.ForceManualGeneration = 2
		e.EnrollUntil = time.Now().Add(time.Hour)
	})
	e2erig.Eventually(t, 20*time.Second, "the new identity to be pinned, attested, and waiting", func() bool {
		pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
		return pin.EnrollmentGeneration == 2 && pin.AttestedHostKey == r.HostKeyFingerprint &&
			r.AgentLogs.Count("waiting for admin approval of this device identity") >= 1
	})
	if r.AgentFingerprint() == fp0 {
		t.Fatal("the old identity came back")
	}
	time.Sleep(time.Second)
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("a forced-manual generation activated by itself")
	}
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.ActivatedBy != "" {
		t.Fatalf("activation recorded: %+v", pin)
	}

	// Admin approval works.
	r.Policy.Approve(e2erig.NS, e2erig.DeviceName, r.AgentFingerprint())
	r.WaitDeviceUp(2)
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.ActivatedBy != api.ActivatedByApproval {
		t.Fatalf("pin %+v", pin)
	}

	// Generation 3 with the force cleared (ForceManualGeneration < generation):
	// the anchor activates the next identity by itself again, once the key that
	// was in use when the device was flagged is rotated: until then the hub
	// refuses it (its pin was voided for the flag).
	r.RotateHostKey()
	r.TrustHostKey()
	r.Policy.Update(e2erig.NS, e2erig.DeviceName, func(e *api.PolicyEntry) {
		e.EnrollmentGeneration, e.EnrollmentEpoch, e.ApprovedFingerprint = 3, "e2e-epoch-3", ""
		e.EnrollUntil = time.Now().Add(time.Hour)
	})
	r.WaitDeviceUp(3)
	if pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName); pin.EnrollmentGeneration != 3 || pin.ActivatedBy != api.ActivatedByDeviceKey {
		t.Fatalf("generation 3 pin %+v", pin)
	}
}

// A device whose host key is not the trusted one is not activated, and the
// agent's log says what to compare.
func TestWrongTrustAnchorStaysPending(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{ManualApproval: true, Attest: true})
	r.Policy.Update(e2erig.NS, e2erig.DeviceName, func(e *api.PolicyEntry) { e.TrustedHostKey = "SHA256:" + strings.Repeat("A", 43) })
	r.StartAgent()
	e2erig.Eventually(t, 20*time.Second, "the agent to wait for approval", func() bool {
		return r.AgentLogs.Count("waiting for admin approval of this device identity") >= 2
	})
	pin := r.Identity.Entry(e2erig.NS, e2erig.DeviceName)
	if pin.AttestedHostKey != r.HostKeyFingerprint || pin.ActivatedBy != "" {
		t.Fatalf("pin %+v", pin)
	}
	if d, _ := r.Hub.SessionCounts(); d != 0 {
		t.Fatal("session despite wrong anchor")
	}
}
