package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/devicekey"
)

// dkRig is an agent rig with a device key file, an envelope file and a fast
// key poll.
type dkRig struct {
	*rig
	keyFile  string
	envelope string
}

func newDKRig(t *testing.T, ho fakehub.Options) *dkRig {
	t.Helper()
	ho.Attest = true
	d := &dkRig{rig: newRig(t, ho)}
	d.keyFile = filepath.Join(d.dir, "ztna_device_key")
	d.envelope = filepath.Join(d.dir, "envelope", api.DeviceKeyEnvelopeKey)
	return d
}

func (d *dkRig) config() Config {
	c := d.rig.config()
	c.DeviceKeyFile, c.DeviceKeyEnvelope = d.keyFile, d.envelope
	c.DeviceKeyPoll = 50 * time.Millisecond
	c.ReattestInterval = 100 * time.Millisecond
	return c
}

// bootstrapKey installs a new key as the bootstrap device key and returns its fingerprint.
func (d *dkRig) bootstrapKey(t *testing.T) string {
	t.Helper()
	priv, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := devicekey.MarshalOpenSSH(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(d.keyFile) // the file is read-only
	if err := os.WriteFile(d.keyFile, b, 0o440); err != nil {
		t.Fatal(err)
	}
	return fingerprintOf(t, priv)
}

// deliver plays device-controller: it seals a new key to the device's RSA key
// and writes the envelope the way the kubelet projects the ConfigMap.
func (d *dkRig) deliver(t *testing.T, serial string) string {
	t.Helper()
	return d.deliverTo(t, testNS, testDevice, serial)
}

func (d *dkRig) deliverTo(t *testing.T, ns, dev, serial string) string {
	t.Helper()
	priv, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, rsaPub := deviceRSA(t)
	env, err := devicekey.Seal(rsaPub, ns, dev, serial, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	if err := os.MkdirAll(filepath.Dir(d.envelope), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := d.envelope + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, d.envelope); err != nil {
		t.Fatal(err)
	}
	return env.Fingerprint
}

func fingerprintOf(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	fp, err := devicekey.Fingerprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func (d *dkRig) deliveredFile() string { return filepath.Join(d.idDir, api.DeliveredDeviceKeyFile) }

// The bootstrap key signs in-process: no exchange directory, no sidecar, and
// the agent advertises attest-v1 and device-key-v1.
func TestBootstrapDeviceKeySignsInProcess(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	fp := d.bootstrapKey(t)
	_, stop := d.start(d.config())
	eventually(t, 20*time.Second, "attested enrollment and session", func() bool {
		return d.hub.PinnedKey(testNS, testDevice) != nil && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
	got := d.hub.Attestation(testNS, testDevice)
	if got.HostKey != fp || !slices.Equal(got.Keys, []string{fp}) || got.Challenges != 1 ||
		!slices.Equal(got.Capabilities, []string{api.CapAttest, api.CapDeviceKey}) {
		t.Fatalf("hub recorded %+v, want device key %s", got, fp)
	}
	if caps := d.hub.SessionCapabilities(testNS, testDevice); !slices.Equal(caps, []string{api.CapServices, api.CapControl, api.CapAttest, api.CapDeviceKey}) {
		t.Fatalf("session capabilities %v", caps)
	}
	// No sidecar: nothing is published for it and the state directory is private.
	if _, err := os.Stat(filepath.Join(d.idDir, "identity.pub")); err == nil {
		t.Error("identity.pub is only written for the deprecated attestor")
	}
	if fi, _ := os.Stat(d.idDir); fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, want 0700", fi.Mode().Perm())
	}
	if _, err := os.Stat(d.deliveredFile()); err == nil {
		t.Error("a bootstrap key must not be copied into the state directory")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	assertNoKeyMaterial(t, d.logs.String())
	if !strings.Contains(d.logs.String(), fp) {
		t.Error("the device key fingerprint should be logged")
	}
}

func assertNoKeyMaterial(t *testing.T, logs string) {
	t.Helper()
	if strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "SSHSIG") || strings.Contains(logs, "ciphertext") {
		t.Errorf("logs leak key or signature material")
	}
}

// An envelope is opened with the device's RSA key, stored 0600 in the identity
// directory in OpenSSH format, and its key attests the enrollment.
func TestEnvelopeIsOpenedStoredAndAttests(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	fp := d.deliver(t, "serial-1")
	_, stop := d.start(d.config())
	eventually(t, 20*time.Second, "attested enrollment and session", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == fp && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
	fi, err := os.Stat(d.deliveredFile())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("delivered key file: %v %v", fi, err)
	}
	b, _ := os.ReadFile(d.deliveredFile())
	priv, err := devicekey.ParseOpenSSH(b)
	if err != nil || fingerprintOf(t, priv) != fp {
		t.Fatalf("stored key: %v", err)
	}
	if !strings.Contains(string(b), "OPENSSH PRIVATE KEY") {
		t.Error("not stored in OpenSSH format")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	assertNoKeyMaterial(t, d.logs.String())

	// A restart without the envelope keeps using the stored key.
	if err := os.Remove(d.envelope); err != nil {
		t.Fatal(err)
	}
	d.hub.ResetEnrollment(testNS, testDevice)
	d.hub.SetEnrollOpen(testNS, testDevice, true)
	_, stop2 := d.start(d.config())
	defer func() { _ = stop2() }()
	eventually(t, 20*time.Second, "re-enrollment with the stored key", func() bool {
		return d.hub.Enrollments(testNS, testDevice) == 2 && d.hub.Attestation(testNS, testDevice).HostKey == fp
	})
}

// The agent signs with every key it holds, once each, at most two.
func TestSignsWithEveryDeviceKey(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	boot := d.bootstrapKey(t)
	delivered := d.deliver(t, "serial-1")
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment", func() bool { return len(d.hub.SessionIDs(api.KindDevice)) == 1 })
	got := d.hub.Attestation(testNS, testDevice)
	if !slices.Equal(got.Keys, []string{boot, delivered}) || got.Challenges != 2 {
		t.Fatalf("hub recorded %+v, want %s and %s", got, boot, delivered)
	}
}

// The same key as bootstrap file and as envelope signs once.
func TestSameKeyTwiceSignsOnce(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	priv, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := devicekey.MarshalOpenSSH(priv)
	if err := os.WriteFile(d.keyFile, b, 0o440); err != nil {
		t.Fatal(err)
	}
	_, rsaPub := deviceRSA(t)
	env, err := devicekey.Seal(rsaPub, testNS, testDevice, "s", priv)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := json.Marshal(env)
	if err := os.MkdirAll(filepath.Dir(d.envelope), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.envelope, eb, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment", func() bool { return len(d.hub.SessionIDs(api.KindDevice)) == 1 })
	if got := d.hub.Attestation(testNS, testDevice); !slices.Equal(got.Keys, []string{env.Fingerprint}) || got.Challenges != 1 {
		t.Fatalf("hub recorded %+v", got)
	}
}

// An envelope that does not open here (another device, a corrupt file) is
// reported once and never used; the agent then enrolls like a phase-1 agent.
func TestUnusableEnvelopeIsReportedOnce(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	d.deliverTo(t, testNS, "another-device", "serial-1")
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "unattested enrollment", func() bool { return len(d.hub.SessionIDs(api.KindDevice)) == 1 })
	time.Sleep(400 * time.Millisecond) // several polls
	if n := strings.Count(d.logs.String(), "device key problem"); n != 1 {
		t.Errorf("the problem was reported %d times", n)
	}
	if _, err := os.Stat(d.deliveredFile()); err == nil {
		t.Error("an envelope for another device was stored")
	}
	if got := d.hub.Attestation(testNS, testDevice); got.HostKey != "" {
		t.Errorf("attested with an unusable envelope: %+v", got)
	}
}

// A device key that arrives while the agent is active (the rtx2000 case) is
// attested once: the same identity enrolls again, the session stays up.
func TestNewKeyIsAttestedWhileActive(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "an active session without any device key", func() bool {
		return len(d.hub.SessionIDs(api.KindDevice)) == 1 && d.hub.Enrollments(testNS, testDevice) == 1
	})
	d.waitTunnelUp(t, 1)
	pinned := append(ed25519.PublicKey(nil), d.hub.PinnedKey(testNS, testDevice)...)
	session := d.hub.SessionIDs(api.KindDevice)[0]

	fp := d.deliver(t, "serial-1")
	eventually(t, 20*time.Second, "the identity to be attested with the delivered key", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == fp
	})
	if !d.hub.PinnedKey(testNS, testDevice).Equal(pinned) {
		t.Fatal("the identity changed")
	}
	if ids := d.hub.SessionIDs(api.KindDevice); len(ids) != 1 || ids[0] != session {
		t.Fatalf("the session was interrupted: %v -> %v", session, ids)
	}
	if n := d.hub.Enrollments(testNS, testDevice); n != 2 {
		t.Fatalf("enrollments = %d, want 2", n)
	}
	// Idle again: no further enrollments while the key set stays the same.
	time.Sleep(500 * time.Millisecond)
	if n := d.hub.Enrollments(testNS, testDevice); n != 2 {
		t.Fatalf("enrollments = %d after the key was attested", n)
	}
}

// Rotation: a new envelope replaces the delivered key; the agent attests the
// same identity again and the old key no longer signs.
func TestRotatedEnvelopeIsAttestedAgain(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	first := d.deliver(t, "serial-1")
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "first attestation", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == first && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
	second := d.deliver(t, "serial-2")
	eventually(t, 20*time.Second, "attestation with the rotated key", func() bool {
		return slices.Equal(d.hub.Attestation(testNS, testDevice).Keys, []string{second})
	})
	b, _ := os.ReadFile(d.deliveredFile())
	if priv, err := devicekey.ParseOpenSSH(b); err != nil || fingerprintOf(t, priv) != second {
		t.Fatalf("stored key: %v", err)
	}
}

// The vd-wg-1 case: an identity pending since it enrolled unattested activates
// by itself when the device key arrives, without a restart.
func TestPendingIdentityActivatesWhenTheKeyArrives(t *testing.T) {
	d := newDKRig(t, fakehub.Options{PendingUntilAttested: true})
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "the pending, unattested pin", func() bool {
		return d.hub.PinnedKey(testNS, testDevice) != nil && strings.Contains(d.logs.String(), "waiting for admin approval")
	})
	if n := len(d.hub.SessionIDs(api.KindDevice)); n != 0 {
		t.Fatalf("%d sessions of an unattested pin", n)
	}
	fp := d.bootstrapKey(t)
	eventually(t, 30*time.Second, "activation by the device key", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == fp && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
}

// With a device key the deprecated attestor is not used, even if configured.
func TestDeviceKeyWinsOverTheAttestor(t *testing.T) {
	ar := newAttestRig(t, true)
	ar.startAttestor(t)
	cfg := ar.config()
	cfg.DeviceKeyFile = filepath.Join(ar.dir, "ztna_device_key")
	cfg.DeviceKeyEnvelope = filepath.Join(ar.dir, "no-envelope")
	priv, err := devicekey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := devicekey.MarshalOpenSSH(priv)
	if err := os.WriteFile(cfg.DeviceKeyFile, b, 0o440); err != nil {
		t.Fatal(err)
	}
	_, stop := ar.start(cfg)
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment", func() bool { return len(ar.hub.SessionIDs(api.KindDevice)) == 1 })
	fp := fingerprintOf(t, priv)
	if got := ar.hub.Attestation(testNS, testDevice); !slices.Equal(got.Keys, []string{fp}) || got.HostKey == ar.hostFP {
		t.Fatalf("hub recorded %+v, want only the device key %s", got, fp)
	}
}

func TestShouldReattestOnAChangedKeySetAtOnce(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	cfg := d.config()
	cfg.ReattestInterval = time.Hour
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.shouldReattest(false) {
		t.Error("re-attesting without a key")
	}
	d.bootstrapKey(t)
	if !a.shouldReattest(false) {
		t.Error("a new key must be attested")
	}
	if a.shouldReattest(false) {
		t.Error("the interval is not honoured for an unchanged set")
	}
	d.bootstrapKey(t) // another key
	if !a.shouldReattest(false) {
		t.Error("a changed set must be attested at once")
	}
	a.mu.Lock()
	a.attestedSet = a.currentAttestSet()
	a.mu.Unlock()
	if a.shouldReattest(false) {
		t.Error("re-attesting a set that was attested")
	}
}

func TestConfigDeviceKeyDefaultsAndEnv(t *testing.T) {
	env := map[string]string{"DEVICE_ID": "d", "NAMESPACE": "n", "DOMAIN": "x.y"}
	get := func(k string) string { return env[k] }
	c, err := ConfigFromEnv(get)
	if err != nil || c.DeviceKeyFile != api.DeviceKeyFile || c.DeviceKeyEnvelope != api.DeviceKeyMountDir+"/"+api.DeviceKeyEnvelopeKey ||
		c.DeviceKeyPoll != DefaultDeviceKeyPoll {
		t.Fatalf("%+v %v", c, err)
	}
	env["DEVICE_KEY_FILE"], env["DEVICE_KEY_ENVELOPE"] = "/k/key", "/k/env.json"
	c, err = ConfigFromEnv(get)
	if err != nil || c.DeviceKeyFile != "/k/key" || c.DeviceKeyEnvelope != "/k/env.json" {
		t.Fatalf("%+v %v", c, err)
	}
}

// Without an exchange directory the identity directory goes back to 0700.
func TestStateDirIsPrivateWithoutAnAttestor(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	if err := os.MkdirAll(r.idDir, StateDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.idDir, StateDirMode); err != nil {
		t.Fatal(err)
	}
	_, stop := r.start(r.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment", func() bool { return len(r.hub.SessionIDs(api.KindDevice)) == 1 })
	if fi, _ := os.Stat(r.idDir); fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, want 0700", fi.Mode().Perm())
	}
}

// An identity the hub holds back (pending) is attested again although the key
// set did not change: the hub records one attestation per pin, and the key it
// preferred then may not be the one it trusts now.
func TestPendingIdentityIsAttestedAgainWithAnUnchangedKeySet(t *testing.T) {
	d := newDKRig(t, fakehub.Options{})
	cfg := d.config()
	cfg.ReattestInterval = time.Hour
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.bootstrapKey(t)
	if !a.shouldReattest(true) {
		t.Fatal("a new key must be attested")
	}
	a.mu.Lock()
	a.attestedSet = a.currentAttestSet()
	a.mu.Unlock()
	if a.shouldReattest(false) {
		t.Error("the watcher re-attested a set that was attested")
	}
	if a.shouldReattest(true) {
		t.Error("the interval is not honoured while pending")
	}
	a.mu.Lock()
	a.lastReattest = time.Now().Add(-2 * time.Hour)
	a.mu.Unlock()
	if !a.shouldReattest(true) {
		t.Error("a pending identity must be attested again after the interval")
	}
}

// The agent holds two device keys, the hub recorded the one it trusted at the
// time and then trusts the other: the session ends, the identity is pending
// and the agent attests it again until the hub records the right key.
func TestTrustMovingToAnotherHeldKeyActivatesTheIdentityAgain(t *testing.T) {
	d := newDKRig(t, fakehub.Options{PendingUntilAttested: true, RenewAfter: time.Second, TTL: 2 * time.Second})
	boot := d.bootstrapKey(t)
	d.hub.SetTrustedKey(testNS, testDevice, boot)
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "activation by the bootstrap key", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == boot && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
	// The delivered key arrives before the hub trusts it: the hub still records the bootstrap key.
	delivered := d.deliver(t, "serial-2")
	eventually(t, 20*time.Second, "attestation with both keys", func() bool {
		return slices.Equal(d.hub.Attestation(testNS, testDevice).Keys, []string{boot, delivered})
	})
	if got := d.hub.Attestation(testNS, testDevice).HostKey; got != boot {
		t.Fatalf("the hub recorded %s, want the trusted %s", got, boot)
	}
	// Trust moves; the enforcer ends the session.
	d.hub.SetTrustedKey(testNS, testDevice, delivered)
	for _, id := range d.hub.SessionIDs(api.KindDevice) {
		d.hub.KillSession(id)
	}
	eventually(t, 30*time.Second, "activation by the delivered key", func() bool {
		return d.hub.Attestation(testNS, testDevice).HostKey == delivered && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
}

// The hub replaced the device's pin while it was away and voided the identity.
// An agent holding the device key starts over with a new identity.
func TestVoidedIdentityIsRotatedWhenEnrollingIt(t *testing.T) {
	d := newDKRig(t, fakehub.Options{RenewAfter: time.Second, TTL: 2 * time.Second})
	d.bootstrapKey(t)
	_, stop := d.start(d.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "session", func() bool { return len(d.hub.SessionIDs(api.KindDevice)) == 1 })
	before := d.hub.Enrollments(testNS, testDevice)
	d.hub.ReplaceIdentity(testNS, testDevice)
	for _, id := range d.hub.SessionIDs(api.KindDevice) {
		d.hub.KillSession(id)
	}
	eventually(t, 30*time.Second, "a new identity and its session", func() bool {
		return d.hub.Enrollments(testNS, testDevice) > before && len(d.hub.SessionIDs(api.KindDevice)) == 1
	})
	if !strings.Contains(d.logs.String(), "the hub voided this device identity") {
		t.Error("no log line about the voided identity")
	}
}
