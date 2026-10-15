package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/attestor"
	"github.com/teknoir/wg-tunnel/pkg/identity"
)

// attestRig adds an exchange directory, an sshd host key directory and an
// in-process attestor to an agent rig.
type attestRig struct {
	*rig
	exchange string
	hostkeys string
	hostFP   string
}

func newAttestRig(t *testing.T, hubAttest bool) *attestRig {
	t.Helper()
	ar := &attestRig{rig: newRig(t, fakehub.Options{Attest: hubAttest}), exchange: t.TempDir(), hostkeys: t.TempDir()}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ar.hostkeys, "ssh_host_ed25519_key"), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	ar.hostFP = ssh.FingerprintSHA256(sp)
	return ar
}

func (ar *attestRig) config() Config {
	c := ar.rig.config()
	c.AttestExchange = ar.exchange
	c.AttestTimeout = 3 * time.Second
	return c
}

func (ar *attestRig) startAttestor(t *testing.T) {
	t.Helper()
	a, err := attestor.New(attestor.Config{
		StateDir: ar.idDir, ExchangeDir: ar.exchange, HostKeysDir: ar.hostkeys,
		Namespace: testNS, DeviceID: testDevice, AgentUIDs: []int{os.Getuid()},
		PollInterval: 20 * time.Millisecond, MinSignInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestEnrollsWithHostKeyAttestation(t *testing.T) {
	ar := newAttestRig(t, true)
	ar.startAttestor(t)
	_, stop := ar.start(ar.config())
	eventually(t, 20*time.Second, "attested enrollment and session", func() bool {
		return ar.hub.PinnedKey(testNS, testDevice) != nil && len(ar.hub.SessionIDs(api.KindDevice)) == 1
	})
	got := ar.hub.Attestation(testNS, testDevice)
	if got.HostKey != ar.hostFP || got.KeyType != ssh.KeyAlgoED25519 || !slices.Contains(got.Capabilities, api.CapAttest) || got.Challenges != 1 {
		t.Fatalf("hub recorded %+v, want host key %s", got, ar.hostFP)
	}
	if caps := ar.hub.SessionCapabilities(testNS, testDevice); !slices.Equal(caps, []string{api.CapServices, api.CapControl, api.CapK3sDiscovery, api.CapAttest}) {
		t.Fatalf("session capabilities %v", caps)
	}
	// identity.pub is next to the identity key and readable by the attestor.
	priv, err := identity.LoadOrCreate(ar.idDir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ar.idDir, attestor.IdentityPubFile))
	if err != nil || strings.TrimSpace(string(b)) != identity.EncodePublicKey(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("identity.pub: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(ar.idDir, attestor.IdentityPubFile)); fi.Mode().Perm() != 0o644 {
		t.Errorf("identity.pub mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(ar.idDir); fi.Mode().Perm() != StateDirMode {
		t.Errorf("state dir mode %v, want %v", fi.Mode().Perm(), StateDirMode)
	}
	if fi, _ := os.Stat(filepath.Join(ar.idDir, identity.KeyFile)); fi.Mode().Perm() != 0o600 {
		t.Errorf("identity.key mode %v", fi.Mode().Perm())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// Neither the host key nor the identity key reached the logs.
	logs := ar.logs.String()
	if strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "SSHSIG") {
		t.Errorf("logs leak key or signature material")
	}
	if !strings.Contains(logs, ar.hostFP) {
		t.Errorf("the attested host key fingerprint should be logged")
	}
}

func TestEnrollWithoutAttestorConfigIsPhase1(t *testing.T) {
	ar := newAttestRig(t, true)
	cfg := ar.rig.config() // no ATTEST_EXCHANGE
	_, stop := ar.start(cfg)
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment", func() bool { return len(ar.hub.SessionIDs(api.KindDevice)) == 1 })
	got := ar.hub.Attestation(testNS, testDevice)
	// Without an attestor the agent never attests or advertises attest-v1
	// (it still advertises the always-on services and control capabilities).
	if got.HostKey != "" || slices.Contains(got.Capabilities, api.CapAttest) || got.Challenges != 0 {
		t.Fatalf("an agent without an attestor must not attest or advertise attest-v1: %+v", got)
	}
	if caps := ar.hub.SessionCapabilities(testNS, testDevice); slices.Contains(caps, api.CapAttest) {
		t.Fatalf("session capabilities %v", caps)
	}
	if _, err := os.Stat(filepath.Join(ar.idDir, attestor.IdentityPubFile)); err == nil {
		t.Error("identity.pub is only written when an attestor is configured")
	}
}

func TestMissingAttestorBlocksEnrollmentUntilItAppears(t *testing.T) {
	ar := newAttestRig(t, true)
	cfg := ar.config()
	cfg.AttestTimeout = 300 * time.Millisecond
	_, stop := ar.start(cfg)
	defer func() { _ = stop() }()
	eventually(t, 10*time.Second, "the agent to report the missing attestor", func() bool {
		return strings.Contains(ar.logs.String(), "did not answer")
	})
	if ar.hub.PinnedKey(testNS, testDevice) != nil {
		t.Fatal("must not enroll unattested while an attestor is configured but silent")
	}
	ar.startAttestor(t)
	eventually(t, 20*time.Second, "enrollment once the attestor runs", func() bool {
		return ar.hub.PinnedKey(testNS, testDevice) != nil && ar.hub.Attestation(testNS, testDevice).HostKey == ar.hostFP
	})
}

func TestAttestorWithoutHostKeyDegradesToUnattestedEnrollment(t *testing.T) {
	ar := newAttestRig(t, true)
	_ = os.Remove(filepath.Join(ar.hostkeys, "ssh_host_ed25519_key"))
	ar.startAttestor(t)
	_, stop := ar.start(ar.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "unattested enrollment", func() bool { return len(ar.hub.SessionIDs(api.KindDevice)) == 1 })
	got := ar.hub.Attestation(testNS, testDevice)
	if got.HostKey != "" || len(got.Capabilities) != 0 {
		t.Fatalf("hub recorded %+v", got)
	}
	if !strings.Contains(ar.logs.String(), "attestor cannot sign") {
		t.Error("no warning about the missing host key")
	}
}

func TestPhase1HubWithoutChallengeEndpointStillEnrolls(t *testing.T) {
	ar := newAttestRig(t, false) // fake hub answers 404 to the challenge
	ar.startAttestor(t)
	_, stop := ar.start(ar.config())
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "enrollment against a phase-1 hub", func() bool { return len(ar.hub.SessionIDs(api.KindDevice)) == 1 })
	if !strings.Contains(ar.logs.String(), "does not support host-key attestation") {
		t.Error("no log line about the old hub")
	}
}

func TestReenrollmentPublishesNewIdentityPubAndAttestsAgain(t *testing.T) {
	ar := newAttestRig(t, true)
	ar.startAttestor(t)
	_, stop := ar.start(ar.config())
	eventually(t, 20*time.Second, "first enrollment", func() bool { return len(ar.hub.SessionIDs(api.KindDevice)) == 1 })
	ar.waitTunnelUp(t, 1)
	first := append(ed25519.PublicKey(nil), ar.hub.PinnedKey(testNS, testDevice)...)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	ar.hub.ResetEnrollment(testNS, testDevice)
	ar.hub.SetEnrollOpen(testNS, testDevice, true)
	_, stop2 := ar.start(ar.config())
	defer func() { _ = stop2() }()
	eventually(t, 30*time.Second, "re-enrollment with a fresh attestation", func() bool {
		return ar.hub.Enrollments(testNS, testDevice) == 2 && len(ar.hub.SessionIDs(api.KindDevice)) == 1
	})
	second := ar.hub.PinnedKey(testNS, testDevice)
	if second.Equal(first) {
		t.Fatal("same identity after reset")
	}
	b, _ := os.ReadFile(filepath.Join(ar.idDir, attestor.IdentityPubFile))
	if strings.TrimSpace(string(b)) != identity.EncodePublicKey(second) {
		t.Fatal("identity.pub was not republished after the rotation")
	}
	if got := ar.hub.Attestation(testNS, testDevice); got.HostKey != ar.hostFP {
		t.Fatalf("second enrollment not attested: %+v", got)
	}
}

func TestConfigAttestExchange(t *testing.T) {
	env := map[string]string{"DEVICE_ID": "d", "NAMESPACE": "n", "DOMAIN": "x.y", "ATTEST_EXCHANGE": "/run/wg-attest"}
	c, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil || c.AttestExchange != "/run/wg-attest" {
		t.Fatalf("%+v %v", c, err)
	}
	env["ATTEST_EXCHANGE"] = "relative/dir"
	if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("relative ATTEST_EXCHANGE accepted")
	}
}

// An identity enrolled without an attestation (the attestor could not sign
// yet) is attested later by the agent itself: after the admin trusts the host
// key nothing else is needed (review finding 20).
func TestPendingUnattestedIdentityIsAttestedLater(t *testing.T) {
	ar := &attestRig{rig: newRig(t, fakehub.Options{Attest: true, PendingUntilAttested: true}), exchange: t.TempDir(), hostkeys: t.TempDir()}
	// No host key yet: the attestor refuses, the agent enrolls like a phase-1 agent.
	ar.startAttestor(t)
	cfg := ar.config()
	cfg.ReattestInterval = 100 * time.Millisecond
	_, stop := ar.start(cfg)
	defer func() { _ = stop() }()
	eventually(t, 20*time.Second, "the unattested enrollment", func() bool {
		return ar.hub.PinnedKey(testNS, testDevice) != nil && strings.Contains(ar.logs.String(), "attestor cannot sign")
	})
	if n := len(ar.hub.SessionIDs(api.KindDevice)); n != 0 {
		t.Fatalf("%d sessions of an unapproved identity", n)
	}
	// sshd generates its host key: the next re-attestation attests the pin.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ar.hostkeys, "ssh_host_ed25519_key"), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	eventually(t, 30*time.Second, "the attestation and the session", func() bool {
		return ar.hub.Attestation(testNS, testDevice).HostKey == ssh.FingerprintSHA256(sp) && len(ar.hub.SessionIDs(api.KindDevice)) == 1
	})
	if !strings.Contains(ar.logs.String(), "attesting it again") {
		t.Error("no log line about the re-attestation")
	}
}

func TestNoReattestationWithoutAnAttestorOrOnceAttested(t *testing.T) {
	a, err := New(Config{DeviceID: "d", Namespace: "n", HubURL: "http://hub", RSAKeyPath: "/x", IdentityDir: t.TempDir(), ReattestInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if a.shouldReattest(false) {
		t.Error("re-attesting without an attestor")
	}
	a.cfg.AttestExchange = "/run/x"
	time.Sleep(2 * time.Millisecond)
	if !a.shouldReattest(false) {
		t.Error("an unattested pending identity must be attested again")
	}
	if a.shouldReattest(false) {
		t.Error("the interval is not honoured")
	}
	time.Sleep(2 * time.Millisecond)
	a.mu.Lock()
	a.attestedSet = legacyAttestSet
	a.mu.Unlock()
	if a.shouldReattest(false) {
		t.Error("re-attesting an identity that was attested")
	}
}
