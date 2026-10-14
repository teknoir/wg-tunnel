package e2erig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/attestor"
)

// setupAttest gives the device a real sshd host key file and runs the real
// attestor against it, as the sidecar does on a device. The agent then talks to
// it through an exchange directory (Rig.AttestExchange).
func (r *Rig) setupAttest(dir string) {
	t := r.T
	keys := filepath.Join(dir, "sshd")
	exchange := filepath.Join(dir, "attest")
	must(t, os.MkdirAll(keys, 0o755))
	must(t, os.MkdirAll(exchange, 0o777))
	must(t, os.Chmod(exchange, 0o777))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(keys, "ssh_host_ed25519_key"), pem.EncodeToMemory(blk), 0o600))
	sp, err := ssh.NewPublicKey(pub)
	must(t, err)
	r.HostKeyFingerprint = ssh.FingerprintSHA256(sp)
	r.AttestExchange = exchange
	r.AddSecret(string(pem.EncodeToMemory(blk)))

	a, err := attestor.New(attestor.Config{
		StateDir: r.IdentityDir, ExchangeDir: exchange, HostKeysDir: keys,
		Namespace: NS, DeviceID: DeviceName, AgentUIDs: []int{os.Getuid()},
		PollInterval: 20 * time.Millisecond, MinSignInterval: 50 * time.Millisecond,
		Logger: logger(r.AgentLogs),
	})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// TrustHostKey plays the admin's "Trust this host key": the policy then
// carries the device's SSH host key fingerprint as the activation anchor.
func (r *Rig) TrustHostKey() {
	r.T.Helper()
	if r.HostKeyFingerprint == "" {
		r.T.Fatal("TrustHostKey needs Options.Attest")
	}
	r.Policy.Update(NS, DeviceName, func(e *api.PolicyEntry) { e.TrustedHostKey = r.HostKeyFingerprint })
}
