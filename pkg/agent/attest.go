package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/attestor"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const (
	// StateDirMode is the mode of the identity directory: traversable by
	// others (the attestor sidecar is root without capabilities), listable and
	// writable by the agent only. The identity key is 0600.
	StateDirMode os.FileMode = 0o711

	// DefaultAttestTimeout is how long the agent waits for the attestor.
	DefaultAttestTimeout = 15 * time.Second
)

// attesting reports whether a host-key attestor is configured (ATTEST_EXCHANGE).
func (a *Agent) attesting() bool { return a.cfg.AttestExchange != "" }

// capabilities are the api.Cap* values advertised in DeviceSessionRequest.
func (a *Agent) capabilities() []string {
	caps := baseCapabilities()
	if a.attesting() {
		caps = append(caps, api.CapAttest)
	}
	if a.cfg.P2P {
		caps = append(caps, api.CapP2P)
	}
	return caps
}

// publishIdentityPub writes identity.pub (base64 raw public key) next to the
// identity key so the attestor can compute the fingerprint without reading
// the private key. It also lets the attestor traverse the state directory.
// Both are best effort for an agent that has no attestor.
func (a *Agent) publishIdentityPub(priv ed25519.PrivateKey) error {
	if !a.attesting() {
		return nil
	}
	dir := a.cfg.IdentityDir
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm() != StateDirMode {
		if err := os.Chmod(dir, StateDirMode); err != nil {
			return fmt.Errorf("making %s traversable for the attestor: %w", dir, err)
		}
	}
	want := identity.EncodePublicKey(priv.Public().(ed25519.PublicKey)) + "\n"
	path := filepath.Join(dir, attestor.IdentityPubFile)
	if cur, err := os.ReadFile(path); err == nil && string(cur) == want {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".identity-pub-*.tmp")
	if err != nil {
		return fmt.Errorf("writing identity.pub: %w", err)
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(want)
	cerr := tmp.Chmod(0o644)
	clerr := tmp.Close()
	if err := errors.Join(werr, cerr, clerr); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("writing identity.pub: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("installing identity.pub: %w", err)
	}
	return nil
}

// attest obtains host-key attestations for the identity pub (base64) from the
// attestor: single-use nonce from the hub, signature by the sidecar.
// (nil, nil) means the hub does not know attestation (phase-1 hub) or the
// attestor said it cannot sign; the caller then enrolls without it.
func (a *Agent) attest(ctx context.Context, rsaPEM []byte, priv ed25519.PrivateKey, pub string) ([]api.HostKeyAttestation, error) {
	// The challenge needs an enrollment JWT of its own: the hub records the
	// jti of every token, and the enrollment below mints another one.
	token, _, err := identity.MintEnrollJWT(rsaPEM, a.sub, pub, identityTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("minting attestation token: %w", err)
	}
	ch, err := wgclient.AttestChallenge(ctx, a.cfg.HubURL, a.cfg.HTTPClient, token)
	if err != nil {
		var he *wgclient.Error
		if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusMethodNotAllowed) && he.Reason == "" {
			a.log.Warn("the hub does not support host-key attestation; enrolling without it")
			return nil, nil
		}
		return nil, fmt.Errorf("requesting attestation challenge: %w", err)
	}
	timeout := a.cfg.AttestTimeout
	if timeout <= 0 {
		timeout = DefaultAttestTimeout
	}
	resp, err := attestor.Exchange(ctx, a.cfg.AttestExchange, attestor.Request{
		Nonce: ch.Nonce, Epoch: ch.EnrollmentEpoch, Generation: ch.EnrollmentGeneration,
	}, timeout, 0)
	var refused *attestor.Refused
	switch {
	case errors.As(err, &refused):
		a.log.Warn("the attestor cannot sign; enrolling without a host-key attestation (an admin must approve the identity)",
			"reason", refused.Message)
		return nil, nil
	case errors.Is(err, attestor.ErrTimeout):
		return nil, fmt.Errorf("the attestor sidecar did not answer within %s; is it running?", timeout)
	case err != nil:
		return nil, err
	}
	out := make([]api.HostKeyAttestation, 0, len(resp.Attestations))
	idPub := priv.Public().(ed25519.PublicKey)
	stmt := api.AttestStatement(a.cfg.Namespace, a.cfg.DeviceID, identity.Fingerprint(idPub), ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
	for _, at := range resp.Attestations {
		if at.Nonce != ch.Nonce {
			continue
		}
		// Check the signature here too, so a broken sidecar is reported as such
		// and not as a refusal by the hub.
		blob, err := base64.StdEncoding.DecodeString(at.Signature)
		if err != nil {
			return nil, errors.New("the attestor returned a malformed signature")
		}
		hk, err := sshsig.Verify(blob, api.AttestNamespace, stmt)
		if err != nil {
			return nil, fmt.Errorf("the attestor's signature does not verify: %w", err)
		}
		a.log.Info("host key attestation obtained", "hostKey", ssh.FingerprintSHA256(hk), "type", hk.Type())
		out = append(out, api.HostKeyAttestation{Nonce: at.Nonce, Signature: at.Signature})
	}
	if len(out) == 0 {
		return nil, errors.New("the attestor returned no attestation for this challenge")
	}
	return out, nil
}
