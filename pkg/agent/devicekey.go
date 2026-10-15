package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/devicekey"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// The device key (api.CapDeviceKey) is what activates the agent's identity
// without an admin. The agent can hold two: the one the trusted bootstrap
// installed (Config.DeviceKeyFile) and the one device-controller delivered
// over MQTT as a sealed envelope (Config.DeviceKeyEnvelope), which it opens
// with the device's bootstrap RSA key and keeps in its identity directory.
// It signs the attestation with every key it holds and lets the hub pick the
// one it trusts, so a rotation needs no coordination.

const (
	// maxDeviceKeys is how many device keys sign an attestation.
	maxDeviceKeys = 2
	// maxEnvelopeSize bounds the envelope file the agent reads.
	maxEnvelopeSize = 64 << 10
	// DefaultDeviceKeyPoll is how often the agent looks for a new device key.
	DefaultDeviceKeyPoll = 15 * time.Second

	// legacyAttestSet is the attestation set of the deprecated attestor
	// sidecar (see attestedSet).
	legacyAttestSet = "attestor"
)

// heldKey is a device key the agent can sign with.
type heldKey struct {
	signer ssh.Signer
	fp     string // "SHA256:<b64>"
}

// deviceKeys returns the device keys this device holds (bootstrap first, then
// the delivered one, without duplicates), after taking over a new envelope. It
// never returns an error: a key that cannot be read or opened is reported once
// and left out.
func (a *Agent) deviceKeys() []heldKey {
	a.dkMu.Lock()
	defer a.dkMu.Unlock()
	a.adoptEnvelope()
	var keys []heldKey
	for _, path := range []string{a.cfg.DeviceKeyFile, a.deliveredKeyPath()} {
		priv, err := readDeviceKeyFile(path)
		if err != nil {
			a.warnOnce("device key "+path, err)
			continue
		}
		if priv == nil {
			continue
		}
		k, err := newHeldKey(priv)
		if err != nil {
			a.warnOnce("device key "+path, err)
			continue
		}
		dup := false
		for _, h := range keys {
			dup = dup || h.fp == k.fp
		}
		if !dup && len(keys) < maxDeviceKeys {
			keys = append(keys, k)
		}
	}
	return keys
}

func (a *Agent) deliveredKeyPath() string {
	return filepath.Join(a.cfg.IdentityDir, api.DeliveredDeviceKeyFile)
}

func newHeldKey(priv ed25519.PrivateKey) (heldKey, error) {
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return heldKey{}, fmt.Errorf("device key: %w", err)
	}
	return heldKey{signer: s, fp: ssh.FingerprintSHA256(s.PublicKey())}, nil
}

// readDeviceKeyFile reads an OpenSSH Ed25519 key; (nil, nil) when the file is
// absent. The error never contains key material.
func readDeviceKeyFile(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	priv, err := devicekey.ParseOpenSSH(b)
	if err != nil {
		return nil, fmt.Errorf("%s is not a usable device key", path)
	}
	return priv, nil
}

// adoptEnvelope opens the envelope (Config.DeviceKeyEnvelope) when its key is
// not the delivered key already stored, and stores it in the identity
// directory (mode 0600, atomically). Called with a.dkMu held.
func (a *Agent) adoptEnvelope() {
	path := a.cfg.DeviceKeyEnvelope
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.warnOnce("envelope "+path, err)
		}
		return
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxEnvelopeSize+1))
	if err != nil || len(b) > maxEnvelopeSize {
		a.warnOnce("envelope "+path, errors.New("unreadable or too large"))
		return
	}
	var env api.DeviceKeyEnvelope
	if err := json.Unmarshal(b, &env); err != nil || env.Fingerprint == "" {
		a.warnOnce("envelope "+path, errors.New("not a device key envelope"))
		return
	}
	if cur, err := readDeviceKeyFile(a.deliveredKeyPath()); err == nil && cur != nil {
		if k, err := newHeldKey(cur); err == nil && k.fp == env.Fingerprint {
			return // already stored
		}
	}
	rsaPEM, err := os.ReadFile(a.cfg.RSAKeyPath)
	if err != nil {
		a.warnOnce("envelope "+env.Fingerprint, fmt.Errorf("reading the device RSA key: %w", err))
		return
	}
	priv, err := devicekey.Open(rsaPEM, a.cfg.Namespace, a.cfg.DeviceID, env)
	if err != nil {
		a.warnOnce("envelope "+env.Fingerprint, err)
		return
	}
	if err := writeDeliveredKey(a.cfg.IdentityDir, a.deliveredKeyPath(), priv); err != nil {
		a.warnOnce("envelope "+env.Fingerprint, err)
		return
	}
	a.log.Info("device key delivered; stored it", "fingerprint", env.Fingerprint, "serial", env.Serial)
}

// writeDeliveredKey writes priv in OpenSSH format to path (mode 0600) by
// writing a temporary file and renaming it.
func writeDeliveredKey(dir, path string, priv ed25519.PrivateKey) error {
	pemBytes, err := devicekey.MarshalOpenSSH(priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".device-key-*.tmp")
	if err != nil {
		return fmt.Errorf("storing the device key: %w", err)
	}
	name := tmp.Name()
	_, werr := tmp.Write(pemBytes)
	cherr := tmp.Chmod(0o600)
	serr := tmp.Sync()
	clerr := tmp.Close()
	if err := errors.Join(werr, cherr, serr, clerr); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("storing the device key: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("installing the device key: %w", err)
	}
	return nil
}

// warnOnce logs a problem with a device key or envelope the first time it
// appears (the files are polled), keyed by what and the error text.
func (a *Agent) warnOnce(what string, err error) {
	k := what + ": " + err.Error()
	if a.dkWarned == nil {
		a.dkWarned = map[string]struct{}{}
	}
	if _, ok := a.dkWarned[k]; ok {
		return
	}
	a.dkWarned[k] = struct{}{}
	a.log.Warn("device key problem", "what", what, "error", err.Error())
}

// attestSetOf identifies the keys an attestation was made with.
func attestSetOf(keys []heldKey) string {
	fps := make([]string, len(keys))
	for i, k := range keys {
		fps[i] = k.fp
	}
	return strings.Join(fps, ",")
}

// legacyAttesting reports whether the deprecated attestor sidecar is the way to
// attest: an exchange directory is configured and no device key exists.
func (a *Agent) legacyAttesting(keys []heldKey) bool {
	return len(keys) == 0 && a.cfg.AttestExchange != ""
}

// currentAttestSet is the set of keys an attestation would be made with now
// ("" when there is nothing to attest with).
func (a *Agent) currentAttestSet() string {
	keys := a.deviceKeys()
	switch {
	case len(keys) > 0:
		return attestSetOf(keys)
	case a.cfg.AttestExchange != "":
		return legacyAttestSet
	}
	return ""
}

// attestDeviceKeys signs the attestation statement of the identity pub with
// every device key, one hub nonce per key. (nil, nil) means the hub does not
// know attestation (phase-1 hub); the caller then enrolls without it.
func (a *Agent) attestDeviceKeys(ctx context.Context, rsaPEM []byte, priv ed25519.PrivateKey, pub string, keys []heldKey) ([]api.HostKeyAttestation, error) {
	idFP := identity.Fingerprint(priv.Public().(ed25519.PublicKey))
	out := make([]api.HostKeyAttestation, 0, len(keys))
	for _, k := range keys {
		// Every challenge needs an enrollment JWT of its own: the hub records
		// the jti of every token, and the enrollment mints another one.
		token, _, err := identity.MintEnrollJWT(rsaPEM, a.sub, pub, identityTokenTTL)
		if err != nil {
			return nil, fmt.Errorf("minting attestation token: %w", err)
		}
		ch, err := wgclient.AttestChallenge(ctx, a.cfg.HubURL, a.cfg.HTTPClient, token)
		if err != nil {
			if hubLacksAttestation(err) {
				a.log.Warn("the hub does not support attestation; enrolling without it")
				return nil, nil
			}
			return nil, fmt.Errorf("requesting attestation challenge: %w", err)
		}
		stmt := api.AttestStatement(a.cfg.Namespace, a.cfg.DeviceID, idFP, ch.EnrollmentEpoch, ch.EnrollmentGeneration, ch.Nonce)
		blob, err := sshsig.Sign(k.signer, api.AttestNamespace, stmt)
		if err != nil {
			return nil, fmt.Errorf("signing the attestation: %w", err)
		}
		out = append(out, api.HostKeyAttestation{Nonce: ch.Nonce, Signature: base64.StdEncoding.EncodeToString(blob)})
		a.log.Info("device key attestation signed", "deviceKey", k.fp)
	}
	return out, nil
}
