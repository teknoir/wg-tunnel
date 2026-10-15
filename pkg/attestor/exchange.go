// Package attestor is the host-key attestation sidecar of the device Deployment
// and the file exchange the agent uses to talk to it.
//
// Deprecated: since rev 3 the agent signs the attestation itself with the
// per-device device key (api.DeviceKeyFile, or an envelope delivered over MQTT,
// see pkg/devicekey). The agent uses this sidecar only on a device that holds no
// device key; the package is removed one release after device-controller
// stopped deploying the sidecar.
//
// The attestor runs as root with every Linux capability dropped, so it can
// read the 0600 root-owned sshd host keys (root owns them, no DAC capability
// is needed) and nothing else. It has no socket: the agent writes request.json
// into a shared directory, the attestor signs the attestation statement of
// pkg/api with the SSH host key (SSHSIG, see pkg/sshsig) and writes
// response.json. The signature is not a secret.
package attestor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// File names inside the exchange directory and the state directory.
const (
	RequestFile  = "request.json"
	ResponseFile = "response.json"
	// IdentityPubFile is written by the agent next to identity.key (base64 raw
	// Ed25519 public key) so the attestor can derive the identity fingerprint
	// without being able to read the private key.
	IdentityPubFile = "identity.pub"

	// MaxRequestBytes is the largest request file the attestor reads.
	MaxRequestBytes = 4 << 10
	// MaxResponseBytes is the largest response file the agent reads.
	MaxResponseBytes = 16 << 10
	// AgentUID is the only uid whose request files the attestor accepts.
	AgentUID = 65532
)

// Request is what the agent asks for: the values of the hub's api.AttestChallenge.
type Request struct {
	Nonce      string `json:"nonce"`
	Epoch      string `json:"epoch"`
	Generation int64  `json:"generation"`
}

// Attestation is one signature (base64 of the binary SSHSIG blob).
type Attestation struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// Response is the attestor's answer. Error is set instead of Attestations when
// the attestor cannot sign (for example, the device has no usable host key);
// Nonce echoes the request either way.
type Response struct {
	Nonce              string        `json:"nonce"`
	Attestations       []Attestation `json:"attestations,omitempty"`
	HostKeyFingerprint string        `json:"hostKeyFingerprint,omitempty"`
	HostKeyType        string        `json:"hostKeyType,omitempty"`
	Error              string        `json:"error,omitempty"`
}

// ErrTimeout means the attestor did not answer in time (absent or not started).
var ErrTimeout = errors.New("attestor did not answer in time")

// Refused is returned by Exchange when the attestor answered with an error: a
// definitive answer, unlike ErrTimeout.
type Refused struct{ Message string }

func (e *Refused) Error() string { return "attestor refused: " + e.Message }

// ValidToken reports whether s is usable as nonce or epoch inside the
// newline-delimited attestation statement: non-empty, short, and made of
// characters that cannot split or confuse it.
func ValidToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':', r == '=', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}

// writeAtomic writes data to dir/name through a temp file in dir and a rename,
// with the given mode (applied explicitly, independent of the umask).
func writeAtomic(dir, name string, data []byte, mode os.FileMode) error {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Exchange is the agent side: it removes any stale response, writes the
// request (mode 0644: the attestor is root without DAC capabilities and
// reads it as "other") and waits up to timeout for the attestor's answer to
// this very nonce. It returns *Refused when the attestor says it cannot sign
// and ErrTimeout when nothing arrives.
func Exchange(ctx context.Context, dir string, req Request, timeout, poll time.Duration) (*Response, error) {
	if !ValidToken(req.Nonce) || !ValidToken(req.Epoch) {
		return nil, errors.New("attestor: challenge contains characters that cannot be attested")
	}
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	_ = os.Remove(filepath.Join(dir, ResponseFile)) // stale; answers are matched by nonce anyway
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(dir, RequestFile, b, 0o644); err != nil {
		return nil, fmt.Errorf("attestor: writing request: %w", err)
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if resp, ok := readResponse(dir, req.Nonce); ok {
			if resp.Error != "" {
				return nil, &Refused{Message: resp.Error}
			}
			return resp, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, ErrTimeout
		case <-tick.C:
		}
	}
}

func readResponse(dir, nonce string) (*Response, bool) {
	p := filepath.Join(dir, ResponseFile)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxResponseBytes {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxResponseBytes+1))
	if err != nil || len(b) > MaxResponseBytes {
		return nil, false
	}
	var r Response
	if json.Unmarshal(b, &r) != nil || r.Nonce != nonce {
		return nil, false
	}
	return &r, true
}
