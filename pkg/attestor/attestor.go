package attestor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
)

// Defaults of the attestor.
const (
	DefaultStateDir    = "/var/lib/teknoir/wg-agent"
	DefaultExchangeDir = "/run/wg-attest"
	DefaultHostKeysDir = "/etc/ssh"

	DefaultPollInterval = time.Second
	// DefaultMinSignInterval is the rate limit: one signature per interval.
	DefaultMinSignInterval = 10 * time.Second

	maxIdentityPubBytes = 256
	maxHostKeyBytes     = 64 << 10
)

// Config configures an Attestor.
type Config struct {
	StateDir    string
	ExchangeDir string
	HostKeysDir string
	// Namespace and DeviceID come from the attestor's own environment, never
	// from the request, so a compromised agent cannot get a signature for
	// another device.
	Namespace string
	DeviceID  string
	// AgentUIDs are the owners whose request files are accepted (default: AgentUID only).
	AgentUIDs       []int
	PollInterval    time.Duration
	MinSignInterval time.Duration
	Logger          *slog.Logger
	Now             func() time.Time
}

func (c *Config) applyDefaults() error {
	if c.Namespace == "" || c.DeviceID == "" {
		return errors.New("attestor: NAMESPACE and DEVICE_ID are required")
	}
	if strings.ContainsAny(c.Namespace+c.DeviceID, "/ \t\r\n") {
		return errors.New("attestor: NAMESPACE and DEVICE_ID must not contain '/' or whitespace")
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	if c.ExchangeDir == "" {
		c.ExchangeDir = DefaultExchangeDir
	}
	if c.HostKeysDir == "" {
		c.HostKeysDir = DefaultHostKeysDir
	}
	if len(c.AgentUIDs) == 0 {
		c.AgentUIDs = []int{AgentUID}
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.MinSignInterval <= 0 {
		c.MinSignInterval = DefaultMinSignInterval
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return nil
}

// ConfigFromEnv reads NAMESPACE and DEVICE_ID; the directories come from flags.
func ConfigFromEnv(getenv func(string) string) Config {
	return Config{Namespace: getenv("NAMESPACE"), DeviceID: getenv("DEVICE_ID")}
}

// Attestor answers attestation requests.
type Attestor struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	lastKey  string // request already answered (nonce|epoch|generation)
	lastSign time.Time
	warned   string // last ignored-request reason, to log it once
}

// New validates cfg and returns an Attestor.
func New(cfg Config) (*Attestor, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	return &Attestor{cfg: cfg, log: cfg.Logger}, nil
}

// Run polls the exchange directory until ctx is cancelled.
func (a *Attestor) Run(ctx context.Context) error {
	a.log.Info("attestor starting", "device", a.cfg.DeviceID, "namespace", a.cfg.Namespace,
		"exchange", a.cfg.ExchangeDir, "hostkeys", a.cfg.HostKeysDir)
	t := time.NewTicker(a.cfg.PollInterval)
	defer t.Stop()
	for {
		a.Poll()
		select {
		case <-ctx.Done():
			a.log.Info("attestor stopping")
			return nil
		case <-t.C:
		}
	}
}

func (a *Attestor) ignore(reason string, attrs ...any) {
	if a.warned == reason {
		return
	}
	a.warned = reason
	a.log.Warn("ignoring attestation request", append([]any{"reason", reason}, attrs...)...)
}

// Poll handles at most one pending request. It never returns an error: a bad
// request is ignored (logged once), a refusal is answered in response.json.
func (a *Attestor) Poll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	path := filepath.Join(a.cfg.ExchangeDir, RequestFile)
	f, uid, fi, err := openRegular(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.ignore("request file cannot be opened", "error", err.Error())
		}
		return
	}
	defer func() { _ = f.Close() }()
	switch {
	case !fi.Mode().IsRegular():
		a.ignore("request is not a regular file")
		return
	case !slices.Contains(a.cfg.AgentUIDs, uid):
		a.ignore("request is not owned by the agent user", "uid", uid)
		return
	case fi.Size() > MaxRequestBytes:
		a.ignore("request file is too large", "bytes", fi.Size())
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxRequestBytes+1))
	if err != nil || len(b) > MaxRequestBytes {
		a.ignore("request file cannot be read")
		return
	}
	var req Request
	if err := json.Unmarshal(b, &req); err != nil || !ValidToken(req.Nonce) || !ValidToken(req.Epoch) || req.Generation < 0 {
		a.ignore("request is malformed")
		return
	}
	a.warned = ""
	key := fmt.Sprintf("%s|%s|%d", req.Nonce, req.Epoch, req.Generation)
	if key == a.lastKey {
		return // answered; the agent has not replaced the file yet
	}
	now := a.cfg.Now()
	if !a.lastSign.IsZero() && now.Sub(a.lastSign) < a.cfg.MinSignInterval {
		return // rate limited: answered at a later poll
	}
	resp := a.answer(req)
	a.lastKey = key
	if resp.Error == "" {
		a.lastSign = now
	}
	out, err := json.Marshal(resp)
	if err != nil {
		a.log.Error("encoding response failed", "error", err.Error())
		return
	}
	if err := writeAtomic(a.cfg.ExchangeDir, ResponseFile, out, 0o644); err != nil {
		a.log.Error("writing response failed", "error", err.Error())
		a.lastKey = "" // try again
		return
	}
	_ = os.Remove(path) // best effort; lastKey already prevents a second answer
	if resp.Error != "" {
		a.log.Warn("attestation refused", "error", resp.Error)
		return
	}
	a.log.Info("host key attestation signed", "hostKey", resp.HostKeyFingerprint, "type", resp.HostKeyType)
}

func (a *Attestor) answer(req Request) *Response {
	fail := func(msg string) *Response { return &Response{Nonce: req.Nonce, Error: msg} }
	idPub, err := readIdentityPub(filepath.Join(a.cfg.StateDir, IdentityPubFile))
	if err != nil {
		return fail("identity public key unavailable: " + err.Error())
	}
	signer, err := loadHostKey(a.cfg.HostKeysDir)
	if err != nil {
		return fail(err.Error())
	}
	stmt := api.AttestStatement(a.cfg.Namespace, a.cfg.DeviceID, identity.Fingerprint(idPub), req.Epoch, req.Generation, req.Nonce)
	blob, err := sshsig.Sign(signer, api.AttestNamespace, stmt)
	if err != nil {
		return fail("signing failed: " + err.Error())
	}
	return &Response{
		Nonce:              req.Nonce,
		Attestations:       []Attestation{{Nonce: req.Nonce, Signature: base64.StdEncoding.EncodeToString(blob)}},
		HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		HostKeyType:        signer.PublicKey().Type(),
	}
}

func readIdentityPub(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxIdentityPubBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxIdentityPubBytes {
		return nil, errors.New("identity.pub is too large")
	}
	pub, err := identity.ParsePublicKey(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("identity.pub is not an Ed25519 public key")
	}
	return pub, nil
}

// loadHostKey returns the ed25519 host key, or the RSA host key (signing with
// rsa-sha2-512) when the device has no ed25519 one. Other types are never used.
func loadHostKey(dir string) (ssh.Signer, error) {
	var lastErr error
	for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_rsa_key"} {
		s, err := readSigner(filepath.Join(dir, name))
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no ssh_host_ed25519_key or ssh_host_rsa_key in the host key directory")
}

func readSigner(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxHostKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	if len(b) > maxHostKeyBytes {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	s, err := ssh.ParsePrivateKey(b)
	clear(b)
	if err != nil {
		// The parser's error never contains key material; keep it short anyway.
		return nil, fmt.Errorf("%s is not a usable unencrypted private key", filepath.Base(path))
	}
	return s, nil
}
