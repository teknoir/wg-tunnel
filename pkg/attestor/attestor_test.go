package attestor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/sshsig"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	t        *testing.T
	state    string
	exchange string
	hostkeys string
	idPub    ed25519.PublicKey
	clk      *clock
	logs     *bytes.Buffer
	a        *Attestor
}

func hostKey(t *testing.T, dir, kind string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	out, err := exec.Command("ssh-keygen", "-q", "-t", kind, "-b", "3072", "-N", "", "-C", "", "-f", filepath.Join(dir, "ssh_host_"+kind+"_key")).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
}

func newRig(t *testing.T, kinds ...string) *rig {
	t.Helper()
	r := &rig{t: t, state: t.TempDir(), exchange: t.TempDir(), hostkeys: t.TempDir(), clk: &clock{t: time.Unix(1_800_000_000, 0)}, logs: &bytes.Buffer{}}
	if len(kinds) == 0 {
		kinds = []string{"ed25519"}
	}
	for _, k := range kinds {
		hostKey(t, r.hostkeys, k)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.idPub = pub
	if err := os.WriteFile(filepath.Join(r.state, IdentityPubFile), []byte(identity.EncodePublicKey(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{
		StateDir: r.state, ExchangeDir: r.exchange, HostKeysDir: r.hostkeys,
		Namespace: "teamspace", DeviceID: "dev-1", AgentUIDs: []int{os.Getuid()},
		Logger: slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    r.clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	return r
}

func (r *rig) request(req Request) {
	r.t.Helper()
	b, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(r.exchange, RequestFile), b, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) response() (*Response, bool) {
	b, err := os.ReadFile(filepath.Join(r.exchange, ResponseFile))
	if err != nil {
		return nil, false
	}
	var resp Response
	if err := json.Unmarshal(b, &resp); err != nil {
		r.t.Fatalf("response is not JSON: %v", err)
	}
	return &resp, true
}

func (r *rig) clearResponse() { _ = os.Remove(filepath.Join(r.exchange, ResponseFile)) }

var req1 = Request{Nonce: "nonce-1", Epoch: "epoch-A", Generation: 3}

func TestSignsStatementWithEd25519HostKey(t *testing.T) {
	r := newRig(t)
	r.request(req1)
	r.a.Poll()
	resp, ok := r.response()
	if !ok || resp.Error != "" || len(resp.Attestations) != 1 {
		t.Fatalf("response %+v ok=%v", resp, ok)
	}
	if resp.HostKeyType != ssh.KeyAlgoED25519 {
		t.Errorf("type %q", resp.HostKeyType)
	}
	blob, err := base64.StdEncoding.DecodeString(resp.Attestations[0].Signature)
	if err != nil {
		t.Fatal(err)
	}
	stmt := api.AttestStatement("teamspace", "dev-1", identity.Fingerprint(r.idPub), "epoch-A", 3, "nonce-1")
	pub, err := sshsig.Verify(blob, api.AttestNamespace, stmt)
	if err != nil {
		t.Fatalf("signature does not verify against the contract statement: %v", err)
	}
	if got := ssh.FingerprintSHA256(pub); got != resp.HostKeyFingerprint {
		t.Errorf("fingerprint %q vs %q", got, resp.HostKeyFingerprint)
	}
	pubFile, _ := os.ReadFile(filepath.Join(r.hostkeys, "ssh_host_ed25519_key.pub"))
	want, _, _, _, _ := ssh.ParseAuthorizedKey(pubFile)
	if ssh.FingerprintSHA256(want) != resp.HostKeyFingerprint {
		t.Error("signed with another key than the host key")
	}
	if resp.Attestations[0].Nonce != "nonce-1" || resp.Nonce != "nonce-1" {
		t.Error("nonce not echoed")
	}
	fi, err := os.Stat(filepath.Join(r.exchange, ResponseFile))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("response mode %v (%v), want 0644", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(r.exchange, RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("request file should be removed after answering")
	}
	// ssh-keygen agrees: it is a valid SSHSIG over the statement.
	sigFile := filepath.Join(t.TempDir(), "sig")
	_ = os.WriteFile(sigFile, []byte(sshsig.Armor(blob)), 0o600)
	cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", api.AttestNamespace, "-s", sigFile)
	cmd.Stdin = bytes.NewReader(stmt)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("ssh-keygen rejects the attestation: %v: %s", err, out)
	}
	// Nothing sensitive in the logs.
	if s := r.logs.String(); strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, identity.EncodePublicKey(r.idPub)) {
		t.Errorf("logs leak key material: %s", s)
	}
}

func TestPrefersEd25519OverRSA(t *testing.T) {
	r := newRig(t, "rsa", "ed25519")
	r.request(req1)
	r.a.Poll()
	resp, _ := r.response()
	if resp == nil || resp.HostKeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("response %+v", resp)
	}
}

func TestFallsBackToRSAWithSHA512(t *testing.T) {
	r := newRig(t, "rsa")
	r.request(req1)
	r.a.Poll()
	resp, _ := r.response()
	if resp == nil || resp.Error != "" || resp.HostKeyType != ssh.KeyAlgoRSA {
		t.Fatalf("response %+v", resp)
	}
	blob, _ := base64.StdEncoding.DecodeString(resp.Attestations[0].Signature)
	stmt := api.AttestStatement("teamspace", "dev-1", identity.Fingerprint(r.idPub), "epoch-A", 3, "nonce-1")
	if _, err := sshsig.Verify(blob, api.AttestNamespace, stmt); err != nil {
		t.Fatalf("rsa attestation does not verify: %v", err)
	}
}

func TestNoHostKeyAnswersWithError(t *testing.T) {
	r := newRig(t)
	_ = os.Remove(filepath.Join(r.hostkeys, "ssh_host_ed25519_key"))
	r.request(req1)
	r.a.Poll()
	resp, ok := r.response()
	if !ok || resp.Error == "" || len(resp.Attestations) != 0 || resp.Nonce != "nonce-1" {
		t.Fatalf("response %+v", resp)
	}
}

func TestMissingIdentityPubAnswersWithError(t *testing.T) {
	r := newRig(t)
	_ = os.Remove(filepath.Join(r.state, IdentityPubFile))
	r.request(req1)
	r.a.Poll()
	if resp, ok := r.response(); !ok || resp.Error == "" {
		t.Fatalf("response %+v", resp)
	}
}

func TestRateLimitOneSignaturePerTenSeconds(t *testing.T) {
	r := newRig(t)
	r.request(req1)
	r.a.Poll()
	if _, ok := r.response(); !ok {
		t.Fatal("first request not answered")
	}
	r.clearResponse()
	r.request(Request{Nonce: "nonce-2", Epoch: "epoch-A", Generation: 3})
	r.clk.add(9 * time.Second)
	r.a.Poll()
	if _, ok := r.response(); ok {
		t.Fatal("second signature within 10 s")
	}
	if _, err := os.Stat(filepath.Join(r.exchange, RequestFile)); err != nil {
		t.Fatal("a rate limited request must stay for a later poll")
	}
	r.clk.add(2 * time.Second)
	r.a.Poll()
	resp, ok := r.response()
	if !ok || resp.Nonce != "nonce-2" {
		t.Fatalf("second request not answered after the interval: %+v", resp)
	}
}

func TestSameRequestAnsweredOnce(t *testing.T) {
	r := newRig(t)
	r.request(req1)
	r.a.Poll()
	r.clearResponse()
	r.request(req1) // the agent re-wrote the identical request
	r.clk.add(time.Minute)
	r.a.Poll()
	if _, ok := r.response(); ok {
		t.Fatal("an answered request was signed again")
	}
}

func TestIgnoresBadRequests(t *testing.T) {
	cases := map[string]func(r *rig){
		"oversized": func(r *rig) {
			b := bytes.Repeat([]byte(" "), MaxRequestBytes+1)
			copy(b, `{"nonce":"n","epoch":"e","generation":1}`)
			_ = os.WriteFile(filepath.Join(r.exchange, RequestFile), b, 0o644)
		},
		"not json": func(r *rig) {
			_ = os.WriteFile(filepath.Join(r.exchange, RequestFile), []byte("nope"), 0o644)
		},
		"newline in nonce": func(r *rig) { r.request(Request{Nonce: "a\nb", Epoch: "e", Generation: 1}) },
		"empty nonce":      func(r *rig) { r.request(Request{Epoch: "e", Generation: 1}) },
		"negative generation": func(r *rig) {
			r.request(Request{Nonce: "n", Epoch: "e", Generation: -1})
		},
		"symlink": func(r *rig) {
			target := filepath.Join(t.TempDir(), "real.json")
			b, _ := json.Marshal(req1)
			_ = os.WriteFile(target, b, 0o644)
			_ = os.Symlink(target, filepath.Join(r.exchange, RequestFile))
		},
		"foreign owner": func(r *rig) {
			r.request(req1)
			r.a.cfg.AgentUIDs = []int{os.Getuid() + 1}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			setup(r)
			r.a.Poll()
			r.a.Poll()
			if resp, ok := r.response(); ok {
				t.Fatalf("answered a bad request: %+v", resp)
			}
		})
	}
}

func TestDirectoryAsRequestIsIgnored(t *testing.T) {
	r := newRig(t)
	if err := os.Mkdir(filepath.Join(r.exchange, RequestFile), 0o755); err != nil {
		t.Fatal(err)
	}
	r.a.Poll()
	if _, ok := r.response(); ok {
		t.Fatal("answered a directory")
	}
}

func TestConfigRequiresDeviceAndNamespace(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty config accepted")
	}
	if _, err := New(Config{Namespace: "a/b", DeviceID: "d"}); err == nil {
		t.Error("slash in namespace accepted")
	}
}

func TestExchangeEndToEnd(t *testing.T) {
	r := newRig(t)
	r.a.cfg.PollInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	resp, err := Exchange(ctx, r.exchange, req1, 5*time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Attestations) != 1 || resp.Attestations[0].Nonce != req1.Nonce {
		t.Fatalf("response %+v", resp)
	}
}

func TestExchangeTimeoutWithoutAttestor(t *testing.T) {
	_, err := Exchange(context.Background(), t.TempDir(), req1, 150*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestExchangeIgnoresStaleResponseOfAnotherNonce(t *testing.T) {
	dir := t.TempDir()
	stale, _ := json.Marshal(Response{Nonce: "old", Attestations: []Attestation{{Nonce: "old", Signature: "AA=="}}})
	_ = os.WriteFile(filepath.Join(dir, ResponseFile), stale, 0o644)
	// Exchange removes it; even if it could not, the nonce would not match.
	_, err := Exchange(context.Background(), dir, req1, 100*time.Millisecond, 10*time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestExchangeRefused(t *testing.T) {
	r := newRig(t)
	_ = os.Remove(filepath.Join(r.hostkeys, "ssh_host_ed25519_key"))
	r.a.cfg.PollInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	_, err := Exchange(ctx, r.exchange, req1, 5*time.Second, 10*time.Millisecond)
	var ref *Refused
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v, want *Refused", err)
	}
}

func TestExchangeRejectsHostileChallenge(t *testing.T) {
	if _, err := Exchange(context.Background(), t.TempDir(), Request{Nonce: "a\nb", Epoch: "e"}, time.Second, 0); err == nil {
		t.Error("newline nonce accepted")
	}
}

func TestValidToken(t *testing.T) {
	for s, want := range map[string]bool{"abc-DEF_1.2:=+/": true, "": false, "a b": false, "a\nb": false, strings.Repeat("a", 129): false, strings.Repeat("a", 128): true} {
		if ValidToken(s) != want {
			t.Errorf("ValidToken(%q) != %v", s, want)
		}
	}
}
