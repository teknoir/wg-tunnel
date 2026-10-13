package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/internal/turntest"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const (
	ns      = "teknoir-demo"
	dev     = "vdev-1"
	hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	secret  = "wg-connect-test-secret"
)

func TestParseArgs(t *testing.T) {
	base := []string{"--hub-url", "https://wg.example.com", "--namespace", ns, "--device", dev, "--known-hosts-file", "/tmp/kh"}
	with := func(extra ...string) []string { return append(append([]string(nil), base...), extra...) }
	ok := [][]string{
		with("--keycloak-token-file", "/t"),
		with("--sa-token-file", "/t", "--on-behalf-of", "user@example.com", "--port", "2222"),
		with("--keycloak-token-file", "/t", "--direct"),
		with("--keycloak-token-file", "/t", "--turn-server", "192.168.2.166:3478"),
	}
	for _, a := range ok {
		if _, err := parseArgs(a, io.Discard); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	o, _ := parseArgs(with("--keycloak-token-file", "/t"), io.Discard)
	if o.port != 22 || o.direct {
		t.Errorf("defaults: %+v", o)
	}
	bad := map[string][]string{
		"no token":            base,
		"both tokens":         with("--keycloak-token-file", "/t", "--sa-token-file", "/s", "--on-behalf-of", "a@b.c"),
		"sa without email":    with("--sa-token-file", "/s"),
		"email without sa":    with("--keycloak-token-file", "/t", "--on-behalf-of", "a@b.c"),
		"bad email":           with("--sa-token-file", "/s", "--on-behalf-of", "not an email"),
		"newline email":       with("--sa-token-file", "/s", "--on-behalf-of", "a@b.c\nx"),
		"direct and turn":     with("--keycloak-token-file", "/t", "--direct", "--turn-server", "1.2.3.4:3478"),
		"port 0":              with("--keycloak-token-file", "/t", "--port", "0"),
		"port 70000":          with("--keycloak-token-file", "/t", "--port", "70000"),
		"extra arg":           with("--keycloak-token-file", "/t", "extra"),
		"token on cmdline":    with("--token", "abc"),
		"bearer on cmdline":   with("--keycloak-token", "abc"),
		"no hub":              {"--namespace", ns, "--device", dev, "--known-hosts-file", "/k", "--keycloak-token-file", "/t"},
		"no namespace":        {"--hub-url", "https://x", "--device", dev, "--known-hosts-file", "/k", "--keycloak-token-file", "/t"},
		"upper-case device":   with("--keycloak-token-file", "/t", "--device", "Dev"),
		"wildcard device":     {"--hub-url", "https://x", "--namespace", ns, "--device", "a*", "--known-hosts-file", "/k", "--keycloak-token-file", "/t"},
		"space in namespace":  {"--hub-url", "https://x", "--namespace", "a b", "--device", dev, "--known-hosts-file", "/k", "--keycloak-token-file", "/t"},
		"no known hosts file": {"--hub-url", "https://x", "--namespace", ns, "--device", dev, "--keycloak-token-file", "/t"},
	}
	for name, a := range bad {
		if _, err := parseArgs(a, io.Discard); err == nil {
			t.Errorf("%s: accepted %v", name, a)
		}
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"--bogus"}, strings.NewReader(""), io.Discard, &stderr); code != exitUsage {
		t.Errorf("usage error exit code = %d", code)
	}
	if code := run(context.Background(), with("--keycloak-token-file", "/t", "--ca-file", "/does/not/exist"), strings.NewReader(""), io.Discard, &stderr); code != exitUsage {
		t.Errorf("bad CA file exit code = %d", code)
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("  abc.def \n")
	if got, err := readToken(p); err != nil || got != "abc.def" {
		t.Fatalf("%q %v", got, err)
	}
	write("rotated\n") // every call re-reads
	if got, _ := readToken(p); got != "rotated" {
		t.Fatalf("not re-read: %q", got)
	}
	write("   \n")
	if _, err := readToken(p); err == nil {
		t.Error("empty token accepted")
	}
	write(strings.Repeat("a", 20_000))
	if _, err := readToken(p); err == nil {
		t.Error("huge token accepted")
	}
	if _, err := readToken(filepath.Join(dir, "missing")); err == nil || strings.Contains(err.Error(), dir) {
		t.Errorf("missing file error: %v", err)
	}
}

type rig struct {
	turn  *turntest.Server
	hub   *fakehub.Hub
	kh    string
	token string
	// atAccept records whether known_hosts already existed when the device's
	// echo server accepted the first connection.
	atAccept atomic.Int32 // 0 none, 1 existed, 2 missing
	// silent makes the device close every connection at once, like a hub
	// refusal does from the client's point of view (no byte ever arrives).
	silent atomic.Bool
}

func newRig(t *testing.T, ho fakehub.Options, withTURN bool) *rig {
	t.Helper()
	r := &rig{}
	if withTURN {
		ho.TURNSecret = secret
		r.turn = turntest.Start(t, secret)
	}
	r.hub = fakehub.New(t, ho)
	r.hub.AddDevice(ns, dev, fakehub.DeviceSpec{SkipAuth: true, AllowedPorts: []int{22}})
	dir := t.TempDir()
	r.kh = filepath.Join(dir, "ssh", "known_hosts")
	r.token = filepath.Join(dir, "token")
	r.setToken(t, "user-token-1")

	_, priv, _ := ed25519.GenerateKey(nil)
	opts := wgclient.Options{
		HubURL: r.hub.URL, Kind: api.KindDevice,
		Credential: func(_ context.Context, pub string) (string, error) {
			tok, _, err := identity.MintIdentityJWT(priv, api.DeviceSubject(ns, dev), pub, 30*time.Second)
			return tok, err
		},
		DeviceRequest: &api.DeviceSessionRequest{Posture: api.Posture{Software: "wg-agent"}, SSHHostKeys: []string{hostKey + " root@box"}},
		Direct:        !withTURN,
	}
	if withTURN {
		opts.TURNServerOverride = r.turn.Addr
	}
	ds, err := wgclient.Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("device session: %v", err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	l, err := ds.Listen(22)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if _, err := os.Stat(r.kh); err == nil {
				r.atAccept.CompareAndSwap(0, 1)
			} else {
				r.atAccept.CompareAndSwap(0, 2)
			}
			go func() {
				defer func() { _ = c.Close() }()
				if r.silent.Load() {
					return
				}
				_, _ = io.Copy(c, c) // "sshd": echoes
			}()
		}
	}()
	return r
}

func (r *rig) setToken(t *testing.T, tok string) {
	t.Helper()
	if err := os.WriteFile(r.token, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) args(extra ...string) []string {
	a := []string{"--hub-url", r.hub.URL, "--namespace", ns, "--device", dev, "--known-hosts-file", r.kh, "--keycloak-token-file", r.token}
	if r.turn != nil {
		a = append(a, "--turn-server", r.turn.Addr)
	} else {
		a = append(a, "--direct")
	}
	return append(a, extra...)
}

type result struct {
	code   int
	stdout *lockedBuf
	stderr *lockedBuf
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func start(t *testing.T, args []string) (stdin *io.PipeWriter, res *result, done <-chan struct{}) {
	t.Helper()
	pr, pw := io.Pipe()
	res = &result{stdout: &lockedBuf{}, stderr: &lockedBuf{}}
	d := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = pw.Close() })
	go func() {
		res.code = run(ctx, args, pr, res.stdout, res.stderr)
		close(d)
	}()
	return pw, res, d
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRelaysStdioAndWritesKnownHostsFirst(t *testing.T) {
	for _, withTURN := range []bool{true, false} {
		name := "turn"
		if !withTURN {
			name = "direct"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t, fakehub.Options{}, withTURN)
			stdin, res, done := start(t, r.args())

			if _, err := stdin.Write([]byte("SSH-2.0-OpenSSH_test\r\n")); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 15*time.Second, "echo on stdout", func() bool { return strings.Contains(res.stdout.String(), "SSH-2.0-OpenSSH_test") })
			if r.atAccept.Load() != 1 {
				t.Fatalf("known_hosts existed when the device saw the first byte: state %d (2 = missing)", r.atAccept.Load())
			}
			b, err := os.ReadFile(r.kh)
			if err != nil {
				t.Fatal(err)
			}
			if want := api.KnownHostsAlias(ns, dev) + " " + hostKey + "\n"; string(b) != want {
				t.Fatalf("known_hosts = %q, want %q", b, want)
			}
			if fi, _ := os.Stat(r.kh); fi.Mode().Perm() != 0o600 {
				t.Fatalf("known_hosts mode %v", fi.Mode().Perm())
			}
			// ssh closing its stdin ends the proxy cleanly.
			_ = stdin.Close()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("did not exit after stdin EOF")
			}
			if res.code != exitOK || res.stderr.String() != "" {
				t.Fatalf("exit %d, stderr %q", res.code, res.stderr.String())
			}
			waitFor(t, 5*time.Second, "client session closed at the hub", func() bool { return len(r.hub.SessionIDs(api.KindClient)) == 0 })
		})
	}
}

func TestTokenFileIsReReadForEveryCall(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second}, true)
	stdin, _, done := start(t, r.args())
	defer func() { _ = stdin.Close(); <-done }()
	waitFor(t, 15*time.Second, "client session", func() bool { return len(r.hub.SessionIDs(api.KindClient)) == 1 })

	r.setToken(t, "user-token-2") // projected token rotated
	waitFor(t, 10*time.Second, "renewal with the rotated token", func() bool {
		for _, c := range r.hub.Calls() {
			if c.Kind == api.KindClient && c.Path == api.RenewPath && c.Bearer == "user-token-2" {
				return true
			}
		}
		return false
	})
	var sawFirst bool
	for _, c := range r.hub.Calls() {
		if c.Kind == api.KindClient && c.Path == api.ClientSessionPath && c.Bearer == "user-token-1" {
			sawFirst = true
		}
	}
	if !sawFirst {
		t.Fatal("session was not created with the first token")
	}
}

func TestSATokenSendsOnBehalfOf(t *testing.T) {
	r := newRig(t, fakehub.Options{}, true)
	if err := os.Rename(r.token, r.token+".sa"); err != nil {
		t.Fatal(err)
	}
	args := []string{"--hub-url", r.hub.URL, "--namespace", ns, "--device", dev, "--known-hosts-file", r.kh,
		"--sa-token-file", r.token + ".sa", "--on-behalf-of", "claude-agent@teknoir.cloud", "--turn-server", r.turn.Addr}
	in2, res2, done2 := start(t, args)
	defer func() { _ = in2.Close(); <-done2 }()
	waitFor(t, 15*time.Second, "client session", func() bool { return len(r.hub.SessionIDs(api.KindClient)) == 1 })
	var onBehalf string
	for _, c := range r.hub.Calls() {
		if c.Path == api.ClientSessionPath {
			onBehalf = c.OnBehalf
		}
	}
	if onBehalf != "claude-agent@teknoir.cloud" {
		t.Fatalf("onBehalfOf at hub = %q (stderr %q)", onBehalf, res2.stderr.String())
	}
}

func TestDenialPrintsOneLineAndForwardsNothing(t *testing.T) {
	r := newRig(t, fakehub.Options{}, true)
	r.hub.SetOnCreate(func(fakehub.Call) *fakehub.Denial {
		return &fakehub.Denial{Status: 403, Reason: api.ReasonDeviceRevoked}
	})
	var read atomic.Bool
	stdin := readTracker{r: strings.NewReader("never forwarded"), read: &read}
	var out, errb bytes.Buffer
	code := run(context.Background(), r.args(), stdin, &out, &errb)
	if code != exitFail {
		t.Fatalf("exit %d", code)
	}
	msg := errb.String()
	if strings.Count(msg, "\n") != 1 || !strings.HasPrefix(msg, "wg-connect: ") || !strings.Contains(msg, api.ReasonDeviceRevoked) {
		t.Fatalf("stderr = %q", msg)
	}
	if strings.Contains(msg, "user-token") {
		t.Fatalf("stderr leaks the token: %q", msg)
	}
	if _, err := os.Stat(r.kh); err == nil {
		t.Fatal("known_hosts written for a denied session")
	}
	if read.Load() || out.Len() != 0 || r.atAccept.Load() != 0 {
		t.Fatal("bytes were forwarded for a denied session")
	}
}

type readTracker struct {
	r    io.Reader
	read *atomic.Bool
}

func (t readTracker) Read(p []byte) (int, error) { t.read.Store(true); return t.r.Read(p) }

func TestMissingTokenFileFails(t *testing.T) {
	r := newRig(t, fakehub.Options{}, true)
	if err := os.Remove(r.token); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	code := run(context.Background(), r.args(), strings.NewReader(""), io.Discard, &errb)
	if code != exitFail || strings.Count(errb.String(), "\n") != 1 || !strings.Contains(errb.String(), "token file") {
		t.Fatalf("exit %d stderr %q", code, errb.String())
	}
}

func TestRevocationEndsTheProxy(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second}, true)
	stdin, res, done := start(t, r.args())
	defer func() { _ = stdin.Close() }()
	if _, err := stdin.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "echo", func() bool { return strings.Contains(res.stdout.String(), "hello") })

	r.hub.SetOnRenew(func(c fakehub.Call) *fakehub.Denial {
		if c.Kind == api.KindClient {
			return &fakehub.Denial{Status: 403, Reason: api.ReasonDeviceRevoked}
		}
		return nil
	})
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("wg-connect kept running after the hub revoked the session")
	}
	if res.code != exitFail || !strings.Contains(res.stderr.String(), api.ReasonDeviceRevoked) || strings.Count(res.stderr.String(), "\n") != 1 {
		t.Fatalf("exit %d, stderr %q", res.code, res.stderr.String())
	}
}

func TestHubKilledConnectionExitsWhenConnCloses(t *testing.T) {
	r := newRig(t, fakehub.Options{}, true)
	stdin, res, done := start(t, r.args())
	defer func() { _ = stdin.Close() }()
	_, _ = stdin.Write([]byte("x"))
	waitFor(t, 15*time.Second, "echo", func() bool { return res.stdout.String() == "x" })
	for _, id := range r.hub.SessionIDs(api.KindClient) {
		r.hub.KillSession(id) // closes the spliced connection at the hub
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("did not exit when the connection closed")
	}
	if res.code == exitOK && res.stderr.String() != "" {
		t.Fatalf("exit 0 with stderr %q", res.stderr.String())
	}
}

// A stream that ends before the device said a byte is a refusal by the hub
// (offline device, revoked port or access, connection limit): ssh must not be
// left with a silent exit 0.
func TestStreamClosedBeforeAnyByteIsAnError(t *testing.T) {
	r := newRig(t, fakehub.Options{}, true)
	r.silent.Store(true)
	var out, errb bytes.Buffer
	pr, pw := io.Pipe() // ssh keeps its end open while it waits for the banner
	defer func() { _ = pw.Close() }()
	done := make(chan int, 1)
	go func() { done <- run(context.Background(), r.args(), pr, &out, &errb) }()
	var code int
	select {
	case code = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("did not exit")
	}
	if code != exitFail {
		t.Fatalf("exit %d; a refused stream must not look like success", code)
	}
	msg := errb.String()
	if strings.Count(msg, "\n") != 1 || !strings.HasPrefix(msg, "wg-connect: the hub closed the connection before the device answered") {
		t.Fatalf("stderr = %q", msg)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
}
