package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/internal/turntest"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const (
	testNS     = "teknoir-demo"
	testDevice = "vdev-1"
	turnSecret = "agent-test-secret"
)

var (
	rsaOnce    sync.Once
	rsaKeyPEM  []byte
	rsaCertPEM []byte
)

// deviceRSA returns a shared RSA device key (PKCS#1 PEM) and its public PEM.
func deviceRSA(t testing.TB) (priv, pub []byte) {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		rsaCertPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	})
	return rsaKeyPEM, rsaCertPEM
}

type rig struct {
	t       *testing.T
	turn    *turntest.Server
	hub     *fakehub.Hub
	dir     string // temp root
	idDir   string
	rsaPath string
	hkGlob  string
	logs    *syncBuffer
	echo    net.Listener
	port    int
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newRig starts TURN, the fake hub (device enrollable, one allowed port that
// leads to a local echo server) and writes the device RSA key and SSH host keys.
func newRig(t *testing.T, ho fakehub.Options) *rig {
	t.Helper()
	ho.TURNSecret = turnSecret
	r := &rig{t: t, turn: turntest.Start(t, turnSecret), hub: fakehub.New(t, ho), dir: t.TempDir(), logs: &syncBuffer{}}
	r.idDir = filepath.Join(r.dir, "identity")
	r.rsaPath = filepath.Join(r.dir, "rsa_private.pem")
	rsaPriv, rsaPub := deviceRSA(t)
	if err := os.WriteFile(r.rsaPath, rsaPriv, 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	r.echo, r.port = l, l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	hk := filepath.Join(r.dir, "ssh")
	if err := os.MkdirAll(hk, 0o755); err != nil {
		t.Fatal(err)
	}
	writeHostKey(t, filepath.Join(hk, "ssh_host_ed25519_key.pub"), " root@host\n")
	r.hkGlob = filepath.Join(hk, "ssh_host_*_key.pub")

	r.hub.AddDevice(testNS, testDevice, fakehub.DeviceSpec{RSACertPEM: rsaPub, AllowedPorts: []int{r.port}, EnrollOpen: true})
	return r
}

func writeHostKey(t testing.TB, path, comment string) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sp)) // "ssh-ed25519 AAAA...\n"
	if err := os.WriteFile(path, []byte(line[:len(line)-1]+comment), 0o644); err != nil {
		t.Fatal(err)
	}
	return line[:len(line)-1]
}

func (r *rig) config() Config {
	return Config{
		DeviceID: testDevice, Namespace: testNS, HubURL: r.hub.URL,
		RSAKeyPath: r.rsaPath, IdentityDir: r.idDir, SSHHostKeysGlob: r.hkGlob,
		TURNServer: r.turn.Addr,
		Logger:     slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Backoff:    Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond, Stable: time.Minute},
		RenewRetry: 200 * time.Millisecond, RenewTimeout: 400 * time.Millisecond,
		HandshakeTimeout: 10 * time.Second,
	}
}

// start runs an agent until the returned stop func is called (which also
// returns Run's error).
func (r *rig) start(cfg Config) (a *Agent, stop func() error) {
	r.t.Helper()
	a, err := New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	var once sync.Once
	var res error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case res = <-done:
			case <-time.After(15 * time.Second):
				r.t.Error("agent did not stop")
			}
		})
		return res
	}
	r.t.Cleanup(func() { _ = stop() })
	return a, stop
}

// waitTunnelUp waits until the agent has logged n established sessions, i.e.
// until its WireGuard handshake with the hub completed. The hub lists a device
// session as soon as it answers the create request, which is BEFORE the agent
// has a tunnel: stopping the agent in that window cannot send the in-tunnel
// close (there is no tunnel yet), so the hub keeps the session until it expires.
// A test that expects shutdown to close the hub session must wait for this first.
func (r *rig) waitTunnelUp(t *testing.T, n int) {
	t.Helper()
	eventually(t, 15*time.Second, "the agent's tunnel to come up", func() bool {
		return strings.Count(r.logs.String(), "wireguard session established") >= n
	})
}

func (r *rig) clientSession(t *testing.T) *wgclient.Session {
	t.Helper()
	var n atomic.Int64
	s, err := wgclient.Create(ctxT(t), wgclient.Options{
		HubURL: r.hub.URL, Kind: api.KindClient,
		Credential: func(context.Context, string) (string, error) { return "user-token-" + string(rune('a'+n.Add(1))), nil },
		ClientRequest: &api.ClientSessionRequest{
			Namespace: testNS, Device: testDevice, Port: r.port, Posture: api.Posture{Software: "tnctl", Version: "test"},
		},
		TURNServerOverride: r.turn.Addr,
	})
	if err != nil {
		t.Fatalf("client Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
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

func roundTrip(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return io.ErrUnexpectedEOF
	}
	return nil
}
