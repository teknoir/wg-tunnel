package wgclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
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
	turnSecret = "test-turn-shared-secret"
	testNS     = "teknoir-demo"
	testDevice = "vdev-1"
)

type rig struct {
	turn *turntest.Server
	hub  *fakehub.Hub
}

func newRig(t *testing.T, o fakehub.Options) *rig {
	t.Helper()
	if o.TURNSecret == "" {
		o.TURNSecret = turnSecret
	}
	r := &rig{turn: turntest.Start(t, turnSecret), hub: fakehub.New(t, o)}
	r.hub.AddDevice(testNS, testDevice, fakehub.DeviceSpec{SkipAuth: true, AllowedPorts: []int{22}})
	return r
}

// deviceCred mints a (throwaway-key) identity JWT per call; the fake hub only
// reads its subject because the device is registered with SkipAuth.
func deviceCred(n *atomic.Int64) wgclient.Credential {
	_, priv, _ := ed25519.GenerateKey(nil)
	return func(_ context.Context, pub string) (string, error) {
		n.Add(1)
		tok, _, err := identity.MintIdentityJWT(priv, api.DeviceSubject(testNS, testDevice), pub, 30*time.Second)
		return tok, err
	}
}

// counter returns a Credential that yields a different token on every call.
func counter(prefix string, n *atomic.Int64) wgclient.Credential {
	return func(_ context.Context, _ string) (string, error) {
		return fmt.Sprintf("%s-%d", prefix, n.Add(1)), nil
	}
}

func (r *rig) turnAddr() string {
	if r.turn == nil {
		return ""
	}
	return r.turn.Addr
}

func (r *rig) deviceOpts(cred wgclient.Credential) wgclient.Options {
	return wgclient.Options{
		HubURL: r.hub.URL, Kind: api.KindDevice, Credential: cred,
		DeviceRequest: &api.DeviceSessionRequest{
			Posture:     api.Posture{Software: "wg-agent", Version: "test"},
			SSHHostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
		},
		TURNServerOverride: r.turnAddr(),
		HandshakeTimeout:   10 * time.Second,
		RenewRetry:         200 * time.Millisecond,
	}
}

func (r *rig) clientOpts(cred wgclient.Credential) wgclient.Options {
	return wgclient.Options{
		HubURL: r.hub.URL, Kind: api.KindClient, Credential: cred,
		ClientRequest: &api.ClientSessionRequest{
			Namespace: testNS, Device: testDevice, Port: 22,
			Posture: api.Posture{Software: "tnctl", Version: "test"},
		},
		TURNServerOverride: r.turnAddr(),
		HandshakeTimeout:   10 * time.Second,
		RenewRetry:         200 * time.Millisecond,
	}
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func create(t *testing.T, o wgclient.Options) *wgclient.Session {
	t.Helper()
	s, err := wgclient.Create(ctxT(t), o)
	if err != nil {
		t.Fatalf("Create(%s): %v", o.Kind, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// echoOn serves an echo server on port of a device session.
func echoOn(t *testing.T, s *wgclient.Session, port int) {
	t.Helper()
	l, err := s.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
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
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
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

// syncBuffer is a goroutine-safe log sink.
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
