package hub

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// recTunnel records when peers are removed.
type recTunnel struct {
	Tunnel
	mu      sync.Mutex
	removed []time.Time
}

func (r *recTunnel) RemovePeer(pub wgkey.PublicKey) error {
	r.mu.Lock()
	r.removed = append(r.removed, time.Now())
	r.mu.Unlock()
	return r.Tunnel.RemovePeer(pub)
}

func (r *recTunnel) firstRemoval() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.removed) == 0 {
		return time.Time{}, false
	}
	return r.removed[0], true
}

// TestRevocationReachesTheClientBeforeThePeerIsRemoved covers every
// hub-initiated teardown: the closed stream's FIN/RST must travel through the
// still installed peer, so the client's own read of its dialed connection
// fails promptly (measured on the client side), and the peers are removed only
// after the flush grace.
func TestRevocationReachesTheClientBeforeThePeerIsRemoved(t *testing.T) {
	const grace = 300 * time.Millisecond
	cases := []struct {
		name    string
		trigger func(w *wgRig, client *wgPeer, sessionID string)
	}{
		{"device flagged compromised", func(w *wgRig, _ *wgPeer, _ string) {
			w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		}},
		{"health check failed", func(w *wgRig, _ *wgPeer, _ string) {
			w.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
		}},
		{"policy revoked", func(w *wgRig, _ *wgPeer, _ string) {
			p := w.policy
			p.State = api.StateRevoked
			w.setPolicy(p)
		}},
		{"port removed from policy", func(w *wgRig, _ *wgPeer, _ string) {
			p := w.policy
			p.AllowedPorts = []int{2222}
			w.setPolicy(p)
		}},
		{"device replaced", func(w *wgRig, _ *wgPeer, _ string) { _ = w.deviceSessionOK() }},
		{"reaper max age", func(w *wgRig, _ *wgPeer, _ string) {
			w.clock.Advance(13 * time.Hour)
			w.h.reap()
		}},
		{"renewal denied", func(w *wgRig, client *wgPeer, id string) {
			w.authz.set(aliceEmail, testNS, false)
			w.users.set(aliceToken, aliceEmail, w.clock.Now().Add(5*time.Minute)) // a refreshed token
			w.h.renewLimit.Forget(id)
			req, _ := http.NewRequest(http.MethodPost, "http://"+api.HubAddress+"/v1/renew", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+aliceToken)
			resp, err := client.httpClient().Do(req)
			if err != nil {
				t.Errorf("renew over the tunnel: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("renew status %d, want 403", resp.StatusCode)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec *recTunnel
			w := newWGDeviceRigHook(t, func(h *Hub) {
				rec = &recTunnel{Tunnel: h.tunnel}
				h.tunnel = rec
			}, func(c *Config) { c.FlushGrace = grace })
			client, cs, _, _ := w.connectClient(aliceToken, nil)
			if client == nil {
				t.Fatal("client session refused")
			}
			c, err := dialSplice(client)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			echo(t, c, "before")

			readErr := make(chan error, 1)
			go func() { _, err := c.Read(make([]byte, 1)); readErr <- err }()
			t0 := time.Now()
			tc.trigger(w, client, cs.SessionID)
			select {
			case err := <-readErr:
				if err == nil {
					t.Fatal("data on a revoked connection")
				}
				t.Logf("client read failed after %v: %v", time.Since(t0).Round(time.Millisecond), err)
			case <-time.After(time.Second):
				t.Fatalf("the client's dialed connection was still open 1s after the revocation (%s)", tc.name)
			}
			waitFor(t, "peer removal", func() bool { _, ok := rec.firstRemoval(); return ok })
			at, _ := rec.firstRemoval()
			if d := at.Sub(t0); d < grace-50*time.Millisecond {
				t.Fatalf("peer removed %v after the revocation, before the %v flush grace", d, grace)
			}
		})
	}
}

// TestHubCloseDeliversFIN checks the shutdown path: the stream closes before
// the peers go.
func TestHubCloseClosesStreams(t *testing.T) {
	w := newWGDeviceRig(t)
	client, _, _, _ := w.connectClient(aliceToken, nil)
	c, err := dialSplice(client)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	echo(t, c, "x")
	readErr := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); readErr <- err }()
	_ = w.h.Close()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("data after hub close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream still open after hub close")
	}
}

// rawTunnel returns the wireguard-go tunnel behind any test wrapper.
func rawTunnel(h *Hub) *wgTunnel {
	t := h.tunnel
	if r, ok := t.(*recTunnel); ok {
		t = r.Tunnel
	}
	return t.(*wgTunnel)
}
