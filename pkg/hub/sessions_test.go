package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

func hostKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestDeviceSessionCreate(t *testing.T) {
	r := newRig(t)
	good := hostKey(t)
	s := r.deviceSessionOK(good+" root@host", "not a key", "ssh-ed25519 AAAA", `command="x" `+good)
	if s.Kind != api.KindDevice || s.HubAddress != api.HubAddress || s.MTU != api.MTU || s.RenewAfterSeconds != 60 {
		t.Fatalf("response %+v", s.SessionResponse)
	}
	if !netip.MustParsePrefix(api.OverlayPrefix).Contains(netip.MustParseAddr(s.Address)) || s.Address == api.HubAddress {
		t.Fatalf("address %s", s.Address)
	}
	if s.HubPublicKey != r.tun.pub.Base64() || s.HubEndpoint != "10.1.2.3:51820" {
		t.Fatalf("hub key/endpoint %s %s", s.HubPublicKey, s.HubEndpoint)
	}
	if len(s.AllowedPorts) != 1 || s.AllowedPorts[0] != 22 {
		t.Fatalf("allowed ports %v", s.AllowedPorts)
	}
	if want := r.clock.Now().Add(3 * time.Minute); !s.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", s.ExpiresAt, want)
	}
	if s.TURN == nil || len(s.TURN.URLs) != 1 || !strings.HasPrefix(s.TURN.Username, fmt.Sprintf("%d:%s/", s.TURN.ExpiresAt.Unix(), testNS)) ||
		!strings.HasSuffix(s.TURN.Username, "/"+s.SessionID) {
		t.Fatalf("TURN %+v", s.TURN)
	}
	if !s.TURN.ExpiresAt.Equal(r.clock.Now().Add(30 * time.Minute)) {
		t.Fatalf("TURN expiry %v", s.TURN.ExpiresAt)
	}
	if r.tun.peerCount() != 1 || r.tun.peers[s.pub].String() != s.Address {
		t.Fatalf("peers %v", r.tun.peers)
	}
	// Only the valid, option-free host key survives, once, without the comment.
	live := r.h.deviceSession(testNS, testDevice)
	if len(live.hostKeys) != 1 || live.hostKeys[0] != strings.TrimSpace(good) {
		t.Fatalf("host keys %q", live.hostKeys)
	}
}

func TestDeviceSessionRequiresEnrollment(t *testing.T) {
	r := newRig(t)
	tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
	st, body := r.post(api.DeviceSessionPath, tok, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonNotEnrolled)
}

func TestDeviceSessionRejects(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	now := r.clock.Now()

	t.Run("token signed by an unpinned identity", func(t *testing.T) {
		o := newDeviceCreds(t)
		tok, req, _ := o.sessionRequest(t, now)
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("legacy RSA enrollment token cannot open a session", func(t *testing.T) {
		tok, _ := r.dev.enrollRequest(t, now)
		_, req, _ := r.dev.sessionRequest(t, now)
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("token bound to another WireGuard key", func(t *testing.T) {
		tok, req, _ := r.dev.sessionRequest(t, now)
		_, other, _ := wgkey.Generate()
		req.WGPublicKey = other.Base64()
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("replayed token", func(t *testing.T) {
		tok, req, _ := r.dev.sessionRequest(t, now)
		if st, body := r.post(api.DeviceSessionPath, tok, req); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		// Same token, even with a fresh WG key bound... it is bound, so reuse the request.
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonReplay)
	})
	t.Run("expired token", func(t *testing.T) {
		tok, req, _ := r.dev.sessionRequest(t, now.Add(-5*time.Minute))
		st, body := r.post(api.DeviceSessionPath, tok, req)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("duplicate WireGuard key", func(t *testing.T) {
		tok, req, _ := r.dev.sessionRequest(t, now)
		if st, body := r.post(api.DeviceSessionPath, tok, req); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		// A client that submits the device's public key must not hijack its peer.
		creq, _ := r.clientReq(22)
		creq.WGPublicKey = req.WGPublicKey
		st, body := r.clientSession(aliceToken, creq)
		wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	})
	t.Run("hub's own key", func(t *testing.T) {
		tok, req, _ := r.dev.sessionRequest(t, now)
		req.WGPublicKey = r.tun.pub.Base64()
		st, _ := r.post(api.DeviceSessionPath, tok, req)
		if st == http.StatusCreated {
			t.Fatal("hub key accepted")
		}
	})
}

func TestDeviceSessionStateDenials(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rig)
		reason string
	}{
		{"compromised flag", func(r *rig) {
			r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
		}, api.ReasonDeviceRevoked},
		{"health check failed flag", func(r *rig) {
			r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"})
		}, api.ReasonDeviceRevoked},
		{"wireguard not enabled", func(r *rig) { r.flags.Set(testNS, testDevice, map[string]string{}) }, api.ReasonDeviceDisabled},
		{"device deleted", func(r *rig) { r.flags.Delete(testNS, testDevice) }, api.ReasonDeviceUnknown},
		{"policy revoked by controller", func(r *rig) { p := r.policy; p.State = api.StateRevoked; r.setPolicy(p) }, api.ReasonDeviceRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.enrollOK()
			tc.mutate(r)
			tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
			st, body := r.post(api.DeviceSessionPath, tok, req)
			wantReason(t, st, body, http.StatusForbidden, tc.reason)
			if r.tun.peerCount() != 0 {
				t.Fatal("no peer may be installed for a denied session")
			}
		})
	}
}

func TestDeviceSessionReplacesPrevious(t *testing.T) {
	r := newRig(t)
	first := r.deviceSessionOK()
	second := r.deviceSessionOK()
	if first.SessionID == second.SessionID || first.Address == second.Address {
		t.Fatal("a new session must get a new id and address")
	}
	// The old peer is removed after the flush grace, synchronously.
	waitFor(t, "old peer removal", func() bool { return r.tun.peerCount() == 1 })
	if _, ok := r.tun.peers[first.pub]; ok {
		t.Fatal("old peer still installed")
	}
	order := strings.Join(r.tun.order, ",")
	if !strings.Contains(order, "add "+second.Address) || !strings.Contains(order, "remove "+first.Address) {
		t.Fatalf("order %s", order)
	}
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatalf("device sessions %d", d)
	}
	// The old overlay address is quarantined, not reusable at once. (It is
	// released right after its peer was removed.)
	waitFor(t, "old address released", func() bool { return r.h.ipam.InUse() == 1 })
}

func TestClientSessionHappyPath(t *testing.T) {
	r := newRig(t)
	good := hostKey(t)
	dev := r.deviceSessionOK(good)
	req, _ := r.clientReq(22)
	st, body := r.clientSession(aliceToken, req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var c api.SessionResponse
	_ = json.Unmarshal(body, &c)
	if c.Kind != api.KindClient || c.SplicePort != api.HubSplicePort || c.TargetPort != 22 || c.TURN == nil {
		t.Fatalf("response %+v", c)
	}
	if len(c.SSHHostKeys) != 1 || c.SSHHostKeys[0] != good {
		t.Fatalf("host keys %v", c.SSHHostKeys)
	}
	if c.Address == dev.Address {
		t.Fatal("client and device share an address")
	}
	if want := r.clock.Now().Add(3 * time.Minute); !c.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v", c.ExpiresAt)
	}
}

func TestClientSessionDenials(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.users.set("bob-token", "bob@example.com", r.clock.Now().Add(time.Minute))

	post := func(tok string, mut func(*api.ClientSessionRequest)) (int, []byte) {
		req, _ := r.clientReq(22)
		if mut != nil {
			mut(&req)
		}
		return r.clientSession(tok, req)
	}
	t.Run("no token", func(t *testing.T) {
		st, body := post("", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("bad token", func(t *testing.T) {
		st, body := post("garbage", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("user without access to the teamspace", func(t *testing.T) {
		st, body := post("bob-token", nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	})
	t.Run("port not allowed", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.Port = 8080 })
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPortNotAllowed)
	})
	t.Run("invalid port", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.Port = 70000 })
		wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	})
	t.Run("invalid device name", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.Device = "Cam/1" })
		wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	})
	t.Run("direct without delegation", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.Direct = true })
		wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	})
	t.Run("onBehalfOf with a Keycloak token", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.OnBehalfOf = "bob@example.com" })
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("onBehalfOf malformed", func(t *testing.T) {
		st, body := post("sa-token", func(q *api.ClientSessionRequest) { q.OnBehalfOf = "Bob@Example.com" })
		wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	})
	t.Run("posture", func(t *testing.T) {
		st, body := post(aliceToken, func(q *api.ClientSessionRequest) { q.Posture.Software = "wg-agent" })
		wantReason(t, st, body, http.StatusForbidden, api.ReasonPosture)
	})
	t.Run("unknown device does not reveal itself to non-members", func(t *testing.T) {
		st, body := post("bob-token", func(q *api.ClientSessionRequest) { q.Device = "no-such" })
		wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	})
	t.Run("authorization backend down", func(t *testing.T) {
		r.authz.mu.Lock()
		r.authz.err = ErrUnavailable
		r.authz.mu.Unlock()
		defer func() { r.authz.mu.Lock(); r.authz.err = nil; r.authz.mu.Unlock() }()
		st, _ := post(aliceToken, nil)
		if st != http.StatusServiceUnavailable {
			t.Fatalf("status %d", st)
		}
	})
	if _, c := r.h.sessionCounts(); c != 0 {
		t.Fatalf("%d client sessions leaked from denied requests", c)
	}
}

func TestClientSessionDeviceStates(t *testing.T) {
	r := newRig(t)
	// No device session yet.
	req, _ := r.clientReq(22)
	st, body := r.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusConflict, api.ReasonDeviceOffline)

	r.deviceSessionOK()
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	req, _ = r.clientReq(22)
	st, body = r.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceRevoked)
}

func TestClientSessionKeycloakTokenExpiryCapsSession(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.users.set("short", aliceEmail, r.clock.Now().Add(30*time.Second))
	req, _ := r.clientReq(22)
	st, body := r.clientSession("short", req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var c api.SessionResponse
	_ = json.Unmarshal(body, &c)
	// token exp (+30s) + 3m grace is earlier than now + 3m? no: +3m30s > +3m, so the TTL wins.
	if want := r.clock.Now().Add(3 * time.Minute); !c.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", c.ExpiresAt, want)
	}
	// An already-expired-but-within-skew token is capped to exp+3m < now+3m.
	r.users.set("stale", aliceEmail, r.clock.Now().Add(-20*time.Second))
	req, _ = r.clientReq(22)
	st, body = r.clientSession("stale", req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	_ = json.Unmarshal(body, &c)
	if want := r.clock.Now().Add(-20*time.Second + 3*time.Minute); !c.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", c.ExpiresAt, want)
	}
}

func TestClientSessionDelegationAndDirect(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.sa.add("sa-token", "term-cam-1", testNS, testDevice)
	r.sa.add("sa-other", "term-cam-2", testNS, "cam-2")

	req, _ := r.clientReq(22)
	req.OnBehalfOf = aliceEmail
	req.Direct = true
	req.Posture.Software = "web-terminal"
	st, body := r.clientSession("sa-token", req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var c api.SessionResponse
	_ = json.Unmarshal(body, &c)
	if c.TURN != nil {
		t.Fatal("direct sessions get no TURN credentials")
	}
	if c.HubEndpoint != "10.1.2.3:51820" {
		t.Fatalf("endpoint %s", c.HubEndpoint)
	}

	// The SA is bound to one device only.
	req2, _ := r.clientReq(22)
	req2.OnBehalfOf = aliceEmail
	st, body = r.clientSession("sa-other", req2)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)

	// The SA acts for a user, but the user is still authorized by SAR.
	r.authz.set("mallory@example.com", testNS, false)
	req3, _ := r.clientReq(22)
	req3.OnBehalfOf = "mallory@example.com"
	st, body = r.clientSession("sa-token", req3)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)

	// Delegating without Direct still yields TURN credentials.
	req4, _ := r.clientReq(22)
	req4.OnBehalfOf = aliceEmail
	st, body = r.clientSession("sa-token", req4)
	_ = json.Unmarshal(body, &c)
	if st != http.StatusCreated || c.TURN == nil {
		t.Fatalf("%d %s", st, body)
	}
}

func TestSessionLimits(t *testing.T) {
	t.Run("per subject and device", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		for range 5 {
			r.clientSessionOK()
		}
		req, _ := r.clientReq(22)
		st, body := r.clientSession(aliceToken, req)
		wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonSessionLimit)
		// Another user is unaffected.
		r.users.set("carol", "carol@example.com", r.clock.Now().Add(time.Minute))
		r.authz.set("carol@example.com", testNS, true)
		req, _ = r.clientReq(22)
		if st, body = r.clientSession("carol", req); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		// Ending a session frees a slot.
		r.h.mu.Lock()
		var one *session
		for _, s := range r.h.clients[devKey{testNS, testDevice}] {
			if s.subject == aliceEmail {
				one = s
				break
			}
		}
		r.h.mu.Unlock()
		r.h.endSession(one, "test")
		r.clientSessionOK()
	})
	t.Run("per namespace", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.MaxPerNamespace = 3 })
		r.deviceSessionOK()
		r.clientSessionOK()
		r.clientSessionOK()
		req, _ := r.clientReq(22)
		st, body := r.clientSession(aliceToken, req)
		wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonSessionLimit)
	})
	t.Run("global", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.MaxSessions = 2 })
		r.deviceSessionOK()
		r.clientSessionOK()
		req, _ := r.clientReq(22)
		st, body := r.clientSession(aliceToken, req)
		wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonSessionLimit)
	})
	t.Run("a failed admission leaks neither peer nor address", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.MaxSessions = 1 })
		r.deviceSessionOK()
		before := r.h.ipam.InUse()
		req, _ := r.clientReq(22)
		r.clientSession(aliceToken, req)
		if r.h.ipam.InUse() != before || r.tun.peerCount() != 1 {
			t.Fatal("denied admission leaked state")
		}
	})
}

func TestRateLimitsApplyBeforeAllocation(t *testing.T) {
	t.Run("per source IP", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.IPRate = 0.001; c.IPBurst = 3 })
		r.enrollOK() // 1
		var last int
		var lastBody []byte
		for range 5 {
			tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
			last, lastBody = r.post(api.DeviceSessionPath, tok, req)
		}
		wantReason(t, last, lastBody, http.StatusTooManyRequests, api.ReasonRateLimited)
		if r.tun.adds > 2 {
			t.Fatalf("%d peers installed; limited requests must not allocate", r.tun.adds)
		}
	})
	t.Run("per subject", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.SubjectRate = 0.001; c.SubjectBurst = 2 })
		r.deviceSessionOK()
		var last int
		var lastBody []byte
		for range 4 {
			req, _ := r.clientReq(22)
			last, lastBody = r.clientSession(aliceToken, req)
		}
		wantReason(t, last, lastBody, http.StatusTooManyRequests, api.ReasonRateLimited)
		// A different user is not limited by alice's bucket.
		r.users.set("carol", "carol@example.com", r.clock.Now().Add(time.Minute))
		r.authz.set("carol@example.com", testNS, true)
		req, _ := r.clientReq(22)
		if st, body := r.clientSession("carol", req); st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("429 carries Retry-After", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.IPRate = 0.001; c.IPBurst = 1 })
		req, _ := http.NewRequest(http.MethodPost, r.srv.URL+api.ClientSessionPath, nil)
		for range 2 {
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
				t.Fatal("no Retry-After")
			}
		}
	})
}

func TestMethodAndBodyLimits(t *testing.T) {
	r := newRig(t)
	resp, err := http.Get(r.srv.URL + api.ClientSessionPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET -> %d", resp.StatusCode)
	}
	big := []byte(`{"namespace":"` + strings.Repeat("a", 20<<10) + `"}`)
	st, body := r.post(api.ClientSessionPath, aliceToken, big)
	if st != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body -> %d %s", st, body)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	r := newRig(t)
	get := func(p string) int {
		resp, err := http.Get(r.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if get(api.HealthzPath) != http.StatusOK {
		t.Fatal("healthz")
	}
	if get("/readyz") != http.StatusServiceUnavailable {
		t.Fatal("readyz must fail until the in-tunnel listeners serve")
	}
	r.h.tunnelServing.Store(true)
	if get("/readyz") != http.StatusOK {
		t.Fatal("readyz")
	}
}

// ---- revocation ----

func TestRevocationEndsDeviceAndClientSessions(t *testing.T) {
	cases := []struct {
		name   string
		ann    map[string]string
		policy func(*rig)
		reason string
	}{
		{"compromised annotation", map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"}, nil, api.ReasonDeviceRevoked},
		{"health check annotation", map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationHealthCheckFailed: "true"}, nil, api.ReasonDeviceRevoked},
		{"wireguard disabled", map[string]string{}, nil, api.ReasonDeviceDisabled},
		{"controller path alone", nil, func(r *rig) { p := r.policy; p.State = api.StateRevoked; r.setPolicy(p) }, api.ReasonDeviceRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			dev := r.deviceSessionOK()
			c1 := r.clientSessionOK()
			c2 := r.clientSessionOK()
			if r.tun.peerCount() != 3 {
				t.Fatalf("peers %d", r.tun.peerCount())
			}
			switch {
			case tc.ann != nil:
				r.flags.Set(testNS, testDevice, tc.ann)
			default:
				tc.policy(r)
			}
			waitFor(t, "sessions to end", func() bool { d, c := r.h.sessionCounts(); return d == 0 && c == 0 })
			waitFor(t, "peers removed", func() bool { return r.tun.peerCount() == 0 })
			for _, ip := range []string{dev.Address, c1.Address, c2.Address} {
				if r.h.sessionByAddr(netip.MustParseAddr(ip)) != nil {
					t.Fatalf("%s still resolves to a session", ip)
				}
			}
			// One decision line, with the reason.
			if n := strings.Count(r.logs.String(), `"op":"revoke"`); n != 1 {
				t.Fatalf("%d revoke lines, want 1:\n%s", n, r.logs.String())
			}
			if !strings.Contains(r.logs.String(), `"reason":"`+tc.reason+`"`) {
				t.Fatalf("no revoke reason %s in logs", tc.reason)
			}
			// New sessions are refused.
			tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
			st, body := r.post(api.DeviceSessionPath, tok, req)
			if st != http.StatusForbidden {
				t.Fatalf("device session after revoke: %d %s", st, body)
			}
			creq, _ := r.clientReq(22)
			st, body = r.clientSession(aliceToken, creq)
			wantReason(t, st, body, http.StatusForbidden, tc.reason)
		})
	}
}

func TestRevocationOnlyAffectsThatDevice(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.clientSessionOK()
	// Changes for an unrelated device do nothing.
	r.flags.Set(testNS, "cam-9", map[string]string{api.AnnotationCompromised: "true"})
	time.Sleep(50 * time.Millisecond)
	if d, c := r.h.sessionCounts(); d != 1 || c != 1 {
		t.Fatalf("sessions %d/%d", d, c)
	}
}

func TestEnforcementOnGenerationBumpAndPortChange(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.clientSessionOK()
	// Narrowing the ports ends the client session that used port 22.
	p := r.policy
	p.AllowedPorts = []int{2222}
	r.setPolicy(p)
	waitFor(t, "client to end", func() bool { _, c := r.h.sessionCounts(); return c == 0 })
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("device session should survive a port change")
	}
	// Resetting enrollment voids the device identity: its session ends.
	p.EnrollmentGeneration = 2
	r.setPolicy(p)
	waitFor(t, "device to end", func() bool { d, _ := r.h.sessionCounts(); return d == 0 })
}

func TestReaperExpiresSessionsAndQuarantinesAddresses(t *testing.T) {
	r := newRig(t)
	dev := r.deviceSessionOK()
	r.clientSessionOK()
	r.clock.Advance(2 * time.Minute)
	r.h.reap()
	if d, c := r.h.sessionCounts(); d != 1 || c != 1 {
		t.Fatalf("sessions expired early: %d/%d", d, c)
	}
	r.clock.Advance(90 * time.Second) // 3.5 min since creation
	r.h.reap()
	if d, c := r.h.sessionCounts(); d != 0 || c != 0 {
		t.Fatalf("sessions not reaped: %d/%d", d, c)
	}
	waitFor(t, "peers removed", func() bool { return r.tun.peerCount() == 0 })
	// The expired device address is not handed out again within the quarantine.
	waitFor(t, "addresses released", func() bool { return r.h.ipam.InUse() == 0 })
	for range 50 {
		ip, _ := r.h.ipam.Alloc()
		if ip.String() == dev.Address {
			t.Fatal("quarantined address reused")
		}
	}
}

// ---- renew / close ----

func TestRenewDevice(t *testing.T) {
	r := newRig(t)
	dev := r.deviceSessionOK()
	r.clock.Advance(60 * time.Second)

	tok := r.dev.renewToken(t, r.clock.Now(), dev.pub.Base64())
	st, body := r.tunnelPost(api.RenewPath, dev.Address, tok, api.RenewRequest{})
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	var resp api.RenewResponse
	_ = json.Unmarshal(body, &resp)
	if want := r.clock.Now().Add(3 * time.Minute); !resp.ExpiresAt.Equal(want) || resp.RenewAfterSeconds != 60 {
		t.Fatalf("response %+v", resp)
	}
	if resp.TURN != nil {
		t.Fatal("TURN must only be rotated when it runs low")
	}
	// The same token again is a replay.
	st, body = r.tunnelPost(api.RenewPath, dev.Address, tok, nil)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonReplay)
	// ...and a denial tears the session down.
	if d, _ := r.h.sessionCounts(); d != 0 {
		t.Fatal("denied renewal must end the session")
	}
}

func TestRenewRejectsMismatchedCredentials(t *testing.T) {
	t.Run("device: token bound to another WireGuard key", func(t *testing.T) {
		r := newRig(t)
		dev := r.deviceSessionOK()
		_, other, _ := wgkey.Generate()
		tok := r.dev.renewToken(t, r.clock.Now(), other.Base64())
		st, body := r.tunnelPost(api.RenewPath, dev.Address, tok, nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		if d, _ := r.h.sessionCounts(); d != 0 {
			t.Fatal("session must be torn down")
		}
	})
	t.Run("device: identity of another device", func(t *testing.T) {
		r := newRig(t)
		dev := r.deviceSessionOK()
		o := newDeviceCreds(t)
		tok, _, _ := identity.MintIdentityJWTAt(o.idPriv, r.dev.sub(), dev.pub.Base64(), 30*time.Second, r.clock.Now())
		st, body := r.tunnelPost(api.RenewPath, dev.Address, tok, nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("device: legacy RSA enrollment token", func(t *testing.T) {
		r := newRig(t)
		dev := r.deviceSessionOK()
		tok, _ := r.dev.enrollRequest(t, r.clock.Now())
		st, body := r.tunnelPost(api.RenewPath, dev.Address, tok, nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("client: another user's token", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		r.users.set("bob-token", "bob@example.com", r.clock.Now().Add(time.Minute))
		r.authz.set("bob@example.com", testNS, true)
		st, body := r.tunnelPost(api.RenewPath, c.Address, "bob-token", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
		if _, n := r.h.sessionCounts(); n != 0 {
			t.Fatal("session must be torn down")
		}
	})
	t.Run("client: a device-kind credential", func(t *testing.T) {
		r := newRig(t)
		dev := r.deviceSessionOK()
		c := r.clientSessionOK()
		tok := r.dev.renewToken(t, r.clock.Now(), dev.pub.Base64())
		st, body := r.tunnelPost(api.RenewPath, c.Address, tok, nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("client: SA token for a Keycloak session", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		r.sa.add("sa-token", "term", testNS, testDevice)
		st, body := r.tunnelPost(api.RenewPath, c.Address, "sa-token", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("sa: a different service account", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		r.sa.add("sa-token", "term-a", testNS, testDevice)
		r.sa.add("sa-token-2", "term-b", testNS, testDevice)
		req, _ := r.clientReq(22)
		req.OnBehalfOf, req.Direct, req.Posture.Software = aliceEmail, true, "web-terminal"
		st, body := r.clientSession("sa-token", req)
		if st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		var c api.SessionResponse
		_ = json.Unmarshal(body, &c)
		st, body = r.tunnelPost(api.RenewPath, c.Address, "sa-token-2", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("no token", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		st, body := r.tunnelPost(api.RenewPath, c.Address, "", nil)
		wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	})
	t.Run("unknown source address", func(t *testing.T) {
		r := newRig(t)
		st, body := r.tunnelPost(api.RenewPath, "100.96.9.9", aliceToken, nil)
		wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
	})
}

func TestRenewReevaluatesPolicy(t *testing.T) {
	t.Run("user lost access", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		r.authz.set(aliceEmail, testNS, false)
		st, body := r.tunnelPost(api.RenewPath, c.Address, aliceToken, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
		if _, n := r.h.sessionCounts(); n != 0 {
			t.Fatal("session must be torn down")
		}
	})
	t.Run("device revoked (flag not yet processed by the enforcer)", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		r.flags.mu.Lock()
		r.flags.m[devKey{testNS, testDevice}] = map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"}
		r.flags.mu.Unlock()
		st, body := r.tunnelPost(api.RenewPath, c.Address, aliceToken, nil)
		wantReason(t, st, body, http.StatusForbidden, api.ReasonDeviceRevoked)
	})
	t.Run("max age", func(t *testing.T) {
		r := newRig(t)
		dev := r.deviceSessionOK()
		start := r.clock.Now()
		for range 300 { // renew every 170s of virtual time until past 12h
			r.clock.Advance(170 * time.Second)
			r.renewLimitReset(dev.SessionID)
			tok := r.dev.renewToken(t, r.clock.Now(), dev.pub.Base64())
			st, body := r.tunnelPost(api.RenewPath, dev.Address, tok, nil)
			age := r.clock.Now().Sub(start)
			if age <= 12*time.Hour {
				if st != http.StatusOK {
					t.Fatalf("renewal refused at age %v: %d %s", age, st, body)
				}
				continue
			}
			wantReason(t, st, body, http.StatusForbidden, api.ReasonSessionMaxAge)
			if d, _ := r.h.sessionCounts(); d != 0 {
				t.Fatal("session must be torn down")
			}
			return
		}
		t.Fatal("session outlived its maximum age")
	})
	t.Run("keycloak renewal updates the token expiry and caps the session", func(t *testing.T) {
		r := newRig(t)
		r.deviceSessionOK()
		c := r.clientSessionOK()
		r.users.set("renewed", aliceEmail, r.clock.Now().Add(-10*time.Second))
		st, body := r.tunnelPost(api.RenewPath, c.Address, "renewed", nil)
		if st != http.StatusOK {
			t.Fatalf("%d %s", st, body)
		}
		var resp api.RenewResponse
		_ = json.Unmarshal(body, &resp)
		if want := r.clock.Now().Add(-10*time.Second + 3*time.Minute); !resp.ExpiresAt.Equal(want) {
			t.Fatalf("expires %v, want %v", resp.ExpiresAt, want)
		}
	})
}

func (r *rig) renewLimitReset(id string) { r.h.renewLimit.Forget(id) }

func TestRenewRotatesTURNWhenLow(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	c := r.clientSessionOK()
	var resp api.RenewResponse
	renew := func() int {
		r.renewLimitReset(c.SessionID)
		r.users.set(aliceToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
		st, body := r.tunnelPost(api.RenewPath, c.Address, aliceToken, nil)
		resp = api.RenewResponse{}
		_ = json.Unmarshal(body, &resp)
		return st
	}
	r.clock.Advance(10 * time.Minute) // 20 min left on the TURN credentials
	if st := renew(); st != http.StatusOK || resp.TURN != nil {
		t.Fatalf("early rotation: %d %+v", st, resp)
	}
	r.clock.Advance(6 * time.Minute) // 14 min left: rotate
	if st := renew(); st != http.StatusOK || resp.TURN == nil {
		t.Fatalf("no rotation: %d %+v", st, resp)
	}
	if !resp.TURN.ExpiresAt.Equal(r.clock.Now().Add(30 * time.Minute)) {
		t.Fatalf("rotated expiry %v", resp.TURN.ExpiresAt)
	}
	if !strings.HasSuffix(resp.TURN.Username, "/"+c.SessionID) {
		t.Fatalf("rotated username %q must stay bound to the session", resp.TURN.Username)
	}
	if st := renew(); st != http.StatusOK || resp.TURN != nil {
		t.Fatalf("rotated twice: %+v", resp)
	}
	// Direct sessions never get TURN credentials.
	r.sa.add("sa-token", "term", testNS, testDevice)
	req, _ := r.clientReq(22)
	req.OnBehalfOf, req.Direct, req.Posture.Software = aliceEmail, true, "web-terminal"
	st, body := r.clientSession("sa-token", req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	var d api.SessionResponse
	_ = json.Unmarshal(body, &d)
	r.clock.Advance(20 * time.Minute)
	r.renewLimitReset(d.SessionID)
	st, body = r.tunnelPost(api.RenewPath, d.Address, "sa-token", nil)
	_ = json.Unmarshal(body, &resp)
	if st != http.StatusOK || resp.TURN != nil {
		t.Fatalf("direct session got TURN: %d %s", st, body)
	}
}

func TestRenewRateLimitedPerSession(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	c := r.clientSessionOK()
	var last int
	for range 10 {
		last, _ = r.tunnelPost(api.RenewPath, c.Address, aliceToken, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last status %d", last)
	}
	// Rate limiting must not tear the session down.
	if _, n := r.h.sessionCounts(); n != 1 {
		t.Fatal("rate limit ended the session")
	}
}

func TestCloseEndsOwnSession(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	c := r.clientSessionOK()
	st, _ := r.tunnelPost(api.CloseSessionPath, c.Address, "", nil)
	if st != http.StatusNoContent {
		t.Fatalf("status %d", st)
	}
	if _, n := r.h.sessionCounts(); n != 0 {
		t.Fatal("client session not closed")
	}
	// The peer outlives the response by a short grace period, then goes.
	waitFor(t, "peer removal after the grace period", func() bool { return r.tun.peerCount() == 1 })
	st, body := r.tunnelPost(api.CloseSessionPath, c.Address, "", nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
}

func TestCloseAllAndShutdown(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.clientSessionOK()
	_ = r.h.Close()
	if r.tun.peerCount() != 0 {
		t.Fatal("peers left after Close")
	}
}
