package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// junkClientRequest posts an (unauthenticated) client session request from the
// client address ip (empty: no address header) to base.
func (r *rig) junkClientRequest(base, ip string) (int, api.Error) {
	r.t.Helper()
	req0, _ := r.clientReq(22)
	raw, _ := json.Marshal(req0)
	req, err := http.NewRequest(http.MethodPost, base+api.ClientSessionPath, bytes.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer junk")
	if ip != "" {
		req.Header.Set(testIPHeader, ip)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var e api.Error
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return resp.StatusCode, e
}

func TestPerIPLimitNeedsATrustedClientAddress(t *testing.T) {
	t.Run("no trusted address: the peer address is never a limiter key", func(t *testing.T) {
		// Behind a mesh sidecar or servicelb every caller has the same peer
		// address; limiting by it would let one caller starve everybody.
		r := newRig(t, func(c *Config) { c.IPRate = 0.001; c.IPBurst = 2; c.ClientIPHeader = "" })
		for i := range 30 {
			if st, e := r.junkClientRequest(r.srv.URL, ""); e.Reason == api.ReasonRateLimited {
				t.Fatalf("request %d: per-IP limit applied without a trusted address (%d)", i, st)
			}
		}
	})
	t.Run("configured header absent or unparseable: also no per-IP key", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.IPRate = 0.001; c.IPBurst = 2; c.ClientIPHeader = testIPHeader })
		for i, ip := range []string{"", "not-an-ip", "", "garbage", "", "", ""} {
			if _, e := r.junkClientRequest(r.srv.URL, ip); e.Reason == api.ReasonRateLimited {
				t.Fatalf("request %d (%q) was limited", i, ip)
			}
		}
	})
	t.Run("trusted address: limited per address", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.IPRate = 0.001; c.IPBurst = 2; c.ClientIPHeader = testIPHeader })
		var limited int
		for range 6 {
			if _, e := r.junkClientRequest(r.srv.URL, "198.51.100.1"); e.Reason == api.ReasonRateLimited {
				limited++
			}
		}
		if limited != 4 {
			t.Fatalf("%d of 6 limited, want 4 (burst 2)", limited)
		}
		// Another address has its own bucket.
		if _, e := r.junkClientRequest(r.srv.URL, "198.51.100.2"); e.Reason == api.ReasonRateLimited {
			t.Fatal("one address exhausted the bucket of another")
		}
		// The first address of an X-Forwarded-For style list is the key.
		if _, e := r.junkClientRequest(r.srv.URL, "198.51.100.3, 10.0.0.1"); e.Reason == api.ReasonRateLimited {
			t.Fatal("list header mishandled")
		}
	})
}

func TestGlobalBackstopLimitsEachEndpointRegardlessOfAddress(t *testing.T) {
	r := newRig(t, func(c *Config) { c.GlobalRate = 0.001; c.GlobalBurst = 3; c.ClientIPHeader = testIPHeader })
	var ok, limited int
	for i := range 8 {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // every request from a new address
		if _, e := r.junkClientRequest(r.srv.URL, ip); e.Reason == api.ReasonRateLimited {
			limited++
		} else {
			ok++
		}
	}
	if ok != 3 || limited != 5 {
		t.Fatalf("passed %d, limited %d; want 3/5", ok, limited)
	}
	// Another endpoint has its own budget, and so does the internal listener.
	tok, req := r.dev.enrollRequest(t, r.clock.Now())
	if st, body := r.enroll(tok, req); st == http.StatusTooManyRequests {
		t.Fatalf("enroll shares the backstop of the session endpoint: %s", body)
	}
	if _, e := r.junkClientRequest(r.isrv.URL, "198.51.100.77"); e.Reason == api.ReasonRateLimited {
		t.Fatal("the internal listener shares the outside backstop")
	}
}

// ---- subject limiter and replay partition ----

func TestSubjectLimiterRunsBeforeTheReplayCache(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SubjectRate = 0.001; c.SubjectBurst = 2 })
	r.enrollOK() // 1 of the 2 enroll tokens
	before := r.h.replay.Len()
	var limited int
	for range 10 {
		tok, req := r.dev.enrollRequest(t, r.clock.Now())
		if st, body := r.enroll(tok, req); st == http.StatusTooManyRequests {
			limited++
			wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonRateLimited)
		}
	}
	if limited < 8 {
		t.Fatalf("only %d of 10 limited", limited)
	}
	if grew := r.h.replay.Len() - before; grew > 1 {
		t.Fatalf("limited requests left %d jti entries in the replay cache", grew)
	}
}

func TestOneSubjectCannotFillTheReplayCacheForOthers(t *testing.T) {
	r := newRig(t, func(c *Config) { c.ReplayCacheSize = 50; c.ReplayPerSubject = 4 })
	r.deviceSessionOK()

	// A second device with its own legacy key and pin.
	other := newDeviceCreds(t)
	other.name = "cam-2"
	r.pol.Set(api.PolicyEntry{
		Device: "cam-2", Namespace: testNS, State: api.StateActive, RSAPublicCert: other.certPEM, AllowedPorts: []int{22},
		EnrollmentGeneration: 1, EnrollmentEpoch: "epoch-1", EnrollUntil: r.clock.Now().Add(time.Hour),
		ApprovedFingerprint: other.fingerprint(),
	})
	r.flags.Set(testNS, "cam-2", map[string]string{api.AnnotationWireGuard: "enabled"})
	if _, _, err := r.ids.Pin(context.Background(), api.IdentityEntry{
		Device: "cam-2", Namespace: testNS, IdentityPublicKey: other.idPubB64, Fingerprint: other.fingerprint(),
		EnrollmentGeneration: 1, EnrollmentEpoch: "epoch-1",
	}); err != nil {
		t.Fatal(err)
	}

	// cam-1 hammers the endpoint with valid, distinct tokens.
	var full int
	for range 20 {
		tok, req, _ := r.dev.sessionRequest(t, r.clock.Now())
		if st, body := r.post(api.DeviceSessionPath, tok, req); st == http.StatusTooManyRequests {
			full++
			wantReason(t, st, body, http.StatusTooManyRequests, api.ReasonRateLimited)
		}
	}
	if full == 0 {
		t.Fatal("cam-1's replay partition never filled")
	}
	// cam-2 is unaffected, and so is cam-1's live session renewal.
	tok, req, _ := other.sessionRequest(t, r.clock.Now())
	if st, body := r.post(api.DeviceSessionPath, tok, req); st != http.StatusCreated {
		t.Fatalf("another device was blocked by cam-1's tokens: %d %s", st, body)
	}
}

func TestReplayEntryOutlivesTheTokenByTheClockSkew(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	tok, req, _ := r.dev.sessionRequest(t, r.clock.Now()) // iat now, exp now+30s
	if st, body := r.post(api.DeviceSessionPath, tok, req); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	// The verifier still accepts the token until exp + MaxClockSkew + 1s (it
	// compares whole seconds); the replay record must not expire earlier.
	r.clock.Advance(30*time.Second + api.MaxClockSkew + 500*time.Millisecond)
	st, body := r.post(api.DeviceSessionPath, tok, req)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonReplay)
}

// ---- Keycloak renewals need a fresh token ----

func TestKeycloakRenewalNeedsAFreshToken(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	c := r.clientSessionOK()
	renew := func() (int, []byte) {
		r.renewLimitReset(c.SessionID)
		return r.tunnelPost(api.RenewPath, c.Address, aliceToken, nil)
	}

	// The token that created the session is not a renewal credential.
	st, body := renew()
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	if _, n := r.h.sessionCounts(); n != 0 {
		t.Fatal("a stale renewal must end the session")
	}

	// Fresh tokens (another jti and a later iat) keep it alive; an old one is refused.
	c = r.clientSessionOK()
	r.users.set(aliceToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	if st, body = renew(); st != http.StatusOK {
		t.Fatalf("fresh token: %d %s", st, body)
	}
	if st, body = renew(); st != http.StatusUnauthorized {
		t.Fatalf("the accepted token must not be accepted again: %d %s", st, body)
	}
}

func TestKeycloakRenewalAcceptsSameSecondTokenWithAnotherJTI(t *testing.T) {
	var s session
	now := time.Unix(1000, 0)
	if !s.acceptToken("a", now) {
		t.Fatal("first token")
	}
	if s.acceptToken("a", now) {
		t.Fatal("same jti, same iat")
	}
	if !s.acceptToken("b", now) {
		t.Fatal("another jti in the same second is a different token")
	}
	if s.acceptToken("a", now.Add(-time.Second)) {
		t.Fatal("an older token must be refused")
	}
	if !s.acceptToken("", now.Add(time.Second)) {
		t.Fatal("a later iat is fresh even without a jti")
	}
	if s.acceptToken("", now.Add(time.Second)) {
		t.Fatal("no jti, same iat: cannot tell it apart")
	}
}

// ---- delegated sessions are keyed by the service account and the email ----

func TestDelegatedQuotasAreKeyedBySAAndEmail(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxPerSubject = 2; c.MaxPerSubjectDevice = 2 })
	r.deviceSessionOK()
	r.sa.add("sa-token", "term-a", testNS, testDevice)
	r.sa.add("sa-token-b", "term-b", testNS, testDevice)
	delegated := func(token, email string) int {
		req, _ := r.clientReq(22)
		req.OnBehalfOf, req.Posture.Software = email, "web-terminal"
		st, _ := r.clientSessionInternal(token, req)
		return st
	}
	for range 2 {
		if st := delegated("sa-token", aliceEmail); st != http.StatusCreated {
			t.Fatalf("status %d", st)
		}
	}
	if st := delegated("sa-token", aliceEmail); st != http.StatusTooManyRequests {
		t.Fatalf("third session of the same (SA, email): %d", st)
	}
	// Another SA naming the same member has its own budget, and so has the
	// member's direct (Keycloak) path: a terminal cannot spend them.
	if st := delegated("sa-token-b", aliceEmail); st != http.StatusCreated {
		t.Fatalf("another SA: %d", st)
	}
	r.clientSessionOK()

	// The per-user rate limit is per (SA, email) too.
	if a, b := (&session{authKind: authSA, saName: "x", subject: aliceEmail}).limitKey(), (&session{authKind: authKeycloak, subject: aliceEmail}).limitKey(); a == b {
		t.Fatal("SA and Keycloak sessions of one email share a limit key")
	}
}

// ---- TURN secret source ----

func TestTURNSecretRereadFailureIsNotRetriedPerMint(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "stunner-system"},
		Data:       map[string][]byte{"secret": []byte("s1")},
	}
	cs := fake.NewSimpleClientset(sec)
	src, err := NewK8sSecretSource(cs, "stunner-system/s", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	src.now = clock.Now
	if v, err := src.Secret(); err != nil || v != "s1" {
		t.Fatalf("%q %v", v, err)
	}
	var gets atomic.Int32
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return true, nil, errors.New("down")
	})
	clock.Advance(2 * time.Minute) // refresh is due and the API is down
	for range 50 {
		if v, err := src.Secret(); err != nil || v != "s1" {
			t.Fatalf("outage: %q %v", v, err)
		}
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("%d API reads for 50 mints during an outage; want 1 per refresh interval", n)
	}
	clock.Advance(2 * time.Minute)
	_, _ = src.Secret()
	if n := gets.Load(); n != 2 {
		t.Fatalf("%d reads after the next interval", n)
	}
}

func TestTURNSecretReadDoesNotBlockOtherMints(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "stunner-system"},
		Data:       map[string][]byte{"secret": []byte("s1")},
	}
	cs := fake.NewSimpleClientset(sec)
	src, _ := NewK8sSecretSource(cs, "stunner-system/s", time.Minute)
	clock := newFakeClock()
	src.now = clock.Now
	_, _ = src.Secret()

	release := make(chan struct{})
	var started atomic.Int32
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		started.Add(1)
		<-release
		return false, nil, nil
	})
	clock.Advance(2 * time.Minute)
	first := make(chan string, 1)
	go func() { v, _ := src.Secret(); first <- v }()
	waitFor(t, "slow read to start", func() bool { return started.Load() == 1 })

	// While one read hangs, everybody else gets the last known value at once.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			if v, err := src.Secret(); err != nil || v != "s1" {
				t.Errorf("blocked or wrong: %q %v", v, err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mints were serialised behind the slow API read")
	}
	if started.Load() != 1 {
		t.Fatalf("%d concurrent reads", started.Load())
	}
	close(release)
	<-first
}

// ---- splice connection cap is taken before the dial ----

// remoteAddrConn reports a chosen remote address.
type remoteAddrConn struct {
	net.Conn
	addr net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.addr }

func TestSpliceReservesTheConnectionSlotBeforeDialling(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxConnsPerSession = 2; c.DialTimeout = 5 * time.Second })
	r.deviceSessionOK()
	c := r.clientSessionOK()

	var dials atomic.Int32
	release := make(chan struct{})
	r.tun.dial = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		dials.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("test: no device")
	}
	var wg sync.WaitGroup
	const attempts = 12
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, b := net.Pipe()
			defer func() { _ = a.Close(); _ = b.Close() }()
			conn := remoteAddrConn{Conn: a, addr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(c.Address + ":40000"))}
			r.h.handleSplice(context.Background(), conn)
		}()
	}
	// All dials that will ever happen are in flight now: only MaxConnsPerSession.
	waitFor(t, "dials to start", func() bool { return dials.Load() >= 2 })
	time.Sleep(200 * time.Millisecond)
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials to the device in flight with a cap of 2", n)
	}
	close(release)
	wg.Wait()
	if n := dials.Load(); n < 2 || n > attempts {
		t.Fatalf("dials %d", n)
	}
	// Failed dials give their slots back.
	s := r.h.sessionByAddr(netip.MustParseAddr(c.Address))
	s.mu.Lock()
	reserved := s.reserved
	s.mu.Unlock()
	if reserved != 0 {
		t.Fatalf("%d slots still reserved after the dials failed", reserved)
	}
	if err := s.reserveConn(2); err != nil {
		t.Fatalf("slot not returned: %v", err)
	}
}
