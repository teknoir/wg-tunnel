package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// ---- clock ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---- log capture ----

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLogger() (*slog.Logger, *syncBuf) {
	buf := &syncBuf{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// ---- policy / flags ----

type fakePolicy struct {
	subscribers
	mu sync.Mutex
	m  map[devKey]api.PolicyEntry
}

func newFakePolicy() *fakePolicy { return &fakePolicy{m: map[devKey]api.PolicyEntry{}} }

func (p *fakePolicy) Get(ns, device string) (api.PolicyEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[devKey{ns, device}]
	return e, ok
}
func (p *fakePolicy) Subscribe(fn func(ns, device string)) { p.add(fn) }
func (p *fakePolicy) HasSynced() bool                      { return true }
func (p *fakePolicy) Set(e api.PolicyEntry) {
	p.mu.Lock()
	p.m[devKey{e.Namespace, e.Device}] = e
	p.mu.Unlock()
	p.notify(e.Namespace, e.Device)
}
func (p *fakePolicy) Delete(ns, device string) {
	p.mu.Lock()
	delete(p.m, devKey{ns, device})
	p.mu.Unlock()
	p.notify(ns, device)
}

type fakeFlags struct {
	subscribers
	mu sync.Mutex
	m  map[devKey]api.FlagsEntry
}

func newFakeFlags() *fakeFlags { return &fakeFlags{m: map[devKey]api.FlagsEntry{}} }

func (f *fakeFlags) Flags(ns, device string) (api.FlagsEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[devKey{ns, device}]
	return e, ok
}
func (f *fakeFlags) Subscribe(fn func(ns, device string)) { f.add(fn) }
func (f *fakeFlags) HasSynced() bool                      { return true }

// Set replaces the flags of a device (creating it) from Device annotations,
// the way the flags watcher mirrors them.
func (f *fakeFlags) Set(ns, device string, ann map[string]string) {
	f.SetEntry(api.FlagsEntry{
		Device: device, Namespace: ns, Exists: true,
		WireGuard:         ann[api.AnnotationWireGuard] == "enabled",
		Compromised:       api.FlagSet(ann[api.AnnotationCompromised]),
		HealthCheckFailed: api.FlagSet(ann[api.AnnotationHealthCheckFailed]),
	})
}

// SetEntry stores an entry as is.
func (f *fakeFlags) SetEntry(e api.FlagsEntry) {
	f.mu.Lock()
	f.m[devKey{e.Namespace, e.Device}] = e
	f.mu.Unlock()
	f.notify(e.Namespace, e.Device)
}

// Delete removes the entry (the Device is gone).
func (f *fakeFlags) Delete(ns, device string) {
	f.mu.Lock()
	delete(f.m, devKey{ns, device})
	f.mu.Unlock()
	f.notify(ns, device)
}

// ---- identity store ----

type memIdentity struct {
	mu        sync.Mutex
	m         map[devKey]api.IdentityEntry
	conflicts int
	voids     int
	getErr    error
	voidErr   error
}

func newMemIdentity() *memIdentity { return &memIdentity{m: map[devKey]api.IdentityEntry{}} }

func (s *memIdentity) Get(_ context.Context, ns, device string) (api.IdentityEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return api.IdentityEntry{}, false, s.getErr
	}
	e, ok := s.m[devKey{ns, device}]
	return e, ok, nil
}

func (s *memIdentity) Pin(_ context.Context, e api.IdentityEntry) (api.IdentityEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := devKey{e.Namespace, e.Device}
	if cur, ok := s.m[k]; ok && cur.EnrollmentGeneration == e.EnrollmentGeneration && cur.EnrollmentEpoch == e.EnrollmentEpoch {
		return cur, false, nil
	}
	s.m[k] = e
	return e, true, nil
}

func (s *memIdentity) Void(_ context.Context, ns, device, reason string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.voidErr != nil {
		return false, s.voidErr
	}
	k := devKey{ns, device}
	cur, ok := s.m[k]
	if !ok || cur.Voided {
		return false, nil
	}
	cur.Voided, cur.VoidedReason, cur.VoidedAt = true, reason, at
	s.m[k] = cur
	s.voids++
	return true, nil
}

func (s *memIdentity) RecordConflict(_ context.Context, ns, device string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := devKey{ns, device}
	cur, ok := s.m[k]
	if !ok {
		return nil
	}
	cur.Conflicts++
	cur.LastConflictAt = at
	s.m[k] = cur
	s.conflicts++
	return nil
}

func (s *memIdentity) entry(ns, device string) api.IdentityEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[devKey{ns, device}]
}

// ---- users / SA / authz ----

type fakeUsers struct {
	mu     sync.Mutex
	tokens map[string]UserIdentity
	err    error
	n      int
}

func newFakeUsers() *fakeUsers { return &fakeUsers{tokens: map[string]UserIdentity{}} }

func (u *fakeUsers) Authenticate(_ context.Context, token string) (UserIdentity, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return UserIdentity{}, u.err
	}
	id, ok := u.tokens[token]
	if !ok {
		return UserIdentity{}, fmt.Errorf("%w: unknown token", ErrUnauthenticated)
	}
	return id, nil
}

// set registers (or re-issues) a token. Every call gives the token a new id and
// a later issue time, the way a refreshed Keycloak access token differs from
// the previous one; renewals need such a fresh token.
func (u *fakeUsers) set(token, email string, exp time.Time) {
	u.mu.Lock()
	u.n++
	u.tokens[token] = UserIdentity{
		Email: email, ExpiresAt: exp,
		TokenID: fmt.Sprintf("%s#%d", token, u.n), IssuedAt: time.Date(2026, 10, 13, 11, 0, 0, 0, time.UTC).Add(time.Duration(u.n) * time.Second),
	}
	u.mu.Unlock()
}

type fakeSA struct {
	mu       sync.Mutex
	tokens   map[string]string    // token -> sa name
	bindings map[string][2]string // sa name -> ns, device
}

func newFakeSA() *fakeSA {
	return &fakeSA{tokens: map[string]string{}, bindings: map[string][2]string{}}
}

func (f *fakeSA) Verify(_ context.Context, token, ns, device, onBehalfOf string) (SAIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ValidEmail(onBehalfOf) {
		return SAIdentity{}, ErrForbidden
	}
	name, ok := f.tokens[token]
	if !ok {
		return SAIdentity{}, ErrUnauthenticated
	}
	if b := f.bindings[name]; b != [2]string{ns, device} {
		return SAIdentity{}, ErrForbidden
	}
	return SAIdentity{Name: name}, nil
}

func (f *fakeSA) add(token, name, ns, device string) {
	f.mu.Lock()
	f.tokens[token] = name
	f.bindings[name] = [2]string{ns, device}
	f.mu.Unlock()
}

type fakeAuthz struct {
	mu      sync.Mutex
	allowed map[string]bool // email|ns
	err     error
	calls   int
}

func newFakeAuthz() *fakeAuthz { return &fakeAuthz{allowed: map[string]bool{}} }

func (a *fakeAuthz) CanExec(_ context.Context, email, ns string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return false, a.err
	}
	return a.allowed[email+"|"+ns], nil
}

func (a *fakeAuthz) set(email, ns string, ok bool) {
	a.mu.Lock()
	a.allowed[email+"|"+ns] = ok
	a.mu.Unlock()
}

// ---- tunnel ----

// fakeTunnel records peers; it cannot carry traffic.
type fakeTunnel struct {
	mu      sync.Mutex
	pub     wgkey.PublicKey
	peers   map[wgkey.PublicKey]netip.Addr
	adds    int
	removes int
	order   []string
	// dial, when set, handles DialContext.
	dial func(context.Context, netip.AddrPort) (net.Conn, error)
}

func newFakeTunnel() *fakeTunnel {
	_, pub, _ := wgkey.Generate()
	return &fakeTunnel{pub: pub, peers: map[wgkey.PublicKey]netip.Addr{}}
}

func (t *fakeTunnel) PublicKey() wgkey.PublicKey { return t.pub }
func (t *fakeTunnel) ListenPort() int            { return 51820 }
func (t *fakeTunnel) Up() bool                   { return true }
func (t *fakeTunnel) Close() error               { return nil }
func (t *fakeTunnel) AddPeer(pub wgkey.PublicKey, ip netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[pub] = ip
	t.adds++
	t.order = append(t.order, "add "+ip.String())
	return nil
}
func (t *fakeTunnel) RemovePeer(pub wgkey.PublicKey) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip := t.peers[pub]
	delete(t.peers, pub)
	t.removes++
	t.order = append(t.order, "remove "+ip.String())
	return nil
}
func (t *fakeTunnel) Listen(netip.AddrPort) (net.Listener, error) {
	return nil, errors.New("fake tunnel cannot listen")
}
func (t *fakeTunnel) DialContext(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if t.dial != nil {
		return t.dial(ctx, ap)
	}
	return nil, errors.New("fake tunnel cannot dial")
}
func (t *fakeTunnel) peerCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.peers)
}

// ---- device credentials ----

const (
	testNS     = "acme"
	testDevice = "cam-1"
)

type deviceCreds struct {
	name     string // device name; testDevice when empty
	rsaKey   *rsa.PrivateKey
	rsaPEM   []byte // private
	certPEM  string // public certificate (policy RSAPublicCert)
	idPriv   ed25519.PrivateKey
	idPubB64 string
}

func newDeviceCreds(t testing.TB) *deviceCreds {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c := &deviceCreds{
		rsaKey:  k,
		rsaPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}),
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	c.newIdentity(t)
	return c
}

// newIdentity replaces the Ed25519 identity (a re-enrollment).
func (c *deviceCreds) newIdentity(t testing.TB) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.idPriv = priv
	c.idPubB64 = identity.EncodePublicKey(pub)
}

// fingerprint is the fingerprint of the current identity key.
func (c *deviceCreds) fingerprint() string {
	return identity.Fingerprint(c.idPriv.Public().(ed25519.PublicKey))
}

func (c *deviceCreds) sub() string {
	if c.name != "" {
		return api.DeviceSubject(testNS, c.name)
	}
	return api.DeviceSubject(testNS, testDevice)
}

// enrollRequest returns the bearer token and body for an enrollment at `now`.
func (c *deviceCreds) enrollRequest(t testing.TB, now time.Time) (string, api.EnrollRequest) {
	t.Helper()
	tok, jti, err := identity.MintEnrollJWTAt(c.rsaPEM, c.sub(), c.idPubB64, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok, api.EnrollRequest{
		IdentityPublicKey: c.idPubB64,
		Proof:             identity.ProveEnroll(c.idPriv, c.sub(), jti),
		Posture:           api.Posture{Software: "wg-agent", Version: "test"},
	}
}

// sessionRequest returns the bearer token and body of a device session with a
// fresh WireGuard key.
func (c *deviceCreds) sessionRequest(t testing.TB, now time.Time, hostKeys ...string) (string, api.DeviceSessionRequest, wgkey.PrivateKey) {
	t.Helper()
	priv, pub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := identity.MintIdentityJWTAt(c.idPriv, c.sub(), pub.Base64(), 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok, api.DeviceSessionRequest{
		WGPublicKey: pub.Base64(), Posture: api.Posture{Software: "wg-agent", Version: "test"}, SSHHostKeys: hostKeys,
	}, priv
}

// renewToken mints an identity token bound to wgKeyB64.
func (c *deviceCreds) renewToken(t testing.TB, now time.Time, wgKeyB64 string) string {
	t.Helper()
	tok, _, err := identity.MintIdentityJWTAt(c.idPriv, c.sub(), wgKeyB64, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
