// Package e2erig assembles the whole ZTNA tunnel in one process for end-to-end
// tests: a pion TURN server with STUNner-style TURN-REST authentication, the
// real hub (pkg/hub) on wireguard-go with in-memory Kubernetes doubles, the
// real device agent (pkg/agent), real client sessions (pkg/wgclient) with
// Keycloak-style tokens verified against a local JWKS server, and a fake sshd
// (a TCP echo server) that the agent forwards to.
//
// Everything listens on 127.0.0.1; nothing leaves the machine.
package e2erig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"

	"github.com/teknoir/wg-tunnel/internal/hubtest"
	"github.com/teknoir/wg-tunnel/internal/turntest"
	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/hub"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// Fixed names and secrets of every rig. The secrets are test values; the
// hygiene check looks for them (and for everything minted at run time) in all
// logs.
const (
	NS         = "teknoir-demo"
	DeviceName = "vdev-1"
	AliceEmail = "alice@example.com"
	BobEmail   = "bob@example.com"
	TURNSecret = "e2e-turn-shared-secret-DO-NOT-LOG"
	kcIssuer   = "https://auth.e2e.test/auth/realms/master"
	kcKID      = "e2e-key-1"
)

// Options tune a rig. The zero value is fine for most scenarios.
type Options struct {
	// StaleAfter is how long the agent's and the clients' relay may receive
	// nothing before it is re-allocated (default: wgclient's 75 s).
	StaleAfter time.Duration
	// RenewAfter is the renewal interval the hub advertises (default 2 s).
	RenewAfter time.Duration
	// DeadAfter is how long agent and clients may receive nothing through
	// WireGuard before a failed renewal ends their session (default 5 s; the
	// product default is 2 * PersistentKeepalive = 50 s).
	DeadAfter time.Duration
	// AgentBackoff bounds the agent's retry delay (default 100 ms .. 400 ms).
	AgentBackoff agent.Backoff
	// Hub lets a test adjust the hub configuration.
	Hub func(*hub.Config)
	// ManualApproval stops the rig from approving the agent's identity: the
	// test plays the admin itself (Rig.Policy.Approve / Rig.ApproveAgent).
	// By default the rig approves every identity the agent pins, the way an
	// admin clicking "Approve identity" in the UI would.
	ManualApproval bool
	// FlagsViaWatcher wires the production path of the Device flags: a fake
	// Device (annotations only) is mirrored by a real hub.FlagsWatcher into
	// flags ConfigMaps of a fake cluster, which the hub reads through a real
	// hub.K8sFlagsSource. Change the annotations with Rig.SetDeviceAnnotations
	// (Rig.Flags is not connected to the hub in this mode).
	FlagsViaWatcher bool
	// Services are the device's initial policy services (phase 2).
	Services []api.ServiceSpec
	// Agent lets a test adjust the agent configuration (resolver, service CIDR ...).
	Agent func(*agent.Config)
	// Attest runs the host-key attestor against a real sshd host key file and
	// configures the agent to use it (Rig.HostKeyFingerprint is the key's
	// SHA256 fingerprint; Rig.TrustHostKey makes it the activation anchor).
	Attest bool
}

// Epoch names of the rig's enrollment windows; tests that reset enrollment
// write a new one.
const (
	Epoch1 = "e2e-epoch-1"
	Epoch2 = "e2e-epoch-2"
)

// LogBuf is a goroutine-safe log sink.
type LogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *LogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// String returns everything logged so far.
func (l *LogBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Count returns how many times sub occurs in the log.
func (l *LogBuf) Count(sub string) int { return strings.Count(l.String(), sub) }

func logger(b *LogBuf) *slog.Logger {
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// Echo is the fake sshd: a TCP echo server.
type Echo struct {
	Port   int
	ln     net.Listener
	active atomic.Int64
	total  atomic.Int64
}

// Active is the number of connections currently open to the echo server.
func (e *Echo) Active() int { return int(e.active.Load()) }

// Total is the number of connections accepted so far.
func (e *Echo) Total() int { return int(e.total.Load()) }

func startEcho(t testing.TB) *Echo {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &Echo{ln: ln, Port: ln.Addr().(*net.TCPAddr).Port}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.total.Add(1)
			e.active.Add(1)
			go func() {
				defer e.active.Add(-1)
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return e
}

var (
	sharedOnce sync.Once
	rsaDev     *rsa.PrivateKey
	rsaDevPEM  []byte
	rsaCert    string
	kcKey      *rsa.PrivateKey
)

// sharedKeys generates the RSA keys once per process (2048-bit generation is
// slow under -race).
func sharedKeys(t testing.TB) {
	t.Helper()
	sharedOnce.Do(func() {
		var err error
		if rsaDev, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if kcKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		rsaDevPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaDev)})
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e-device"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaDev.PublicKey, rsaDev)
		if err != nil {
			panic(err)
		}
		rsaCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	})
}

// Rig is one complete system.
type Rig struct {
	T    testing.TB
	Opts Options

	TURN     *turntest.Server
	Hub      *hub.Hub
	HubURL   string
	Policy   *hubtest.Policy
	Flags    *hubtest.Flags
	Identity *hubtest.Identity
	Authz    *hubtest.Authz
	Echo     *Echo
	// Web is a second echo server, the target of the external test services.
	// The agent refuses loopback targets; the rig lets exactly the echo
	// servers through with the agent's AllowTarget test hook (the hub, the
	// policy and every other rule are the production ones).
	Web *Echo

	// HostKey is the SSH host key the agent reports ("ssh-ed25519 AAAA...").
	HostKey    string
	RSAKeyPath string
	// HostKeyFingerprint and AttestExchange are set by Options.Attest.
	HostKeyFingerprint string
	AttestExchange     string
	IdentityDir        string

	HubLogs, AgentLogs, ClientLogs *LogBuf

	hostKeysGlob string
	allowMu      sync.Mutex
	allowLoop    map[uint16]bool
	metaClient   *metafake.FakeMetadataClient
	secMu        sync.Mutex
	secrets      map[string]struct{}
	agentRuns    int
}

// New builds and starts the TURN server, the hub (data plane and HTTP API)
// and the fake sshd. The agent is started with StartAgent.
func New(t testing.TB, opts Options) *Rig {
	t.Helper()
	sharedKeys(t)
	if opts.RenewAfter <= 0 {
		opts.RenewAfter = 2 * time.Second
	}
	if opts.DeadAfter <= 0 {
		opts.DeadAfter = 5 * time.Second
	}
	if opts.AgentBackoff.Min <= 0 {
		opts.AgentBackoff = agent.Backoff{Min: 100 * time.Millisecond, Max: 400 * time.Millisecond, Stable: time.Minute}
	}
	r := &Rig{
		T: t, Opts: opts,
		Policy: hubtest.NewPolicy(), Flags: hubtest.NewFlags(), Identity: hubtest.NewIdentity(), Authz: hubtest.NewAuthz(),
		HubLogs: &LogBuf{}, AgentLogs: &LogBuf{}, ClientLogs: &LogBuf{},
		secrets: map[string]struct{}{},
	}
	r.AddSecret(TURNSecret)
	dir := t.TempDir()

	r.TURN = turntest.Start(t, TURNSecret)
	r.Echo = startEcho(t)
	r.Web = startEcho(t)
	r.allowLoop = map[uint16]bool{uint16(r.Web.Port): true}

	// Device files: the legacy RSA key, the SSH host key, the identity dir.
	r.RSAKeyPath = filepath.Join(dir, "rsa_private.pem")
	must(t, os.WriteFile(r.RSAKeyPath, rsaDevPEM, 0o600))
	for _, line := range strings.Split(string(rsaDevPEM), "\n") {
		if len(line) > 16 && !strings.HasPrefix(line, "-----") {
			r.AddSecret(line)
		}
	}
	hostDir := filepath.Join(dir, "ssh")
	must(t, os.MkdirAll(hostDir, 0o755))
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	sshPub, err := ssh.NewPublicKey(hostPub)
	must(t, err)
	r.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	must(t, os.WriteFile(filepath.Join(hostDir, "ssh_host_ed25519_key.pub"), []byte(r.HostKey+" root@e2e\n"), 0o644))
	r.hostKeysGlob = filepath.Join(hostDir, "ssh_host_*_key.pub")
	r.IdentityDir = filepath.Join(dir, "identity")
	if opts.Attest {
		r.setupAttest(dir)
	}

	// Keycloak: a JWKS endpoint for the test realm key.
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kcKID, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(kcKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kcKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)
	users, err := hub.NewKeycloakVerifier(hub.KeycloakConfig{Issuer: kcIssuer, JWKSURL: jwks.URL})
	must(t, err)

	// Policy: active, enrollment window open, the fake sshd's port allowed.
	r.Policy.Set(api.PolicyEntry{
		Device: DeviceName, Namespace: NS, State: api.StateActive, RSAPublicCert: rsaCert,
		AllowedPorts: []int{r.Echo.Port}, EnrollmentGeneration: 1, EnrollmentEpoch: Epoch1, EnrollUntil: time.Now().Add(time.Hour),
		Services: opts.Services,
	})
	r.Flags.Set(NS, DeviceName, map[string]string{api.AnnotationWireGuard: "enabled"})
	r.Authz.Set(AliceEmail, NS, true)
	r.Authz.Set(BobEmail, NS, true)

	cfg := hub.Config{
		PodIP: "127.0.0.1", Logger: logger(r.HubLogs), RenewAfter: opts.RenewAfter,
		IPRate: 1000, IPBurst: 1000, SubjectRate: 1000, SubjectBurst: 1000,
		GlobalRate: 100000, GlobalBurst: 100000,
	}
	if opts.Hub != nil {
		opts.Hub(&cfg)
	}
	var flags hub.DeviceFlags = r.Flags
	if opts.FlagsViaWatcher {
		flags = r.startFlagsWatcher()
	}
	h, err := hub.New(cfg, hub.Deps{
		Policy: r.Policy, Flags: flags, Identity: r.Identity, Users: users, Authz: r.Authz,
		TURN: hub.NewTURNMinter(func() (string, error) { return TURNSecret, nil },
			[]string{"turn:" + r.TURN.Addr + "?transport=udp"}, 30*time.Minute, nil),
	})
	must(t, err)
	r.Hub = h
	t.Cleanup(func() { _ = h.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.ServeTunnel(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Error("e2erig: ServeTunnel did not stop")
		}
	})
	srv := httptest.NewServer(r.recording(h.Handler()))
	t.Cleanup(srv.Close)
	r.HubURL = srv.URL
	Eventually(t, 10*time.Second, "hub ready", h.Ready)
	return r
}

// startFlagsWatcher runs the flags watcher against a fake Device and returns
// the flags source the hub reads.
func (r *Rig) startFlagsWatcher() hub.DeviceFlags {
	t := r.T
	scheme := runtime.NewScheme()
	must(t, metav1.AddMetaToScheme(scheme))
	dev := &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "teknoir.org/v1", Kind: "Device"},
		ObjectMeta: metav1.ObjectMeta{Name: DeviceName, Namespace: NS, Annotations: map[string]string{api.AnnotationWireGuard: "enabled"}},
	}
	r.metaClient = metafake.NewSimpleMetadataClient(scheme, dev)
	cs := fake.NewSimpleClientset()
	w, err := hub.NewFlagsWatcher(cs, r.metaClient, hub.FlagsWatcherConfig{Namespace: api.HubNamespace, Logger: logger(&LogBuf{})})
	must(t, err)
	src, err := hub.NewK8sFlagsSource(cs, api.HubNamespace, logger(&LogBuf{}))
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	src.Start(ctx)
	t.Cleanup(func() { cancel(); <-done })
	Eventually(t, 10*time.Second, "flags to reach the hub", func() bool {
		e, ok := src.Flags(NS, DeviceName)
		return src.HasSynced() && ok && e.WireGuard
	})
	return src
}

// SetDeviceAnnotations patches the fake Device's annotations (FlagsViaWatcher
// only): the given keys are set, the keys with an empty value are removed.
func (r *Rig) SetDeviceAnnotations(ann map[string]string) {
	r.T.Helper()
	if r.metaClient == nil {
		r.T.Fatal("SetDeviceAnnotations needs Options.FlagsViaWatcher")
	}
	patch := map[string]any{}
	for k, v := range ann {
		if v == "" {
			patch[k] = nil
		} else {
			patch[k] = v
		}
	}
	body, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": patch}})
	must(r.T, err)
	gvr := hub.DeviceGVR
	_, err = r.metaClient.Resource(gvr).Namespace(NS).Patch(context.Background(), DeviceName, types.MergePatchType, body, metav1.PatchOptions{})
	must(r.T, err)
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// AddSecret registers a value that must never appear in any log.
func (r *Rig) AddSecret(s string) {
	if s == "" {
		return
	}
	r.secMu.Lock()
	r.secrets[s] = struct{}{}
	r.secMu.Unlock()
}

// recording notes every bearer credential the hub receives and every TURN
// password it hands out.
func (r *Rig) recording(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); ok {
			r.AddSecret(strings.TrimSpace(tok))
		}
		rec := &bodyRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, req)
		var v struct {
			TURN *api.TURNCredentials `json:"turn"`
		}
		if json.Unmarshal(rec.buf.Bytes(), &v) == nil && v.TURN != nil {
			r.AddSecret(v.TURN.Password)
		}
	})
}

type bodyRecorder struct {
	http.ResponseWriter
	buf bytes.Buffer
}

func (b *bodyRecorder) Write(p []byte) (int, error) {
	if b.buf.Len() < 64<<10 {
		b.buf.Write(p)
	}
	return b.ResponseWriter.Write(p)
}

// UserToken mints a Keycloak-style access token for email (azp teknoir-cli).
func (r *Rig) UserToken(email string) string {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": kcIssuer, "azp": "teknoir-cli", "email": email, "email_verified": true,
		"sub": "user-" + email, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
	})
	tok.Header["kid"] = kcKID
	s, err := tok.SignedString(kcKey)
	must(r.T, err)
	r.AddSecret(s)
	return s
}

// ClientOptions returns the options of a client session for email to the
// device's fake sshd port, through TURN.
func (r *Rig) ClientOptions(email string) wgclient.Options {
	return wgclient.Options{
		HubURL: r.HubURL,
		Kind:   api.KindClient,
		Credential: func(context.Context, string) (string, error) {
			return r.UserToken(email), nil
		},
		ClientRequest: &api.ClientSessionRequest{
			Namespace: NS, Device: DeviceName, Port: r.Echo.Port,
			Posture: api.Posture{Software: "tnctl", Version: "e2e", OS: "linux", Arch: "amd64"},
		},
		Logger:           logger(r.ClientLogs),
		StaleAfter:       r.Opts.StaleAfter,
		HandshakeTimeout: 20 * time.Second,
		RenewRetry:       500 * time.Millisecond,
		RenewTimeout:     3 * time.Second,
		DeadAfter:        r.Opts.DeadAfter,
	}
}

// NewClient creates a client session for email. The caller owns the session.
func (r *Rig) NewClient(ctx context.Context, email string) (*wgclient.Session, error) {
	s, err := wgclient.Create(ctx, r.ClientOptions(email))
	if err != nil {
		return nil, err
	}
	if t := s.Response().TURN; t != nil {
		r.AddSecret(t.Password)
	}
	return s, nil
}

// MustClient is NewClient that fails the test and closes the session at the end.
func (r *Rig) MustClient(email string) *wgclient.Session {
	r.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := r.NewClient(ctx, email)
	if err != nil {
		r.T.Fatalf("client session for %s: %v", email, err)
	}
	r.T.Cleanup(func() { _ = s.Close() })
	return s
}

// AgentConfig is the agent configuration of this rig.
func (r *Rig) AgentConfig() agent.Config {
	cfg := r.agentConfig()
	if r.Opts.Agent != nil {
		r.Opts.Agent(&cfg)
	}
	return cfg
}

func (r *Rig) agentConfig() agent.Config {
	return agent.Config{
		DeviceID: DeviceName, Namespace: NS, HubURL: r.HubURL,
		RSAKeyPath: r.RSAKeyPath, IdentityDir: r.IdentityDir,
		SSHHostKeysGlob: r.hostKeysGlob, ForwardHost: "127.0.0.1",
		Logger: logger(r.AgentLogs), Backoff: r.Opts.AgentBackoff,
		StaleAfter: r.Opts.StaleAfter, HandshakeTimeout: 20 * time.Second,
		RenewRetry: 500 * time.Millisecond, RenewTimeout: 3 * time.Second,
		DeadAfter: r.Opts.DeadAfter, AttestExchange: r.AttestExchange,
		// The ssh service reaches the fake sshd (the echo server) instead of port 22.
		SSHPort:     r.Echo.Port,
		AllowTarget: r.allowLoopback,
	}
}

// allowLoopback is the agent's AllowTarget test hook: the echo servers of the
// rig are loopback listeners and the only loopback targets that pass.
func (r *Rig) allowLoopback(ap netip.AddrPort) bool {
	r.allowMu.Lock()
	defer r.allowMu.Unlock()
	return r.allowLoop[ap.Port()]
}

// SetServices replaces the services of the device's policy (the way
// device-controller does when the annotation changes).
func (r *Rig) SetServices(specs ...api.ServiceSpec) {
	r.Policy.Update(NS, DeviceName, func(p *api.PolicyEntry) { p.Services = specs })
}

// WebService is an external http service that reaches the Web echo server.
func (r *Rig) WebService(id string) api.ServiceSpec {
	return api.ServiceSpec{ID: id, Kind: api.ServiceKindExternal, Target: "127.0.0.1", Port: r.Web.Port, Protocol: api.ProtocolHTTP, Web: true}
}

// ServiceClientOptions returns the options of a client session for email bound
// to a named service (ssh included) instead of the raw echo port.
func (r *Rig) ServiceClientOptions(email, service string) wgclient.Options {
	o := r.ClientOptions(email)
	o.ClientRequest.Service, o.ClientRequest.Port = service, 0
	return o
}

// MustServiceClient is MustClient for a named service.
func (r *Rig) MustServiceClient(email, service string) *wgclient.Session {
	r.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := wgclient.Create(ctx, r.ServiceClientOptions(email, service))
	if err != nil {
		r.T.Fatalf("client session for %s, service %s: %v", email, service, err)
	}
	if t := s.Response().TURN; t != nil {
		r.AddSecret(t.Password)
	}
	r.T.Cleanup(func() { _ = s.Close() })
	return s
}

// Agent is a running wg-agent.
type Agent struct {
	cancel context.CancelFunc
	done   chan error
}

// Stop stops the agent and waits for it.
func (a *Agent) Stop() error {
	a.cancel()
	return <-a.done
}

// StartAgent runs the real agent against the hub; it is stopped at test end.
func (r *Rig) StartAgent() *Agent {
	r.T.Helper()
	a, err := agent.New(r.AgentConfig())
	must(r.T, err)
	ctx, cancel := context.WithCancel(context.Background())
	ag := &Agent{cancel: cancel, done: make(chan error, 1)}
	go func() { ag.done <- a.Run(ctx) }()
	r.secMu.Lock()
	r.agentRuns++
	r.secMu.Unlock()
	var once sync.Once
	if !r.Opts.ManualApproval {
		go r.autoApprove(ctx)
	}
	r.T.Cleanup(func() {
		once.Do(func() {
			cancel()
			select {
			case <-ag.done:
			case <-time.After(15 * time.Second):
				r.T.Error("e2erig: agent did not stop")
			}
		})
	})
	return ag
}

// ApproveAgent plays the admin: it approves the identity currently pinned for
// the device (waiting for the agent to enroll first) by writing its
// fingerprint into the policy, the way device-controller copies the
// approved-identity annotation.
func (r *Rig) ApproveAgent() {
	r.T.Helper()
	Eventually(r.T, 30*time.Second, "the agent to pin an identity", func() bool { return r.approveOnce() })
}

// approveOnce approves the pinned identity if it belongs to the current
// enrollment and is not yet approved; it reports whether one is pinned.
func (r *Rig) approveOnce() bool {
	pol, ok := r.Policy.Get(NS, DeviceName)
	pin := r.Identity.Entry(NS, DeviceName)
	if !ok || pin.Fingerprint == "" || pin.Voided ||
		pin.EnrollmentGeneration != pol.EnrollmentGeneration || pin.EnrollmentEpoch != pol.EnrollmentEpoch {
		return false
	}
	if pol.ApprovedFingerprint != pin.Fingerprint {
		r.Policy.Approve(NS, DeviceName, pin.Fingerprint)
	}
	return true
}

func (r *Rig) autoApprove(ctx context.Context) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.approveOnce()
		}
	}
}

// WaitDeviceUp waits until the hub has a device session and the agent has
// exposed its ports n times in total (n is 1 for the first session, 2 after
// one re-connect, ...).
func (r *Rig) WaitDeviceUp(n int) {
	r.T.Helper()
	Eventually(r.T, 30*time.Second, fmt.Sprintf("device session #%d to be up", n), func() bool {
		d, _ := r.Hub.SessionCounts()
		return d == 1 && r.AgentLogs.Count(`"msg":"exposing port"`) >= n
	})
}

// AgentFingerprint is the fingerprint of the identity key currently on disk.
func (r *Rig) AgentFingerprint() string {
	r.T.Helper()
	return LoadFingerprint(r.T, r.IdentityDir)
}

// RoundTrip writes msg to c and reads it back.
func RoundTrip(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: got %d bytes, want %d", len(buf), len(msg))
	}
	return nil
}

// EchoVia opens a new connection through sess and echoes msg, retrying until
// it works or the timeout passes. It returns the last error on failure.
func EchoVia(sess *wgclient.Session, msg string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := sess.Dial(ctx)
		cancel()
		if err == nil {
			err = RoundTrip(c, msg)
			_ = c.Close()
			if err == nil {
				return nil
			}
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	return last
}

// Eventually polls cond until it holds or d passes.
func Eventually(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", d, what)
}

// Secrets returns every credential and password seen so far, plus the contents
// of the agent's identity key files.
func (r *Rig) Secrets() []string {
	r.secMu.Lock()
	out := make([]string, 0, len(r.secrets))
	for s := range r.secrets {
		out = append(out, s)
	}
	r.secMu.Unlock()
	entries, _ := os.ReadDir(r.IdentityDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.IdentityDir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, strings.TrimSpace(string(b)))
		for _, f := range strings.Fields(string(b)) {
			if len(f) >= 16 && !strings.HasPrefix(f, "-----") {
				out = append(out, f)
			}
		}
	}
	return out
}

// AssertLogHygiene fails the test if any secret, JWT, key material or
// Authorization header shows up in the hub, agent or client logs. It also
// fails if the check had nothing to look at (empty logs or no secrets), so it
// cannot pass vacuously.
func (r *Rig) AssertLogHygiene() {
	r.T.Helper()
	logs := map[string]string{"hub": r.HubLogs.String(), "agent": r.AgentLogs.String(), "client": r.ClientLogs.String()}
	for name, l := range logs {
		if len(l) < 200 {
			r.T.Errorf("%s log is nearly empty (%d bytes); the hygiene check would be vacuous", name, len(l))
		}
	}
	secrets := r.Secrets()
	if len(secrets) < 10 {
		r.T.Errorf("only %d secrets were collected; expected many tokens and passwords", len(secrets))
	}
	for i, s := range secrets {
		if len(s) < 8 {
			continue
		}
		for name, l := range logs {
			if strings.Contains(l, s) {
				r.T.Errorf("%s log contains secret #%d (%d bytes, starts %.3q...)", name, i, len(s), s)
			}
		}
	}
	for _, marker := range []string{"eyJ", "PRIVATE KEY", "BEGIN CERTIFICATE", "Bearer ", "Authorization", "authorization"} {
		for name, l := range logs {
			if strings.Contains(l, marker) {
				r.T.Errorf("%s log contains %q", name, marker)
			}
		}
	}
}
