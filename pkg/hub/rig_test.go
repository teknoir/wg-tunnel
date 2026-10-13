package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

const (
	aliceEmail = "alice@example.com"
	aliceToken = "alice-keycloak-token-SECRET"
	turnSecret = "turn-shared-secret-SECRET"
)

// rig is a hub with in-memory fakes and an HTTP front.
type rig struct {
	t      *testing.T
	h      *Hub
	pol    *fakePolicy
	flags  *fakeFlags
	ids    *memIdentity
	users  *fakeUsers
	sa     *fakeSA
	authz  *fakeAuthz
	tun    *fakeTunnel
	clock  *fakeClock
	logs   *syncBuf
	srv    *httptest.Server
	dev    *deviceCreds
	policy api.PolicyEntry

	smu     sync.Mutex
	secrets []string // credentials used in the test; they must never reach the logs
}

func (r *rig) addSecret(s string) {
	if s == "" {
		return
	}
	r.smu.Lock()
	r.secrets = append(r.secrets, s)
	r.smu.Unlock()
}

// noteTURN records TURN passwords found in a response body.
func (r *rig) noteTURN(body []byte) {
	var v struct {
		TURN *api.TURNCredentials `json:"turn"`
	}
	if json.Unmarshal(body, &v) == nil && v.TURN != nil {
		r.addSecret(v.TURN.Password)
	}
}

type rigOpt func(*Config)

func newRig(t *testing.T, opts ...rigOpt) *rig { t.Helper(); return buildRig(t, false, opts...) }

// newWGRig builds a hub with a real wireguard-go tunnel listening on loopback.
func newWGRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	return buildRig(t, true, append([]rigOpt{func(c *Config) { c.PodIP = "127.0.0.1" }}, opts...)...)
}

func buildRig(t *testing.T, realWG bool, opts ...rigOpt) *rig {
	t.Helper()
	logger, logs := captureLogger()
	r := &rig{
		t: t, pol: newFakePolicy(), flags: newFakeFlags(), ids: newMemIdentity(), users: newFakeUsers(),
		sa: newFakeSA(), authz: newFakeAuthz(), tun: newFakeTunnel(), clock: newFakeClock(), logs: logs,
		dev: newDeviceCreds(t),
	}
	cfg := Config{
		Namespace: api.HubNamespace, PodIP: "10.1.2.3", Logger: logger, Now: r.clock.Now,
		IPRate: 1000, IPBurst: 1000, SubjectRate: 1000, SubjectBurst: 1000,
		ReapInterval: time.Hour, // tests call reap() themselves
	}
	for _, o := range opts {
		o(&cfg)
	}
	deps := Deps{
		Policy: r.pol, Flags: r.flags, Identity: r.ids, Users: r.users, SA: r.sa, Authz: r.authz,
		TURN: NewTURNMinter(func() (string, error) { return turnSecret, nil }, []string{"turn:turn.example.com:3478?transport=udp"}, 30*time.Minute, r.clock.Now),
	}
	if !realWG {
		deps.Tunnel = r.tun
	}
	h, err := New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	t.Cleanup(func() { _ = h.Close() })
	r.srv = httptest.NewServer(h.Handler())
	t.Cleanup(r.srv.Close)

	r.policy = api.PolicyEntry{
		Device: testDevice, Namespace: testNS, State: api.StateActive, RSAPublicCert: r.dev.certPEM,
		AllowedPorts: []int{22}, EnrollmentGeneration: 1, EnrollUntil: r.clock.Now().Add(15 * time.Minute),
	}
	r.setPolicy(r.policy)
	r.flags.Set(testNS, testDevice, map[string]string{api.AnnotationWireGuard: "enabled"})
	r.authz.set(aliceEmail, testNS, true)
	r.users.set(aliceToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	return r
}

func (r *rig) setPolicy(p api.PolicyEntry) { r.policy = p; r.pol.Set(p) }

func (r *rig) post(path, token string, body any) (int, []byte) {
	r.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			r.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, r.srv.URL+path, rd)
	if err != nil {
		r.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		r.addSecret(token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	r.noteTURN(out)
	return resp.StatusCode, out
}

// wantReason asserts a denial.
func wantReason(t *testing.T, status int, body []byte, wantStatus int, wantReason string) {
	t.Helper()
	var e api.Error
	_ = json.Unmarshal(body, &e)
	if status != wantStatus || e.Reason != wantReason {
		t.Fatalf("got %d %q (%s), want %d %q", status, e.Reason, strings.TrimSpace(string(body)), wantStatus, wantReason)
	}
}

func (r *rig) enroll(tok string, req api.EnrollRequest) (int, []byte) {
	return r.post(api.DeviceEnrollPath, tok, req)
}

// enrollOK enrolls the rig's device identity at the current time.
func (r *rig) enrollOK() api.EnrollResponse {
	r.t.Helper()
	tok, req := r.dev.enrollRequest(r.t, r.clock.Now())
	st, body := r.enroll(tok, req)
	if st != http.StatusCreated && st != http.StatusOK {
		r.t.Fatalf("enroll: %d %s", st, body)
	}
	var resp api.EnrollResponse
	_ = json.Unmarshal(body, &resp)
	return resp
}

type devSess struct {
	api.SessionResponse
	priv wgkey.PrivateKey
	pub  wgkey.PublicKey
}

// deviceSessionOK creates a device session (enrolling first if needed).
func (r *rig) deviceSessionOK(hostKeys ...string) devSess {
	r.t.Helper()
	if _, found, _ := r.ids.Get(context.Background(), testNS, testDevice); !found {
		r.enrollOK()
	}
	tok, req, priv := r.dev.sessionRequest(r.t, r.clock.Now(), hostKeys...)
	st, body := r.post(api.DeviceSessionPath, tok, req)
	if st != http.StatusCreated {
		r.t.Fatalf("device session: %d %s", st, body)
	}
	var resp api.SessionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		r.t.Fatal(err)
	}
	pub, _ := priv.Public()
	return devSess{SessionResponse: resp, priv: priv, pub: pub}
}

func (r *rig) clientReq(port int) (api.ClientSessionRequest, wgkey.PrivateKey) {
	priv, pub, err := wgkey.Generate()
	if err != nil {
		r.t.Fatal(err)
	}
	return api.ClientSessionRequest{
		Namespace: testNS, Device: testDevice, Port: port, WGPublicKey: pub.Base64(),
		Posture: api.Posture{Software: "tnctl", Version: "test"},
	}, priv
}

func (r *rig) clientSession(token string, req api.ClientSessionRequest) (int, []byte) {
	return r.post(api.ClientSessionPath, token, req)
}

func (r *rig) clientSessionOK() api.SessionResponse {
	r.t.Helper()
	req, _ := r.clientReq(22)
	st, body := r.clientSession(aliceToken, req)
	if st != http.StatusCreated {
		r.t.Fatalf("client session: %d %s", st, body)
	}
	var resp api.SessionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		r.t.Fatal(err)
	}
	return resp
}

// tunnelPost calls the in-tunnel API as if from overlay address ip.
func (r *rig) tunnelPost(path, ip, token string, body any) (int, []byte) {
	r.t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, path, rd)
	req.RemoteAddr = netip.AddrPortFrom(netip.MustParseAddr(ip), 40000).String()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		r.addSecret(token)
	}
	rec := httptest.NewRecorder()
	r.h.tunnelHandler().ServeHTTP(rec, req)
	r.noteTURN(rec.Body.Bytes())
	return rec.Code, rec.Body.Bytes()
}
