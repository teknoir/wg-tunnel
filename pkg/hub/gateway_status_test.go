package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

const (
	bobEmail    = "bob@example.com"
	backstageSA = "system:serviceaccount:teknoir-system:backstage"
	gwToken     = "gateway-sa-token-SECRET"
)

// VerifyDelegate makes the fake SA verifier accept gateway sessions.
func (f *fakeSA) VerifyDelegate(ctx context.Context, token, ns, device string) (SAIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, ok := f.tokens[token]
	if !ok {
		return SAIdentity{}, ErrUnauthenticated
	}
	if b := f.bindings[name]; b != [2]string{ns, device} {
		return SAIdentity{}, ErrForbidden
	}
	return SAIdentity{Name: name}, nil
}

// gwSession creates a gateway (perConn) session for service.
func gwSession(w *wgRig, service string) (*wgPeer, api.SessionResponse) {
	w.t.Helper()
	return w.serviceClient(gwToken, service, func(q *api.ClientSessionRequest) {
		q.Posture.Software, q.Direct = "web-gateway", true
	})
}

// dialAs opens a spliced connection for user and returns it with the hub's answer.
func dialAs(p *wgPeer, service, as string) (net.Conn, api.ConnectResponse, error) {
	c, err := dialSplice(p)
	if err != nil {
		return nil, api.ConnectResponse{}, err
	}
	wrapped, resp, err := connectproto.Handshake(c, api.ConnectRequest{Service: service, As: as}, 5*time.Second)
	if err != nil {
		_ = c.Close()
		return nil, resp, err
	}
	return wrapped, resp, nil
}

func TestGatewaySessionAuthorizesEveryConnectionForItsOwnUser(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	w.authz.set(bobEmail, testNS, true)

	cli, resp := gwSession(w, "web")
	if resp.Service != "web" {
		t.Fatalf("service %q", resp.Service)
	}
	// Alice and Bob share one session; each connection names its user.
	ca, ans, err := dialAs(cli, "web", aliceEmail)
	if err != nil || !ans.OK {
		t.Fatalf("alice: %v %+v", err, ans)
	}
	echo(t, ca, "alice talking")
	cb, ans, err := dialAs(cli, "web", bobEmail)
	if err != nil || !ans.OK {
		t.Fatalf("bob: %v %+v", err, ans)
	}
	echo(t, cb, "bob talking")
	want := []api.ConnectRequest{{Service: "web", As: aliceEmail}, {Service: "web", As: bobEmail}}
	if got := agent.connects(); !slices.Equal(got, want) {
		t.Fatalf("agent saw %+v, want %+v", got, want)
	}
	// The console lists both users on the one session.
	s := w.h.sessionByAddr(cli.addr)
	if got := s.info().Subject; got != aliceEmail+", "+bobEmail {
		t.Errorf("subject %q", got)
	}
	if got := s.info().Software; got != "web-gateway" {
		t.Errorf("software %q", got)
	}
	_ = ca.Close()
	_ = cb.Close()

	// A user without access to the teamspace is refused before the agent hears of it.
	w.authz.set(bobEmail, testNS, false)
	before := len(agent.connects())
	_, ans, err = dialAs(cli, "web", bobEmail)
	if err != nil || ans.OK || ans.Reason != api.ReasonForbidden {
		t.Fatalf("bob without access: err %v answer %+v", err, ans)
	}
	// An unknown user is not authorized either (the fake answers false).
	if _, ans, _ = dialAs(cli, "web", "mallory@example.com"); ans.OK || ans.Reason != api.ReasonForbidden {
		t.Fatalf("unknown user: %+v", ans)
	}
	if after := len(agent.connects()); after != before {
		t.Fatalf("the agent was contacted for a denied user (%d -> %d)", before, after)
	}
	// The hub never takes the user from anywhere but the preamble: another
	// service or a malformed user is a bad request.
	for _, req := range []api.ConnectRequest{{Service: "ssh", As: aliceEmail}, {Service: "web"}, {Service: "web", As: "Alice@Example.com"}, {Service: "web", As: "a b@example.com"}} {
		c, err := dialSplice(cli)
		if err != nil {
			t.Fatal(err)
		}
		_, ans, err := connectproto.Handshake(c, req, 5*time.Second)
		_ = c.Close()
		if err != nil || ans.OK || ans.Reason != api.ReasonBadRequest {
			t.Errorf("%+v: err %v answer %+v", req, err, ans)
		}
	}
	logs := w.logs.String()
	if !strings.Contains(logs, `"subject":"bob@example.com via sa:wgt-cam-1"`) {
		t.Errorf("the denied connection was not attributed to the user:\n%s", logs)
	}
	if strings.Contains(logs, gwToken) {
		t.Error("the SA token reached the logs")
	}
}

func TestGatewaySessionRules(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	req, _ := w.clientReq(0)
	req.Service, req.Port, req.Direct, req.Posture.Software = "web", 0, true, "web-gateway"

	// Not on the outside API, not with a user token, not for another device.
	st, body := w.postTo(w.srv.URL, api.ClientSessionPath, gwToken, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	st, body = w.clientSessionInternal(aliceToken, req)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	w.sa.add("other-token", "wgt-other", testNS, "other-device")
	st, body = w.clientSessionInternal("other-token", req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)

	// One session per web service fits in the gateway's quota (the user quota is 5).
	for i := range 8 {
		cli, _ := gwSession(w, "web")
		if cli == nil {
			t.Fatalf("session %d refused", i)
		}
	}
	// The in-tunnel renewal needs the SA token and takes the client-reported path.
	cli, resp := gwSession(w, "web")
	_ = cli
	s := w.h.sessionByAddr(cli.addr)
	if s == nil || !s.perConn || s.subject != "" {
		t.Fatalf("session %+v", s)
	}
	code, out := w.tunnelPost(api.RenewPath, resp.Address, gwToken, api.RenewRequest{Posture: api.Posture{Software: "web-gateway"}, Path: api.PathDirect})
	if code != http.StatusOK {
		t.Fatalf("renew: %d %s", code, out)
	}
	if got := s.info().Path; got != api.PathDirect {
		t.Errorf("path %q", got)
	}
	// An unknown path value is ignored.
	w.tunnelPost(api.RenewPath, resp.Address, gwToken, api.RenewRequest{Posture: api.Posture{Software: "web-gateway"}, Path: "carrier-pigeon"})
	if got := s.info().Path; got != api.PathDirect {
		t.Errorf("path %q after a bogus report", got)
	}
	// A renewal with another token ends the session like any denied renewal.
	code, out = w.tunnelPost(api.RenewPath, resp.Address, "wrong-token", api.RenewRequest{Posture: api.Posture{Software: "web-gateway"}})
	wantReason(t, code, out, http.StatusUnauthorized, api.ReasonUnauthenticated)
	if w.h.sessionByAddr(cli.addr) != nil {
		t.Error("the session survived a renewal with a foreign token")
	}
}

func TestGatewaySessionEndsWithItsService(t *testing.T) {
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	cli, _ := gwSession(w, "web")
	c, ans, err := dialAs(cli, "web", aliceEmail)
	if err != nil || !ans.OK {
		t.Fatalf("%v %+v", err, ans)
	}
	echo(t, c, "up")
	withServices(w.rig, camSvc) // web is no longer defined
	waitFor(t, "the gateway session to end", func() bool { return w.h.sessionByAddr(cli.addr) == nil })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("the connection survived the service removal (%d, %v)", n, err)
	}
}

// ---- status listener ----

type fakeStatusAuth struct {
	mu    sync.Mutex
	users map[string]string
	err   error
	calls int
}

func (f *fakeStatusAuth) Authenticate(_ context.Context, token string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	u, ok := f.users[token]
	if !ok {
		return "", fmt.Errorf("%w: unknown token", ErrUnauthenticated)
	}
	return u, nil
}

const (
	backstageToken = "backstage-sa-token-SECRET"
	otherSAToken   = "some-other-pod-token-SECRET"
)

type statusRig struct {
	*wgRig
	agent *svcAgent
	srv   *httptest.Server
	auth  *fakeStatusAuth
}

func newStatusRig(t *testing.T) *statusRig {
	t.Helper()
	agent := &svcAgent{}
	w := newSvcRig(t, capsFull, []api.ServiceSpec{webSvc}, agent)
	w.sa.add(gwToken, "wgt-cam-1", testNS, testDevice)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA, otherSAToken: "system:serviceaccount:teknoir-demo:default-editor"}}
	w.h.deps.Status, w.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(w.h.StatusHandler())
	t.Cleanup(srv.Close)
	return &statusRig{wgRig: w, agent: agent, srv: srv, auth: auth}
}

func (s *statusRig) call(method, path, token string, hdr map[string]string) (int, []byte) {
	s.t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		s.addSecret(token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (s *statusRig) get(token string) (int, []byte) {
	return s.call("GET", api.StatusDevicePath+testNS+"/"+testDevice, token, nil)
}

func TestStatusListenerAuthentication(t *testing.T) {
	s := newStatusRig(t)
	st, body := s.get("")
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	st, body = s.get("garbage")
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	// A perfectly valid service account that is not Backstage.
	st, body = s.get(otherSAToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	// A user token of the platform is no service account token at all.
	st, body = s.get(aliceToken)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	// The API server being down is a 503, not a pass.
	s.auth.mu.Lock()
	s.auth.err = fmt.Errorf("%w: down", ErrUnavailable)
	s.auth.mu.Unlock()
	if st, _ := s.get(backstageToken); st != http.StatusServiceUnavailable {
		t.Errorf("api server down: %d", st)
	}
	s.auth.mu.Lock()
	s.auth.err = nil
	s.auth.mu.Unlock()
	if st, body = s.get(backstageToken); st != http.StatusOK {
		t.Fatalf("backstage: %d %s", st, body)
	}
	// The admin action needs the same identity.
	st, body = s.call("POST", api.AdminEndSessionPath+"abc/end", otherSAToken, nil)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)

	// Without configuration the listener refuses everything, even the right token.
	s.h.cfg.BackstageSA = ""
	st, body = s.get(backstageToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	s.h.cfg.BackstageSA = backstageSA
	s.h.deps.Status = nil
	st, body = s.get(backstageToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	if strings.Contains(s.logs.String(), backstageToken) || strings.Contains(s.logs.String(), otherSAToken) {
		t.Error("a token reached the logs")
	}
}

func TestStatusListenerRoutesAndBadRequests(t *testing.T) {
	s := newStatusRig(t)
	st, body := s.call("GET", api.StatusDevicePath+testNS+"/nope", backstageToken, nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonDeviceUnknown)
	st, body = s.call("GET", api.StatusDevicePath+"UPPER/dev", backstageToken, nil)
	wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	if st, _ := s.call("POST", api.StatusDevicePath+testNS+"/"+testDevice, backstageToken, nil); st != http.StatusMethodNotAllowed {
		t.Errorf("POST on status: %d", st)
	}
	if st, _ := s.call("GET", api.AdminEndSessionPath+"x/end", backstageToken, nil); st != http.StatusMethodNotAllowed {
		t.Errorf("GET on end: %d", st)
	}
	if st, _ := s.call("GET", "/v1/anything-else", backstageToken, nil); st != http.StatusNotFound {
		t.Errorf("unknown path: %d", st)
	}
	if st, _ := s.call("GET", api.HealthzPath, "", nil); st != http.StatusOK {
		t.Errorf("healthz: %d", st)
	}
}

func decodeStatus(t *testing.T, body []byte) api.DeviceLiveStatus {
	t.Helper()
	var st api.DeviceLiveStatus
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return st
}

func TestStatusReportsTheLiveDevice(t *testing.T) {
	s := newStatusRig(t)
	// Real traffic: a user session through the splice, and a gateway session.
	user, _ := s.serviceClient(aliceToken, "web")
	uc, err := dialSplice(user)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("0123456789", 100)
	echo(t, uc, payload)
	gw, _ := gwSession(s.wgRig, "web")
	gc, ans, err := dialAs(gw, "web", aliceEmail)
	if err != nil || !ans.OK {
		t.Fatalf("%v %+v", err, ans)
	}
	echo(t, gc, "gw")

	stc, body := s.get(backstageToken)
	if stc != http.StatusOK {
		t.Fatalf("%d %s", stc, body)
	}
	st := decodeStatus(t, body)
	if !st.Connected || st.ConnectedSince.IsZero() || st.AgentVersion != "test" || st.Transport != "turn" || st.NAT != "unknown" {
		t.Errorf("device block: %+v", st)
	}
	if !slices.Equal(st.Capabilities, capsFull) {
		t.Errorf("capabilities %v", st.Capabilities)
	}
	if st.LastHandshake.IsZero() || time.Since(st.LastHandshake) > time.Minute {
		t.Errorf("last handshake %v", st.LastHandshake)
	}
	if st.IdentityPending {
		t.Error("an approved identity is pending")
	}
	if len(st.Sessions) != 2 {
		t.Fatalf("sessions %+v", st.Sessions)
	}
	byApp := map[string]api.ClientSessionInfo{}
	for _, c := range st.Sessions {
		byApp[c.Software] = c
	}
	u, g := byApp["tnctl"], byApp["web-gateway"]
	if u.Subject != aliceEmail || u.Service != "web" || u.Path != api.PathHub || u.ID == "" || u.Since.IsZero() {
		t.Errorf("user session: %+v", u)
	}
	if g.Subject != aliceEmail || g.Service != "web" {
		t.Errorf("gateway session: %+v", g)
	}
	if u.BytesIn < int64(len(payload)) || u.BytesOut < int64(len(payload)) {
		t.Errorf("bytes in/out %d/%d, want at least %d each way", u.BytesIn, u.BytesOut, len(payload))
	}
	if g.BytesIn != 2 || g.BytesOut != 2 {
		t.Errorf("gateway bytes %d/%d, want 2/2 (the preamble is not payload)", g.BytesIn, g.BytesOut)
	}
	// The gateway session is listed without a user once the connection closed.
	_ = gc.Close()
	waitFor(t, "the connection to close", func() bool { return s.h.sessionByAddr(gw.addr).connCount() == 0 })
	st = decodeStatus(t, func() []byte { _, b := s.get(backstageToken); return b }())
	for _, c := range st.Sessions {
		if c.Software == "web-gateway" && c.Subject != "" {
			t.Errorf("idle gateway session still lists %q", c.Subject)
		}
	}
	_ = uc.Close()
}

// The live identity carries the attested host key and the activation source,
// from the hub's store (review finding 1, hub part).
func TestStatusIdentityCarriesTheAttestation(t *testing.T) {
	r := newRig(t)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
	r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(srv.Close)
	hk := newTestHostKey(t, "ed25519")
	r.trust(hk)
	if st, body := r.attestedEnroll(r.dev, hk); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if st, body := r.deviceSessionStatus(); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	req, _ := http.NewRequest("GET", srv.URL+api.StatusDevicePath+testNS+"/"+testDevice, nil)
	req.Header.Set("Authorization", "Bearer "+backstageToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	id := decodeStatus(t, b).Identity
	if id == nil || id.AttestedHostKey != hk.fp || id.AttestedHostKeyType != "ssh-ed25519" || id.ActivatedBy != api.ActivatedByDeviceKey ||
		id.Fingerprint != r.dev.fingerprint() || id.Voided || id.EnrollmentGeneration != r.policy.EnrollmentGeneration {
		t.Fatalf("identity %+v", id)
	}
}

func TestStatusOfAnOfflineAndPendingDevice(t *testing.T) {
	r := newRig(t)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
	r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(srv.Close)
	get := func() api.DeviceLiveStatus {
		req, _ := http.NewRequest("GET", srv.URL+api.StatusDevicePath+testNS+"/"+testDevice, nil)
		req.Header.Set("Authorization", "Bearer "+backstageToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		return decodeStatus(t, b)
	}
	// Nothing enrolled: offline, nothing pending, an empty (not null) session list.
	st := get()
	if st.Connected || st.IdentityPending || st.Sessions == nil || len(st.Sessions) != 0 || st.Identity != nil {
		t.Errorf("fresh device: %+v", st)
	}
	// Enrolled but not approved: waiting for an admin.
	r.enrollOK()
	if st = get(); st.Connected || !st.IdentityPending {
		t.Errorf("enrolled device: %+v", st)
	}
	// The pin is reported from the hub's identity store (attested host key, if any).
	if st.Identity == nil || st.Identity.Fingerprint != r.dev.fingerprint() || st.Identity.AttestedHostKey != "" ||
		st.Identity.EnrollmentEpoch != r.policy.EnrollmentEpoch || st.Identity.ActivatedBy != "" {
		t.Errorf("identity of the unattested pin: %+v", st.Identity)
	}
	r.approve()
	if st = get(); st.IdentityPending {
		t.Errorf("approved device: %+v", st)
	}
	// Without the approval the pinned identity waits again.
	p := r.policy
	p.ApprovedFingerprint = ""
	r.setPolicy(p)
	if st = get(); !st.IdentityPending {
		t.Errorf("approval removed: %+v", st)
	}
}

func TestAdminEndSession(t *testing.T) {
	s := newStatusRig(t)
	user, resp := s.serviceClient(aliceToken, "web")
	c, err := dialSplice(user)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "before")

	// Not an existing session, not a client session, not a valid id.
	st, body := s.call("POST", api.AdminEndSessionPath+strings.Repeat("0", 32)+"/end", backstageToken, nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
	st, body = s.call("POST", api.AdminEndSessionPath+s.devSess.SessionID+"/end", backstageToken, nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
	if devs, _ := s.h.SessionCounts(); devs != 1 {
		t.Fatal("a device session was ended through the admin endpoint")
	}

	st, body = s.call("POST", api.AdminEndSessionPath+resp.SessionID+"/end", backstageToken, map[string]string{StatusRequesterHeader: aliceEmail})
	if st != http.StatusNoContent {
		t.Fatalf("end: %d %s", st, body)
	}
	if s.h.sessionByAddr(user.addr) != nil {
		t.Error("session still registered")
	}
	// The spliced stream was closed like in a revocation.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("the connection survived (%d, %v)", n, err)
	}
	// A second end finds nothing; the in-tunnel renewal of the ended session fails.
	st, body = s.call("POST", api.AdminEndSessionPath+resp.SessionID+"/end", backstageToken, nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonSessionUnknown)
	code, out := s.tunnelPost(api.RenewPath, resp.Address, aliceToken, api.RenewRequest{Posture: api.Posture{Software: "tnctl"}})
	wantReason(t, code, out, http.StatusNotFound, api.ReasonSessionUnknown)
	// The decision log has the requester; a missing or malformed one is "unknown".
	logs := s.logs.String()
	if !strings.Contains(logs, `"op":"admin_end"`) || !strings.Contains(logs, `"requester":"alice@example.com"`) ||
		!strings.Contains(logs, `"via":"`+backstageSA+`"`) {
		t.Errorf("no admin_end decision with the requester:\n%s", logs)
	}
	user2, resp2 := s.serviceClient(aliceToken, "web")
	st, _ = s.call("POST", api.AdminEndSessionPath+resp2.SessionID+"/end", backstageToken, map[string]string{StatusRequesterHeader: "not an email <x>"})
	if st != http.StatusNoContent || !strings.Contains(s.logs.String(), `"requester":"unknown"`) {
		t.Errorf("malformed requester: %d", st)
	}
	_ = user2
	// Ending a gateway session is the same call; the device is untouched.
	gw, gresp := gwSession(s.wgRig, "web")
	if st, _ = s.call("POST", api.AdminEndSessionPath+gresp.SessionID+"/end", backstageToken, nil); st != http.StatusNoContent {
		t.Fatalf("end gateway session: %d", st)
	}
	if s.h.sessionByAddr(gw.addr) != nil {
		t.Error("gateway session still registered")
	}
	if devs, _ := s.h.SessionCounts(); devs != 1 {
		t.Error("the device session ended")
	}
}

func TestParseLastHandshake(t *testing.T) {
	dump := "private_key=aa\nlisten_port=51820\n" +
		"public_key=11\nendpoint=1.2.3.4:5\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" +
		"public_key=22\nlast_handshake_time_sec=1760443200\nlast_handshake_time_nsec=500\ntx_bytes=1\n" +
		"public_key=33\nlast_handshake_time_sec=7\nlast_handshake_time_nsec=0\n"
	if ts, ok := parseLastHandshake(dump, "22"); !ok || ts.Unix() != 1760443200 || ts.Nanosecond() != 500 {
		t.Errorf("peer 22: %v %v", ts, ok)
	}
	if ts, ok := parseLastHandshake(dump, "11"); !ok || !ts.IsZero() {
		t.Errorf("peer 11 never handshook: %v %v", ts, ok)
	}
	if _, ok := parseLastHandshake(dump, "99"); ok {
		t.Error("unknown peer reported")
	}
}

func TestK8sStatusAuthRequiresItsOwnAudience(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	var spec authnv1.TokenReviewSpec
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		spec = tr.Spec
		switch tr.Spec.Token {
		case "backstage":
			return true, &authnv1.TokenReview{Status: authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: backstageSA}, Audiences: tr.Spec.Audiences}}, nil
		case "apiserver-token": // valid for the API server only; an apiserver that ignores audiences says so
			return true, &authnv1.TokenReview{Status: authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: backstageSA}, Audiences: []string{"https://kubernetes.default.svc"}}}, nil
		case "anonymous":
			return true, &authnv1.TokenReview{Status: authnv1.TokenReviewStatus{Authenticated: true, Audiences: tr.Spec.Audiences}}, nil
		case "broken":
			return true, nil, fmt.Errorf("apiserver down")
		}
		return true, &authnv1.TokenReview{Status: authnv1.TokenReviewStatus{Authenticated: false}}, nil
	})
	a := NewK8sStatusAuth(cs)
	if u, err := a.Authenticate(context.Background(), "backstage"); err != nil || u != backstageSA {
		t.Fatalf("%q %v", u, err)
	}
	// The review is for the status audience only, so an ordinary pod token
	// (API-server audience, replayable against the API server) is refused.
	if len(spec.Audiences) != 1 || spec.Audiences[0] != api.StatusTokenAudience {
		t.Errorf("audiences %v, want [%s]", spec.Audiences, api.StatusTokenAudience)
	}
	if a2 := NewK8sStatusAuth(cs, "custom-aud"); true {
		if u, err := a2.Authenticate(context.Background(), "backstage"); err != nil || u != backstageSA || spec.Audiences[0] != "custom-aud" {
			t.Errorf("STATUS_AUDIENCE override: %q %v %v", u, err, spec.Audiences)
		}
	}
	for tok, want := range map[string]error{"apiserver-token": ErrUnauthenticated, "nobody": ErrUnauthenticated, "anonymous": ErrUnauthenticated, "": ErrUnauthenticated, "broken": ErrUnavailable,
		strings.Repeat("x", maxBearerTokenSize+1): ErrUnauthenticated} {
		if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, want) {
			t.Errorf("token %.8q: %v, want %v", tok, err, want)
		}
	}
}

func TestK8sVerifyDelegateKeepsTheTokenAndDeviceChecks(t *testing.T) {
	bound := map[string]string{api.SAAnnotationNamespace: "acme", api.SAAnnotationDevice: "cam-1"}
	cs := k8sfake.NewSimpleClientset(saFixture("wgt-cam-1", bound), saUnmanaged("wgt-unmanaged", bound))
	var calls atomic.Int32
	user := func(sa string) authnv1.UserInfo {
		return authnv1.UserInfo{Username: "system:serviceaccount:" + api.HubNamespace + ":" + sa}
	}
	tokenReviewReactor(cs, &calls, map[string]authnv1.TokenReviewStatus{
		"ok":        {Authenticated: true, User: user("wgt-cam-1"), Audiences: []string{api.SATokenAudience}},
		"unmanaged": {Authenticated: true, User: user("wgt-unmanaged"), Audiences: []string{api.SATokenAudience}},
		"api-aud":   {Authenticated: true, User: user("wgt-cam-1")},
	})
	d := NewK8sSADelegation(cs, api.HubNamespace)
	var _ DelegateVerifier = d
	ctx := context.Background()
	if id, err := d.VerifyDelegate(ctx, "ok", "acme", "cam-1"); err != nil || id.Name != "wgt-cam-1" {
		t.Fatalf("%+v %v", id, err)
	}
	for name, tc := range map[string]struct {
		tok, ns, dev string
		want         error
	}{
		"another device":    {"ok", "acme", "cam-2", ErrForbidden},
		"unmanaged SA":      {"unmanaged", "acme", "cam-1", ErrForbidden},
		"API audience only": {"api-aud", "acme", "cam-1", ErrUnauthenticated},
		"empty token":       {"", "acme", "cam-1", ErrUnauthenticated},
	} {
		if _, err := d.VerifyDelegate(ctx, tc.tok, tc.ns, tc.dev); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
