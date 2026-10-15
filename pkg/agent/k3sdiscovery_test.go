package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// fakeK8sAPI stands in for the Kubernetes API server of the device.
type fakeK8sAPI struct {
	mu     sync.Mutex
	srv    *httptest.Server
	status int
	body   string
	hits   int
	auth   []string
	query  []string
	path   []string
}

func newFakeK8sAPI(t *testing.T) *fakeK8sAPI {
	t.Helper()
	f := &fakeK8sAPI{status: http.StatusOK, body: `{"items":[]}`}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits++
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.query = append(f.query, r.URL.RawQuery)
		f.path = append(f.path, r.URL.Path)
		status, body := f.status, f.body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeK8sAPI) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeK8sAPI) hitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

// k3sRig is a lister wired to the fake API with a token and a CA file and a
// fake clock.
type k3sRig struct {
	api       *fakeK8sAPI
	lister    *k3sLister
	tokenFile string
	now       time.Time
	mu        sync.Mutex
}

func newK3sRig(t *testing.T) *k3sRig {
	t.Helper()
	f := newFakeK8sAPI(t)
	dir := t.TempDir()
	r := &k3sRig{api: f, tokenFile: filepath.Join(dir, "token"), now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	caFile := filepath.Join(dir, "ca.crt")
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemCA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.tokenFile, []byte("token-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.lister = newK3sLister(k3sConfig{APIURL: f.srv.URL, TokenFile: r.tokenFile, CAFile: caFile, Now: func() time.Time {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.now
	}})
	return r
}

func (r *k3sRig) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = r.now.Add(d)
}

func (r *k3sRig) list(t *testing.T) api.K3sServiceList {
	t.Helper()
	return r.lister.List(t.Context())
}

const k3sTwoServices = `{"metadata":{"resourceVersion":"1"},"items":[
 {"metadata":{"namespace":"teknoir","name":"notebook","labels":{"a":"b"},"annotations":{"secret":"value"}},
  "spec":{"type":"ClusterIP","clusterIP":"10.43.0.9","selector":{"app":"nb"},"ports":[{"name":"http","port":8888,"protocol":"TCP","appProtocol":"http","targetPort":8888}]}},
 {"metadata":{"namespace":"monitoring","name":"prometheus"},
  "spec":{"clusterIP":"10.43.0.10","ports":[{"port":9090,"protocol":"TCP"}]}},
 {"metadata":{"namespace":"default","name":"kubernetes"},"spec":{"type":"ClusterIP","clusterIP":"10.43.0.1","ports":[{"name":"https","port":443,"protocol":"TCP"}]}},
 {"metadata":{"namespace":"monitoring","name":"grafana"},"spec":{"type":"NodePort","clusterIP":"10.43.0.11","ports":[{"port":3000,"protocol":"TCP"}]}},
 {"metadata":{"namespace":"","name":"nameless"},"spec":{}}
]}`

func TestK3sListMapsAndSorts(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusOK, k3sTwoServices)
	got := r.list(t)
	if got.Error != "" || got.Truncated {
		t.Fatalf("%+v", got)
	}
	var names []string
	for _, s := range got.Services {
		names = append(names, s.Namespace+"/"+s.Name)
	}
	if want := "default/kubernetes monitoring/grafana monitoring/prometheus teknoir/notebook"; strings.Join(names, " ") != want {
		t.Fatalf("order %v, want %s", names, want)
	}
	nb := got.Services[3]
	if nb.Type != "ClusterIP" || nb.ClusterIP != "10.43.0.9" || len(nb.Ports) != 1 ||
		nb.Ports[0] != (api.K3sServicePort{Name: "http", Port: 8888, Protocol: "TCP", AppProtocol: "http"}) {
		t.Errorf("notebook %+v", nb)
	}
	if got.Services[2].Type != "ClusterIP" { // an API server that omits the type
		t.Errorf("default type %q", got.Services[2].Type)
	}
	if got.Services[1].Type != "NodePort" {
		t.Errorf("type %q", got.Services[1].Type)
	}
	if !got.ObservedAt.Equal(r.now) {
		t.Errorf("observedAt %s", got.ObservedAt)
	}
	// Metadata only: nothing of labels, annotations or selectors survives.
	raw, _ := json.Marshal(got)
	for _, leak := range []string{"secret", "annotations", "labels", "selector", "targetPort"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("answer contains %q: %s", leak, raw)
		}
	}
	// The request: one page, the token as bearer, cluster-wide.
	if q := r.api.query[0]; q != fmt.Sprintf("limit=%d", api.MaxK3sServices) {
		t.Errorf("query %q", q)
	}
	if p := r.api.path[0]; p != "/api/v1/services" {
		t.Errorf("path %q", p)
	}
	if a := r.api.auth[0]; a != "Bearer token-one" {
		t.Errorf("authorization header %q", a)
	}
}

func TestK3sListCacheAndTokenReread(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusOK, k3sTwoServices)
	first := r.list(t)
	r.api.set(http.StatusOK, `{"items":[]}`)
	r.advance(9 * time.Second)
	if again := r.list(t); len(again.Services) != len(first.Services) || r.api.hitCount() != 1 {
		t.Fatalf("not cached: %d services, %d hits", len(again.Services), r.api.hitCount())
	}
	// A rotated token is picked up by the next fetch.
	if err := os.WriteFile(r.tokenFile, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Second)
	if fresh := r.list(t); len(fresh.Services) != 0 || r.api.hitCount() != 2 {
		t.Fatalf("not refreshed: %+v, %d hits", fresh, r.api.hitCount())
	}
	if a := r.api.auth[1]; a != "Bearer token-two" {
		t.Errorf("authorization header %q", a)
	}
}

func TestK3sListConcurrentCallsShareOneFetch(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusOK, k3sTwoServices)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := r.lister.List(t.Context()); got.Error != "" {
				t.Errorf("%+v", got)
			}
		}()
	}
	wg.Wait()
	if n := r.api.hitCount(); n != 1 {
		t.Errorf("%d API calls for 8 concurrent requests", n)
	}
}

func TestK3sListPermissionErrors(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		r := newK3sRig(t)
		r.api.set(status, `{"kind":"Status","message":"services is forbidden: User \"system:serviceaccount:x:y\" cannot list"}`)
		got := r.list(t)
		if got.Error != k3sErrNoPermission || got.Services == nil || len(got.Services) != 0 {
			t.Errorf("%d: %+v", status, got)
		}
		if strings.Contains(got.Error, "serviceaccount") {
			t.Errorf("%d: the API's message leaked: %q", status, got.Error)
		}
	}
	// No token at all (the pod has no ServiceAccount token mounted).
	r := newK3sRig(t)
	if err := os.Remove(r.tokenFile); err != nil {
		t.Fatal(err)
	}
	if got := r.list(t); got.Error != k3sErrNoPermission || len(got.Services) != 0 || r.api.hitCount() != 0 {
		t.Errorf("no token: %+v, %d hits", got, r.api.hitCount())
	}
	// An empty token file counts as no token.
	r = newK3sRig(t)
	if err := os.WriteFile(r.tokenFile, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := r.list(t); got.Error != k3sErrNoPermission {
		t.Errorf("empty token: %+v", got)
	}
}

func TestK3sListOtherFailures(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusInternalServerError, "boom")
	if got := r.list(t); got.Error != "the Kubernetes API of the device answered 500" || len(got.Services) != 0 {
		t.Errorf("500: %+v", got)
	}
	r = newK3sRig(t)
	r.api.set(http.StatusOK, "<html>not json</html>")
	if got := r.list(t); got.Error != k3sErrBadAnswer {
		t.Errorf("garbage: %+v", got)
	}
	// A CA that does not match the server: the connection is refused, the
	// token is never sent.
	r = newK3sRig(t)
	if err := os.WriteFile(r.lister.cfg.CAFile, unrelatedCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := r.list(t); got.Error != k3sErrUnreachable || r.api.hitCount() != 0 {
		t.Errorf("untrusted server: %+v, %d hits", got, r.api.hitCount())
	}
	// Unreadable CA, unreachable server, no cluster.
	r = newK3sRig(t)
	if err := os.WriteFile(r.lister.cfg.CAFile, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := r.list(t); got.Error != k3sErrUnreachable {
		t.Errorf("bad CA: %+v", got)
	}
	r = newK3sRig(t)
	r.api.srv.Close()
	if got := r.list(t); got.Error != k3sErrUnreachable {
		t.Errorf("server down: %+v", got)
	}
	l := newK3sLister(k3sConfigFromEnv(func(string) string { return "" }))
	if got := l.List(t.Context()); got.Error != k3sErrNoCluster || got.Services == nil {
		t.Errorf("no cluster: %+v", got)
	}
}

func TestK3sListTimesOut(t *testing.T) {
	r := newK3sRig(t)
	block := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); slow.Close() })
	if err := os.WriteFile(r.lister.cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: slow.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	r.lister.cfg.APIURL, r.lister.cfg.Timeout = slow.URL, 200*time.Millisecond
	start := time.Now()
	if got := r.list(t); got.Error != k3sErrUnreachable {
		t.Errorf("%+v", got)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
}

func TestK3sListTruncation(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusOK, `{"metadata":{"continue":"abc"},"items":[{"metadata":{"namespace":"a","name":"b"},"spec":{"clusterIP":"None"}}]}`)
	got := r.list(t)
	if !got.Truncated || len(got.Services) != 1 || got.Services[0].ClusterIP != "None" || got.Error != "" {
		t.Errorf("%+v", got)
	}
	// An API server that ignores the limit still cannot exceed the cap.
	r = newK3sRig(t)
	r.api.set(http.StatusOK, manyServices(api.MaxK3sServices+25))
	got = r.list(t)
	if !got.Truncated || len(got.Services) != api.MaxK3sServices {
		t.Errorf("%d services, truncated=%v", len(got.Services), got.Truncated)
	}
	// Exactly the cap is not truncated.
	r = newK3sRig(t)
	r.api.set(http.StatusOK, manyServices(api.MaxK3sServices))
	got = r.list(t)
	if got.Truncated || len(got.Services) != api.MaxK3sServices {
		t.Errorf("%d services, truncated=%v", len(got.Services), got.Truncated)
	}
}

func manyServices(n int) string {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"metadata":{"namespace":"ns","name":"svc-%04d"},"spec":{}}`, i)
	}
	b.WriteString(`]}`)
	return b.String()
}

// unrelatedCA is a PEM certificate that did not sign the fake API server.
func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestK3sListPortCap(t *testing.T) {
	var ports []string
	for i := range api.MaxK3sServicePorts + 10 {
		ports = append(ports, fmt.Sprintf(`{"name":"p%d","port":%d,"protocol":"UDP"}`, i, 1000+i))
	}
	r := newK3sRig(t)
	r.api.set(http.StatusOK, `{"items":[{"metadata":{"namespace":"a","name":"many"},"spec":{"ports":[`+strings.Join(ports, ",")+`]}}]}`)
	got := r.list(t)
	if len(got.Services) != 1 || len(got.Services[0].Ports) != api.MaxK3sServicePorts {
		t.Fatalf("%+v", got)
	}
	if last := got.Services[0].Ports[api.MaxK3sServicePorts-1]; last.Port != 1000+api.MaxK3sServicePorts-1 || last.Protocol != "UDP" {
		t.Errorf("last port %+v", last)
	}
}

// ---- the control route ----

func k3sControlRig(t *testing.T, r *k3sRig) *controlServer {
	t.Helper()
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	c, _, _ := controlRig(t)
	mux := http.NewServeMux()
	mux.HandleFunc(api.ControlK3sServicesPath, c.k3sHandler(r.lister))
	c.srv.Handler = mux
	return c
}

func k3sCall(c *controlServer, method, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, api.ControlK3sServicesPath, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	c.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func TestK3sControlRoute(t *testing.T) {
	r := newK3sRig(t)
	r.api.set(http.StatusOK, k3sTwoServices)
	c := k3sControlRig(t, r)
	hub := api.HubAddress + ":51000"

	rec := k3sCall(c, http.MethodGet, hub)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var got api.K3sServiceList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Services) != 4 {
		t.Fatalf("%v %+v", err, got)
	}
	// Same access checks as the other control handlers.
	if rec := k3sCall(c, http.MethodGet, "100.96.0.9:51000"); rec.Code != http.StatusForbidden {
		t.Errorf("stranger got %d", rec.Code)
	}
	if rec := k3sCall(c, http.MethodGet, "garbage"); rec.Code != http.StatusForbidden {
		t.Errorf("unparsable peer got %d", rec.Code)
	}
	if rec := k3sCall(c, http.MethodPost, hub); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Errorf("POST got %d", rec.Code)
	}
	if n := r.api.hitCount(); n != 1 {
		t.Errorf("a refused request reached the API server (%d hits)", n)
	}
	// A permission problem is a 200 with the reason.
	r2 := newK3sRig(t)
	r2.api.set(http.StatusForbidden, "{}")
	rec = k3sCall(k3sControlRig(t, r2), http.MethodGet, hub)
	got = api.K3sServiceList{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got.Error != k3sErrNoPermission || !strings.Contains(rec.Body.String(), `"services":[]`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

// The real control server serves the route and, outside a cluster, says so.
func TestK3sRouteIsRegistered(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	c, _, _ := controlRig(t)
	rec := k3sCall(c, http.MethodGet, api.HubAddress+":51000")
	var got api.K3sServiceList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got.Error != k3sErrNoCluster {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := k3sCall(c, http.MethodGet, "100.96.0.9:1"); rec.Code != http.StatusForbidden {
		t.Errorf("stranger got %d", rec.Code)
	}
}

func TestK3sConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c := k3sConfigFromEnv(env(map[string]string{"KUBERNETES_SERVICE_HOST": "10.43.0.1", "KUBERNETES_SERVICE_PORT": "443"}))
	if c.APIURL != "https://10.43.0.1:443" || c.TokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" || c.CAFile != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" {
		t.Errorf("%+v", c)
	}
	if c := k3sConfigFromEnv(env(map[string]string{"KUBERNETES_SERVICE_HOST": "fd00::1", "KUBERNETES_SERVICE_PORT": "6443"})); c.APIURL != "https://[fd00::1]:6443" {
		t.Errorf("ipv6: %q", c.APIURL)
	}
	if c := k3sConfigFromEnv(env(nil)); c.APIURL != "" {
		t.Errorf("no env: %q", c.APIURL)
	}
}
