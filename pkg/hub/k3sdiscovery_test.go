package hub

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

var capsK3s = []string{api.CapServices, api.CapControl, api.CapK3sDiscovery}

const k3sRequester = "alice@example.com"

// k3sRig is a hub with a live agent (real WireGuard) that advertises
// k3s-discovery-v1 and answers the control route with whatever the test sets.
type k3sRig struct {
	*statusRig
	hits atomic.Int32
}

func newK3sRig(t *testing.T, answer http.HandlerFunc) *k3sRig {
	t.Helper()
	k := &k3sRig{}
	agent := &svcAgent{k3s: func(w http.ResponseWriter, r *http.Request) {
		k.hits.Add(1)
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		answer(w, r)
	}}
	w := newSvcRig(t, capsK3s, []api.ServiceSpec{webSvc}, agent)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA, otherSAToken: "system:serviceaccount:teknoir-demo:default-editor"}}
	w.h.deps.Status, w.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(w.h.StatusHandler())
	t.Cleanup(srv.Close)
	k.statusRig = &statusRig{wgRig: w, agent: agent, srv: srv, auth: auth}
	return k
}

func (k *k3sRig) get(token string) (int, []byte) {
	return k.call("GET", api.StatusDevicePath+testNS+"/"+testDevice+api.StatusK3sServicesSuffix, token, map[string]string{api.StatusRequesterHeader: k3sRequester})
}

func (k *k3sRig) list(t *testing.T) api.K3sServiceList {
	t.Helper()
	st, body := k.get(backstageToken)
	if st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	var out api.K3sServiceList
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if !strings.Contains(string(body), `"services":[`) {
		t.Fatalf("services must be a list, not null: %s", body)
	}
	return out
}

func sendK3s(l api.K3sServiceList) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, l) }
}

var k3sNotebook = api.K3sService{
	Namespace: "teknoir", Name: "notebook", Type: "ClusterIP", ClusterIP: "10.43.0.9",
	Ports: []api.K3sServicePort{{Name: "http", Port: 8888, Protocol: "TCP", AppProtocol: "http"}},
}

func TestK3sServicesPassThrough(t *testing.T) {
	agentTime := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) // a device clock is not trusted
	k := newK3sRig(t, sendK3s(api.K3sServiceList{
		Services:   []api.K3sService{k3sNotebook, {Namespace: "monitoring", Name: "prometheus", Type: "NodePort", ClusterIP: "10.43.0.10", Ports: []api.K3sServicePort{{Port: 9090, Protocol: "TCP"}}}},
		Truncated:  true,
		ObservedAt: agentTime,
	}))
	got := k.list(t)
	if len(got.Services) != 2 || !got.Truncated || got.Error != "" {
		t.Fatalf("%+v", got)
	}
	if got.Services[0].Name != "notebook" || got.Services[0].Ports[0] != k3sNotebook.Ports[0] || got.Services[1].Type != "NodePort" {
		t.Errorf("%+v", got.Services)
	}
	if !got.ObservedAt.Equal(k.clock.Now()) {
		t.Errorf("observedAt %s, want the hub's clock %s", got.ObservedAt, k.clock.Now())
	}
	logs := k.logs.String()
	if !strings.Contains(logs, `"requester":"`+k3sRequester+`"`) || !strings.Contains(logs, `"op":"k3s_services"`) {
		t.Errorf("no audit line with the requester: %s", logs)
	}
	if strings.Contains(logs, backstageToken) {
		t.Error("the token reached the logs")
	}
	// A requester that is no email is logged as unknown.
	k.call("GET", api.StatusDevicePath+testNS+"/"+testDevice+api.StatusK3sServicesSuffix, backstageToken, map[string]string{api.StatusRequesterHeader: "not an email"})
	if !strings.Contains(k.logs.String(), `"requester":"unknown"`) {
		t.Error("a bad requester was not replaced")
	}
}

func TestK3sServicesAuthentication(t *testing.T) {
	k := newK3sRig(t, sendK3s(api.K3sServiceList{Services: []api.K3sService{k3sNotebook}}))
	st, body := k.get("")
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	st, body = k.get("garbage")
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	st, body = k.get(otherSAToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	st, body = k.get(aliceToken)
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	k.auth.mu.Lock()
	k.auth.err = fmt.Errorf("%w: down", ErrUnavailable)
	k.auth.mu.Unlock()
	if st, _ := k.get(backstageToken); st != http.StatusServiceUnavailable {
		t.Errorf("api server down: %d", st)
	}
	k.auth.mu.Lock()
	k.auth.err = nil
	k.auth.mu.Unlock()
	// Not configured: refused even with the right token.
	k.h.cfg.BackstageSA = ""
	st, body = k.get(backstageToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	k.h.cfg.BackstageSA = backstageSA
	k.h.deps.Status = nil
	st, body = k.get(backstageToken)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	if n := k.hits.Load(); n != 0 {
		t.Errorf("the agent was asked %d times for callers that failed authentication", n)
	}
	// Only GET.
	k.h.deps.Status = k.auth
	st, _ = k.call("POST", api.StatusDevicePath+testNS+"/"+testDevice+api.StatusK3sServicesSuffix, backstageToken, nil)
	if st != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", st)
	}
	if got := k.list(t); len(got.Services) != 1 {
		t.Errorf("%+v", got)
	}
}

func TestK3sServicesRoutesAndBadRequests(t *testing.T) {
	k := newK3sRig(t, sendK3s(api.K3sServiceList{}))
	st, body := k.call("GET", api.StatusDevicePath+testNS+"/nope"+api.StatusK3sServicesSuffix, backstageToken, nil)
	wantReason(t, st, body, http.StatusNotFound, api.ReasonDeviceUnknown)
	st, body = k.call("GET", api.StatusDevicePath+"UPPER/dev"+api.StatusK3sServicesSuffix, backstageToken, nil)
	wantReason(t, st, body, http.StatusBadRequest, api.ReasonBadRequest)
	if n := k.hits.Load(); n != 0 {
		t.Errorf("the agent was asked %d times", n)
	}
	// The live-status route is unchanged.
	if st, body := k.get2(); st != http.StatusOK || !strings.Contains(string(body), `"connected":true`) {
		t.Errorf("status: %d %s", st, body)
	}
}

func (k *k3sRig) get2() (int, []byte) { return k.statusRig.get(backstageToken) }

func TestK3sServicesOfflineDevice(t *testing.T) {
	r := newRig(t)
	auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
	r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
	srv := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(srv.Close)
	got := getK3s(t, srv.URL)
	if got.Error != "the device is offline" || got.Services == nil || len(got.Services) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestK3sServicesOldAgent(t *testing.T) {
	for name, caps := range map[string][]string{
		"phase 1":      nil,
		"no discovery": capsFull,
		"no control":   {api.CapServices, api.CapK3sDiscovery},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.devCaps = caps
			r.deviceSessionOK()
			auth := &fakeStatusAuth{users: map[string]string{backstageToken: backstageSA}}
			r.h.deps.Status, r.h.cfg.BackstageSA = auth, backstageSA
			srv := httptest.NewServer(r.h.StatusHandler())
			t.Cleanup(srv.Close)
			got := getK3s(t, srv.URL)
			if got.Error != "the device agent is too old to list services" || len(got.Services) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func getK3s(t *testing.T, base string) api.K3sServiceList {
	t.Helper()
	req, _ := http.NewRequest("GET", base+api.StatusDevicePath+testNS+"/"+testDevice+api.StatusK3sServicesSuffix, nil)
	req.Header.Set("Authorization", "Bearer "+backstageToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var out api.K3sServiceList
	if err := json.Unmarshal(b, &out); err != nil || !strings.Contains(string(b), `"services":[]`) {
		t.Fatalf("%v: %s", err, b)
	}
	return out
}

func TestK3sServicesAgentReportsAProblem(t *testing.T) {
	k := newK3sRig(t, sendK3s(api.K3sServiceList{
		Services: []api.K3sService{k3sNotebook}, // ignored: an error means no list
		Error:    "the agent has no permission to list Services yet\x1b[31m\n",
	}))
	got := k.list(t)
	if got.Error != "the agent has no permission to list Services yet[31m" || len(got.Services) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestK3sServicesGarbageFromTheAgent(t *testing.T) {
	huge := strings.Repeat("x", maxK3sAnswerBody+10)
	cases := map[string]http.HandlerFunc{
		"not json":    func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>nope</html>") },
		"empty":       func(http.ResponseWriter, *http.Request) {},
		"wrong shape": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"services":"many"}`) },
		"agent 500":   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"agent 403":   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
		},
		"oversized":     func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"error":"`+huge+`"}`) },
		"oversized pad": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"services":[]}`+huge) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			k := newK3sRig(t, h)
			got := k.list(t)
			if got.Error != k3sErrBadAnswer || len(got.Services) != 0 {
				t.Fatalf("%+v", got)
			}
			if strings.Contains(k.logs.String(), "xxxxxxxxxx") {
				t.Error("the agent's bytes reached the logs")
			}
		})
	}
}

func TestK3sServicesAgentDoesNotAnswerInTime(t *testing.T) {
	old := k3sAgentTimeout
	k3sAgentTimeout = 300 * time.Millisecond
	t.Cleanup(func() { k3sAgentTimeout = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	k := newK3sRig(t, func(http.ResponseWriter, *http.Request) { <-release })
	start := time.Now()
	got := k.list(t)
	if got.Error != k3sErrNoAnswer || len(got.Services) != 0 {
		t.Fatalf("%+v", got)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
}

// An agent that sends more than the contract allows is cut to the caps.
func TestK3sServicesOversizedListIsCapped(t *testing.T) {
	var all []api.K3sService
	for i := range api.MaxK3sServices + 50 {
		s := api.K3sService{Namespace: "ns", Name: fmt.Sprintf("svc-%04d", i), Type: "ClusterIP"}
		for p := range api.MaxK3sServicePorts + 5 {
			s.Ports = append(s.Ports, api.K3sServicePort{Port: 1000 + p, Protocol: "TCP"})
		}
		all = append(all, s)
	}
	k := newK3sRig(t, sendK3s(api.K3sServiceList{Services: all}))
	got := k.list(t)
	if len(got.Services) != api.MaxK3sServices || !got.Truncated {
		t.Fatalf("%d services, truncated=%v", len(got.Services), got.Truncated)
	}
	for _, s := range got.Services {
		if len(s.Ports) != api.MaxK3sServicePorts {
			t.Fatalf("%s has %d ports", s.Name, len(s.Ports))
		}
	}
}

func TestSanitizeK3sList(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	long := strings.Repeat("a", 254)
	in := api.K3sServiceList{
		ObservedAt: now.Add(-100 * 24 * time.Hour),
		Services: []api.K3sService{
			{Namespace: "ok", Name: "fine", Type: "LoadBalancer", ClusterIP: "10.43.0.2", Ports: []api.K3sServicePort{
				{Name: "web", Port: 80, Protocol: "TCP", AppProtocol: "http"},
				{Name: "zero", Port: 0, Protocol: "TCP"},
				{Name: "big", Port: 65536, Protocol: "TCP"},
				{Name: "neg", Port: -1},
				{Name: strings.Repeat("p", 64), Port: 81},
				{Name: "ctl\x00", Port: 82},
				{Name: "app", Port: 83, AppProtocol: "a\nb"},
				{Name: "proto", Port: 84, Protocol: "ICMP"},
				{Port: 85, Protocol: "UDP"},
			}},
			{Namespace: "", Name: "nons"},
			{Namespace: "ns", Name: ""},
			{Namespace: "ns", Name: long},
			{Namespace: "ns", Name: "ctl\x1b[0m"},
			{Namespace: "ns", Name: "bad\xff"},
			{Namespace: "ns", Name: "headless", Type: "Bogus", ClusterIP: "None"},
			{Namespace: "ns", Name: "v6", ClusterIP: "FD00:0:0::1"},
			{Namespace: "ns", Name: "junkip", ClusterIP: "<script>"},
		},
	}
	got := sanitizeK3sList(in, now)
	want := map[string]api.K3sService{
		"fine":     {Namespace: "ok", Name: "fine", Type: "LoadBalancer", ClusterIP: "10.43.0.2"},
		"headless": {Namespace: "ns", Name: "headless", ClusterIP: "None"},
		"v6":       {Namespace: "ns", Name: "v6", ClusterIP: "fd00::1"},
		"junkip":   {Namespace: "ns", Name: "junkip"},
	}
	if len(got.Services) != len(want) {
		t.Fatalf("%d services kept: %+v", len(got.Services), got.Services)
	}
	for _, s := range got.Services {
		w := want[s.Name]
		if s.Name == "fine" {
			// A port with an unusable appProtocol keeps the port and loses the hint.
			wantPorts := []api.K3sServicePort{
				in.Services[0].Ports[0],
				{Name: "app", Port: 83},
				{Name: "proto", Port: 84},
				{Port: 85, Protocol: "UDP"},
			}
			if !slices.Equal(s.Ports, wantPorts) {
				t.Errorf("ports %+v, want %+v", s.Ports, wantPorts)
			}
			s.Ports = nil
		}
		if s.Namespace != w.Namespace || s.Type != w.Type || s.ClusterIP != w.ClusterIP || len(s.Ports) != 0 {
			t.Errorf("%s: %+v, want %+v", s.Name, s, w)
		}
	}
	if !got.ObservedAt.Equal(now) || got.Truncated || got.Error != "" {
		t.Errorf("%+v", got)
	}
	// Truncated from the agent is kept; the error text is bounded and clean.
	got = sanitizeK3sList(api.K3sServiceList{Truncated: true}, now)
	if !got.Truncated || got.Services == nil {
		t.Errorf("%+v", got)
	}
	got = sanitizeK3sList(api.K3sServiceList{Error: strings.Repeat("é", 400)}, now)
	if len(got.Error) > k3sMaxErrorLen || !k3sText(got.Error, k3sMaxErrorLen) || got.Error == "" {
		t.Errorf("error %d bytes", len(got.Error))
	}
	got = sanitizeK3sList(api.K3sServiceList{Error: "\x00\x01"}, now)
	if got.Error != k3sErrAgentError {
		t.Errorf("error %q", got.Error)
	}
}
