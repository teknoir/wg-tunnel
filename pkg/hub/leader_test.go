package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ---- the standby gate ----

func standbyBody(t *testing.T, resp *http.Response) api.Error {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var e api.Error
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("not an api.Error: %q", b)
	}
	return e
}

// TestStandbyAnswers503OnEveryAPIRoute: a replica that does not lead refuses
// every outside, internal and status API request with 503 / internal, before it
// looks at credentials, whatever the method. A leading replica answers the same
// requests differently (the contrast proves the gate, not the routes).
func TestStandbyAnswers503OnEveryAPIRoute(t *testing.T) {
	r := newRig(t)
	status := httptest.NewServer(r.h.StatusHandler())
	t.Cleanup(status.Close)

	type route struct{ base, method, path string }
	routes := []route{}
	for _, base := range []string{r.srv.URL, r.isrv.URL} {
		for _, p := range []string{api.DeviceEnrollPath, api.AttestChallengePath, api.DeviceSessionPath, api.ClientSessionPath} {
			routes = append(routes, route{base, http.MethodPost, p}, route{base, http.MethodGet, p})
		}
	}
	routes = append(routes,
		route{status.URL, http.MethodGet, api.StatusDevicePath + testNS + "/" + testDevice},
		route{status.URL, http.MethodGet, api.StatusDevicePath + testNS + "/" + testDevice + api.StatusK3sServicesSuffix},
		route{status.URL, http.MethodPost, api.AdminEndSessionPath + "abc/end"},
	)
	do := func(rt route) *http.Response {
		req, _ := http.NewRequest(rt.method, rt.base+rt.path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+aliceToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	r.h.SetLeading(false)
	for _, rt := range routes {
		resp := do(rt)
		e := standbyBody(t, resp)
		if resp.StatusCode != http.StatusServiceUnavailable || e.Reason != api.ReasonInternal || e.Message != "hub standby" {
			t.Errorf("standby %s %s: %d %+v, want 503 internal \"hub standby\"", rt.method, rt.path, resp.StatusCode, e)
		}
	}
	r.h.SetLeading(true)
	for _, rt := range routes {
		resp := do(rt)
		e := standbyBody(t, resp)
		if resp.StatusCode == http.StatusServiceUnavailable && e.Message == "hub standby" {
			t.Errorf("leading %s %s still answers standby", rt.method, rt.path)
		}
	}
}

// TestStandbyCreatesNoSession: even a valid device session request (a split
// brain: the routing still points at the standby) creates nothing and consumes
// nothing; the same request works once the replica leads.
func TestStandbyCreatesNoSession(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	tok, req, _ := r.dev.sessionRequest(r.t, r.clock.Now())

	r.h.SetLeading(false)
	st, body := r.post(api.DeviceSessionPath, tok, req)
	if st != http.StatusServiceUnavailable || !strings.Contains(string(body), `"internal"`) {
		t.Fatalf("standby device session: %d %s", st, body)
	}
	if d, c := r.h.SessionCounts(); d != 0 || c != 0 {
		t.Fatalf("a standby holds sessions: devices %d clients %d", d, c)
	}
	// The refusal did not burn the token (no replay entry).
	r.h.SetLeading(true)
	if st, body := r.post(api.DeviceSessionPath, tok, req); st != http.StatusCreated {
		t.Fatalf("device session after SetLeading(true): %d %s", st, body)
	}
}

// TestStandbyProbesAndMetric: /healthz and /readyz do not depend on leadership
// (the standby must be Ready or rollouts and the PDB stall), the in-tunnel API
// is not gated, and wghub_leader follows SetLeading.
func TestStandbyProbesAndMetric(t *testing.T) {
	w := newWGDeviceRig(t)
	status := httptest.NewServer(w.h.StatusHandler())
	t.Cleanup(status.Close)
	metrics := func() string {
		rec := httptest.NewRecorder()
		w.h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	if !strings.Contains(metrics(), "wghub_leader 1\n") {
		t.Fatalf("a hub without election must report wghub_leader 1:\n%s", metrics())
	}

	w.h.SetLeading(false)
	if !strings.Contains(metrics(), "wghub_leader 0\n") {
		t.Fatalf("standby must report wghub_leader 0:\n%s", metrics())
	}
	for _, u := range []string{w.srv.URL + "/healthz", w.srv.URL + "/readyz", w.isrv.URL + "/healthz", w.isrv.URL + "/readyz", status.URL + "/healthz"} {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("standby GET %s: %d, want 200", u, resp.StatusCode)
		}
	}
	if !w.h.Ready() {
		t.Error("a standby must stay Ready")
	}
	// The in-tunnel API is not gated: the existing device session renews.
	rt := w.dev.renewToken(t, w.clock.Now(), w.devSess.pub.Base64())
	if st, body := w.tunnelPost(api.RenewPath, w.devSess.Address, rt, nil); st != http.StatusOK {
		t.Errorf("in-tunnel renew on a standby: %d %s", st, body)
	}
}

// ---- Leader (with a fake elector and patcher) ----

type fakeElector struct {
	mu         sync.Mutex
	onStarted  func()
	started    chan struct{}
	events     *eventLog
	runErr     chan error // Run returns this (lost lease)
	successor  bool
	waitCalled int
}

func newFakeElector(ev *eventLog) *fakeElector {
	return &fakeElector{started: make(chan struct{}), events: ev, runErr: make(chan error, 1)}
}

func (e *fakeElector) Run(ctx context.Context, onStarted func()) error {
	e.mu.Lock()
	e.onStarted = onStarted
	e.mu.Unlock()
	close(e.started)
	select {
	case err := <-e.runErr:
		return err
	case <-ctx.Done():
		e.events.add("release")
		return nil
	}
}

func (e *fakeElector) WaitSuccessor(_ context.Context, _ time.Duration) bool {
	e.mu.Lock()
	e.waitCalled++
	ok := e.successor
	e.mu.Unlock()
	e.events.add("wait")
	return ok
}

func (e *fakeElector) win(t *testing.T) {
	t.Helper()
	<-e.started
	e.mu.Lock()
	f := e.onStarted
	e.mu.Unlock()
	f()
}

type eventLog struct {
	mu sync.Mutex
	ev []string
	at map[string]time.Time
}

func (l *eventLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, s)
	if l.at == nil {
		l.at = map[string]time.Time{}
	}
	l.at[s] = time.Now()
}

func (l *eventLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

type fakePatcher struct {
	mu     sync.Mutex
	events *eventLog
	h      *Hub
	fail   int // fail this many calls first
	calls  int
	roles  []bool
	// leadingAtStandby is h.Leading() at the time of each standby patch.
	leadingAtStandby []bool
}

func (p *fakePatcher) SetRole(_ context.Context, leader bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls <= p.fail {
		return errors.New("api server unavailable")
	}
	p.roles = append(p.roles, leader)
	if leader {
		p.events.add("role:leader")
	} else {
		p.leadingAtStandby = append(p.leadingAtStandby, p.h != nil && p.h.Leading())
		p.events.add("role:standby")
	}
	return nil
}

func (p *fakePatcher) last() (bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.roles) == 0 {
		return false, false
	}
	return p.roles[len(p.roles)-1], true
}

func newLeaderRig(t *testing.T, mutate func(*LeaderConfig)) (*rig, *Leader, *fakeElector, *fakePatcher, *eventLog) {
	t.Helper()
	r := newRig(t)
	ev := &eventLog{}
	el := newFakeElector(ev)
	p := &fakePatcher{events: ev, h: r.h}
	cfg := LeaderConfig{Elector: el, Patcher: p, PatchRetry: 10 * time.Millisecond, HandoverSettle: 50 * time.Millisecond}
	if mutate != nil {
		mutate(&cfg)
	}
	l := NewLeader(r.h, cfg)
	return r, l, el, p, ev
}

// TestLeaderServesOnlyWhileElected: standby and labelled standby at start, the
// leader label and serving only after the election was won.
func TestLeaderServesOnlyWhileElected(t *testing.T) {
	r, l, el, p, _ := newLeaderRig(t, nil)
	if r.h.Leading() {
		t.Fatal("NewLeader must leave the hub in standby")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	waitFor(t, "the standby label at start", func() bool { leader, ok := p.last(); return ok && !leader })
	if r.h.Leading() {
		t.Fatal("serving before the election was won")
	}
	el.win(t)
	waitFor(t, "serving", r.h.Leading)
	waitFor(t, "the leader label", func() bool { leader, ok := p.last(); return ok && leader })
}

// TestLeaderRolePatchRetriesAndNeverAffectsReadiness: a patch that keeps
// failing is retried, counted and logged, and neither readiness nor serving
// depends on it.
func TestLeaderRolePatchRetriesAndNeverAffectsReadiness(t *testing.T) {
	w := newWGDeviceRig(t)
	ev := &eventLog{}
	el := newFakeElector(ev)
	p := &fakePatcher{events: ev, h: w.h, fail: 3}
	l := NewLeader(w.h, LeaderConfig{Elector: el, Patcher: p, PatchRetry: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	el.win(t)
	waitFor(t, "serving", w.h.Leading)
	waitFor(t, "the label to land after 3 failures", func() bool { leader, ok := p.last(); return ok && leader })

	rec := httptest.NewRecorder()
	w.h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "wghub_role_patch_errors_total 3\n") {
		t.Errorf("patch errors not counted:\n%s", rec.Body.String())
	}
	if !w.h.Ready() {
		t.Error("readiness changed with a failing patch")
	}
	if !strings.Contains(w.logs.String(), "role patch failed") {
		t.Error("failed patches are not logged")
	}
}

// TestLeaderShutdownSequence: the planned handover runs in the documented
// order: stop serving, label standby (while not serving), release the lease,
// wait for the successor, settle, then the agents are told.
func TestLeaderShutdownSequence(t *testing.T) {
	agent := &svcAgent{}
	w, _ := noticeRig(t, capsFull, agent, 20*time.Millisecond)
	ev := &eventLog{}
	el := newFakeElector(ev)
	el.successor = true
	p := &fakePatcher{events: ev, h: w.h}
	l := NewLeader(w.h, LeaderConfig{Elector: el, Patcher: p, PatchRetry: 10 * time.Millisecond, HandoverWait: time.Second, HandoverSettle: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	waitFor(t, "the standby label at start", func() bool { leader, ok := p.last(); return ok && !leader })
	el.win(t)
	waitFor(t, "serving as leader", func() bool { leader, ok := p.last(); return ok && leader && w.h.Leading() })

	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := ev.list()
	want := []string{"role:standby", "role:leader", "role:standby", "release", "wait"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v, want %v", got, want)
	}
	if last := p.leadingAtStandby[len(p.leadingAtStandby)-1]; last {
		t.Error("the standby label was set while the hub still served")
	}
	notices := agent.revokes()
	if len(notices) != 1 || notices[0].Reason != api.ReasonHubHandover {
		t.Fatalf("notices %+v, want one hub_handover", notices)
	}
	if d := notices[0].at.Sub(ev.at["wait"]); d < 190*time.Millisecond {
		t.Errorf("the device was told %v after the successor appeared, want at least the settle time", d)
	}
	if w.h.Leading() {
		t.Error("hub leads after shutdown")
	}
	rec := httptest.NewRecorder()
	w.h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `wghub_handover_total{result="successor"} 1`) {
		t.Errorf("handover result not counted:\n%s", rec.Body.String())
	}
}

// TestLeaderShutdownWithoutSuccessor: with nobody to take over (HandoverWait 0,
// one replica) the sequence does not wait.
func TestLeaderShutdownWithoutSuccessorDoesNotWait(t *testing.T) {
	_, l, el, p, _ := newLeaderRig(t, func(c *LeaderConfig) { c.HandoverSettle = 5 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	el.win(t)
	waitFor(t, "leader label", func() bool { leader, ok := p.last(); return ok && leader })
	t0 := time.Now()
	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("shutdown took %v with HandoverWait 0 and HandoverSettle 5s", d)
	}
	if el.waitCalled != 0 {
		t.Error("waited for a successor with HandoverWait 0")
	}
}

// TestStandbyShutdownSkipsTheWait: a replica that never led has nothing to hand
// over: no wait, no settle.
func TestStandbyShutdownSkipsTheWait(t *testing.T) {
	_, l, el, _, _ := newLeaderRig(t, func(c *LeaderConfig) { c.HandoverWait = 5 * time.Second; c.HandoverSettle = 5 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	<-el.started
	t0 := time.Now()
	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 2*time.Second || el.waitCalled != 0 {
		t.Fatalf("a standby waited: %v, waits %d", d, el.waitCalled)
	}
}

// TestLeaderLostLeaseStopsServing: a lost lease ends serving at once and is
// reported on Lost(); a later win in the same process is impossible (the
// caller exits).
func TestLeaderLostLeaseStopsServing(t *testing.T) {
	r, l, el, p, _ := newLeaderRig(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	el.win(t)
	waitFor(t, "serving", r.h.Leading)
	el.runErr <- ErrLostLease
	select {
	case <-l.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("Lost() not closed")
	}
	if r.h.Leading() {
		t.Fatal("still serving after the lease was lost")
	}
	waitFor(t, "standby label", func() bool { leader, ok := p.last(); return ok && !leader })
}

// A win that arrives after Shutdown began must not turn serving back on.
func TestWinAfterShutdownIsIgnored(t *testing.T) {
	r, l, el, _, _ := newLeaderRig(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.Start(ctx)
	<-el.started
	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	el.mu.Lock()
	f := el.onStarted
	el.mu.Unlock()
	f()
	if r.h.Leading() {
		t.Fatal("a late election win re-enabled serving after shutdown")
	}
}
