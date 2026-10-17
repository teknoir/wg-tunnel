package hub

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

//go:embed testdata/org-gate-vectors.json
var orgVectorsJSON []byte

type orgVector struct {
	ID   int `json:"id"`
	User struct {
		Email       string            `json:"email"`
		Superadmin  bool              `json:"superadmin"`
		ClaimSets   []ClaimSetRef     `json:"claimSets"`
		Annotations map[string]string `json:"annotations"`
		Unreadable  bool              `json:"unreadable"`
	} `json:"user"`
	Device struct {
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"device"`
	Expect string `json:"expect"`
	Why    string `json:"why"`
}

func (v orgVector) projection() UserProjection {
	email := v.User.Email
	if email == "" {
		email = "claude-agent@teknoir.cloud"
	}
	p := UserProjection{Name: "u", Email: email, Annotations: v.User.Annotations, ClaimSets: v.User.ClaimSets}
	if v.User.Superadmin {
		p.Role = "superadmin"
	}
	return p
}

type allowAllSAR struct{}

func (allowAllSAR) CanExec(context.Context, string, string) (bool, error) { return true, nil }

// gateHub is a Hub reduced to what canOpen needs.
func gateHub(mode string, authz Authorizer, org OrgSource, flags DeviceFlags) *Hub {
	logger, _ := captureLogger()
	return &Hub{cfg: Config{OrgGateMode: mode}, log: logger, met: newMetrics(),
		deps: Deps{Authz: authz, Org: org, Flags: flags}}
}

func TestOrgGateVectors(t *testing.T) {
	var file struct {
		Namespace string      `json:"namespace"`
		Vectors   []orgVector `json:"vectors"`
	}
	if err := json.Unmarshal(orgVectorsJSON, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 23 {
		t.Fatalf("expected 23 vectors, have %d", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Why, func(t *testing.T) {
			p := v.projection()
			ns := v.Device.Namespace
			org, flags := newFakeOrg(), newFakeFlags()
			org.set(buildOrgDoc([]UserProjection{p}, ns, nil))
			if v.User.Unreadable {
				org.setMissing(ns, true)
			}
			flags.Set(ns, "dev", v.Device.Annotations)
			entry, entryOK := flags.Flags(ns, "dev")
			doc, docOK := org.Doc(ns)

			email := strings.ToLower(strings.TrimSpace(p.Email))
			allow, reason := orgDecision(doc, docOK, entry, entryOK, email)
			if got := map[bool]string{true: "allow", false: "deny"}[allow]; got != v.Expect {
				t.Fatalf("vector %d: orgDecision %s (%s), want %s", v.ID, got, reason, v.Expect)
			}
			// canOpen with the identity exactly as given (a mixed-case email is invalid).
			den, err := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags).canOpen(context.Background(), p.Email, ns, "dev")
			if err != nil {
				t.Fatal(err)
			}
			if got := map[bool]string{true: "allow", false: "deny"}[den == nil]; got != v.Expect {
				t.Fatalf("vector %d: canOpen %s, want %s", v.ID, got, v.Expect)
			}
		})
	}
}

func TestBuildOrgDoc(t *testing.T) {
	ns := "acme"
	ann := func(member, units string) map[string]string {
		m := map[string]string{}
		if member != "" {
			m[api.AnnotationOrgMemberPref+ns] = member
		}
		if units != "" {
			m[api.AnnotationOrgUnitsPref+ns] = units
		}
		return m
	}
	users := []UserProjection{
		{Name: "a", Email: " Alice@Example.com ", Annotations: ann("true", `["b-unit","a-unit","a-unit","bad id!","-x",1]`)},
		{Name: "bob", Email: "bob@example.com", Annotations: ann("false", `["u"]`)},
		{Name: "carol", Email: "carol@example.com", Role: "superadmin"},
		{Name: "dan", Email: "dan@example.com", ClaimSets: []ClaimSetRef{{"owner", ns}, {"developer", ns}}, Annotations: ann("true", "")},
		{Name: "eve", Email: "eve@example.com", ClaimSets: []ClaimSetRef{{"owner", "other"}}},
		{Name: "bad", Email: "not an email"},
		{Name: "empty", Email: ""},
		{Name: "frank", Email: "frank@example.com", Annotations: ann("true", "not json")},
		{Name: "gina", Email: "gina@example.com", Annotations: ann("true", `"a-unit"`)},
		{Name: "dup1", Email: "dup@example.com", Role: "superadmin", Annotations: ann("true", `["u"]`)},
		{Name: "dup2", Email: "DUP@example.com"},
		{Name: "other-ns-member", Email: "zed@example.com", Annotations: map[string]string{api.AnnotationOrgMemberPref + "elsewhere": "true"}},
	}
	got, err := marshalOrgDoc(buildOrgDoc(users, ns, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"namespace":"acme","members":{` +
		`"alice@example.com":{"units":["a-unit","b-unit"]},` +
		`"dan@example.com":{"units":[]},` +
		`"dup@example.com":{"units":[]},` +
		`"frank@example.com":{"units":[]},` +
		`"gina@example.com":{"units":[]}},` +
		`"exempt":["carol@example.com","dan@example.com"]}`
	if got != want {
		t.Fatalf("doc\n got %s\nwant %s", got, want)
	}
}

func TestBuildOrgDocEmptyIsCanonical(t *testing.T) {
	got, _ := marshalOrgDoc(buildOrgDoc(nil, "acme", nil))
	if got != `{"v":1,"namespace":"acme","members":{},"exempt":[]}` {
		t.Fatal(got)
	}
}

func TestStripUserKeepsOnlyWhatTheGateReads(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "teknoir.org/v1", "kind": "User",
		"metadata": map[string]any{
			"name": "alice-at-example.com", "resourceVersion": "42", "uid": "SECRET-UID",
			"labels": map[string]any{"l": "SECRET-LABEL"},
			"annotations": map[string]any{
				"teknoir.org/org-tree-member-acme": "true", "teknoir.org/org-tree-units-acme": `["u"]`,
				"kubectl.kubernetes.io/last-applied-configuration": "SECRET-ANN", "teknoir.org/other": "SECRET-OTHER",
			},
			"managedFields": []any{map[string]any{"manager": "SECRET-MF"}},
		},
		"spec": map[string]any{
			"email": "alice@example.com", "name": "SECRET-NAME", "avatar": "SECRET-AVATAR",
			"claims_v0": map[string]any{"role": "developer", "extra": "SECRET-CLAIM"},
			"claim_set": []any{map[string]any{"name": "owner", "namespace": "acme", "extra": "SECRET-CS"}},
		},
		"status": map[string]any{"set_initial_password": "SECRET-PASSWORD"},
	}}
	out, err := stripUser(u)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("transform kept data: %s", raw)
	}
	if _, found, _ := unstructured.NestedMap(out.(*unstructured.Unstructured).Object, "status"); found {
		t.Fatal("status kept")
	}
	want := UserProjection{Name: "alice-at-example.com", Email: "alice@example.com", Role: "developer",
		ClaimSets:   []ClaimSetRef{{"owner", "acme"}},
		Annotations: map[string]string{"teknoir.org/org-tree-member-acme": "true", "teknoir.org/org-tree-units-acme": `["u"]`}}
	got := projectUser(out.(*unstructured.Unstructured))
	if got.Name != want.Name || got.Email != want.Email || got.Role != want.Role ||
		len(got.ClaimSets) != 1 || got.ClaimSets[0] != want.ClaimSets[0] || len(got.Annotations) != 2 {
		t.Fatalf("projection %+v", got)
	}
	if out.(*unstructured.Unstructured).GetResourceVersion() != "42" {
		t.Fatal("resourceVersion dropped")
	}
	if p2, _ := stripUser("not an object"); p2 != "not an object" {
		t.Fatal("non-objects pass through")
	}
}

func orgCM(name string, labels map[string]string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: api.HubNamespace, Labels: labels}, Data: data}
}

func TestParseOrgConfigMapIsStrict(t *testing.T) {
	good := `{"v":1,"namespace":"acme","members":{"a@b.co":{"units":["u"]}},"exempt":[]}`
	lbl := map[string]string{api.OrgLabel: "true", api.PolicyTeamspaceLabel: "acme"}
	if d, p := ParseOrgConfigMap(orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: good})); p != "" || d.Members["a@b.co"].Units[0] != "u" {
		t.Fatalf("valid doc: %q %+v", p, d)
	}
	bad := map[string]*corev1.ConfigMap{
		"garbage":       orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: "{{{"}),
		"empty":         orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: ""}),
		"no key":        orgCM("ztna-org-acme", lbl, map[string]string{"other": good}),
		"wrong version": orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: strings.Replace(good, `"v":1`, `"v":2`, 1)}),
		"no version":    orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: `{"namespace":"acme"}`}),
		"unknown field": orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: strings.Replace(good, `"exempt":[]`, `"exempt":[],"x":1`, 1)}),
		"trailing":      orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: good + "{}"}),
		"ns mismatch":   orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: strings.Replace(good, `"acme"`, `"evil"`, 1)}),
		"name mismatch": orgCM("ztna-org-evil", lbl, map[string]string{api.OrgDataKey: good}),
		"no org label":  orgCM("ztna-org-acme", map[string]string{api.PolicyTeamspaceLabel: "acme"}, map[string]string{api.OrgDataKey: good}),
		"null members":  orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: `{"v":1,"namespace":"acme","members":null,"exempt":[]}`}),
		"null exempt":   orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: `{"v":1,"namespace":"acme","members":{},"exempt":null}`}),
		"bad member":    orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: `{"v":1,"namespace":"acme","members":{"NOT AN EMAIL":{"units":[]}},"exempt":[]}`}),
		"bad exempt":    orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: `{"v":1,"namespace":"acme","members":{},"exempt":["x y"]}`}),
		"no ns label":   orgCM("ztna-org-acme", map[string]string{api.OrgLabel: "true"}, map[string]string{api.OrgDataKey: good}),
	}
	for name, cm := range bad {
		if _, p := ParseOrgConfigMap(cm); p == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// The store treats a bad ConfigMap as missing and drops a former good one.
	logger, _ := captureLogger()
	st := newOrgStore(logger)
	st.apply(orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: good}))
	if _, ok := st.Doc("acme"); !ok {
		t.Fatal("good doc missing")
	}
	st.apply(orgCM("ztna-org-acme", lbl, map[string]string{api.OrgDataKey: "garbage"}))
	if _, ok := st.Doc("acme"); ok {
		t.Fatal("garbage must read as missing")
	}
}

func TestParseOrgGateMode(t *testing.T) {
	for in, want := range map[string]string{"": "enforce", "enforce": "enforce", "audit": "audit", "off": "off"} {
		if got, err := ParseOrgGateMode(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"Enforce", "on", "true", " off"} {
		if _, err := ParseOrgGateMode(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func orgDocOf(ns, email string, units ...string) api.OrgDoc {
	if units == nil {
		units = []string{}
	}
	return api.OrgDoc{V: 1, Namespace: ns, Members: map[string]api.OrgMember{email: {Units: units}}, Exempt: []string{}}
}

func TestCanOpenModes(t *testing.T) {
	const me = "m@example.com"
	setup := func() (*fakeOrg, *fakeFlags) {
		org, flags := newFakeOrg(), newFakeFlags()
		org.set(orgDocOf("acme", me, "u1"))
		flags.Set("acme", "far", map[string]string{api.AnnotationOrgPath: "x/y"})
		flags.Set("acme", "near", map[string]string{api.AnnotationOrgPath: "x/u1"})
		return org, flags
	}
	ctx := context.Background()
	t.Run("enforce is the default and denies out of scope", func(t *testing.T) {
		org, flags := setup()
		h := gateHub("", allowAllSAR{}, org, flags)
		h.cfg.OrgGateMode, _ = ParseOrgGateMode("")
		den, err := h.canOpen(ctx, me, "acme", "far")
		if err != nil || den == nil || den.reason != api.ReasonForbidden || den.msg != orgMsgScope {
			t.Fatalf("%v %+v", err, den)
		}
		if den, _ := h.canOpen(ctx, me, "acme", "near"); den != nil {
			t.Fatalf("in scope: %+v", den)
		}
	})
	t.Run("unavailable data denies with its own message", func(t *testing.T) {
		org, flags := setup()
		org.setMissing("acme", true)
		den, _ := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags).canOpen(ctx, me, "acme", "near")
		if den == nil || den.msg != orgMsgUnavailable || den.reason != api.ReasonForbidden {
			t.Fatalf("%+v", den)
		}
		org.setMissing("acme", false)
		if den, _ := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags).canOpen(ctx, me, "acme", "ghost"); den == nil || den.msg != orgMsgUnavailable {
			t.Fatalf("missing flags entry must deny members: %+v", den)
		}
		// A flags entry from an older watcher (no org fields) is unknown.
		e, _ := flags.Flags("acme", "near")
		e.OrgKnown = false
		flags.SetEntry(e)
		if den, _ := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags).canOpen(ctx, me, "acme", "near"); den == nil || den.msg != orgMsgUnavailable {
			t.Fatalf("unknown placement must deny members: %+v", den)
		}
		// Non-members are unaffected by missing data.
		if den, _ := gateHub(OrgGateEnforce, allowAllSAR{}, org, flags).canOpen(ctx, "other@example.com", "acme", "ghost"); den != nil {
			t.Fatalf("non-member: %+v", den)
		}
	})
	t.Run("audit allows and counts would_deny", func(t *testing.T) {
		org, flags := setup()
		h := gateHub(OrgGateAudit, allowAllSAR{}, org, flags)
		if den, err := h.canOpen(ctx, me, "acme", "far"); den != nil || err != nil {
			t.Fatalf("%+v %v", den, err)
		}
		if n := counterValue(t, h.met.orgGate, "audit", "would_deny", orgReasonScope); n != 1 {
			t.Fatalf("would_deny count %v", n)
		}
	})
	t.Run("off skips the gate", func(t *testing.T) {
		org, flags := setup()
		h := gateHub(OrgGateOff, allowAllSAR{}, org, flags)
		if den, _ := h.canOpen(ctx, me, "acme", "far"); den != nil {
			t.Fatalf("%+v", den)
		}
	})
	t.Run("SAR first, errors as before", func(t *testing.T) {
		org, flags := setup()
		a := newFakeAuthz()
		h := gateHub(OrgGateEnforce, a, org, flags)
		den, err := h.canOpen(ctx, me, "acme", "near")
		if err != nil || den == nil || den.msg != "no access to this teamspace" {
			t.Fatalf("SAR deny: %v %+v", err, den)
		}
		a.err = errors.New("boom")
		if den, err := h.canOpen(ctx, me, "acme", "near"); err == nil || den != nil {
			t.Fatalf("SAR error must be returned: %v %+v", err, den)
		}
	})
	t.Run("invalid emails are denied before the SAR", func(t *testing.T) {
		org, flags := setup()
		a := newFakeAuthz()
		h := gateHub(OrgGateEnforce, a, org, flags)
		for _, e := range []string{"", "M@example.com", "no-at", " m@example.com"} {
			if den, _ := h.canOpen(ctx, e, "acme", "near"); den == nil {
				t.Errorf("%q allowed", e)
			}
		}
		if a.calls != 0 {
			t.Fatalf("SAR called %d times", a.calls)
		}
	})
}

func TestOrgDecisionPaths(t *testing.T) {
	doc := orgDocOf("acme", "m@x.io", "u1")
	doc.Exempt = []string{"boss@x.io"}
	e := func(path, node string) api.FlagsEntry {
		return api.FlagsEntry{OrgKnown: true, OrgPath: path, OrgNodeID: node}
	}
	cases := []struct {
		name  string
		entry api.FlagsEntry
		ok    bool
		email string
		want  bool
	}{
		{"exempt without entry", api.FlagsEntry{}, false, "boss@x.io", true},
		{"unit on path", e("a/u1/b", ""), true, "m@x.io", true},
		{"case sensitive", e("a/U1", ""), true, "m@x.io", false},
		{"node id only", e("", "u1"), true, "m@x.io", true},
		{"path wins over node id", e("a/b", "u1"), true, "m@x.io", false},
		{"empty parts", e("//", ""), true, "m@x.io", true},
		{"no entry", api.FlagsEntry{}, false, "m@x.io", false},
	}
	for _, c := range cases {
		if got, r := orgDecision(doc, true, c.entry, c.ok, c.email); got != c.want {
			t.Errorf("%s: %v (%s)", c.name, got, r)
		}
	}
	// A unit id that fails validation in the document never matches.
	bad := orgDocOf("acme", "m@x.io", "bad id")
	if ok, _ := orgDecision(bad, true, e("bad id", ""), true, "m@x.io"); ok {
		t.Fatal("invalid unit id matched")
	}
}

// ---- rig: session create, placement change, document change ----

func (r *rig) setOrgDevice(path string) {
	ann := map[string]string{api.AnnotationWireGuard: "enabled"}
	if path != "" {
		ann[api.AnnotationOrgPath] = path
	}
	r.flags.Set(testNS, testDevice, ann)
}

func TestOrgGateAtSessionCreate(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.org.set(orgDocOf(testNS, aliceEmail, "u1"))

	r.setOrgDevice("a/b")
	req, _ := r.clientReq(22)
	st, body := r.clientSession(aliceToken, req)
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	if !strings.Contains(string(body), orgMsgScope) {
		t.Fatalf("message: %s", body)
	}
	if _, n := r.h.sessionCounts(); n != 0 {
		t.Fatal("no session may exist")
	}

	r.setOrgDevice("a/u1")
	req, _ = r.clientReq(22)
	if st, body = r.clientSession(aliceToken, req); st != http.StatusCreated {
		t.Fatalf("in scope: %d %s", st, body)
	}

	// A missing flags entry at create denies members (fail closed).
	r2 := newRig(t)
	r2.deviceSessionOK()
	r2.org.set(orgDocOf(testNS, aliceEmail, "u1"))
	r2.flags.Delete(testNS, testDevice)
	req, _ = r2.clientReq(22)
	if st, _ = r2.clientSession(aliceToken, req); st == http.StatusCreated {
		t.Fatal("session created without a flags entry")
	}
}

func TestOrgGateEndsSessionWhenPlacementChanges(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.org.set(orgDocOf(testNS, aliceEmail, "u1"))
	r.setOrgDevice("a/u1")
	r.clientSessionOK()
	if _, n := r.h.sessionCounts(); n != 1 {
		t.Fatal("no session")
	}
	calls := r.authz.calls

	r.setOrgDevice("a/elsewhere") // the device moved out of the user's units
	waitFor(t, "client session to end", func() bool { _, n := r.h.sessionCounts(); return n == 0 })
	if r.authz.calls != calls {
		t.Fatal("the immediate org check must not call the SubjectAccessReview")
	}
	if d, _ := r.h.sessionCounts(); d != 1 {
		t.Fatal("the device session must stay")
	}
	if !strings.Contains(r.logs.String(), `"reason":"forbidden"`) {
		t.Fatal("no revoke decision logged")
	}

	// A changed document ends sessions too (units removed).
	r.setOrgDevice("a/u1")
	r.clientSessionOK()
	r.org.set(orgDocOf(testNS, aliceEmail, "other"))
	waitFor(t, "session to end after the document changed", func() bool { _, n := r.h.sessionCounts(); return n == 0 })

	// ... and a document that disappears (fail closed).
	r.org.set(orgDocOf(testNS, aliceEmail, "u1"))
	r.clientSessionOK()
	r.org.setMissing(testNS, true)
	waitFor(t, "session to end after the document vanished", func() bool { _, n := r.h.sessionCounts(); return n == 0 })
}

func TestOrgGateAuditAndOffKeepSessions(t *testing.T) {
	for _, mode := range []string{OrgGateAudit, OrgGateOff} {
		r := newRig(t, func(c *Config) { c.OrgGateMode = mode })
		r.deviceSessionOK()
		r.org.set(orgDocOf(testNS, aliceEmail, "u1"))
		r.setOrgDevice("a/u1")
		r.clientSessionOK()
		r.setOrgDevice("a/elsewhere")
		time.Sleep(150 * time.Millisecond)
		if _, n := r.h.sessionCounts(); n != 1 {
			t.Fatalf("%s: session ended", mode)
		}
		req, _ := r.clientReq(22)
		if st, body := r.clientSession(aliceToken, req); st != http.StatusCreated {
			t.Fatalf("%s: %d %s", mode, st, body)
		}
	}
}

func TestHubRequiresOrgSourceUnlessOff(t *testing.T) {
	logger, _ := captureLogger()
	deps := Deps{Policy: newFakePolicy(), Flags: newFakeFlags(), Identity: newMemIdentity(), Users: newFakeUsers(), Authz: newFakeAuthz(),
		TURN: NewTURNMinter(func() (string, error) { return "s", nil }, []string{"turn:t:3478"}, time.Minute, nil), Tunnel: newFakeTunnel()}
	if _, err := New(Config{Logger: logger}, deps); err == nil {
		t.Fatal("no Org source in enforce mode must be refused")
	}
	if _, err := New(Config{Logger: logger, OrgGateMode: "bogus", ReapInterval: time.Hour}, deps); err == nil {
		t.Fatal("invalid mode must be refused")
	}
	deps.Tunnel = newFakeTunnel()
	h, err := New(Config{Logger: logger, OrgGateMode: OrgGateOff, ReapInterval: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
}

// ---- watcher ----

func userObj(name, email, role string, ann map[string]string) *unstructured.Unstructured {
	a := map[string]any{}
	for k, v := range ann {
		a[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "teknoir.org/v1", "kind": "User",
		"metadata": map[string]any{"name": name, "annotations": a},
		"spec":     map[string]any{"email": email, "claims_v0": map[string]any{"role": role}},
		"status":   map[string]any{"set_initial_password": "SECRET-PASSWORD"},
	}}
}

func (r *watcherRig) orgDoc(ns string) (api.OrgDoc, string, bool) {
	r.t.Helper()
	cm, err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), api.OrgConfigMapName(ns), metav1.GetOptions{})
	if err != nil {
		return api.OrgDoc{}, "", false
	}
	d, problem := ParseOrgConfigMap(cm)
	if problem != "" {
		r.t.Fatalf("watcher wrote an invalid org ConfigMap: %s", problem)
	}
	return d, cm.Data[api.OrgDataKey], true
}

func (r *watcherRig) putUser(u *unstructured.Unstructured) {
	r.t.Helper()
	c := r.dc.Resource(UserGVR)
	if _, err := c.Get(context.Background(), u.GetName(), metav1.GetOptions{}); err == nil {
		if _, err := c.Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
			r.t.Fatal(err)
		}
		return
	}
	if _, err := c.Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *watcherRig) orgWrites() int {
	n := 0
	for _, a := range r.cs.Actions() {
		if a.GetResource().Resource == "configmaps" && (a.GetVerb() == "create" || a.GetVerb() == "update" || a.GetVerb() == "delete") {
			if c, ok := a.(interface{ GetName() string }); ok && strings.HasPrefix(c.GetName(), api.OrgConfigMapPrefix) {
				n++
			}
		}
	}
	return n
}

func TestFlagsWatcherWritesTheOrgDocument(t *testing.T) {
	member := map[string]string{api.AnnotationOrgMemberPref + "acme": "true", api.AnnotationOrgUnitsPref + "acme": `["u1"]`}
	r := newWatcherRig(t,
		deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationOrgPath: "a/u1", api.AnnotationOrgNodeID: "u1", "other": "x"}),
		deviceMeta("quiet", "cam-9", map[string]string{"unrelated": "x"}), // no ztna annotation: no flags, no org doc
	)
	r.putUser(userObj("m-at-x.io", "M@X.io", "developer", member))
	waitFor(t, "org doc", func() bool {
		d, _, ok := r.orgDoc("acme")
		return ok && d.Members["m@x.io"].Units != nil && len(d.Members["m@x.io"].Units) == 1
	})
	d, raw, _ := r.orgDoc("acme")
	if raw != `{"v":1,"namespace":"acme","members":{"m@x.io":{"units":["u1"]}},"exempt":[]}` || len(d.Exempt) != 0 {
		t.Fatalf("doc %s", raw)
	}
	cm, _ := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), "ztna-org-acme", metav1.GetOptions{})
	if cm.Labels[api.OrgLabel] != "true" || cm.Labels[api.PolicyTeamspaceLabel] != "acme" || len(cm.Data) != 1 || strings.Contains(raw, "SECRET") {
		t.Fatalf("labels/data %v %v", cm.Labels, cm.Data)
	}
	if _, _, ok := r.orgDoc("quiet"); ok {
		t.Fatal("a teamspace without flags entries got an org document")
	}

	// The flags entry carries the placement.
	e, _ := r.flags("acme", "cam-1")
	if !e.OrgKnown || e.OrgPath != "a/u1" || e.OrgNodeID != "u1" {
		t.Fatalf("flags %+v", e)
	}

	// The transform kept nothing else of the User.
	for _, o := range r.w.userInf.GetStore().List() {
		raw, _ := json.Marshal(o)
		if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "status") {
			t.Fatalf("informer retained %s", raw)
		}
	}

	// Moving the Device updates the entry (an org annotation alone is enough).
	r.patch("acme", "cam-1", api.AnnotationOrgPath, "a/u2")
	waitFor(t, "placement mirrored", func() bool { e, _ := r.flags("acme", "cam-1"); return e.OrgPath == "a/u2" })
	r.patch("acme", "cam-1", api.AnnotationOrgNodeID, "u2")
	waitFor(t, "node id mirrored", func() bool { e, _ := r.flags("acme", "cam-1"); return e.OrgNodeID == "u2" })

	// A change of a User updates the document; one the gate does not read does nothing.
	r.putUser(userObj("m-at-x.io", "m@x.io", "superadmin", member))
	waitFor(t, "exempt", func() bool { d, _, _ := r.orgDoc("acme"); return len(d.Exempt) == 1 })
	before := r.orgWrites()
	u := userObj("m-at-x.io", "m@x.io", "superadmin", member)
	u.SetLabels(map[string]string{"irrelevant": "change"})
	_ = unstructured.SetNestedField(u.Object, "other", "spec", "name")
	r.putUser(u)
	time.Sleep(200 * time.Millisecond)
	if after := r.orgWrites(); after != before {
		t.Fatalf("%d needless org writes", after-before)
	}

	// Removing the last flags entry of the teamspace removes the document.
	if err := r.mc.Resource(DeviceGVR).Namespace("acme").Delete(context.Background(), "cam-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "org doc removed", func() bool { _, _, ok := r.orgDoc("acme"); return !ok })
}

func TestFlagsWatcherRepairsAndCleansOrgDocuments(t *testing.T) {
	r := newWatcherRig(t, deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}))
	waitFor(t, "org doc", func() bool { _, _, ok := r.orgDoc("acme"); return ok })
	if err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Delete(context.Background(), "ztna-org-acme", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "org doc restored", func() bool { _, _, ok := r.orgDoc("acme"); return ok })
	// Tampering is repaired too.
	cm, _ := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), "ztna-org-acme", metav1.GetOptions{})
	cm.Data[api.OrgDataKey] = `{"v":1,"namespace":"acme","members":{"evil@x.io":{"units":[]}},"exempt":["evil@x.io"]}`
	if _, err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "org doc repaired", func() bool { d, _, _ := r.orgDoc("acme"); return len(d.Exempt) == 0 && len(d.Members) == 0 })
}

func TestFlagsWatcherDeletesOrphanOrgDocumentsAtStartup(t *testing.T) {
	orphan := orgCM("ztna-org-gone", map[string]string{api.OrgLabel: "true", api.PolicyTeamspaceLabel: "gone"},
		map[string]string{api.OrgDataKey: `{"v":1,"namespace":"gone","members":{},"exempt":[]}`})
	r := newWatcherRigCMs(t, []runtime.Object{orphan})
	waitFor(t, "orphan removed", func() bool {
		_, err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), "ztna-org-gone", metav1.GetOptions{})
		return err != nil
	})
}

func counterValue(t *testing.T, c *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.WithLabelValues(labels...).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// Nothing is written (and the watcher is not ready) before the Users were listed.
func TestFlagsWatcherWaitsForTheUserInformer(t *testing.T) {
	release := make(chan struct{})
	dc := newUserClient()
	dc.PrependReactor("list", "users", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-release
		return false, nil, nil
	})
	scheme := runtime.NewScheme()
	_ = metav1.AddMetaToScheme(scheme)
	mc := metafake.NewSimpleMetadataClient(scheme, deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}))
	cs := fake.NewSimpleClientset()
	logger, _ := captureLogger()
	w, err := NewFlagsWatcher(cs, mc, dc, FlagsWatcherConfig{Resync: time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(300 * time.Millisecond)
	if w.Ready() {
		t.Fatal("ready before the User informer synced")
	}
	// Device flags are mirrored without waiting for the Users ...
	waitFor(t, "flags before the Users synced", func() bool {
		_, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Get(ctx, api.FlagsConfigMapName("acme", "cam-1"), metav1.GetOptions{})
		return err == nil
	})
	// ... but no org document is written (or deleted) before then.
	if _, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Get(ctx, "ztna-org-acme", metav1.GetOptions{}); err == nil {
		t.Fatal("org document written before the Users synced")
	}
	close(release)
	waitFor(t, "ready", w.Ready)
	waitFor(t, "org doc", func() bool {
		_, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Get(ctx, "ztna-org-acme", metav1.GetOptions{})
		return err == nil
	})
}

// A placement change between the first check and the registration of the
// session must not leave it up (the enforcer did not see it yet).
func TestOrgGateRechecksAfterAdmission(t *testing.T) {
	r := newRig(t)
	r.deviceSessionOK()
	r.org.set(orgDocOf(testNS, aliceEmail, "u1"))
	r.setOrgDevice("a/u1")
	r.h.testHookAfterAdmit = func() { r.setOrgDevice("a/elsewhere") }
	req, _ := r.clientReq(22)
	st, body := r.clientSession(aliceToken, req)
	r.h.testHookAfterAdmit = nil
	wantReason(t, st, body, http.StatusForbidden, api.ReasonForbidden)
	if _, n := r.h.sessionCounts(); n != 0 {
		t.Fatal("session left open")
	}
}

// A document with the org label but a non-canonical name is deleted.
func TestFlagsWatcherDeletesMisnamedOrgDocument(t *testing.T) {
	cm := orgCM("ztna-org-wrong", map[string]string{api.OrgLabel: "true", api.PolicyTeamspaceLabel: "acme"}, map[string]string{api.OrgDataKey: "{}"})
	r := newWatcherRigCMs(t, []runtime.Object{cm}, deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}))
	waitFor(t, "misnamed document deleted", func() bool {
		_, err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), "ztna-org-wrong", metav1.GetOptions{})
		return err != nil
	})
}
