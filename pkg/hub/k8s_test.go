package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ---- SA delegation ----

func saFixture(name string, ann map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: api.HubNamespace, Annotations: ann}}
}

func tokenReviewReactor(cs *fake.Clientset, calls *atomic.Int32, results map[string]authnv1.TokenReviewStatus) {
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		calls.Add(1)
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != api.SATokenAudience {
			return true, nil, errors.New("TokenReview must request exactly the ztna audience")
		}
		tr = tr.DeepCopy()
		tr.Status = results[tr.Spec.Token]
		return true, tr, nil
	})
}

func TestK8sSADelegation(t *testing.T) {
	bound := map[string]string{api.SAAnnotationNamespace: "acme", api.SAAnnotationDevice: "cam-1"}
	cs := fake.NewSimpleClientset(
		saFixture("term-cam-1", bound),
		saFixture("term-other", map[string]string{api.SAAnnotationNamespace: "acme", api.SAAnnotationDevice: "cam-2"}),
		saFixture("term-bare", nil),
	)
	var calls atomic.Int32
	user := func(sa string) authnv1.UserInfo {
		return authnv1.UserInfo{Username: "system:serviceaccount:" + api.HubNamespace + ":" + sa}
	}
	tokenReviewReactor(cs, &calls, map[string]authnv1.TokenReviewStatus{
		"tok-bound":    {Authenticated: true, User: user("term-cam-1"), Audiences: []string{api.SATokenAudience}},
		"tok-other":    {Authenticated: true, User: user("term-other"), Audiences: []string{api.SATokenAudience}},
		"tok-bare":     {Authenticated: true, User: user("term-bare"), Audiences: []string{api.SATokenAudience}},
		"tok-ghost":    {Authenticated: true, User: user("ghost"), Audiences: []string{api.SATokenAudience}},
		"tok-badaud":   {Authenticated: true, User: user("term-cam-1"), Audiences: []string{"https://kubernetes.default.svc"}},
		"tok-otherns":  {Authenticated: true, User: authnv1.UserInfo{Username: "system:serviceaccount:acme:term-cam-1"}, Audiences: []string{api.SATokenAudience}},
		"tok-human":    {Authenticated: true, User: authnv1.UserInfo{Username: "alice@example.com"}, Audiences: []string{api.SATokenAudience}},
		"tok-unauth":   {Authenticated: false, Error: "expired"},
		"tok-nested":   {Authenticated: true, User: user("a:b"), Audiences: []string{api.SATokenAudience}},
		"tok-nopfx":    {Authenticated: true, User: authnv1.UserInfo{Username: "system:serviceaccount:" + api.HubNamespace + ":"}, Audiences: []string{api.SATokenAudience}},
		"tok-noaud-ok": {Authenticated: true, User: user("term-cam-1")},
	})
	d := NewK8sSADelegation(cs, api.HubNamespace)
	ctx := context.Background()

	tests := []struct {
		name       string
		token      string
		ns, device string
		email      string
		wantErr    error // nil = success
	}{
		{"bound SA, matching device", "tok-bound", "acme", "cam-1", "alice@example.com", nil},
		{"audience not echoed by the API server is tolerated", "tok-noaud-ok", "acme", "cam-1", "alice@example.com", nil},
		{"bound to another device (namespace/device mismatch)", "tok-bound", "acme", "cam-2", "alice@example.com", ErrForbidden},
		{"bound to another namespace", "tok-bound", "evil", "cam-1", "alice@example.com", ErrForbidden},
		{"SA bound to cam-2 asked for cam-1", "tok-other", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"SA without annotations", "tok-bare", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"SA that no longer exists", "tok-ghost", "acme", "cam-1", "alice@example.com", ErrUnauthenticated},
		{"wrong audience", "tok-badaud", "acme", "cam-1", "alice@example.com", ErrUnauthenticated},
		{"SA from another namespace", "tok-otherns", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"not a service account", "tok-human", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"unauthenticated token", "tok-unauth", "acme", "cam-1", "alice@example.com", ErrUnauthenticated},
		{"nested name", "tok-nested", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"empty SA name", "tok-nopfx", "acme", "cam-1", "alice@example.com", ErrForbidden},
		{"onBehalfOf uppercase", "tok-bound", "acme", "cam-1", "Alice@example.com", ErrForbidden},
		{"onBehalfOf not an email", "tok-bound", "acme", "cam-1", "alice", ErrForbidden},
		{"onBehalfOf empty", "tok-bound", "acme", "cam-1", "", ErrForbidden},
		{"empty token", "", "acme", "cam-1", "alice@example.com", ErrUnauthenticated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := d.Verify(ctx, tc.token, tc.ns, tc.device, tc.email)
			if tc.wantErr == nil {
				if err != nil || id.Name != "term-cam-1" {
					t.Fatalf("got %+v, %v", id, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestK8sSADelegationTokenReviewOutage(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	_, err := NewK8sSADelegation(cs, api.HubNamespace).Verify(context.Background(), "t", "acme", "cam-1", "alice@example.com")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

// ---- SAR ----

func TestK8sAuthorizer(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var got authzv1.SubjectAccessReviewSpec
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview).DeepCopy()
		got = sar.Spec
		sar.Status.Allowed = sar.Spec.User == "alice@example.com"
		return true, sar, nil
	})
	a := NewK8sAuthorizer(cs)
	ok, err := a.CanExec(context.Background(), "alice@example.com", "acme")
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	ra := got.ResourceAttributes
	if ra == nil || ra.Namespace != "acme" || ra.Verb != "create" || ra.Resource != "pods" || ra.Subresource != "exec" {
		t.Fatalf("wrong review: %+v", got)
	}
	if ok, _ := a.CanExec(context.Background(), "bob@example.com", "acme"); ok {
		t.Fatal("bob must be denied")
	}
	if ok, err := a.CanExec(context.Background(), "BOB", "acme"); ok || err != nil {
		t.Fatalf("invalid identity must deny without asking the API: %v %v", ok, err)
	}
	cs.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("down")
	})
	if ok, err := a.CanExec(context.Background(), "alice@example.com", "acme"); ok || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage must deny with ErrUnavailable: %v %v", ok, err)
	}
}

func TestK8sAuthorizerDeniedWinsOverAllowed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview).DeepCopy()
		sar.Status.Allowed, sar.Status.Denied = true, true
		return true, sar, nil
	})
	if ok, _ := NewK8sAuthorizer(cs).CanExec(context.Background(), "alice@example.com", "acme"); ok {
		t.Fatal("explicit denial must win")
	}
}

// ---- policy ----

func policyCM(ns, dev string, mut func(*corev1.ConfigMap, *api.PolicyEntry)) *corev1.ConfigMap {
	e := api.PolicyEntry{Device: dev, Namespace: ns, State: api.StateActive, AllowedPorts: []int{22}, EnrollmentGeneration: 3}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: api.PolicyConfigMapName(ns, dev), Namespace: api.HubNamespace,
			Labels: map[string]string{api.PolicyLabel: "true", api.PolicyTeamspaceLabel: ns, api.PolicyDeviceLabel: dev},
		},
	}
	if mut != nil {
		mut(cm, &e)
	}
	if cm.Data == nil {
		raw, _ := json.Marshal(e)
		cm.Data = map[string]string{api.PolicyDataKey: string(raw)}
	}
	return cm
}

func TestPolicyStoreValidation(t *testing.T) {
	logger, _ := captureLogger()
	tests := []struct {
		name string
		mut  func(*corev1.ConfigMap, *api.PolicyEntry)
		ok   bool
	}{
		{"valid", nil, true},
		{"entry namespace disagrees with label", func(_ *corev1.ConfigMap, e *api.PolicyEntry) { e.Namespace = "other" }, false},
		{"entry device disagrees with label", func(_ *corev1.ConfigMap, e *api.PolicyEntry) { e.Device = "cam-9" }, false},
		{"teamspace label changed", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) { cm.Labels[api.PolicyTeamspaceLabel] = "other" }, false},
		{"device label changed", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) { cm.Labels[api.PolicyDeviceLabel] = "cam-9" }, false},
		{"policy label false", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) { cm.Labels[api.PolicyLabel] = "false" }, false},
		{"wrong ConfigMap name", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) { cm.Name = "ztna-policy-acme.other" }, false},
		{"missing key", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) { cm.Data = map[string]string{"other": "x"} }, false},
		{"malformed JSON", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) {
			cm.Data = map[string]string{api.PolicyDataKey: "{nope"}
		}, false},
		{"invalid label value", func(cm *corev1.ConfigMap, _ *api.PolicyEntry) {
			cm.Labels[api.PolicyTeamspaceLabel] = "Acme_"
			cm.Name = api.PolicyConfigMapName("Acme_", "cam-1")
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newPolicyStore(logger)
			s.apply(policyCM("acme", "cam-1", tc.mut))
			e, ok := s.Get("acme", "cam-1")
			if ok != tc.ok {
				t.Fatalf("Get ok=%v, want %v", ok, tc.ok)
			}
			if ok && (e.EnrollmentGeneration != 3 || !portAllowed(e.AllowedPorts, 22)) {
				t.Fatalf("entry %+v", e)
			}
			// A rejected entry must not be reachable under any key.
			for _, k := range [][2]string{{"other", "cam-1"}, {"acme", "cam-9"}, {"Acme_", "cam-1"}} {
				if _, ok := s.Get(k[0], k[1]); ok {
					t.Fatalf("entry reachable under %v", k)
				}
			}
		})
	}
}

func TestPolicyStoreNotifiesAndFailsClosedOnBadUpdate(t *testing.T) {
	logger, _ := captureLogger()
	s := newPolicyStore(logger)
	var mu sync.Mutex
	var events []devKey
	s.Subscribe(func(ns, d string) { mu.Lock(); events = append(events, devKey{ns, d}); mu.Unlock() })

	cm := policyCM("acme", "cam-1", nil)
	s.apply(cm)
	if _, ok := s.Get("acme", "cam-1"); !ok {
		t.Fatal("not stored")
	}
	// Someone tampers: the update disagrees with the labels. The previous
	// (possibly more permissive) entry must NOT stay in force.
	bad := policyCM("acme", "cam-1", func(_ *corev1.ConfigMap, e *api.PolicyEntry) { e.Namespace = "evil" })
	s.apply(bad)
	if _, ok := s.Get("acme", "cam-1"); ok {
		t.Fatal("invalid update must remove the entry (fail closed)")
	}
	s.apply(cm)
	s.remove(cm)
	if _, ok := s.Get("acme", "cam-1"); ok {
		t.Fatal("delete not applied")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 4 {
		t.Fatalf("events %v", events)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestK8sPolicySourceInformer(t *testing.T) {
	logger, _ := captureLogger()
	good := policyCM("acme", "cam-1", nil)
	unlabelled := policyCM("acme", "cam-2", nil)
	unlabelled.Labels = nil // not selected by the informer at all
	cs := fake.NewSimpleClientset(good, unlabelled)
	src, err := NewK8sPolicySource(cs, api.HubNamespace, logger)
	if err != nil {
		t.Fatal(err)
	}
	var events atomic.Int32
	src.Subscribe(func(string, string) { events.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.Start(ctx)
	waitFor(t, "policy sync", src.HasSynced)
	if _, ok := src.Get("acme", "cam-1"); !ok {
		t.Fatal("labelled ConfigMap not loaded")
	}
	if _, ok := src.Get("acme", "cam-2"); ok {
		t.Fatal("unlabelled ConfigMap must not be loaded")
	}

	// Live update: revoke.
	upd := policyCM("acme", "cam-1", func(_ *corev1.ConfigMap, e *api.PolicyEntry) { e.State = api.StateRevoked })
	if _, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revoked policy", func() bool { e, _ := src.Get("acme", "cam-1"); return e.State == api.StateRevoked })
	if err := cs.CoreV1().ConfigMaps(api.HubNamespace).Delete(ctx, upd.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "policy delete", func() bool { _, ok := src.Get("acme", "cam-1"); return !ok })
	if events.Load() < 3 {
		t.Fatalf("only %d change events", events.Load())
	}
}

// ---- device flags ----

func TestFlagStore(t *testing.T) {
	f := newFlagStore()
	var n atomic.Int32
	f.Subscribe(func(string, string) { n.Add(1) })
	obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "cam-1", Namespace: "acme", Annotations: map[string]string{
		api.AnnotationWireGuard: "enabled", "unrelated": "x", "kubectl.kubernetes.io/last-applied-configuration": "SECRET",
	}}}
	f.apply(obj)
	ann, ok := f.Annotations("acme", "cam-1")
	if !ok || ann[api.AnnotationWireGuard] != "enabled" || len(ann) != 1 {
		t.Fatalf("annotations %v %v (only ztna annotations may be kept)", ann, ok)
	}
	f.apply(obj) // unchanged: no event
	if n.Load() != 1 {
		t.Fatalf("events %d, want 1", n.Load())
	}
	upd := obj.DeepCopy()
	upd.Annotations[api.AnnotationCompromised] = "true"
	f.apply(upd)
	if n.Load() != 2 {
		t.Fatalf("events %d, want 2", n.Load())
	}
	f.remove(upd)
	if _, ok := f.Annotations("acme", "cam-1"); ok || n.Load() != 3 {
		t.Fatalf("delete not applied (events %d)", n.Load())
	}
}

func TestK8sDeviceFlagsMetadataInformer(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dev := &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "teknoir.org/v1", Kind: "Device"},
		ObjectMeta: metav1.ObjectMeta{Name: "cam-1", Namespace: "acme", Annotations: map[string]string{api.AnnotationWireGuard: "enabled"}},
	}
	mc := metafake.NewSimpleMetadataClient(scheme, dev)
	flags, err := NewK8sDeviceFlags(mc)
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	flags.Subscribe(func(string, string) { n.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flags.Start(ctx)
	waitFor(t, "flags sync", flags.HasSynced)
	ann, ok := flags.Annotations("acme", "cam-1")
	if !ok || ann[api.AnnotationWireGuard] != "enabled" {
		t.Fatalf("got %v %v", ann, ok)
	}

	gvr := schema.GroupVersionResource{Group: "teknoir.org", Version: "v1", Resource: "devices"}
	if gvr != DeviceGVR {
		t.Fatalf("unexpected GVR %v", DeviceGVR)
	}
	upd := dev.DeepCopy()
	upd.Annotations[api.AnnotationHealthCheckFailed] = "true"
	patchObj := &metav1.PartialObjectMetadata{TypeMeta: dev.TypeMeta, ObjectMeta: upd.ObjectMeta}
	_ = patchObj
	// The fake metadata client supports merge patches on annotations.
	body := []byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:"true"}}}`, api.AnnotationHealthCheckFailed))
	if _, err := mc.Resource(gvr).Namespace("acme").Patch(ctx, "cam-1", "application/merge-patch+json", body, metav1.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "health flag", func() bool {
		a, _ := flags.Annotations("acme", "cam-1")
		return a[api.AnnotationHealthCheckFailed] == "true"
	})
	if err := mc.Resource(gvr).Namespace("acme").Delete(ctx, "cam-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "device delete", func() bool { _, ok := flags.Annotations("acme", "cam-1"); return !ok })
	if n.Load() < 3 {
		t.Fatalf("only %d events", n.Load())
	}
}

// ---- identity store ----

func idEntry(gen int64, key string) api.IdentityEntry {
	return api.IdentityEntry{Device: "cam-1", Namespace: "acme", IdentityPublicKey: key, Fingerprint: "SHA256:" + key, EnrollmentGeneration: gen, EnrolledAt: time.Unix(1, 0).UTC()}
}

func TestK8sIdentityStorePinSemantics(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewK8sIdentityStore(cs, api.HubNamespace)
	ctx := context.Background()

	if _, found, err := s.Get(ctx, "acme", "cam-1"); found || err != nil {
		t.Fatalf("empty store: %v %v", found, err)
	}
	cur, created, err := s.Pin(ctx, idEntry(1, "keyA"))
	if err != nil || !created || cur.IdentityPublicKey != "keyA" {
		t.Fatalf("first pin: %+v %v %v", cur, created, err)
	}
	// Same generation, different key: the existing pin stays.
	cur, created, err = s.Pin(ctx, idEntry(1, "keyB"))
	if err != nil || created || cur.IdentityPublicKey != "keyA" {
		t.Fatalf("second pin must not replace: %+v %v %v", cur, created, err)
	}
	// Older generation: no.
	cur, created, _ = s.Pin(ctx, idEntry(0, "keyZ"))
	if created || cur.IdentityPublicKey != "keyA" {
		t.Fatalf("older generation must not replace: %+v %v", cur, created)
	}
	// Newer generation: the old pin is void and replaced.
	cur, created, err = s.Pin(ctx, idEntry(2, "keyC"))
	if err != nil || !created || cur.IdentityPublicKey != "keyC" || cur.EnrollmentGeneration != 2 {
		t.Fatalf("newer generation must replace: %+v %v %v", cur, created, err)
	}
	got, found, err := s.Get(ctx, "acme", "cam-1")
	if err != nil || !found || got.IdentityPublicKey != "keyC" {
		t.Fatalf("get: %+v %v %v", got, found, err)
	}

	// The ConfigMap carries the documented name and labels.
	cm, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Get(ctx, api.IdentityConfigMapName("acme", "cam-1"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Labels[api.IdentityLabel] != "true" || cm.Labels[api.PolicyTeamspaceLabel] != "acme" || cm.Labels[api.PolicyDeviceLabel] != "cam-1" {
		t.Fatalf("labels %v", cm.Labels)
	}
}

func TestK8sIdentityStoreRecordConflict(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewK8sIdentityStore(cs, api.HubNamespace)
	ctx := context.Background()
	at := time.Unix(1000, 0).UTC()
	// No pin: nothing to record against, and nothing is created.
	if err := s.RecordConflict(ctx, "acme", "cam-1", at); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.Get(ctx, "acme", "cam-1"); found {
		t.Fatal("RecordConflict must not create a pin")
	}
	_, _, _ = s.Pin(ctx, idEntry(1, "keyA"))
	for range 3 {
		if err := s.RecordConflict(ctx, "acme", "cam-1", at); err != nil {
			t.Fatal(err)
		}
	}
	got, _, _ := s.Get(ctx, "acme", "cam-1")
	if got.Conflicts != 3 || !got.LastConflictAt.Equal(at) || got.IdentityPublicKey != "keyA" {
		t.Fatalf("got %+v", got)
	}
}

func TestK8sIdentityStoreRetriesOnConflict(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewK8sIdentityStore(cs, api.HubNamespace)
	ctx := context.Background()
	_, _, _ = s.Pin(ctx, idEntry(1, "keyA"))

	var updates atomic.Int32
	cs.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if updates.Add(1) <= 2 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "x", errors.New("stale"))
		}
		return false, nil, nil
	})
	if err := s.RecordConflict(ctx, "acme", "cam-1", time.Now()); err != nil {
		t.Fatalf("conflicts must be retried: %v", err)
	}
	if updates.Load() != 3 {
		t.Fatalf("update attempts %d, want 3", updates.Load())
	}
	got, _, _ := s.Get(ctx, "acme", "cam-1")
	if got.Conflicts != 1 {
		t.Fatalf("conflicts %d", got.Conflicts)
	}

	// Persistent conflicts give up with ErrUnavailable instead of looping.
	cs.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "x", errors.New("stale"))
	})
	if err := s.RecordConflict(ctx, "acme", "cam-1", time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestK8sIdentityStoreCreateRace(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewK8sIdentityStore(cs, api.HubNamespace)
	ctx := context.Background()
	// Both goroutines see "not found", both try to create: one gets
	// AlreadyExists, re-reads and must lose.
	var wg sync.WaitGroup
	var wins atomic.Int32
	var keys sync.Map
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("key%d", i)
			cur, created, err := s.Pin(ctx, idEntry(1, key))
			if err != nil {
				t.Error(err)
				return
			}
			if created {
				wins.Add(1)
			}
			keys.Store(cur.IdentityPublicKey, true)
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent pins succeeded, want exactly 1", wins.Load())
	}
	n := 0
	keys.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("callers saw %d different effective pins, want 1", n)
	}
}

func TestK8sIdentityStoreRejectsForeignAndCorruptData(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := NewK8sIdentityStore(cs, api.HubNamespace)
	ctx := context.Background()
	mk := func(data string) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: api.IdentityConfigMapName("acme", "cam-1"), Namespace: api.HubNamespace},
			Data:       map[string]string{api.IdentityDataKey: data},
		}
		_ = cs.CoreV1().ConfigMaps(api.HubNamespace).Delete(ctx, cm.Name, metav1.DeleteOptions{})
		if _, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk(`{"device":"cam-2","namespace":"acme","identityPublicKey":"k"}`)
	if _, found, err := s.Get(ctx, "acme", "cam-1"); err == nil || found {
		t.Fatalf("foreign entry must be an error, got found=%v err=%v", found, err)
	}
	mk(`{nope`)
	if _, found, err := s.Get(ctx, "acme", "cam-1"); err == nil || found {
		t.Fatalf("corrupt entry must be an error, got found=%v err=%v", found, err)
	}
	// A pin that cannot be read is never overwritten by an enrollment.
	if _, created, err := s.Pin(ctx, idEntry(5, "keyX")); err == nil || created {
		t.Fatalf("Pin over a corrupt entry must fail, got created=%v err=%v", created, err)
	}
}

// ---- TURN secret source ----

func TestK8sSecretSourceAndMinter(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stunner-auth-secret", Namespace: "stunner-system"},
		Data:       map[string][]byte{"secret": []byte("s1")},
	}
	cs := fake.NewSimpleClientset(sec)
	src, err := NewK8sSecretSource(cs, "stunner-system/stunner-auth-secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	src.now = clock.Now
	if v, err := src.Secret(); err != nil || v != "s1" {
		t.Fatalf("got %q %v", v, err)
	}
	// Rotation is picked up after the refresh interval.
	sec2 := sec.DeepCopy()
	sec2.Data["secret"] = []byte("s2")
	if _, err := cs.CoreV1().Secrets("stunner-system").Update(context.Background(), sec2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := src.Secret(); v != "s1" {
		t.Fatalf("served %q before the refresh interval", v)
	}
	clock.Advance(2 * time.Minute)
	if v, _ := src.Secret(); v != "s2" {
		t.Fatalf("rotation not picked up: %q", v)
	}
	// API outage: the last value keeps serving.
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("down")
	})
	clock.Advance(2 * time.Minute)
	if v, err := src.Secret(); err != nil || v != "s2" {
		t.Fatalf("outage: %q %v", v, err)
	}

	for _, bad := range []string{"", "nosep", "a/", "/b", "a/b/c"} {
		if _, err := NewK8sSecretSource(cs, bad, 0); err == nil {
			t.Errorf("ref %q accepted", bad)
		}
	}

	m := NewTURNMinter(src.Secret, SplitList(" turn:a:3478?transport=udp , ,turn:b:3478 "), 30*time.Minute, clock.Now)
	c, err := m.Mint("acme", "sess1")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.URLs) != 2 || c.Password == "" || !c.ExpiresAt.Equal(clock.Now().Add(30*time.Minute).Truncate(time.Second)) {
		t.Fatalf("creds %+v", c)
	}
	if want := fmt.Sprintf("%d:acme/sess1", c.ExpiresAt.Unix()); c.Username != want {
		t.Fatalf("username %q, want %q", c.Username, want)
	}
	if _, err := m.Mint("ac:me", "x"); err == nil {
		t.Fatal("user ids with ':' must be refused")
	}
}
