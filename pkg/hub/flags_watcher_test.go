package hub

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

func deviceMeta(ns, name string, ann map[string]string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "teknoir.org/v1", Kind: "Device"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann},
	}
}

type watcherRig struct {
	t      *testing.T
	cs     *fake.Clientset
	mc     *metafake.FakeMetadataClient
	w      *FlagsWatcher
	writes atomic.Int32 // create + update + delete of flags ConfigMaps
}

func newWatcherRig(t *testing.T, devices ...runtime.Object) *watcherRig {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	r := &watcherRig{t: t, cs: fake.NewSimpleClientset(), mc: metafake.NewSimpleMetadataClient(scheme, devices...)}
	r.cs.PrependReactor("*", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		switch a.GetVerb() {
		case "create", "update", "delete":
			r.writes.Add(1)
		}
		return false, nil, nil
	})
	logger, _ := captureLogger()
	w, err := NewFlagsWatcher(r.cs, r.mc, FlagsWatcherConfig{Namespace: api.HubNamespace, Resync: time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	r.w = w
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "watcher ready", w.Ready)
	return r
}

func (r *watcherRig) flags(ns, device string) (api.FlagsEntry, bool) {
	r.t.Helper()
	cm, err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), api.FlagsConfigMapName(ns, device), metav1.GetOptions{})
	if err != nil {
		return api.FlagsEntry{}, false
	}
	e, problem := ParseFlagsConfigMap(cm)
	if problem != "" {
		r.t.Fatalf("watcher wrote an invalid flags ConfigMap: %s", problem)
	}
	return e, true
}

func (r *watcherRig) patch(ns, device, key, val string) {
	r.t.Helper()
	body := []byte(fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, key, val))
	if _, err := r.mc.Resource(DeviceGVR).Namespace(ns).Patch(context.Background(), device, "application/merge-patch+json", body, metav1.PatchOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

func TestFlagsWatcherMirrorsAnnotatedDevicesOnly(t *testing.T) {
	r := newWatcherRig(t,
		deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled", "unrelated": "x", "kubectl.kubernetes.io/last-applied-configuration": "SECRET"}),
		deviceMeta("acme", "cam-2", map[string]string{"unrelated": "x"}),
		deviceMeta("acme", "cam-3", nil),
	)
	waitFor(t, "cam-1 flags", func() bool { e, ok := r.flags("acme", "cam-1"); return ok && e.WireGuard && e.Exists })
	// Devices ZTNA never touched get no ConfigMap at all.
	time.Sleep(100 * time.Millisecond)
	for _, d := range []string{"cam-2", "cam-3"} {
		if _, ok := r.flags("acme", d); ok {
			t.Fatalf("%s has a flags ConfigMap although it has no ztna annotation", d)
		}
	}
	// Nothing but the three booleans and the names reaches the ConfigMap.
	cm, _ := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Get(context.Background(), api.FlagsConfigMapName("acme", "cam-1"), metav1.GetOptions{})
	if cm.Labels[api.FlagsLabel] != "true" || cm.Labels[api.PolicyTeamspaceLabel] != "acme" || cm.Labels[api.PolicyDeviceLabel] != "cam-1" {
		t.Fatalf("labels %v", cm.Labels)
	}
	if got := cm.Data[api.FlagsDataKey]; len(cm.Data) != 1 || containsAny(got, "SECRET", "unrelated") {
		t.Fatalf("data %v", cm.Data)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

func TestFlagsWatcherFollowsChangesAndWritesOnlyOnChange(t *testing.T) {
	r := newWatcherRig(t, deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}))
	waitFor(t, "initial flags", func() bool { _, ok := r.flags("acme", "cam-1"); return ok })

	r.patch("acme", "cam-1", api.AnnotationCompromised, " True ") // the shared parser accepts it
	waitFor(t, "compromised", func() bool { e, _ := r.flags("acme", "cam-1"); return e.Compromised })
	r.patch("acme", "cam-1", api.AnnotationCompromised, "false")
	waitFor(t, "cleared", func() bool { e, _ := r.flags("acme", "cam-1"); return !e.Compromised && e.WireGuard })
	r.patch("acme", "cam-1", api.AnnotationHealthCheckFailed, "true")
	waitFor(t, "health", func() bool { e, _ := r.flags("acme", "cam-1"); return e.HealthCheckFailed })

	// An annotation that does not change the entry causes no write.
	before := r.writes.Load()
	r.patch("acme", "cam-1", api.AnnotationReason, "operator note") // ztna annotation, no flag
	r.patch("acme", "cam-1", "unrelated", "x")
	time.Sleep(200 * time.Millisecond)
	if after := r.writes.Load(); after != before {
		t.Fatalf("%d needless ConfigMap writes", after-before)
	}

	// Disabling WireGuard keeps the entry (Exists) and clears the switch.
	r.patch("acme", "cam-1", api.AnnotationWireGuard, "disabled")
	waitFor(t, "disabled", func() bool { e, ok := r.flags("acme", "cam-1"); return ok && e.Exists && !e.WireGuard })
}

func TestFlagsWatcherRemovesFlagsOfDeletedDevicesAndRepairsDrift(t *testing.T) {
	r := newWatcherRig(t, deviceMeta("acme", "cam-1", map[string]string{api.AnnotationWireGuard: "enabled"}))
	waitFor(t, "flags", func() bool { _, ok := r.flags("acme", "cam-1"); return ok })

	// Someone deletes the flags ConfigMap: it comes back.
	if err := r.cs.CoreV1().ConfigMaps(api.HubNamespace).Delete(context.Background(), api.FlagsConfigMapName("acme", "cam-1"), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "flags restored", func() bool { _, ok := r.flags("acme", "cam-1"); return ok })

	// The Device goes away: so do its flags (the hub then treats it as not enabled).
	if err := r.mc.Resource(DeviceGVR).Namespace("acme").Delete(context.Background(), "cam-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "flags removed", func() bool { _, ok := r.flags("acme", "cam-1"); return !ok })
}

func TestFlagsWatcherCleansUpOrphansAtStartup(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = metav1.AddMetaToScheme(scheme)
	orphan, err := BuildFlagsConfigMap(api.HubNamespace, api.FlagsEntry{Device: "gone", Namespace: "acme", Exists: true, WireGuard: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := fake.NewSimpleClientset(orphan)
	mc := metafake.NewSimpleMetadataClient(scheme)
	logger, _ := captureLogger()
	w, err := NewFlagsWatcher(cs, mc, FlagsWatcherConfig{Resync: time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "orphan removed", func() bool {
		_, err := cs.CoreV1().ConfigMaps(api.HubNamespace).Get(ctx, orphan.Name, metav1.GetOptions{})
		return err != nil
	})
}

// The hub's view: a missing flags entry (watcher down, Device gone) is "not
// enabled", never "enabled by default".
func TestHubTreatsMissingFlagsAsNotEnabled(t *testing.T) {
	pol := newFakePolicy()
	pol.Set(api.PolicyEntry{Namespace: "acme", Device: "cam-1", State: api.StateActive})
	logger, _ := captureLogger()
	store := newFlagStore(logger)
	if eff := computeEffective(pol, store, "acme", "cam-1"); eff.Active || eff.Reason != api.ReasonDeviceUnknown {
		t.Fatalf("no entry: %+v", eff)
	}
	gone, _ := BuildFlagsConfigMap(api.HubNamespace, api.FlagsEntry{Device: "cam-1", Namespace: "acme", Exists: false, WireGuard: true}, nil)
	store.apply(gone)
	if eff := computeEffective(pol, store, "acme", "cam-1"); eff.Active {
		t.Fatalf("an entry with Exists=false must not be active: %+v", eff)
	}
	on, _ := BuildFlagsConfigMap(api.HubNamespace, api.FlagsEntry{Device: "cam-1", Namespace: "acme", Exists: true, WireGuard: true}, nil)
	store.apply(on)
	if eff := computeEffective(pol, store, "acme", "cam-1"); !eff.Active {
		t.Fatalf("enabled entry: %+v", eff)
	}
	store.remove(on)
	if eff := computeEffective(pol, store, "acme", "cam-1"); eff.Active {
		t.Fatalf("deleted entry must revoke: %+v", eff)
	}
}
