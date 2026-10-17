package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// DeviceGVR is the Device custom resource.
var DeviceGVR = schema.GroupVersionResource{Group: "teknoir.org", Version: "v1", Resource: "devices"}

// UserGVR is the (cluster-scoped) User custom resource.
var UserGVR = schema.GroupVersionResource{Group: "teknoir.org", Version: "v1", Resource: "users"}

// ztnaAnnotationPrefix marks every annotation that belongs to the ZTNA tunnel.
const ztnaAnnotationPrefix = "ztna.teknoir.org/"

// FlagsWatcherConfig configures a FlagsWatcher.
type FlagsWatcherConfig struct {
	// Namespace is the hub namespace (HUB_NAMESPACE) the flags ConfigMaps live in.
	Namespace string
	// Resync is the interval of the full reconciliation pass (default 5m).
	Resync time.Duration
	Logger *slog.Logger
	Now    func() time.Time
}

// FlagsWatcher mirrors the security-relevant Device annotations into flags
// ConfigMaps (api.FlagsConfigMapName) of the hub namespace. It is the only
// ztna component that reads Device objects (metadata only: names and
// annotations, never the spec with its keys), and it has no ingress, so the
// internet-facing hub never holds Device RBAC.
//
// It writes a ConfigMap only when the entry changed, for every Device that has
// any ztna.teknoir.org/* annotation or already has a flags ConfigMap. When the
// Device is gone, the ConfigMap is deleted; the hub treats a missing entry as
// "not enabled" and revokes.
type FlagsWatcher struct {
	cfg FlagsWatcherConfig
	log *slog.Logger
	cs  kubernetes.Interface

	devInf  cache.SharedIndexInformer
	cmInf   cache.SharedIndexInformer
	userInf cache.SharedIndexInformer // transformed: see stripUser
	orgInf  cache.SharedIndexInformer
	queue   workqueue.TypedRateLimitingInterface[devKey]

	ready atomic.Bool
	met   *watcherMetrics
}

type watcherMetrics struct {
	reg    *prometheus.Registry
	writes *prometheus.CounterVec
	errors prometheus.Counter
	orgW   *prometheus.CounterVec
}

func newWatcherMetrics() *watcherMetrics {
	m := &watcherMetrics{
		reg: prometheus.NewRegistry(),
		writes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wgflags_writes_total", Help: "Flags ConfigMap writes by action (create, update, delete).",
		}, []string{"action"}),
		errors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wgflags_errors_total", Help: "Failed reconciliations (retried).",
		}),
		orgW: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wgflags_org_writes_total", Help: "Org ConfigMap writes by action (create, update, delete).",
		}, []string{"action"}),
	}
	m.reg.MustRegister(m.writes, m.errors, m.orgW)
	return m
}

// NewFlagsWatcher creates the watcher. mc reads Device metadata cluster-wide,
// dc reads the Users (only the fields the org gate needs are kept), cs reads
// and writes the flags and org ConfigMaps in cfg.Namespace.
func NewFlagsWatcher(cs kubernetes.Interface, mc metadata.Interface, dc dynamic.Interface, cfg FlagsWatcherConfig) (*FlagsWatcher, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = api.HubNamespace
	}
	if cfg.Resync <= 0 {
		cfg.Resync = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	w := &FlagsWatcher{
		cfg: cfg, log: cfg.Logger, cs: cs, met: newWatcherMetrics(),
		queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[devKey]()),
	}
	w.devInf = metadatainformer.NewFilteredMetadataInformer(mc, DeviceGVR, metav1.NamespaceAll, 0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, nil).Informer()
	w.userInf = dynamicinformer.NewFilteredDynamicInformer(dc, UserGVR, metav1.NamespaceAll, 0, cache.Indexers{}, nil).Informer()
	if err := w.userInf.SetTransform(stripUser); err != nil {
		return nil, err
	}
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(cfg.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = api.FlagsLabel + "=true" }))
	w.cmInf = factory.Core().V1().ConfigMaps().Informer()
	orgFactory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(cfg.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = api.OrgLabel + "=true" }))
	w.orgInf = orgFactory.Core().V1().ConfigMaps().Informer()

	_, err := w.devInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(o any) { w.enqueueDevice(o) },
		UpdateFunc: func(oldObj, newObj any) {
			o, _ := oldObj.(*metav1.PartialObjectMetadata)
			n, _ := newObj.(*metav1.PartialObjectMetadata)
			if o != nil && n != nil && sameZtnaAnnotations(o.Annotations, n.Annotations) && sameOrgAnnotations(o.Annotations, n.Annotations) {
				return
			}
			w.enqueueDevice(newObj)
		},
		DeleteFunc: func(o any) { w.enqueueDevice(o) },
	})
	if err != nil {
		return nil, err
	}
	_, err = w.cmInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { w.enqueueConfigMap(o) },
		UpdateFunc: func(_, n any) { w.enqueueConfigMap(n) },
		DeleteFunc: func(o any) { w.enqueueConfigMap(o) },
	})
	if err != nil {
		return nil, err
	}
	_, err = w.orgInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { w.enqueueOrgConfigMap(o) },
		UpdateFunc: func(_, n any) { w.enqueueOrgConfigMap(n) },
		DeleteFunc: func(o any) { w.enqueueOrgConfigMap(o) },
	})
	if err != nil {
		return nil, err
	}
	_, err = w.userInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(o any) { w.queue.Add(devKey{}) },
		UpdateFunc: func(o, n any) {
			ou, _ := o.(*unstructured.Unstructured)
			nu, _ := n.(*unstructured.Unstructured)
			if ou != nil && nu != nil && reflect.DeepEqual(projectUser(ou), projectUser(nu)) {
				return // nothing the org gate reads changed
			}
			w.queue.Add(devKey{})
		},
		DeleteFunc: func(o any) { w.queue.Add(devKey{}) },
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

func ztnaAnnotations(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if strings.HasPrefix(k, ztnaAnnotationPrefix) {
			out[k] = v
		}
	}
	return out
}

func sameZtnaAnnotations(a, b map[string]string) bool {
	return sameAnnotationMaps(ztnaAnnotations(a), ztnaAnnotations(b))
}

func sameAnnotationMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func orgAnnotations(in map[string]string) map[string]string {
	return map[string]string{api.AnnotationOrgPath: in[api.AnnotationOrgPath], api.AnnotationOrgNodeID: in[api.AnnotationOrgNodeID]}
}

func sameOrgAnnotations(a, b map[string]string) bool {
	return sameAnnotationMaps(orgAnnotations(a), orgAnnotations(b))
}

func (w *FlagsWatcher) enqueueOrgConfigMap(o any) {
	if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
		o = t.Obj
	}
	if cm, ok := o.(*corev1.ConfigMap); ok {
		if ns := cm.Labels[api.PolicyTeamspaceLabel]; validLabel(ns) {
			w.queue.Add(devKey{ns: ns})
		}
	}
}

func (w *FlagsWatcher) enqueueDevice(o any) {
	if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
		o = t.Obj
	}
	if m, ok := o.(*metav1.PartialObjectMetadata); ok && validLabel(m.Namespace) && validLabel(m.Name) {
		w.queue.Add(devKey{m.Namespace, m.Name})
	}
}

func (w *FlagsWatcher) enqueueConfigMap(o any) {
	if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
		o = t.Obj
	}
	cm, ok := o.(*corev1.ConfigMap)
	if !ok {
		return
	}
	ns, dev := cm.Labels[api.PolicyTeamspaceLabel], cm.Labels[api.PolicyDeviceLabel]
	if validLabel(ns) && validLabel(dev) && cm.Name == api.FlagsConfigMapName(ns, dev) {
		w.queue.Add(devKey{ns, dev})
	}
}

// desiredEntry is what the flags ConfigMap of a Device should say.
func desiredEntry(m *metav1.PartialObjectMetadata, now time.Time) api.FlagsEntry {
	return api.FlagsEntry{
		Device: m.Name, Namespace: m.Namespace, Exists: true,
		WireGuard:         m.Annotations[api.AnnotationWireGuard] == "enabled",
		Compromised:       api.FlagSet(m.Annotations[api.AnnotationCompromised]),
		HealthCheckFailed: api.FlagSet(m.Annotations[api.AnnotationHealthCheckFailed]),
		ObservedAt:        now,
		OrgKnown:          true,
		OrgPath:           m.Annotations[api.AnnotationOrgPath],
		OrgNodeID:         m.Annotations[api.AnnotationOrgNodeID],
	}
}

// Ready reports whether both informers are synced.
func (w *FlagsWatcher) Ready() bool { return w.ready.Load() }

// Handler serves /healthz, /readyz and /metrics.
func (w *FlagsWatcher) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.HealthzPath, func(rw http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(rw, "ok\n") })
	mux.HandleFunc("/readyz", func(rw http.ResponseWriter, _ *http.Request) {
		if !w.Ready() {
			http.Error(rw, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(rw, "ok\n")
	})
	mux.Handle("/metrics", promhttp.HandlerFor(w.met.reg, promhttp.HandlerOpts{}))
	return mux
}

// Run starts the informers and mirrors flags until ctx is done.
func (w *FlagsWatcher) Run(ctx context.Context) error {
	defer w.queue.ShutDown()
	go w.devInf.Run(ctx.Done())
	go w.cmInf.Run(ctx.Done())
	go w.userInf.Run(ctx.Done())
	go w.orgInf.Run(ctx.Done())
	// No org document is written before the Users have been listed.
	if !cache.WaitForCacheSync(ctx.Done(), w.devInf.HasSynced, w.cmInf.HasSynced, w.userInf.HasSynced, w.orgInf.HasSynced) {
		return errors.New("flags watcher: informers did not sync")
	}
	w.resync() // also covers flags ConfigMaps whose Device vanished while we were down
	w.ready.Store(true)
	w.log.Info("flags watcher ready", "namespace", w.cfg.Namespace)

	go func() {
		t := time.NewTicker(w.cfg.Resync)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.resync()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		w.queue.ShutDown()
	}()
	for {
		key, shutdown := w.queue.Get()
		if shutdown {
			return nil
		}
		err := w.reconcile(ctx, key)
		if err != nil {
			w.met.errors.Inc()
			w.log.Warn("flags reconcile failed; retrying", "ns", key.ns, "device", key.device, "err", err.Error())
			w.queue.AddRateLimited(key)
		} else {
			w.queue.Forget(key)
		}
		w.queue.Done(key)
	}
}

// resync enqueues every Device with ztna annotations and every flags ConfigMap.
func (w *FlagsWatcher) resync() {
	for _, o := range w.devInf.GetStore().List() {
		if m, ok := o.(*metav1.PartialObjectMetadata); ok && len(ztnaAnnotations(m.Annotations)) > 0 {
			w.enqueueDevice(m)
		}
	}
	for _, o := range w.cmInf.GetStore().List() {
		w.enqueueConfigMap(o)
	}
	w.queue.Add(devKey{}) // every teamspace's org document, orphans included
}

// reconcile brings the flags ConfigMap of one device in line with the Device.
func (w *FlagsWatcher) reconcile(ctx context.Context, k devKey) error {
	if k.device == "" { // org documents: one teamspace, or (empty ns) all of them
		if k.ns == "" {
			w.enqueueAllOrg()
			return nil
		}
		return w.reconcileOrg(ctx, k.ns)
	}
	err := w.reconcileDevice(ctx, k)
	if err == nil {
		w.queue.Add(devKey{ns: k.ns}) // the teamspace may have gained or lost its last flags entry
	}
	return err
}

func (w *FlagsWatcher) reconcileDevice(ctx context.Context, k devKey) error {
	cms := w.cs.CoreV1().ConfigMaps(w.cfg.Namespace)
	name := api.FlagsConfigMapName(k.ns, k.device)

	var cm *corev1.ConfigMap
	if o, ok, _ := w.cmInf.GetStore().GetByKey(w.cfg.Namespace + "/" + name); ok {
		cm, _ = o.(*corev1.ConfigMap)
	}
	var dev *metav1.PartialObjectMetadata
	if o, ok, _ := w.devInf.GetStore().GetByKey(k.ns + "/" + k.device); ok {
		dev, _ = o.(*metav1.PartialObjectMetadata)
	}

	if dev == nil {
		if cm == nil {
			return nil
		}
		err := cms.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		w.met.writes.WithLabelValues("delete").Inc()
		w.log.Info("device gone; flags removed", "ns", k.ns, "device", k.device)
		return nil
	}
	if cm == nil && len(ztnaAnnotations(dev.Annotations)) == 0 {
		return nil // never touched by ZTNA
	}
	want := desiredEntry(dev, w.cfg.Now())
	if cm != nil {
		if cur, problem := ParseFlagsConfigMap(cm); problem == "" && sameFlags(cur, want) {
			return nil // write only on change
		}
	}
	obj, err := BuildFlagsConfigMap(w.cfg.Namespace, want, cm)
	if err != nil {
		return err
	}
	action := "update"
	if cm == nil {
		action = "create"
		_, err = cms.Create(ctx, obj, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("flags ConfigMap appeared concurrently: %w", err) // retried with the fresh cache
		}
	} else {
		_, err = cms.Update(ctx, obj, metav1.UpdateOptions{})
	}
	if err != nil {
		return err
	}
	w.met.writes.WithLabelValues(action).Inc()
	w.log.Info("flags mirrored", "ns", k.ns, "device", k.device, "action", action,
		"wireguard", want.WireGuard, "compromised", want.Compromised, "healthCheckFailed", want.HealthCheckFailed)
	return nil
}

// stripUser is the informer transform of the User objects. It keeps ONLY what
// the org gate reads (name, resourceVersion, the org-tree member and units
// annotations, spec.email, spec.claims_v0.role and the name and namespace of
// spec.claim_set entries); the status (which holds an initial password), the
// other annotations and the rest of the spec never stay in memory.
func stripUser(obj any) (any, error) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return obj, nil // e.g. DeletedFinalStateUnknown
	}
	p := projectUser(u)
	out := &unstructured.Unstructured{Object: map[string]any{}}
	out.SetAPIVersion(u.GetAPIVersion())
	out.SetKind(u.GetKind())
	out.SetName(p.Name)
	out.SetResourceVersion(u.GetResourceVersion())
	if len(p.Annotations) > 0 {
		out.SetAnnotations(p.Annotations)
	}
	_ = unstructured.SetNestedField(out.Object, p.Email, "spec", "email")
	_ = unstructured.SetNestedField(out.Object, p.Role, "spec", "claims_v0", "role")
	sets := make([]any, 0, len(p.ClaimSets))
	for _, c := range p.ClaimSets {
		sets = append(sets, map[string]any{"name": c.Name, "namespace": c.Namespace})
	}
	_ = unstructured.SetNestedSlice(out.Object, sets, "spec", "claim_set")
	return out, nil
}

// projectUser extracts the UserProjection of a (possibly stripped) User.
func projectUser(u *unstructured.Unstructured) UserProjection {
	p := UserProjection{Name: u.GetName(), Annotations: map[string]string{}}
	for k, v := range u.GetAnnotations() {
		if strings.HasPrefix(k, api.AnnotationOrgMemberPref) || strings.HasPrefix(k, api.AnnotationOrgUnitsPref) {
			p.Annotations[k] = v
		}
	}
	p.Email, _, _ = unstructured.NestedString(u.Object, "spec", "email")
	p.Role, _, _ = unstructured.NestedString(u.Object, "spec", "claims_v0", "role")
	sets, _, _ := unstructured.NestedSlice(u.Object, "spec", "claim_set")
	for _, e := range sets {
		if m, ok := e.(map[string]any); ok {
			n, _ := m["name"].(string)
			ns, _ := m["namespace"].(string)
			p.ClaimSets = append(p.ClaimSets, ClaimSetRef{Name: n, Namespace: ns})
		}
	}
	return p
}

// teamspacesWithFlags returns the teamspaces that have at least one desired
// flags entry: a Device with a ztna annotation or an existing flags ConfigMap.
func (w *FlagsWatcher) teamspacesWithFlags() map[string]bool {
	out := map[string]bool{}
	for _, o := range w.devInf.GetStore().List() {
		if m, ok := o.(*metav1.PartialObjectMetadata); ok && validLabel(m.Namespace) && validLabel(m.Name) && len(ztnaAnnotations(m.Annotations)) > 0 {
			out[m.Namespace] = true
		}
	}
	for _, o := range w.cmInf.GetStore().List() {
		if cm, ok := o.(*corev1.ConfigMap); ok {
			if ns, dev := cm.Labels[api.PolicyTeamspaceLabel], cm.Labels[api.PolicyDeviceLabel]; validLabel(ns) && cm.Name == api.FlagsConfigMapName(ns, dev) {
				out[ns] = true
			}
		}
	}
	return out
}

// enqueueAllOrg queues the org reconciliation of every teamspace that has flags
// entries or an org ConfigMap (the latter so orphans are deleted).
func (w *FlagsWatcher) enqueueAllOrg() {
	all := w.teamspacesWithFlags()
	for _, o := range w.orgInf.GetStore().List() {
		if cm, ok := o.(*corev1.ConfigMap); ok {
			if ns := cm.Labels[api.PolicyTeamspaceLabel]; validLabel(ns) {
				all[ns] = true
			} else if err := w.cs.CoreV1().ConfigMaps(w.cfg.Namespace).Delete(context.Background(), cm.Name, metav1.DeleteOptions{}); err == nil {
				w.met.orgW.WithLabelValues("delete").Inc() // mislabelled: nothing could ever own it
			}
		}
	}
	for ns := range all {
		w.queue.Add(devKey{ns: ns})
	}
}

// reconcileOrg brings ztna-org-<ns> in line with the Users: present (canonical
// JSON, written only on change) while the teamspace has flags entries, deleted
// otherwise.
func (w *FlagsWatcher) reconcileOrg(ctx context.Context, ns string) error {
	cms := w.cs.CoreV1().ConfigMaps(w.cfg.Namespace)
	name := api.OrgConfigMapName(ns)
	var cm *corev1.ConfigMap
	if o, ok, _ := w.orgInf.GetStore().GetByKey(w.cfg.Namespace + "/" + name); ok {
		cm, _ = o.(*corev1.ConfigMap)
	}
	if !w.teamspacesWithFlags()[ns] {
		if cm == nil {
			return nil
		}
		if err := cms.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		w.met.orgW.WithLabelValues("delete").Inc()
		w.log.Info("teamspace has no flags entries; org document removed", "ns", ns)
		return nil
	}
	var users []UserProjection
	for _, o := range w.userInf.GetStore().List() {
		if u, ok := o.(*unstructured.Unstructured); ok {
			users = append(users, projectUser(u))
		}
	}
	raw, err := marshalOrgDoc(buildOrgDoc(users, ns, w.log))
	if err != nil {
		return err
	}
	if cm != nil && cm.Labels[api.OrgLabel] == "true" && cm.Labels[api.PolicyTeamspaceLabel] == ns &&
		len(cm.Data) == 1 && cm.Data[api.OrgDataKey] == raw {
		return nil // write only on change
	}
	var obj *corev1.ConfigMap
	if cm != nil {
		obj = cm.DeepCopy()
	} else {
		obj = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: w.cfg.Namespace}}
	}
	if obj.Labels == nil {
		obj.Labels = map[string]string{}
	}
	obj.Labels[api.OrgLabel] = "true"
	obj.Labels[api.PolicyTeamspaceLabel] = ns
	obj.Data = map[string]string{api.OrgDataKey: raw}
	action := "update"
	if cm == nil {
		action = "create"
		_, err = cms.Create(ctx, obj, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("org ConfigMap appeared concurrently: %w", err)
		}
	} else {
		_, err = cms.Update(ctx, obj, metav1.UpdateOptions{})
	}
	if err != nil {
		return err
	}
	w.met.orgW.WithLabelValues(action).Inc()
	w.log.Info("org document mirrored", "ns", ns, "action", action)
	return nil
}
