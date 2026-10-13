package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ParseFlagsConfigMap validates a flags ConfigMap. A ConfigMap that is
// malformed, mislabelled or whose entry disagrees with its name is treated as
// absent (fail closed). The returned string is the problem, empty when valid.
func ParseFlagsConfigMap(cm *corev1.ConfigMap) (api.FlagsEntry, string) {
	var e api.FlagsEntry
	if cm.Labels[api.FlagsLabel] != "true" {
		return e, "missing flags label"
	}
	raw, ok := cm.Data[api.FlagsDataKey]
	if !ok {
		return e, "missing " + api.FlagsDataKey
	}
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return api.FlagsEntry{}, "malformed flags JSON"
	}
	if !validLabel(e.Namespace) || !validLabel(e.Device) {
		return api.FlagsEntry{}, "invalid teamspace or device"
	}
	if cm.Name != api.FlagsConfigMapName(e.Namespace, e.Device) {
		return api.FlagsEntry{}, "name does not match entry"
	}
	return e, ""
}

// BuildFlagsConfigMap renders the flags ConfigMap of an entry in hubNS. prev,
// when given, is updated in place of a fresh object (keeps resourceVersion).
func BuildFlagsConfigMap(hubNS string, e api.FlagsEntry, prev *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var cm *corev1.ConfigMap
	if prev != nil {
		cm = prev.DeepCopy()
	} else {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: api.FlagsConfigMapName(e.Namespace, e.Device), Namespace: hubNS}}
	}
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	cm.Labels[api.FlagsLabel] = "true"
	cm.Labels[api.PolicyTeamspaceLabel] = e.Namespace
	cm.Labels[api.PolicyDeviceLabel] = e.Device
	cm.Data = map[string]string{api.FlagsDataKey: string(raw)}
	return cm, nil
}

// sameFlags compares two entries ignoring the observation time.
func sameFlags(a, b api.FlagsEntry) bool {
	a.ObservedAt = b.ObservedAt
	return a == b
}

// flagStore holds the parsed flags ConfigMaps.
type flagStore struct {
	subscribers
	log *slog.Logger

	mu     sync.RWMutex
	byName map[string]devKey
	m      map[devKey]api.FlagsEntry
	synced func() bool
}

func newFlagStore(log *slog.Logger) *flagStore {
	return &flagStore{log: log, byName: map[string]devKey{}, m: map[devKey]api.FlagsEntry{}}
}

func (f *flagStore) apply(cm *corev1.ConfigMap) {
	e, problem := ParseFlagsConfigMap(cm)
	if problem != "" {
		f.log.Warn("ignoring flags ConfigMap", "configmap", cm.Name, "problem", problem)
		f.remove(cm)
		return
	}
	key := devKey{e.Namespace, e.Device}
	f.mu.Lock()
	old, existed := f.m[key]
	f.m[key] = e
	f.byName[cm.Name] = key
	f.mu.Unlock()
	if !existed || !sameFlags(old, e) {
		f.notify(key.ns, key.device)
	}
}

func (f *flagStore) remove(cm *corev1.ConfigMap) {
	f.mu.Lock()
	key, ok := f.byName[cm.Name]
	if ok {
		delete(f.byName, cm.Name)
		delete(f.m, key)
	}
	f.mu.Unlock()
	if ok {
		f.notify(key.ns, key.device)
	}
}

// Flags implements DeviceFlags.
func (f *flagStore) Flags(ns, device string) (api.FlagsEntry, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.m[devKey{ns, device}]
	return e, ok
}

// Subscribe implements DeviceFlags.
func (f *flagStore) Subscribe(fn func(ns, device string)) { f.add(fn) }

// HasSynced implements DeviceFlags.
func (f *flagStore) HasSynced() bool { return f.synced != nil && f.synced() }

// K8sFlagsSource is a DeviceFlags backed by a ConfigMap informer on the hub
// namespace, restricted to ConfigMaps labelled api.FlagsLabel=true. Those are
// written by `wg-hub flags-watcher`, the only component that reads Devices,
// so the internet-facing hub needs no Device access at all.
type K8sFlagsSource struct {
	*flagStore
	factory informers.SharedInformerFactory
}

// NewK8sFlagsSource creates the source; call Start to run the informer.
func NewK8sFlagsSource(cs kubernetes.Interface, hubNamespace string, log *slog.Logger) (*K8sFlagsSource, error) {
	store := newFlagStore(log)
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(hubNamespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = api.FlagsLabel + "=true" }))
	inf := factory.Core().V1().ConfigMaps().Informer()
	reg, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(o any) {
			if cm, ok := o.(*corev1.ConfigMap); ok {
				store.apply(cm)
			}
		},
		UpdateFunc: func(_, o any) {
			if cm, ok := o.(*corev1.ConfigMap); ok {
				store.apply(cm)
			}
		},
		DeleteFunc: func(o any) {
			if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
				o = t.Obj
			}
			if cm, ok := o.(*corev1.ConfigMap); ok {
				store.remove(cm)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	store.synced = reg.HasSynced
	return &K8sFlagsSource{flagStore: store, factory: factory}, nil
}

// Start runs the informer until ctx is done.
func (f *K8sFlagsSource) Start(ctx context.Context) { f.factory.Start(ctx.Done()) }
