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

// subscribers is a small fan-out list shared by the sources.
type subscribers struct {
	mu  sync.RWMutex
	fns []func(ns, device string)
}

func (s *subscribers) add(fn func(ns, device string)) {
	s.mu.Lock()
	s.fns = append(s.fns, fn)
	s.mu.Unlock()
}

func (s *subscribers) notify(ns, device string) {
	s.mu.RLock()
	fns := s.fns
	s.mu.RUnlock()
	for _, fn := range fns {
		fn(ns, device)
	}
}

// policyStore holds the parsed policy ConfigMaps. A ConfigMap that is
// malformed, mislabelled or whose entry disagrees with its labels is treated
// as absent (fail closed).
type policyStore struct {
	subscribers
	log *slog.Logger

	mu      sync.RWMutex
	byName  map[string]policyItem
	entries map[devKey]string // device -> ConfigMap name
	synced  func() bool
}

type policyItem struct {
	key   devKey
	entry api.PolicyEntry
}

func newPolicyStore(log *slog.Logger) *policyStore {
	return &policyStore{log: log, byName: map[string]policyItem{}, entries: map[devKey]string{}}
}

// parsePolicy validates a policy ConfigMap.
func parsePolicy(cm *corev1.ConfigMap) (devKey, api.PolicyEntry, string) {
	var zero api.PolicyEntry
	if cm.Labels[api.PolicyLabel] != "true" {
		return devKey{}, zero, "missing policy label"
	}
	ns, dev := cm.Labels[api.PolicyTeamspaceLabel], cm.Labels[api.PolicyDeviceLabel]
	if !validLabel(ns) || !validLabel(dev) {
		return devKey{}, zero, "invalid teamspace or device label"
	}
	if cm.Name != api.PolicyConfigMapName(ns, dev) {
		return devKey{}, zero, "name does not match labels"
	}
	raw, ok := cm.Data[api.PolicyDataKey]
	if !ok {
		return devKey{}, zero, "missing " + api.PolicyDataKey
	}
	var e api.PolicyEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return devKey{}, zero, "malformed policy JSON"
	}
	if e.Namespace != ns || e.Device != dev {
		return devKey{}, zero, "entry namespace/device disagree with labels"
	}
	return devKey{ns, dev}, e, ""
}

func (p *policyStore) apply(cm *corev1.ConfigMap) {
	key, entry, problem := parsePolicy(cm)
	if problem != "" {
		p.log.Warn("ignoring policy ConfigMap", "configmap", cm.Name, "problem", problem)
		p.remove(cm)
		return
	}
	p.mu.Lock()
	p.byName[cm.Name] = policyItem{key: key, entry: entry}
	p.entries[key] = cm.Name
	p.mu.Unlock()
	p.notify(key.ns, key.device)
}

func (p *policyStore) remove(cm *corev1.ConfigMap) {
	p.mu.Lock()
	it, ok := p.byName[cm.Name]
	if ok {
		delete(p.byName, cm.Name)
		if p.entries[it.key] == cm.Name {
			delete(p.entries, it.key)
		}
	}
	p.mu.Unlock()
	if ok {
		p.notify(it.key.ns, it.key.device)
	}
}

// Get implements PolicySource.
func (p *policyStore) Get(ns, device string) (api.PolicyEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	name, ok := p.entries[devKey{ns, device}]
	if !ok {
		return api.PolicyEntry{}, false
	}
	return p.byName[name].entry, true
}

// Subscribe implements PolicySource.
func (p *policyStore) Subscribe(fn func(ns, device string)) { p.add(fn) }

// HasSynced implements PolicySource.
func (p *policyStore) HasSynced() bool { return p.synced != nil && p.synced() }

// K8sPolicySource is a PolicySource backed by a ConfigMap informer on the hub
// namespace, restricted to ConfigMaps labelled api.PolicyLabel=true.
type K8sPolicySource struct {
	*policyStore
	factory informers.SharedInformerFactory
}

// NewK8sPolicySource creates the source; call Start to run the informer.
func NewK8sPolicySource(cs kubernetes.Interface, hubNamespace string, log *slog.Logger) (*K8sPolicySource, error) {
	store := newPolicyStore(log)
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(hubNamespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = api.PolicyLabel + "=true" }))
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
	return &K8sPolicySource{policyStore: store, factory: factory}, nil
}

// Start runs the informer until ctx is done.
func (p *K8sPolicySource) Start(ctx context.Context) { p.factory.Start(ctx.Done()) }
