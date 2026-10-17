package hub

import (
	"context"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// orgStore holds the parsed org ConfigMaps. A ConfigMap that fails the strict
// parse is treated as absent.
type orgStore struct {
	subscribers
	log *slog.Logger

	mu     sync.RWMutex
	byName map[string]string // ConfigMap name -> teamspace
	docs   map[string]api.OrgDoc
	synced func() bool
}

func newOrgStore(log *slog.Logger) *orgStore {
	return &orgStore{log: log, byName: map[string]string{}, docs: map[string]api.OrgDoc{}}
}

func (s *orgStore) apply(cm *corev1.ConfigMap) {
	doc, problem := ParseOrgConfigMap(cm)
	if problem != "" {
		s.log.Warn("ignoring org ConfigMap", "configmap", cm.Name, "problem", problem)
		s.remove(cm)
		return
	}
	s.mu.Lock()
	s.byName[cm.Name] = doc.Namespace
	s.docs[doc.Namespace] = doc
	s.mu.Unlock()
	s.notify(doc.Namespace, "")
}

func (s *orgStore) remove(cm *corev1.ConfigMap) {
	s.mu.Lock()
	ns, ok := s.byName[cm.Name]
	if ok {
		delete(s.byName, cm.Name)
		delete(s.docs, ns)
	}
	s.mu.Unlock()
	if ok {
		s.notify(ns, "")
	}
}

// Doc implements OrgSource.
func (s *orgStore) Doc(ns string) (api.OrgDoc, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.docs[ns]
	return d, ok
}

// Subscribe implements OrgSource.
func (s *orgStore) Subscribe(fn func(ns, device string)) { s.add(fn) }

// HasSynced implements OrgSource.
func (s *orgStore) HasSynced() bool { return s.synced != nil && s.synced() }

// K8sOrgSource is an OrgSource backed by a ConfigMap informer on the hub
// namespace, restricted to ConfigMaps labelled api.OrgLabel=true.
type K8sOrgSource struct {
	*orgStore
	factory informers.SharedInformerFactory
}

// NewK8sOrgSource creates the source; call Start to run the informer.
func NewK8sOrgSource(cs kubernetes.Interface, hubNamespace string, log *slog.Logger) (*K8sOrgSource, error) {
	store := newOrgStore(log)
	factory := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithNamespace(hubNamespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = api.OrgLabel + "=true" }))
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
	return &K8sOrgSource{orgStore: store, factory: factory}, nil
}

// Start runs the informer until ctx is done.
func (s *K8sOrgSource) Start(ctx context.Context) { s.factory.Start(ctx.Done()) }
