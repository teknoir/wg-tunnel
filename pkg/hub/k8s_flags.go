package hub

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/tools/cache"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// DeviceGVR is the Device custom resource.
var DeviceGVR = schema.GroupVersionResource{Group: "teknoir.org", Version: "v1", Resource: "devices"}

var relevantAnnotations = []string{
	api.AnnotationWireGuard, api.AnnotationCompromised, api.AnnotationHealthCheckFailed,
	api.AnnotationReason, api.AnnotationReenroll,
}

// flagStore keeps the relevant annotations of every Device.
type flagStore struct {
	subscribers
	mu     sync.RWMutex
	m      map[devKey]map[string]string
	synced func() bool
}

func newFlagStore() *flagStore { return &flagStore{m: map[devKey]map[string]string{}} }

func pickAnnotations(in map[string]string) map[string]string {
	out := make(map[string]string, len(relevantAnnotations))
	for _, k := range relevantAnnotations {
		if v, ok := in[k]; ok {
			out[k] = v
		}
	}
	return out
}

func sameAnnotations(a, b map[string]string) bool {
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

func (f *flagStore) apply(obj *metav1.PartialObjectMetadata) {
	key := devKey{obj.Namespace, obj.Name}
	ann := pickAnnotations(obj.Annotations)
	f.mu.Lock()
	old, existed := f.m[key]
	f.m[key] = ann
	f.mu.Unlock()
	if !existed || !sameAnnotations(old, ann) {
		f.notify(key.ns, key.device)
	}
}

func (f *flagStore) remove(obj *metav1.PartialObjectMetadata) {
	key := devKey{obj.Namespace, obj.Name}
	f.mu.Lock()
	_, existed := f.m[key]
	delete(f.m, key)
	f.mu.Unlock()
	if existed {
		f.notify(key.ns, key.device)
	}
}

// Annotations implements DeviceFlags.
func (f *flagStore) Annotations(ns, device string) (map[string]string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	a, ok := f.m[devKey{ns, device}]
	return a, ok // never mutated after being stored
}

// Subscribe implements DeviceFlags.
func (f *flagStore) Subscribe(fn func(ns, device string)) { f.add(fn) }

// HasSynced implements DeviceFlags.
func (f *flagStore) HasSynced() bool { return f.synced != nil && f.synced() }

// K8sDeviceFlags is a DeviceFlags backed by a metadata-only informer on the
// Device resource in all namespaces: the hub never receives device specs
// (which hold private keys), only names and annotations.
type K8sDeviceFlags struct {
	*flagStore
	informer cache.SharedIndexInformer
}

// NewK8sDeviceFlags creates the source; call Start to run the informer.
func NewK8sDeviceFlags(mc metadata.Interface) (*K8sDeviceFlags, error) {
	return newK8sDeviceFlags(metadatainformer.NewFilteredMetadataInformer(mc, DeviceGVR, metav1.NamespaceAll, 0, cache.Indexers{}, nil).Informer())
}

func newK8sDeviceFlags(inf cache.SharedIndexInformer) (*K8sDeviceFlags, error) {
	store := newFlagStore()
	reg, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(o any) {
			if m, ok := o.(*metav1.PartialObjectMetadata); ok {
				store.apply(m)
			}
		},
		UpdateFunc: func(_, o any) {
			if m, ok := o.(*metav1.PartialObjectMetadata); ok {
				store.apply(m)
			}
		},
		DeleteFunc: func(o any) {
			if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
				o = t.Obj
			}
			if m, ok := o.(*metav1.PartialObjectMetadata); ok {
				store.remove(m)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	store.synced = reg.HasSynced
	return &K8sDeviceFlags{flagStore: store, informer: inf}, nil
}

// Start runs the informer until ctx is done.
func (f *K8sDeviceFlags) Start(ctx context.Context) { go f.informer.Run(ctx.Done()) }
