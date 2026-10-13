package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

const identityRetries = 8

// K8sIdentityStore keeps the TOFU pins in ConfigMaps of the hub namespace
// (api.IdentityConfigMapName, labelled api.IdentityLabel=true plus the
// teamspace and device labels). Writes use optimistic concurrency: a conflict
// re-reads and retries, so two concurrent enrollments cannot both win.
type K8sIdentityStore struct {
	cs kubernetes.Interface
	ns string
}

var _ IdentityStore = (*K8sIdentityStore)(nil)

// NewK8sIdentityStore returns a store writing into hubNamespace.
func NewK8sIdentityStore(cs kubernetes.Interface, hubNamespace string) *K8sIdentityStore {
	return &K8sIdentityStore{cs: cs, ns: hubNamespace}
}

func (s *K8sIdentityStore) decode(cm *corev1.ConfigMap, ns, device string) (api.IdentityEntry, error) {
	var e api.IdentityEntry
	raw, ok := cm.Data[api.IdentityDataKey]
	if !ok {
		return e, fmt.Errorf("identity ConfigMap %s has no %s", cm.Name, api.IdentityDataKey)
	}
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return e, fmt.Errorf("identity ConfigMap %s is malformed", cm.Name)
	}
	if e.Namespace != ns || e.Device != device {
		return e, fmt.Errorf("identity ConfigMap %s belongs to another device", cm.Name)
	}
	return e, nil
}

// Get implements IdentityStore. A ConfigMap that cannot be trusted is an error
// (the hub then refuses the request), never "no pin".
func (s *K8sIdentityStore) Get(ctx context.Context, ns, device string) (api.IdentityEntry, bool, error) {
	cm, err := s.cs.CoreV1().ConfigMaps(s.ns).Get(ctx, api.IdentityConfigMapName(ns, device), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return api.IdentityEntry{}, false, nil
	}
	if err != nil {
		return api.IdentityEntry{}, false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	e, err := s.decode(cm, ns, device)
	if err != nil {
		return api.IdentityEntry{}, false, err
	}
	return e, true, nil
}

// mutate applies fn to the current entry with optimistic concurrency. fn
// returns the entry to write, or nil to leave things as they are.
func (s *K8sIdentityStore) mutate(ctx context.Context, ns, device string, fn func(cur *api.IdentityEntry) *api.IdentityEntry) (wrote bool, err error) {
	name := api.IdentityConfigMapName(ns, device)
	cms := s.cs.CoreV1().ConfigMaps(s.ns)
	for range identityRetries {
		cm, err := cms.Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			next := fn(nil)
			if next == nil {
				return false, nil
			}
			obj, err := s.build(name, ns, device, *next, nil)
			if err != nil {
				return false, err
			}
			if _, err := cms.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				if apierrors.IsAlreadyExists(err) {
					continue
				}
				return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			return true, nil
		case err != nil:
			return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		cur, derr := s.decode(cm, ns, device)
		if derr != nil {
			return false, derr // never overwrite a pin that cannot be read
		}
		next := fn(&cur)
		if next == nil {
			return false, nil
		}
		obj, err := s.build(name, ns, device, *next, cm)
		if err != nil {
			return false, err
		}
		if _, err := cms.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: identity update kept conflicting", ErrUnavailable)
}

func (s *K8sIdentityStore) build(name, ns, device string, e api.IdentityEntry, prev *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	e.Namespace, e.Device = ns, device
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var cm *corev1.ConfigMap
	if prev != nil {
		cm = prev.DeepCopy() // keeps the resourceVersion for the optimistic update
	} else {
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.ns}}
	}
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	cm.Labels[api.IdentityLabel] = "true"
	cm.Labels[api.PolicyTeamspaceLabel] = ns
	cm.Labels[api.PolicyDeviceLabel] = device
	cm.Data = map[string]string{api.IdentityDataKey: string(raw)}
	return cm, nil
}

// Pin implements IdentityStore. An existing pin of the SAME enrollment epoch
// and generation is never replaced (first wins per epoch, voided or not); a pin
// of any other epoch or generation is void and is replaced.
func (s *K8sIdentityStore) Pin(ctx context.Context, entry api.IdentityEntry) (api.IdentityEntry, bool, error) {
	if !validLabel(entry.Namespace) || !validLabel(entry.Device) {
		return api.IdentityEntry{}, false, errors.New("hub: invalid identity entry")
	}
	current := entry
	wrote, err := s.mutate(ctx, entry.Namespace, entry.Device, func(cur *api.IdentityEntry) *api.IdentityEntry {
		if cur != nil && cur.EnrollmentGeneration == entry.EnrollmentGeneration && cur.EnrollmentEpoch == entry.EnrollmentEpoch {
			current = *cur
			return nil
		}
		current = entry
		return &entry
	})
	if err != nil {
		return api.IdentityEntry{}, false, err
	}
	return current, wrote, nil
}

// Void implements IdentityStore.
func (s *K8sIdentityStore) Void(ctx context.Context, ns, device, reason string, at time.Time) (bool, error) {
	if !validLabel(ns) || !validLabel(device) {
		return false, errors.New("hub: invalid identity entry")
	}
	return s.mutate(ctx, ns, device, func(cur *api.IdentityEntry) *api.IdentityEntry {
		if cur == nil || cur.Voided {
			return nil // nothing pinned, or already void
		}
		next := *cur
		next.Voided, next.VoidedReason, next.VoidedAt = true, reason, at
		return &next
	})
}

// RecordConflict implements IdentityStore.
func (s *K8sIdentityStore) RecordConflict(ctx context.Context, ns, device string, at time.Time) error {
	_, err := s.mutate(ctx, ns, device, func(cur *api.IdentityEntry) *api.IdentityEntry {
		if cur == nil {
			return nil // nothing is pinned, so there is nothing to conflict with
		}
		next := *cur
		next.Conflicts++
		next.LastConflictAt = at
		return &next
	})
	return err
}
