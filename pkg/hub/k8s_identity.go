package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// ErrFingerprintVoided is returned by IdentityStore.Pin when the identity to
// pin was voided before (it is in IdentityEntry.VoidedFingerprints, or is the
// fingerprint of the current voided pin). A voided identity is never pinned
// again, in any epoch or generation.
var ErrFingerprintVoided = errors.New("hub: identity fingerprint was voided")

// VoidEntry returns cur marked void, with its fingerprint appended to the
// bounded VoidedFingerprints history.
func VoidEntry(cur api.IdentityEntry, reason string, at time.Time) api.IdentityEntry {
	cur.Voided, cur.VoidedReason, cur.VoidedAt = true, reason, at
	cur.VoidedFingerprints = appendVoided(cur.VoidedFingerprints, cur.Fingerprint)
	cur.DistrustedKeys = distrustedAfterVoid(cur)
	return cur
}

// flagVoid reports whether a pin was voided because the device was flagged
// compromised or failed its health check.
func flagVoid(e api.IdentityEntry) bool {
	return e.Voided && (e.VoidedReason == api.RevokeCompromised || e.VoidedReason == api.RevokeHealthCheckFailed)
}

// distrustedAfterVoid is e's DistrustedKeys, plus the key that attested e when
// e is void for a flag (whoever caused the flag may hold that key). Entries
// voided before DistrustedKeys existed are covered the same way.
func distrustedAfterVoid(e api.IdentityEntry) []string {
	if flagVoid(e) && e.AttestedHostKey != "" {
		return appendBounded(e.DistrustedKeys, e.AttestedHostKey, api.MaxDistrustedKeys)
	}
	return slices.Clone(e.DistrustedKeys)
}

// appendBounded appends v (newest last), drops duplicates and empty values and
// keeps the newest limit. It never modifies list in place.
func appendBounded(list []string, v string, limit int) []string {
	out := make([]string, 0, len(list)+1)
	for _, f := range list {
		if f != v && f != "" {
			out = append(out, f)
		}
	}
	if v != "" {
		out = append(out, v)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// appendVoided appends fp (newest last), drops duplicates and keeps the newest
// api.MaxVoidedFingerprints. It never modifies list in place.
func appendVoided(list []string, fp string) []string {
	return appendBounded(list, fp, api.MaxVoidedFingerprints)
}

// IsVoidedFingerprint reports whether fp was voided according to e: either it
// is in the history, or it is the fingerprint of e itself while e is void
// (entries voided before the history existed).
func IsVoidedFingerprint(e api.IdentityEntry, fp string) bool {
	if fp == "" {
		return false
	}
	if e.Voided && e.Fingerprint == fp {
		return true
	}
	return slices.Contains(e.VoidedFingerprints, fp)
}

// ReplacePin is the Pin policy shared by every IdentityStore (the hub's
// ConfigMap store and the in-memory fakes). cur is the stored entry or nil.
//   - same == true: cur is the pin of the SAME epoch and generation; it stays
//     (first wins per epoch, voided or not).
//   - err == ErrFingerprintVoided: entry carries an identity that was voided
//     before; it is not pinned.
//   - otherwise next is the entry to store: entry, carrying over the voided
//     fingerprint history (including cur's own fingerprint when cur is void)
//     and the conflict history of the device it replaces, and the keys that
//     are distrusted (DistrustedKeys).
func ReplacePin(cur *api.IdentityEntry, entry api.IdentityEntry) (next api.IdentityEntry, same bool, err error) {
	if cur == nil {
		return entry, false, nil
	}
	if cur.EnrollmentGeneration == entry.EnrollmentGeneration && cur.EnrollmentEpoch == entry.EnrollmentEpoch {
		return api.IdentityEntry{}, true, nil
	}
	if IsVoidedFingerprint(*cur, entry.Fingerprint) {
		return api.IdentityEntry{}, false, ErrFingerprintVoided
	}
	next = entry
	history := cur.VoidedFingerprints
	if cur.Voided {
		history = appendVoided(history, cur.Fingerprint)
	}
	var merged []string
	for _, f := range history {
		merged = appendVoided(merged, f)
	}
	for _, f := range entry.VoidedFingerprints {
		merged = appendVoided(merged, f)
	}
	next.VoidedFingerprints = merged
	// The keys whose pins were voided for a flag stay distrusted across pins
	// (cur's own key too when cur is void): a later pin must not make the hub
	// forget them.
	var distrusted []string
	for _, k := range distrustedAfterVoid(*cur) {
		distrusted = appendBounded(distrusted, k, api.MaxDistrustedKeys)
	}
	for _, k := range entry.DistrustedKeys {
		distrusted = appendBounded(distrusted, k, api.MaxDistrustedKeys)
	}
	next.DistrustedKeys = distrusted
	next.Conflicts = cur.Conflicts + entry.Conflicts
	next.LastConflictAt = cur.LastConflictAt
	if entry.LastConflictAt.After(next.LastConflictAt) {
		next.LastConflictAt = entry.LastConflictAt
	}
	return next, false, nil
}

// Pin implements IdentityStore. An existing pin of the SAME enrollment epoch
// and generation is never replaced (first wins per epoch, voided or not); a pin
// of any other epoch or generation is void and is replaced, carrying over the
// voided fingerprint and conflict history. A voided identity is refused with
// ErrFingerprintVoided.
func (s *K8sIdentityStore) Pin(ctx context.Context, entry api.IdentityEntry) (api.IdentityEntry, bool, error) {
	if !validLabel(entry.Namespace) || !validLabel(entry.Device) {
		return api.IdentityEntry{}, false, errors.New("hub: invalid identity entry")
	}
	current := entry
	var refused error
	wrote, err := s.mutate(ctx, entry.Namespace, entry.Device, func(cur *api.IdentityEntry) *api.IdentityEntry {
		next, same, err := ReplacePin(cur, entry)
		if err != nil {
			refused = err
			return nil
		}
		if same {
			current = *cur
			return nil
		}
		current = next
		return &next
	})
	if refused != nil {
		return api.IdentityEntry{}, false, refused
	}
	if err != nil {
		return api.IdentityEntry{}, false, err
	}
	return current, wrote, nil
}

// Update implements IdentityStore.
func (s *K8sIdentityStore) Update(ctx context.Context, ns, device string, fn func(cur api.IdentityEntry) *api.IdentityEntry) (api.IdentityEntry, bool, bool, error) {
	if !validLabel(ns) || !validLabel(device) {
		return api.IdentityEntry{}, false, false, errors.New("hub: invalid identity entry")
	}
	var current api.IdentityEntry
	found := false
	wrote, err := s.mutate(ctx, ns, device, func(cur *api.IdentityEntry) *api.IdentityEntry {
		if cur == nil {
			found, current = false, api.IdentityEntry{}
			return nil
		}
		found, current = true, *cur
		next := fn(*cur)
		if next == nil {
			return nil
		}
		current = *next
		return next
	})
	if err != nil {
		return api.IdentityEntry{}, false, false, err
	}
	return current, found, wrote, nil
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
		next := VoidEntry(*cur, reason, at)
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
