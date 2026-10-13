// Package hubtest holds in-memory test doubles for the collaborators of
// pkg/hub (the Kubernetes-backed policy, device flags, identity store and
// SubjectAccessReview), for end-to-end tests outside the hub package.
package hubtest

import (
	"context"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/hub"
)

type key struct{ ns, device string }

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
	fns := append([](func(string, string)){}, s.fns...)
	s.mu.RUnlock()
	for _, fn := range fns {
		fn(ns, device)
	}
}

// Policy is a hub.PolicySource.
type Policy struct {
	subscribers
	mu sync.Mutex
	m  map[key]api.PolicyEntry
}

var _ hub.PolicySource = (*Policy)(nil)

func NewPolicy() *Policy { return &Policy{m: map[key]api.PolicyEntry{}} }

func (p *Policy) Get(ns, device string) (api.PolicyEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[key{ns, device}]
	return e, ok
}
func (p *Policy) Subscribe(fn func(ns, device string)) { p.add(fn) }
func (p *Policy) HasSynced() bool                      { return true }

// Set stores the entry and notifies the hub.
func (p *Policy) Set(e api.PolicyEntry) {
	p.mu.Lock()
	p.m[key{e.Namespace, e.Device}] = e
	p.mu.Unlock()
	p.notify(e.Namespace, e.Device)
}

// Update applies fn to the stored entry of a device and notifies the hub.
func (p *Policy) Update(ns, device string, fn func(*api.PolicyEntry)) {
	p.mu.Lock()
	e := p.m[key{ns, device}]
	fn(&e)
	p.m[key{ns, device}] = e
	p.mu.Unlock()
	p.notify(ns, device)
}

// Approve records the admin-approved identity fingerprint in the policy, the
// way device-controller copies the approved-identity annotation.
func (p *Policy) Approve(ns, device, fingerprint string) {
	p.Update(ns, device, func(e *api.PolicyEntry) { e.ApprovedFingerprint = fingerprint })
}

// Flags is a hub.DeviceFlags (the flags store the flags watcher fills).
type Flags struct {
	subscribers
	mu sync.Mutex
	m  map[key]api.FlagsEntry
}

var _ hub.DeviceFlags = (*Flags)(nil)

func NewFlags() *Flags { return &Flags{m: map[key]api.FlagsEntry{}} }

func (f *Flags) Flags(ns, device string) (api.FlagsEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[key{ns, device}]
	return e, ok
}
func (f *Flags) Subscribe(fn func(ns, device string)) { f.add(fn) }
func (f *Flags) HasSynced() bool                      { return true }

// Set replaces the flags of a device (creating it) from Device annotations,
// the way the flags watcher mirrors them, and notifies the hub.
func (f *Flags) Set(ns, device string, ann map[string]string) {
	f.mu.Lock()
	f.m[key{ns, device}] = api.FlagsEntry{
		Device: device, Namespace: ns, Exists: true,
		WireGuard:         ann[api.AnnotationWireGuard] == "enabled",
		Compromised:       api.FlagSet(ann[api.AnnotationCompromised]),
		HealthCheckFailed: api.FlagSet(ann[api.AnnotationHealthCheckFailed]),
	}
	f.mu.Unlock()
	f.notify(ns, device)
}

// Delete removes the entry (the Device is gone) and notifies the hub.
func (f *Flags) Delete(ns, device string) {
	f.mu.Lock()
	delete(f.m, key{ns, device})
	f.mu.Unlock()
	f.notify(ns, device)
}

// Identity is a hub.IdentityStore.
type Identity struct {
	mu        sync.Mutex
	m         map[key]api.IdentityEntry
	conflicts int
}

var _ hub.IdentityStore = (*Identity)(nil)

func NewIdentity() *Identity { return &Identity{m: map[key]api.IdentityEntry{}} }

func (s *Identity) Get(_ context.Context, ns, device string) (api.IdentityEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key{ns, device}]
	return e, ok, nil
}

func (s *Identity) Pin(_ context.Context, e api.IdentityEntry) (api.IdentityEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{e.Namespace, e.Device}
	if cur, ok := s.m[k]; ok && cur.EnrollmentGeneration == e.EnrollmentGeneration && cur.EnrollmentEpoch == e.EnrollmentEpoch {
		return cur, false, nil
	}
	s.m[k] = e
	return e, true, nil
}

func (s *Identity) Void(_ context.Context, ns, device, reason string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{ns, device}
	cur, ok := s.m[k]
	if !ok || cur.Voided {
		return false, nil
	}
	cur.Voided, cur.VoidedReason, cur.VoidedAt = true, reason, at
	s.m[k] = cur
	return true, nil
}

func (s *Identity) RecordConflict(_ context.Context, ns, device string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{ns, device}
	if cur, ok := s.m[k]; ok {
		cur.Conflicts++
		cur.LastConflictAt = at
		s.m[k] = cur
		s.conflicts++
	}
	return nil
}

// Entry returns the current pin of a device (zero value when none).
func (s *Identity) Entry(ns, device string) api.IdentityEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key{ns, device}]
}

// Authz is a hub.Authorizer (SubjectAccessReview) with switchable answers.
type Authz struct {
	mu      sync.Mutex
	allowed map[string]bool
}

var _ hub.Authorizer = (*Authz)(nil)

func NewAuthz() *Authz { return &Authz{allowed: map[string]bool{}} }

func (a *Authz) CanExec(_ context.Context, email, ns string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.allowed[email+"|"+ns], nil
}

// Set grants or revokes exec access of email in ns.
func (a *Authz) Set(email, ns string, ok bool) {
	a.mu.Lock()
	a.allowed[email+"|"+ns] = ok
	a.mu.Unlock()
}
