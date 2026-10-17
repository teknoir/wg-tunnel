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
		OrgKnown:          true, OrgPath: ann[api.AnnotationOrgPath], OrgNodeID: ann[api.AnnotationOrgNodeID],
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

// Org is a hub.OrgSource. A teamspace without a document gets an empty one (no
// members), so tests that ignore the org gate see no restriction; Set installs
// a real document and SetMissing makes the teamspace's document unavailable,
// which denies everyone in it (members and non-members).
type Org struct {
	subscribers
	mu      sync.Mutex
	docs    map[string]api.OrgDoc
	missing map[string]bool
}

var _ hub.OrgSource = (*Org)(nil)

func NewOrg() *Org { return &Org{docs: map[string]api.OrgDoc{}, missing: map[string]bool{}} }

func (o *Org) Doc(ns string) (api.OrgDoc, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.missing[ns] {
		return api.OrgDoc{}, false
	}
	if d, ok := o.docs[ns]; ok {
		return d, true
	}
	return api.OrgDoc{V: api.OrgDocVersion, Namespace: ns, Members: map[string]api.OrgMember{}, Exempt: []string{}}, true
}
func (o *Org) Subscribe(fn func(ns, device string)) { o.add(fn) }
func (o *Org) HasSynced() bool                      { return true }

// Set installs the document of a teamspace and notifies the hub.
func (o *Org) Set(doc api.OrgDoc) {
	o.mu.Lock()
	o.docs[doc.Namespace] = doc
	delete(o.missing, doc.Namespace)
	o.mu.Unlock()
	o.notify(doc.Namespace, "")
}

// SetMissing makes (or stops making) the document of a teamspace unavailable
// and notifies the hub.
func (o *Org) SetMissing(ns string, missing bool) {
	o.mu.Lock()
	o.missing[ns] = missing
	o.mu.Unlock()
	o.notify(ns, "")
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
	var curP *api.IdentityEntry
	cur, ok := s.m[k]
	if ok {
		curP = &cur
	}
	next, same, err := hub.ReplacePin(curP, e)
	if err != nil {
		return api.IdentityEntry{}, false, err
	}
	if same {
		return cur, false, nil
	}
	s.m[k] = next
	return next, true, nil
}

func (s *Identity) Void(_ context.Context, ns, device, reason string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{ns, device}
	cur, ok := s.m[k]
	if !ok || cur.Voided {
		return false, nil
	}
	s.m[k] = hub.VoidEntry(cur, reason, at)
	return true, nil
}

func (s *Identity) Update(_ context.Context, ns, device string, fn func(api.IdentityEntry) *api.IdentityEntry) (api.IdentityEntry, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{ns, device}
	cur, ok := s.m[k]
	if !ok {
		return api.IdentityEntry{}, false, false, nil
	}
	if next := fn(cur); next != nil {
		s.m[k] = *next
		return *next, true, true, nil
	}
	return cur, true, false, nil
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

// SA is a hub.SADelegation (and hub.DelegateVerifier): delegating service
// accounts of the hub namespace, each bound to one device.
type SA struct {
	mu       sync.Mutex
	tokens   map[string]string    // token -> service account name
	bindings map[string][2]string // name -> namespace, device
}

var (
	_ hub.SADelegation     = (*SA)(nil)
	_ hub.DelegateVerifier = (*SA)(nil)
)

func NewSA() *SA { return &SA{tokens: map[string]string{}, bindings: map[string][2]string{}} }

// Add registers a service account token bound to (ns, device).
func (s *SA) Add(token, name, ns, device string) {
	s.mu.Lock()
	s.tokens[token] = name
	s.bindings[name] = [2]string{ns, device}
	s.mu.Unlock()
}

func (s *SA) Verify(ctx context.Context, token, ns, device, onBehalfOf string) (hub.SAIdentity, error) {
	if !hub.ValidEmail(onBehalfOf) {
		return hub.SAIdentity{}, hub.ErrForbidden
	}
	return s.VerifyDelegate(ctx, token, ns, device)
}

func (s *SA) VerifyDelegate(_ context.Context, token, ns, device string) (hub.SAIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := s.tokens[token]
	if !ok {
		return hub.SAIdentity{}, hub.ErrUnauthenticated
	}
	if s.bindings[name] != [2]string{ns, device} {
		return hub.SAIdentity{}, hub.ErrForbidden
	}
	return hub.SAIdentity{Name: name}, nil
}

// StatusAuth is a hub.StatusAuthenticator: bearer tokens of service accounts
// and the usernames the API server would report for them.
type StatusAuth struct {
	mu    sync.Mutex
	users map[string]string
}

var _ hub.StatusAuthenticator = (*StatusAuth)(nil)

func NewStatusAuth() *StatusAuth { return &StatusAuth{users: map[string]string{}} }

// Add registers a token for username.
func (s *StatusAuth) Add(token, username string) {
	s.mu.Lock()
	s.users[token] = username
	s.mu.Unlock()
}

func (s *StatusAuth) Authenticate(_ context.Context, token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[token]; ok {
		return u, nil
	}
	return "", hub.ErrUnauthenticated
}
