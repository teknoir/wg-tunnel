package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Limits of the grant store.
const (
	// MaxGrants bounds the live pairs of one device.
	MaxGrants = 64
	// MaxGrantTTL bounds Grant.TTLSeconds (the contract default is
	// api.DefaultGrantTTL; the hub renews every 60 s).
	MaxGrantTTL = 600
	// MaxTombstones bounds the remembered removed pair IDs; the oldest are
	// forgotten first.
	MaxTombstones = 1024
	// TombstoneTTL is how long a removed pair ID stays refused.
	TombstoneTTL = time.Hour
	maxIDLen     = 64
)

var pairIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ErrStaleGrantSet is returned for a grant set whose (HubInstance, Seq) is
// older than the last one applied.
var ErrStaleGrantSet = errors.New("stale grant set")

// GrantHooks connect the store to the plane-B WireGuard device (wave B).
// They are called with the store locked and must not call back into it.
type GrantHooks struct {
	// Add installs the peer of g (allowed_ip = ClientAddress/32). A non-nil
	// error refuses the grant: it is not stored and not acknowledged.
	Add func(g api.Grant) error
	// Remove uninstalls the peer of g. It is called for every end of a live
	// grant: removed by the hub, expired, replaced by a different key or
	// address, dropped by a hub instance change or by DropAll.
	Remove func(g api.Grant)
}

// GrantStoreOptions configures a GrantStore. Zero values select the defaults.
type GrantStoreOptions struct {
	Hooks GrantHooks
	// Now is the clock. It MUST return readings that carry Go's monotonic
	// clock (time.Now does): grants expire relative to receipt, on the agent's
	// own monotonic clock, never against wall-clock time (device clocks are
	// not trusted and may step). Tests pass a fake that advances a time.Now
	// reading.
	Now          func() time.Time
	MaxGrants    int
	MaxTTL       time.Duration
	Tombstones   int
	TombstoneTTL time.Duration
}

type grantEntry struct {
	g       api.Grant
	expires time.Time
}

// GrantStore holds the plane-B grants the hub pushed to this device. It
// implements the ordering rules of the contract:
//
//   - a GrantSet is the full desired list, applied only if (HubInstance, Seq)
//     is newer than the last applied set (the same Seq again is a harmless
//     duplicate, an older one is ErrStaleGrantSet);
//   - a changed HubInstance drops every pair first (a restarted hub numbers
//     from scratch and knows none of the old pairs);
//   - a pair that was live and is absent from a newer set is removed and
//     tombstoned: its ID is refused from then on;
//   - every grant carries a relative TTL, restarted by every set that lists it
//     and enforced lazily on every lookup and eagerly by Sweep.
//
// It is safe for concurrent use.
type GrantStore struct {
	opts GrantStoreOptions

	mu       sync.Mutex
	instance string
	seq      uint64
	haveSeq  bool
	grants   map[string]*grantEntry
	tombs    map[string]time.Time // pair ID -> forget-after
	tombSeq  []string             // insertion order, for eviction
}

// NewGrantStore returns an empty store.
func NewGrantStore(opts GrantStoreOptions) *GrantStore {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxGrants <= 0 {
		opts.MaxGrants = MaxGrants
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = MaxGrantTTL * time.Second
	}
	if opts.Tombstones <= 0 {
		opts.Tombstones = MaxTombstones
	}
	if opts.TombstoneTTL <= 0 {
		opts.TombstoneTTL = TombstoneTTL
	}
	return &GrantStore{opts: opts, grants: map[string]*grantEntry{}, tombs: map[string]time.Time{}}
}

// ApplyResult describes what Apply did. The lists are sorted.
type ApplyResult struct {
	// Duplicate is true when the set repeated the last applied Seq: nothing
	// changed and Accepted is the current live list.
	Duplicate bool
	// InstanceChanged is true when every earlier pair was dropped first.
	InstanceChanged bool
	// Accepted are the live pair IDs after the set (what the GrantAck lists).
	Accepted []string
	Added    []string
	Updated  []string
	Removed  []string
	// Rejected maps the pair IDs the store refused to the reason.
	Rejected map[string]string
}

// Apply applies a grant set.
func (s *GrantStore) Apply(set api.GrantSet) (ApplyResult, error) {
	if set.HubInstance == "" || len(set.HubInstance) > maxIDLen {
		return ApplyResult{}, errors.New("grant set: invalid hubInstance")
	}
	if len(set.Grants) > s.opts.MaxGrants {
		return ApplyResult{}, fmt.Errorf("grant set: more than %d grants", s.opts.MaxGrants)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	s.expireLocked(now)
	s.forgetTombsLocked(now)

	var res ApplyResult
	switch {
	case !s.haveSeq || set.HubInstance != s.instance:
		if s.haveSeq {
			res.InstanceChanged = true
		}
		res.Removed = append(res.Removed, s.dropAllLocked()...)
		clear(s.tombs)
		s.tombSeq = nil
		s.instance = set.HubInstance
	case set.Seq < s.seq:
		return ApplyResult{}, ErrStaleGrantSet
	case set.Seq == s.seq:
		res.Duplicate = true
		res.Accepted = s.liveIDsLocked()
		return res, nil
	}
	s.seq, s.haveSeq = set.Seq, true

	desired := make(map[string]struct{}, len(set.Grants))
	keys := map[string]string{}  // client key -> pair
	addrs := map[string]string{} // client address -> pair
	rejected := map[string]string{}
	reject := func(id, why string) {
		if id == "" {
			id = "(no id)"
		}
		rejected[id] = why
	}
	type item struct {
		g   api.Grant
		ttl time.Duration
	}
	var items []item
	for _, g := range set.Grants {
		ttl, err := s.validateGrant(g)
		switch {
		case err != nil:
			reject(g.PairID, err.Error())
			continue
		case s.tombs[g.PairID].After(now):
			reject(g.PairID, "pair was removed")
			continue
		}
		if _, dup := desired[g.PairID]; dup {
			reject(g.PairID, "duplicate pair id in the set")
			continue
		}
		if other, dup := keys[g.ClientWGPublicKey]; dup {
			reject(g.PairID, "client key already used by pair "+other)
			continue
		}
		if other, dup := addrs[g.ClientAddress]; dup {
			reject(g.PairID, "client address already used by pair "+other)
			continue
		}
		desired[g.PairID] = struct{}{}
		keys[g.ClientWGPublicKey], addrs[g.ClientAddress] = g.PairID, g.PairID
		items = append(items, item{g, ttl})
	}

	// Pairs the hub no longer lists are gone for good.
	for id, e := range s.grants {
		if _, keep := desired[id]; !keep {
			s.removeLocked(id, e, now, true)
			res.Removed = append(res.Removed, id)
		}
	}
	for _, it := range items {
		g := it.g
		g.Services = slices.Clone(g.Services)
		g.ClientCandidates = slices.Clone(g.ClientCandidates)
		if old, ok := s.grants[g.PairID]; ok {
			if old.g.ClientWGPublicKey != g.ClientWGPublicKey || old.g.ClientAddress != g.ClientAddress {
				// A different peer: not an extension.
				s.removeLocked(g.PairID, old, now, false)
				res.Removed = append(res.Removed, g.PairID)
				if why := s.addLocked(g, now.Add(it.ttl)); why != "" {
					reject(g.PairID, why)
					continue
				}
				res.Added = append(res.Added, g.PairID)
				continue
			}
			old.g, old.expires = g, now.Add(it.ttl)
			res.Updated = append(res.Updated, g.PairID)
			continue
		}
		if len(s.grants) >= s.opts.MaxGrants {
			reject(g.PairID, "too many live grants")
			continue
		}
		if why := s.addLocked(g, now.Add(it.ttl)); why != "" {
			reject(g.PairID, why)
			continue
		}
		res.Added = append(res.Added, g.PairID)
	}
	if len(rejected) > 0 {
		res.Rejected = rejected
	}
	res.Accepted = s.liveIDsLocked()
	slices.Sort(res.Added)
	slices.Sort(res.Updated)
	slices.Sort(res.Removed)
	return res, nil
}

func (s *GrantStore) addLocked(g api.Grant, expires time.Time) string {
	if s.opts.Hooks.Add != nil {
		if err := s.opts.Hooks.Add(g); err != nil {
			return "peer not installed: " + err.Error()
		}
	}
	s.grants[g.PairID] = &grantEntry{g: g, expires: expires}
	return ""
}

// removeLocked ends a live grant; tomb remembers its ID as removed by the hub.
func (s *GrantStore) removeLocked(id string, e *grantEntry, now time.Time, tomb bool) {
	delete(s.grants, id)
	if s.opts.Hooks.Remove != nil {
		s.opts.Hooks.Remove(e.g)
	}
	if !tomb {
		return
	}
	if _, ok := s.tombs[id]; !ok {
		s.tombSeq = append(s.tombSeq, id)
	}
	s.tombs[id] = now.Add(s.opts.TombstoneTTL)
	for len(s.tombSeq) > s.opts.Tombstones {
		delete(s.tombs, s.tombSeq[0])
		s.tombSeq = s.tombSeq[1:]
	}
}

func (s *GrantStore) dropAllLocked() []string {
	ids := make([]string, 0, len(s.grants))
	for id, e := range s.grants {
		ids = append(ids, id)
		delete(s.grants, id)
		if s.opts.Hooks.Remove != nil {
			s.opts.Hooks.Remove(e.g)
		}
	}
	slices.Sort(ids)
	return ids
}

func (s *GrantStore) forgetTombsLocked(now time.Time) {
	kept := s.tombSeq[:0]
	for _, id := range s.tombSeq {
		if exp, ok := s.tombs[id]; ok {
			if exp.After(now) {
				kept = append(kept, id)
			} else {
				delete(s.tombs, id)
			}
		}
	}
	s.tombSeq = kept
}

func (s *GrantStore) expireLocked(now time.Time) []string {
	var gone []string
	for id, e := range s.grants {
		if !now.Before(e.expires) {
			delete(s.grants, id)
			if s.opts.Hooks.Remove != nil {
				s.opts.Hooks.Remove(e.g)
			}
			gone = append(gone, id)
		}
	}
	slices.Sort(gone)
	return gone
}

func (s *GrantStore) liveIDsLocked() []string {
	now := s.opts.Now()
	ids := make([]string, 0, len(s.grants))
	for id, e := range s.grants {
		if now.Before(e.expires) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

var p2pPrefix = netip.MustParsePrefix(api.P2PPrefix)

func (s *GrantStore) validateGrant(g api.Grant) (time.Duration, error) {
	if !pairIDRE.MatchString(g.PairID) {
		return 0, errors.New("invalid pair id")
	}
	if _, err := wgkey.ParsePublic(g.ClientWGPublicKey); err != nil {
		return 0, errors.New("invalid client WireGuard key")
	}
	a, err := netip.ParseAddr(g.ClientAddress)
	if err != nil || !a.Is4() || !p2pPrefix.Contains(a) {
		return 0, errors.New("client address is not in the plane-B network")
	}
	if len(g.Services) == 0 || len(g.Services) > api.MaxServices {
		return 0, errors.New("a grant needs between 1 and " + fmt.Sprint(api.MaxServices) + " services")
	}
	for _, id := range g.Services {
		if !svc.ValidID(id) {
			return 0, errors.New("invalid service id")
		}
	}
	if len(g.ClientCandidates) > api.MaxP2PCandidates {
		return 0, errors.New("too many candidates")
	}
	ttl := time.Duration(g.TTLSeconds) * time.Second
	if g.TTLSeconds <= 0 || ttl > s.opts.MaxTTL {
		return 0, errors.New("ttlSeconds out of range")
	}
	return ttl, nil
}

// Sweep removes expired grants and returns their pair IDs. It is cheap; the
// agent calls it about once a second, but lookups never rely on it.
func (s *GrantStore) Sweep() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	s.forgetTombsLocked(now)
	return s.expireLocked(now)
}

// DropAll removes every grant (the agent's plane-A session ended) and
// forgets the hub instance. It returns the removed pair IDs.
func (s *GrantStore) DropAll() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := s.dropAllLocked()
	clear(s.tombs)
	s.tombSeq = nil
	s.instance, s.seq, s.haveSeq = "", 0, false
	return ids
}

// Get returns a live grant.
func (s *GrantStore) Get(pairID string) (api.Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.grants[pairID]
	if !ok || !s.opts.Now().Before(e.expires) {
		return api.Grant{}, false
	}
	return cloneGrant(e.g), true
}

// ByClientAddress returns the live grant of the plane-B client address.
func (s *GrantStore) ByClientAddress(addr netip.Addr) (api.Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	for _, e := range s.grants {
		if e.g.ClientAddress == addr.Unmap().String() && now.Before(e.expires) {
			return cloneGrant(e.g), true
		}
	}
	return api.Grant{}, false
}

// Allows reports whether pairID is live and may reach the service.
func (s *GrantStore) Allows(pairID, service string) bool {
	g, ok := s.Get(pairID)
	return ok && slices.Contains(g.Services, service)
}

// Snapshot returns the live grants, sorted by pair ID.
func (s *GrantStore) Snapshot() []api.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	var out []api.Grant
	for _, e := range s.grants {
		if now.Before(e.expires) {
			out = append(out, cloneGrant(e.g))
		}
	}
	slices.SortFunc(out, func(a, b api.Grant) int {
		switch {
		case a.PairID < b.PairID:
			return -1
		case a.PairID > b.PairID:
			return 1
		}
		return 0
	})
	return out
}

// Position returns the (hubInstance, seq) of the last applied set.
func (s *GrantStore) Position() (instance string, seq uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.instance, s.seq, s.haveSeq
}

func cloneGrant(g api.Grant) api.Grant {
	g.Services = slices.Clone(g.Services)
	g.ClientCandidates = slices.Clone(g.ClientCandidates)
	return g
}
