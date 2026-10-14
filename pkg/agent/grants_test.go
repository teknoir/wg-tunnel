package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// fakeClock advances a real time.Now reading, so every value keeps Go's
// monotonic clock reading, as the store requires.
type fakeClock struct {
	mu   sync.Mutex
	base time.Time
	off  time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{base: time.Now()} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.off)
}
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.off += d; c.mu.Unlock() }

type hookLog struct {
	mu      sync.Mutex
	events  []string
	failAdd map[string]bool
}

func (h *hookLog) hooks() GrantHooks {
	return GrantHooks{
		Add: func(g api.Grant) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.failAdd[g.PairID] {
				return errors.New("no room")
			}
			h.events = append(h.events, "add "+g.PairID)
			return nil
		},
		Remove: func(g api.Grant) {
			h.mu.Lock()
			h.events = append(h.events, "remove "+g.PairID)
			h.mu.Unlock()
		},
	}
}

func (h *hookLog) take() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := strings.Join(h.events, ",")
	h.events = nil
	return s
}

func testGrant(t testing.TB, id string, n int, services ...string) api.Grant {
	t.Helper()
	_, pub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(services) == 0 {
		services = []string{"ssh"}
	}
	return api.Grant{
		PairID: id, ClientWGPublicKey: pub.Base64(), ClientAddress: fmt.Sprintf("100.97.0.%d", n),
		Services: services, TTLSeconds: 90,
	}
}

func set(inst string, seq uint64, gs ...api.Grant) api.GrantSet {
	return api.GrantSet{HubInstance: inst, Seq: seq, Grants: gs}
}

func newTestStore(clock *fakeClock, h *hookLog) *GrantStore {
	return NewGrantStore(GrantStoreOptions{Hooks: h.hooks(), Now: clock.Now})
}

func mustApply(t *testing.T, s *GrantStore, gs api.GrantSet) ApplyResult {
	t.Helper()
	res, err := s.Apply(gs)
	if err != nil {
		t.Fatalf("Apply(%s/%d): %v", gs.HubInstance, gs.Seq, err)
	}
	return res
}

func TestGrantStoreOrdering(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	a, b := testGrant(t, "pa", 1), testGrant(t, "pb", 2)

	res := mustApply(t, s, set("hub-1", 5, a, b))
	if !slices.Equal(res.Accepted, []string{"pa", "pb"}) || !slices.Equal(res.Added, []string{"pa", "pb"}) {
		t.Fatalf("first set: %+v", res)
	}
	if got := h.take(); got != "add pa,add pb" {
		t.Fatalf("hooks %q", got)
	}

	// Older and equal Seq of the same instance.
	if _, err := s.Apply(set("hub-1", 4, a)); !errors.Is(err, ErrStaleGrantSet) {
		t.Fatalf("older set: %v", err)
	}
	res = mustApply(t, s, set("hub-1", 5, a)) // retry of a lost ack: no change
	if !res.Duplicate || !slices.Equal(res.Accepted, []string{"pa", "pb"}) || h.take() != "" {
		t.Fatalf("duplicate: %+v", res)
	}
	if _, ok := s.Get("pb"); !ok {
		t.Fatal("a duplicate set removed a pair")
	}

	// A newer set without pb removes it.
	res = mustApply(t, s, set("hub-1", 6, a))
	if !slices.Equal(res.Removed, []string{"pb"}) || !slices.Equal(res.Accepted, []string{"pa"}) || h.take() != "remove pb" {
		t.Fatalf("removal: %+v", res)
	}
	// Gaps in Seq are fine.
	mustApply(t, s, set("hub-1", 100, a))
	if in, seq, ok := s.Position(); in != "hub-1" || seq != 100 || !ok {
		t.Fatalf("position %s %d %v", in, seq, ok)
	}
}

func TestGrantStoreTombstones(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	a, b := testGrant(t, "pa", 1), testGrant(t, "pb", 2)
	mustApply(t, s, set("hub-1", 1, a, b))
	mustApply(t, s, set("hub-1", 2, a)) // pb removed
	h.take()

	// A later set (a hub bug, or a stale cache) that lists pb again: refused.
	res := mustApply(t, s, set("hub-1", 3, a, b))
	if why := res.Rejected["pb"]; !strings.Contains(why, "removed") || slices.Contains(res.Accepted, "pb") || h.take() != "" {
		t.Fatalf("tombstoned pair came back: %+v", res)
	}
	// The same key under a NEW pair ID is a new pair and is fine.
	b2 := b
	b2.PairID = "pb2"
	res = mustApply(t, s, set("hub-1", 4, a, b2))
	if !slices.Equal(res.Accepted, []string{"pa", "pb2"}) {
		t.Fatalf("new pair id: %+v", res)
	}

	// Tombstones are forgotten after their TTL.
	clock.Advance(TombstoneTTL + time.Minute)
	a.TTLSeconds, b.TTLSeconds = 90, 90
	res = mustApply(t, s, set("hub-1", 5, a, b))
	if !slices.Contains(res.Added, "pb") {
		t.Fatalf("tombstone never expires: %+v", res)
	}
}

func TestGrantStoreTombstoneBound(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := NewGrantStore(GrantStoreOptions{Hooks: h.hooks(), Now: clock.Now, Tombstones: 3})
	var seq uint64
	for i := range 6 {
		seq++
		mustApply(t, s, set("hub-1", seq, testGrant(t, fmt.Sprintf("p%d", i), 1)))
	}
	seq++
	mustApply(t, s, set("hub-1", seq)) // p5 removed too
	s.mu.Lock()
	n := len(s.tombs)
	s.mu.Unlock()
	if n != 3 {
		t.Fatalf("%d tombstones with a bound of 3", n)
	}
}

func TestGrantStoreHubInstanceChangeDropsEverything(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	a, b := testGrant(t, "pa", 1), testGrant(t, "pb", 2)
	mustApply(t, s, set("hub-1", 50, a, b))
	mustApply(t, s, set("hub-1", 51, a)) // pb tombstoned
	h.take()

	// The new hub numbers from 1 and knows nobody: all old pairs go, and the
	// tombstones go with them (pb may be a fresh pair of the new hub).
	c := testGrant(t, "pc", 3)
	res := mustApply(t, s, set("hub-2", 1, b, c))
	if !res.InstanceChanged || !slices.Equal(res.Removed, []string{"pa"}) || !slices.Equal(res.Accepted, []string{"pb", "pc"}) {
		t.Fatalf("instance change: %+v", res)
	}
	if got := h.take(); got != "remove pa,add pb,add pc" {
		t.Fatalf("hooks %q", got)
	}
	// The old instance's late traffic is now the stale one.
	if _, err := s.Apply(set("hub-1", 99, a)); err != nil {
		t.Fatalf("a set from the previous instance is just another instance change: %v", err)
	}
}

func TestGrantStoreRelativeTTL(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	a := testGrant(t, "pa", 1)
	a.TTLSeconds = 90
	mustApply(t, s, set("hub-1", 1, a))
	clock.Advance(89 * time.Second)
	if !s.Allows("pa", "ssh") {
		t.Fatal("grant expired early")
	}
	// A renewal (newer set listing it) restarts the TTL from receipt.
	res := mustApply(t, s, set("hub-1", 2, a))
	if !slices.Equal(res.Updated, []string{"pa"}) || h.take() != "add pa" {
		t.Fatalf("renewal: %+v", res)
	}
	clock.Advance(89 * time.Second)
	if !s.Allows("pa", "ssh") {
		t.Fatal("renewal did not restart the TTL")
	}
	// Lookups fail closed at expiry, before any Sweep ran.
	clock.Advance(2 * time.Second)
	if s.Allows("pa", "ssh") {
		t.Fatal("expired grant still allowed")
	}
	if _, ok := s.ByClientAddress(netip.MustParseAddr("100.97.0.1")); ok {
		t.Fatal("expired grant found by address")
	}
	if len(s.Snapshot()) != 0 {
		t.Fatal("expired grant in the snapshot")
	}
	if got := s.Sweep(); !slices.Equal(got, []string{"pa"}) || h.take() != "remove pa" {
		t.Fatalf("sweep removed %v", got)
	}
	if got := s.Sweep(); len(got) != 0 {
		t.Fatalf("second sweep removed %v", got)
	}
	// Expiry is not a hub removal: if the hub still lists the pair, it returns.
	res = mustApply(t, s, set("hub-1", 3, a))
	if !slices.Equal(res.Added, []string{"pa"}) {
		t.Fatalf("pair did not come back after expiry: %+v", res)
	}
}

func TestGrantStoreNoRenewalMeansExpiry(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	mustApply(t, s, set("hub-1", 1, testGrant(t, "pa", 1), testGrant(t, "pb", 2)))
	h.take()
	clock.Advance(91 * time.Second) // the hub went away: nothing renews
	// An apply for a newer set drops what already expired, with hooks.
	mustApply(t, s, set("hub-1", 2))
	if got := h.take(); got != "remove pa,remove pb" && got != "remove pb,remove pa" {
		t.Fatalf("hooks %q", got)
	}
}

func TestGrantStoreKeyChangeIsNotAnExtension(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	a := testGrant(t, "pa", 1)
	mustApply(t, s, set("hub-1", 1, a))
	h.take()
	other := testGrant(t, "pa", 1) // same pair ID, new client key
	res := mustApply(t, s, set("hub-1", 2, other))
	if h.take() != "remove pa,add pa" || !slices.Equal(res.Added, []string{"pa"}) || !slices.Equal(res.Removed, []string{"pa"}) {
		t.Fatalf("key change: %+v", res)
	}
	got, _ := s.Get("pa")
	if got.ClientWGPublicKey != other.ClientWGPublicKey {
		t.Fatal("old key still stored")
	}
	// Changing only the services updates in place, with no peer churn.
	other.Services = []string{"ssh", "web"}
	mustApply(t, s, set("hub-1", 3, other))
	if h.take() != "" || !s.Allows("pa", "web") {
		t.Fatal("service change should not touch the peer")
	}
	// ...and narrowing takes effect at once.
	other.Services = []string{"ssh"}
	mustApply(t, s, set("hub-1", 4, other))
	if s.Allows("pa", "web") {
		t.Fatal("removed service still allowed")
	}
}

func TestGrantStoreValidationAndHookRefusal(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{failAdd: map[string]bool{"pfail": true}}
	s := newTestStore(clock, h)
	good := testGrant(t, "pgood", 1)
	badKey := testGrant(t, "pbadkey", 2)
	badKey.ClientWGPublicKey = "not-a-key"
	badAddr := testGrant(t, "pbadaddr", 3)
	badAddr.ClientAddress = "100.96.0.7" // plane A, not B
	noSvc := testGrant(t, "pnosvc", 4)
	noSvc.Services = nil
	badSvc := testGrant(t, "pbadsvc", 5, "Bad Id")
	zeroTTL := testGrant(t, "pzero", 6)
	zeroTTL.TTLSeconds = 0
	hugeTTL := testGrant(t, "phuge", 7)
	hugeTTL.TTLSeconds = 100000
	badID := testGrant(t, "has spaces", 8)
	dupKey := testGrant(t, "pdupkey", 9)
	dupKey.ClientWGPublicKey = good.ClientWGPublicKey
	dupAddr := testGrant(t, "pdupaddr", 1)
	fail := testGrant(t, "pfail", 10)

	res := mustApply(t, s, set("hub-1", 1, good, badKey, badAddr, noSvc, badSvc, zeroTTL, hugeTTL, badID, dupKey, dupAddr, fail))
	if !slices.Equal(res.Accepted, []string{"pgood"}) {
		t.Fatalf("accepted %v (rejected %v)", res.Accepted, res.Rejected)
	}
	for _, id := range []string{"pbadkey", "pbadaddr", "pnosvc", "pbadsvc", "pzero", "phuge", "has spaces", "pdupkey", "pdupaddr", "pfail"} {
		if res.Rejected[id] == "" {
			t.Errorf("%s was not rejected", id)
		}
	}
	if _, err := s.Apply(api.GrantSet{Seq: 2}); err == nil {
		t.Fatal("set without hubInstance accepted")
	}
	tooMany := make([]api.Grant, MaxGrants+1)
	if _, err := s.Apply(set("hub-1", 3, tooMany...)); err == nil {
		t.Fatal("oversized set accepted")
	}
}

func TestGrantStoreDropAllOnSessionEnd(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	mustApply(t, s, set("hub-1", 7, testGrant(t, "pa", 1)))
	h.take()
	if got := s.DropAll(); !slices.Equal(got, []string{"pa"}) || h.take() != "remove pa" {
		t.Fatalf("DropAll %v", got)
	}
	if _, _, ok := s.Position(); ok {
		t.Fatal("position kept after DropAll")
	}
	// A fresh start accepts any Seq again.
	mustApply(t, s, set("hub-1", 1, testGrant(t, "pa", 1)))
}

func TestGrantStoreByClientAddressAndSnapshotAreCopies(t *testing.T) {
	clock, h := newFakeClock(), &hookLog{}
	s := newTestStore(clock, h)
	mustApply(t, s, set("hub-1", 1, testGrant(t, "pa", 1, "ssh", "web")))
	g, ok := s.ByClientAddress(netip.MustParseAddr("100.97.0.1"))
	if !ok || g.PairID != "pa" {
		t.Fatal("not found by address")
	}
	g.Services[0] = "tampered"
	if !s.Allows("pa", "ssh") {
		t.Fatal("caller mutated the store through a returned grant")
	}
}
