package hub

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestLimiterBurstRefillAndKeys(t *testing.T) {
	clock := newFakeClock()
	l := newLimiter(1, 3, 100, clock.Now)
	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("burst request %d refused", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Second {
		t.Fatalf("4th request: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("keys must be independent")
	}
	clock.Advance(1100 * time.Millisecond)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("token should have refilled")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestLimiterBoundedKeys(t *testing.T) {
	clock := newFakeClock()
	l := newLimiter(1, 1, 10, clock.Now)
	for i := range 100 {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if l.Len() != 10 {
		t.Fatalf("limiter tracks %d keys, want 10", l.Len())
	}
}

func TestReplayCache(t *testing.T) {
	clock := newFakeClock()
	c := newReplayCache(3, clock.Now)
	exp := clock.Now().Add(time.Minute)
	if err := c.Check("a", exp); err != nil {
		t.Fatal(err)
	}
	if err := c.Check("a", exp); !errors.Is(err, errReplay) {
		t.Fatalf("replay not detected: %v", err)
	}
	_ = c.Check("b", exp)
	_ = c.Check("c", exp)
	if err := c.Check("d", exp); !errors.Is(err, errReplayFull) {
		t.Fatalf("a full cache of live entries must refuse, got %v", err)
	}
	clock.Advance(2 * time.Minute)
	if err := c.Check("d", clock.Now().Add(time.Minute)); err != nil {
		t.Fatalf("expired entries must be reclaimed: %v", err)
	}
	if err := c.Check("a", clock.Now().Add(time.Minute)); err != nil {
		t.Fatalf("an expired jti may be recorded again: %v", err)
	}
	if c.Len() > 3 {
		t.Fatalf("cache exceeds its bound: %d", c.Len())
	}
}

type countingAuthz struct {
	allow bool
	err   error
	calls int
}

func (c *countingAuthz) CanExec(context.Context, string, string) (bool, error) {
	c.calls++
	return c.allow, c.err
}

func TestCachedAuthorizer(t *testing.T) {
	clock := newFakeClock()
	inner := &countingAuthz{allow: true}
	c := newCachedAuthorizer(inner, 5*time.Second, 2, clock.Now)
	ctx := context.Background()

	for range 3 {
		if ok, err := c.CanExec(ctx, "a@x", "ns"); !ok || err != nil {
			t.Fatalf("got %v %v", ok, err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("answers not cached: %d calls", inner.calls)
	}
	// A deny is cached too, but only for the TTL.
	inner.allow = false
	if ok, _ := c.CanExec(ctx, "a@x", "ns"); !ok {
		t.Fatal("cached allow expected within TTL")
	}
	clock.Advance(5*time.Second + time.Millisecond)
	if ok, _ := c.CanExec(ctx, "a@x", "ns"); ok {
		t.Fatal("expired entry must be re-evaluated")
	}
	before := inner.calls
	if ok, _ := c.CanExec(ctx, "a@x", "ns"); ok || inner.calls != before {
		t.Fatalf("deny must be cached (calls %d -> %d)", before, inner.calls)
	}
	// Keys are (user, namespace).
	_, _ = c.CanExec(ctx, "a@x", "other")
	if inner.calls != before+1 {
		t.Fatal("different namespace must not share the entry")
	}
	// Bounded.
	_, _ = c.CanExec(ctx, "b@x", "ns")
	_, _ = c.CanExec(ctx, "c@x", "ns")
	if c.Len() != 2 {
		t.Fatalf("cache holds %d entries, want 2", c.Len())
	}
}

func TestCachedAuthorizerErrorsDenyAndAreNotCached(t *testing.T) {
	clock := newFakeClock()
	inner := &countingAuthz{allow: true, err: errors.New("api down")}
	c := newCachedAuthorizer(inner, 5*time.Second, 10, clock.Now)
	ctx := context.Background()
	if ok, err := c.CanExec(ctx, "a@x", "ns"); ok || err == nil {
		t.Fatalf("error must deny: %v %v", ok, err)
	}
	inner.err = nil
	if ok, err := c.CanExec(ctx, "a@x", "ns"); !ok || err != nil {
		t.Fatalf("error must not be cached: %v %v", ok, err)
	}
}
