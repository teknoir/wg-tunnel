package hub

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

// limiter is a keyed token bucket with a bounded number of keys (LRU
// eviction). It protects the create and enroll endpoints; it is consulted
// before any allocation or backend call.
type limiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	max   int
	ll    *list.List
	m     map[string]*list.Element
	now   func() time.Time
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

func newLimiter(ratePerSec float64, burst, maxKeys int, now func() time.Time) *limiter {
	return &limiter{
		rate: ratePerSec, burst: float64(burst), max: maxKeys,
		ll: list.New(), m: map[string]*list.Element{}, now: now,
	}
}

// Allow takes one token for key. When it refuses, retryAfter is the time until
// a token is available.
func (l *limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	el, found := l.m[key]
	if !found {
		b := &bucket{key: key, tokens: l.burst - 1, last: now}
		l.m[key] = l.ll.PushFront(b)
		for l.ll.Len() > l.max {
			old := l.ll.Back()
			l.ll.Remove(old)
			delete(l.m, old.Value.(*bucket).key)
		}
		return true, 0
	}
	l.ll.MoveToFront(el)
	b := el.Value.(*bucket)
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(l.burst, b.tokens+d*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if l.rate <= 0 {
		return false, time.Minute
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// Forget drops the state of key.
func (l *limiter) Forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.m[key]; ok {
		l.ll.Remove(el)
		delete(l.m, key)
	}
}

// Len returns the number of tracked keys.
func (l *limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}

var (
	errReplay     = errors.New("token replayed")
	errReplayFull = errors.New("replay cache full")
)

// replayCache remembers JWT ids until the token would no longer verify. It is
// bounded: when full of live entries it refuses (fail closed) rather than
// forgetting.
type replayCache struct {
	mu  sync.Mutex
	m   map[string]time.Time
	max int
	now func() time.Time
}

func newReplayCache(max int, now func() time.Time) *replayCache {
	return &replayCache{m: map[string]time.Time{}, max: max, now: now}
}

// Check records key until `until`. It returns errReplay when key is already
// recorded and still live, and errReplayFull when the cache has no room.
func (c *replayCache) Check(key string, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, ok := c.m[key]; ok {
		if now.Before(exp) {
			return errReplay
		}
		delete(c.m, key)
	}
	if len(c.m) >= c.max {
		c.sweepLocked(now)
		if len(c.m) >= c.max {
			return errReplayFull
		}
	}
	c.m[key] = until
	return nil
}

func (c *replayCache) sweepLocked(now time.Time) {
	for k, exp := range c.m {
		if !now.Before(exp) {
			delete(c.m, k)
		}
	}
}

// Sweep removes expired entries.
func (c *replayCache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
}

// Len returns the number of entries.
func (c *replayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
