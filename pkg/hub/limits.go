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
// partitioned per subject: one subject can neither fill the cache nor evict the
// entries of another. It is bounded twice (per subject and overall); when a
// bound is hit with live entries it refuses (fail closed) rather than
// forgetting.
type replayCache struct {
	mu         sync.Mutex
	m          map[string]map[string]time.Time // subject -> jti -> valid until
	total      int
	max        int
	maxSubject int
	now        func() time.Time
}

func newReplayCache(max, maxPerSubject int, now func() time.Time) *replayCache {
	if maxPerSubject <= 0 || maxPerSubject > max {
		maxPerSubject = max
	}
	return &replayCache{m: map[string]map[string]time.Time{}, max: max, maxSubject: maxPerSubject, now: now}
}

// Check records id of subject until `until`. It returns errReplay when the id
// is already recorded and still live, and errReplayFull when the subject's
// partition (or the whole cache) has no room.
func (c *replayCache) Check(subject, id string, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	part := c.m[subject]
	if exp, ok := part[id]; ok {
		if now.Before(exp) {
			return errReplay
		}
		delete(part, id)
		c.total--
	}
	if len(part) >= c.maxSubject {
		c.sweepSubjectLocked(subject, now)
		part = c.m[subject]
		if len(part) >= c.maxSubject {
			return errReplayFull
		}
	}
	if c.total >= c.max {
		c.sweepLocked(now)
		part = c.m[subject]
		if c.total >= c.max {
			return errReplayFull
		}
	}
	if part == nil {
		part = map[string]time.Time{}
		c.m[subject] = part
	}
	part[id] = until
	c.total++
	return nil
}

func (c *replayCache) sweepSubjectLocked(subject string, now time.Time) {
	part := c.m[subject]
	for id, exp := range part {
		if !now.Before(exp) {
			delete(part, id)
			c.total--
		}
	}
	if len(part) == 0 {
		delete(c.m, subject)
	}
}

func (c *replayCache) sweepLocked(now time.Time) {
	for subject := range c.m {
		c.sweepSubjectLocked(subject, now)
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
	return c.total
}
