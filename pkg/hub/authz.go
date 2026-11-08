package hub

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// CachedAuthorizer wraps an Authorizer with a short-lived, bounded LRU cache of
// allow and deny answers; the CanExec and CanAdmin answers are cached under
// separate keys. Errors are never cached and always deny (fail closed).
type CachedAuthorizer struct {
	inner Authorizer
	ttl   time.Duration
	max   int
	now   func() time.Time

	mu sync.Mutex
	ll *list.List
	m  map[string]*list.Element
}

type authzEntry struct {
	key     string
	allowed bool
	expires time.Time
}

// NewCachedAuthorizer caches inner's answers for ttl, keeping at most max.
func NewCachedAuthorizer(inner Authorizer, ttl time.Duration, max int) *CachedAuthorizer {
	return newCachedAuthorizer(inner, ttl, max, time.Now)
}

func newCachedAuthorizer(inner Authorizer, ttl time.Duration, max int, now func() time.Time) *CachedAuthorizer {
	return &CachedAuthorizer{inner: inner, ttl: ttl, max: max, now: now, ll: list.New(), m: map[string]*list.Element{}}
}

// CanExec implements Authorizer.
func (c *CachedAuthorizer) CanExec(ctx context.Context, email, ns string) (bool, error) {
	return c.cached("exec\x00"+email+"\x00"+ns, func() (bool, error) { return c.inner.CanExec(ctx, email, ns) })
}

// CanAdmin implements Authorizer. Its answers are cached separately from
// CanExec's for the same (email, ns): the two checks are different questions.
func (c *CachedAuthorizer) CanAdmin(ctx context.Context, email, ns string) (bool, error) {
	return c.cached("admin\x00"+email+"\x00"+ns, func() (bool, error) { return c.inner.CanAdmin(ctx, email, ns) })
}

// cached answers key from the LRU, filling it with ask on a miss. Errors are
// never cached.
func (c *CachedAuthorizer) cached(key string, ask func() (bool, error)) (bool, error) {
	now := c.now()
	c.mu.Lock()
	if el, ok := c.m[key]; ok {
		e := el.Value.(*authzEntry)
		if now.Before(e.expires) {
			c.ll.MoveToFront(el)
			allowed := e.allowed
			c.mu.Unlock()
			return allowed, nil
		}
		c.ll.Remove(el)
		delete(c.m, key)
	}
	c.mu.Unlock()

	allowed, err := ask()
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok { // concurrent fill
		c.ll.Remove(el)
	}
	c.m[key] = c.ll.PushFront(&authzEntry{key: key, allowed: allowed, expires: c.now().Add(c.ttl)})
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, old.Value.(*authzEntry).key)
	}
	return allowed, nil
}

// Len returns the number of cached answers.
func (c *CachedAuthorizer) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
