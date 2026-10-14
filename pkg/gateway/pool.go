package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Session is what the gateway needs from a hub session: a *wgclient.Session
// of a delegating gateway client session satisfies it.
type Session interface {
	// DialAs opens a connection to the session's service for the end user.
	DialAs(ctx context.Context, as string) (net.Conn, error)
	// Done is closed when the session has ended (revoked, expired, closed).
	Done() <-chan struct{}
	Close() error
}

// SessionFactory creates the delegated session of one device service.
type SessionFactory func(ctx context.Context, service string) (Session, error)

const (
	// failedTTL: a failed session creation is remembered this long, so a page
	// that fires dozens of requests does not hammer the hub's create limiter.
	failedTTL = 2 * time.Second
	// transportIdle: per-user transports unused this long are dropped.
	transportIdle = 2 * time.Minute
	// maxTransports bounds the per-(service, user) transports of one service.
	maxTransports = 256
)

// upstream is the HTTP transport of one (service, user): a connection of the
// session carries one user (ConnectRequest.As), so connections are never
// shared between users.
type upstream struct {
	tr   *http.Transport
	born time.Time
	last time.Time
}

// entry is the pooled session of one service.
type entry struct {
	svc   string
	ready chan struct{} // closed when sess or err is set
	sess  Session
	err   error
	at    time.Time // creation finished

	mu      sync.Mutex
	active  int
	lastUse time.Time
	up      map[string]*upstream
	sems    map[string]chan struct{}
	dead    bool
}

// pool keeps at most one live session per service id, created lazily.
type pool struct {
	create  SessionFactory
	timeout time.Duration
	now     func() time.Time

	mu     sync.Mutex
	m      map[string]*entry
	closed bool
	wg     sync.WaitGroup
}

func newPool(create SessionFactory, timeout time.Duration, now func() time.Time) *pool {
	return &pool{create: create, timeout: timeout, now: now, m: map[string]*entry{}}
}

var errClosed = errors.New("gateway: shutting down")

// acquire returns the entry of svc with a live session, creating it if need
// be, and marks it in use. The caller must call release exactly once.
func (p *pool) acquire(ctx context.Context, svc string) (*entry, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errClosed
		}
		e := p.m[svc]
		if e != nil {
			select {
			case <-e.ready:
				if e.err != nil && p.now().Sub(e.at) >= failedTTL {
					delete(p.m, svc)
					e = nil
				}
			default:
			}
		}
		if e == nil {
			e = &entry{svc: svc, ready: make(chan struct{}), up: map[string]*upstream{}, sems: map[string]chan struct{}{}, lastUse: p.now()}
			p.m[svc] = e
			p.wg.Add(1)
			go p.build(e)
		}
		p.mu.Unlock()

		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e.err != nil {
			return nil, e.err
		}
		e.mu.Lock()
		if e.dead {
			e.mu.Unlock()
			continue // the session ended meanwhile: build a new one
		}
		e.active++
		e.lastUse = p.now()
		e.mu.Unlock()
		return e, nil
	}
}

// build creates the session of e. It runs detached from the request that
// started it: other requests wait for the same session.
func (p *pool) build(e *entry) {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	sess, err := p.create(ctx, e.svc)
	e.sess, e.err, e.at = sess, err, p.now()
	close(e.ready)
	if err != nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-sess.Done()
		p.drop(e)
	}()
}

// drop removes e (its session ended) and closes its idle connections.
func (p *pool) drop(e *entry) {
	p.mu.Lock()
	if p.m[e.svc] == e {
		delete(p.m, e.svc)
	}
	p.mu.Unlock()
	e.mu.Lock()
	e.dead = true
	ups := e.up
	e.up = map[string]*upstream{}
	e.mu.Unlock()
	for _, u := range ups {
		u.tr.CloseIdleConnections()
	}
}

// invalidate ends the session of e and forgets it; the next request builds a
// new one. In-flight requests on it fail.
func (p *pool) invalidate(e *entry) {
	if e.sess == nil {
		return
	}
	e.mu.Lock()
	e.dead = true
	e.mu.Unlock()
	p.drop(e)
	_ = e.sess.Close()
}

func (p *pool) release(e *entry) {
	e.mu.Lock()
	e.active--
	e.lastUse = p.now()
	e.mu.Unlock()
}

// sem returns the connection semaphore of (e, user): at most limit open
// connections of one user to the service, counting upgraded (WebSocket) and
// streaming ones until they close, which MaxConnsPerHost does not. The
// semaphore outlives the user's transports (a retired transport's busy
// connections still hold slots).
func (e *entry) sem(user string, limit int) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	ch := e.sems[user]
	if ch == nil {
		ch = make(chan struct{}, limit)
		e.sems[user] = ch
	}
	return ch
}

// transport returns the transport of (e, user), creating it on first use. A
// transport older than maxAge is retired for new requests (its idle
// connections are closed at once, busy ones when they go idle): a connection is
// authorized once, when it is opened, and a keep-alive connection must not
// outlive a revoked access for long.
func (e *entry) transport(user string, now time.Time, maxAge time.Duration, mk func(as string) *http.Transport) *http.Transport {
	e.mu.Lock()
	defer e.mu.Unlock()
	if u := e.up[user]; u != nil {
		if maxAge <= 0 || now.Sub(u.born) <= maxAge {
			u.last = now
			return u.tr
		}
		u.tr.CloseIdleConnections()
		delete(e.up, user)
	}
	if len(e.up) >= maxTransports { // evict the least recently used
		var oldest string
		var ot time.Time
		for k, u := range e.up {
			if oldest == "" || u.last.Before(ot) {
				oldest, ot = k, u.last
			}
		}
		e.up[oldest].tr.CloseIdleConnections()
		delete(e.up, oldest)
	}
	u := &upstream{tr: mk(user), born: now, last: now}
	e.up[user] = u
	return u.tr
}

// sweep drops idle per-user transports and closes sessions that nobody used
// for idle.
func (p *pool) sweep(idle time.Duration) {
	now := p.now()
	p.mu.Lock()
	entries := make([]*entry, 0, len(p.m))
	for _, e := range p.m {
		entries = append(entries, e)
	}
	p.mu.Unlock()
	for _, e := range entries {
		select {
		case <-e.ready:
		default:
			continue
		}
		if e.err != nil {
			continue
		}
		e.mu.Lock()
		for k, u := range e.up {
			if now.Sub(u.last) > transportIdle && e.active == 0 {
				u.tr.CloseIdleConnections()
				delete(e.up, k)
			}
		}
		for k, ch := range e.sems { // no open connection: forget the semaphore
			if len(ch) == 0 && e.up[k] == nil {
				delete(e.sems, k)
			}
		}
		closeIt := e.active == 0 && now.Sub(e.lastUse) > idle && !e.dead
		if closeIt {
			e.dead = true
		}
		ups := e.up
		if closeIt {
			e.up = map[string]*upstream{}
		}
		e.mu.Unlock()
		if closeIt {
			for _, u := range ups {
				u.tr.CloseIdleConnections()
			}
			_ = e.sess.Close() // Done follows and drop removes the entry
			p.drop(e)
		}
	}
}

// closeAll ends every session and refuses new requests.
func (p *pool) closeAll() {
	p.mu.Lock()
	p.closed = true
	entries := make([]*entry, 0, len(p.m))
	for _, e := range p.m {
		entries = append(entries, e)
	}
	p.mu.Unlock()
	for _, e := range entries {
		<-e.ready
		if e.err == nil {
			_ = e.sess.Close()
		}
	}
	p.wg.Wait()
}

// size returns the number of pooled sessions (tests).
func (p *pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
