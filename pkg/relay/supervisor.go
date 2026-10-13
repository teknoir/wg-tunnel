package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/turnbind"
)

// Reasons passed to SupervisorConfig.OnSwap.
const (
	ReasonInitial       = "initial"
	ReasonStale         = "stale"          // nothing received for StaleAfter
	ReasonRefreshFailed = "refresh_failed" // pion failed to refresh the allocation or permissions
	ReasonRotate        = "rotate"         // Rotate was called (new TURN credentials)
)

// Defaults for SupervisorConfig.
const (
	DefaultStaleAfter      = 75 * time.Second
	DefaultAllocateTimeout = 15 * time.Second
	DefaultMinBackoff      = time.Second
	DefaultMaxBackoff      = 30 * time.Second
)

// SupervisorConfig configures a Supervisor. Bind is required, and at least one
// of Creds and Initial.
type SupervisorConfig struct {
	// Bind receives each new relay as its PacketConn.
	Bind *turnbind.Bind
	// Creds returns the current TURN configuration. It is called for the first
	// allocation (unless Initial is set) and for every re-allocation that is
	// not a Rotate. When nil, the last used configuration is reused.
	Creds func(ctx context.Context) (Config, error)
	// Initial is used for the first allocation instead of calling Creds.
	Initial *Config
	// LastReceive reports when the tunnel last received a packet. Default:
	// Bind.LastReceive. Callers may combine it with the WireGuard handshake
	// time. NOTE: an idle WireGuard tunnel receives nothing for up to ~2 minutes
	// (keepalives are one-way); the 75 s default assumes the caller exchanges
	// traffic at least every ~60 s (the session renewal does), otherwise raise
	// StaleAfter.
	LastReceive func() time.Time
	// StaleAfter is how long without a receive (counted from the later of the
	// last receive and the last swap) marks the relay dead. Default 75 s.
	StaleAfter time.Duration
	// CheckInterval is how often staleness is evaluated. Default StaleAfter/5
	// (at most 5 s).
	CheckInterval time.Duration
	// AllocateTimeout bounds one allocation attempt. Default 15 s.
	AllocateTimeout time.Duration
	// MinBackoff and MaxBackoff bound the retry delay after a failed attempt
	// (doubling). The old relay stays installed meanwhile.
	MinBackoff, MaxBackoff time.Duration
	// OnSwap is called after a swap, with the old relay already closed. Use it to
	// nudge WireGuard into sending a keepalive (turnbind.Nudge) so the remote
	// side re-learns the endpoint at once.
	OnSwap func(reason string)
	// Logf, if set, receives one line per decision. It must not be given
	// credentials; the supervisor never logs them.
	Logf func(format string, args ...any)
}

// Supervisor keeps a working relay installed in a turnbind.Bind. It
// re-allocates and swaps when the relay goes stale, when pion reports a refresh
// failure, or when Rotate is called. It makes the new allocation before it
// retires the old one, and closes the old relay right after the swap, so two
// allocations exist only for the duration of one allocation attempt.
type Supervisor struct {
	cfg SupervisorConfig

	mu       sync.Mutex
	cur      *Relay
	curSince time.Time
	lastCfg  Config
	pending  *Config
	started  bool
	closed   bool

	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

// NewSupervisor validates cfg and applies defaults.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.Bind == nil {
		return nil, errors.New("relay: supervisor needs a Bind")
	}
	if cfg.Creds == nil && cfg.Initial == nil {
		return nil, errors.New("relay: supervisor needs Creds or Initial")
	}
	if cfg.LastReceive == nil {
		cfg.LastReceive = cfg.Bind.LastReceive
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = DefaultStaleAfter
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = min(cfg.StaleAfter/5, 5*time.Second)
	}
	if cfg.CheckInterval < 5*time.Millisecond {
		cfg.CheckInterval = 5 * time.Millisecond
	}
	if cfg.AllocateTimeout <= 0 {
		cfg.AllocateTimeout = DefaultAllocateTimeout
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultMinBackoff
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(DefaultMaxBackoff, cfg.MinBackoff)
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Supervisor{cfg: cfg, wake: make(chan struct{}, 1), done: make(chan struct{})}, nil
}

// Start makes the first allocation synchronously (so a bad configuration fails
// fast), installs it in the Bind and starts supervising until ctx is cancelled
// or Close is called.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return errors.New("relay: supervisor already started or closed")
	}
	s.started = true
	s.mu.Unlock()

	var rc Config
	if s.cfg.Initial != nil {
		rc = *s.cfg.Initial
	} else {
		var err error
		if rc, err = s.cfg.Creds(ctx); err != nil {
			s.markNotStarted()
			return fmt.Errorf("relay: fetching TURN credentials: %w", err)
		}
	}
	r, err := s.allocate(ctx, rc)
	if err != nil {
		s.markNotStarted()
		return err
	}
	s.install(r, rc)

	lctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	go s.loop(lctx)
	s.cfg.Logf("relay: initial allocation %s via %s", r.RelayedAddr(), rc.Server)
	if s.cfg.OnSwap != nil {
		s.cfg.OnSwap(ReasonInitial)
	}
	return nil
}

func (s *Supervisor) markNotStarted() {
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
}

// Current returns the installed relay, or nil.
func (s *Supervisor) Current() *Relay {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Rotate re-allocates now with cfg (new TURN credentials, or a new server) and
// swaps. Later automatic re-allocations call Creds, or reuse cfg if Creds is
// nil. Returns immediately; if the attempt fails it is retried with backoff
// and the old relay stays in place meanwhile.
func (s *Supervisor) Rotate(cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.closed {
		return errors.New("relay: supervisor is not running")
	}
	s.pending = &cfg
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Close stops supervising, detaches and closes the current relay. The Bind is
// left open with no conn (Send then fails with turnbind.ErrNoConn).
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel, started := s.cancel, s.started
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-s.done
	}
	if !started {
		return nil
	}
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	return closeConn(s.cfg.Bind.Swap(nil))
}

func closeConn(c io.Closer) error {
	if c == nil {
		return nil
	}
	return c.Close()
}

func (s *Supervisor) allocate(ctx context.Context, rc Config) (*Relay, error) {
	actx, cancel := context.WithTimeout(ctx, s.cfg.AllocateTimeout)
	defer cancel()
	return Allocate(actx, rc)
}

func (s *Supervisor) install(r *Relay, rc Config) {
	old := s.cfg.Bind.Swap(r)
	s.mu.Lock()
	s.cur, s.curSince, s.lastCfg = r, time.Now(), rc
	s.mu.Unlock()
	_ = closeConn(old)
}

func (s *Supervisor) loop(ctx context.Context) {
	defer close(s.done)
	tick := time.NewTicker(s.cfg.CheckInterval)
	defer tick.Stop()

	var (
		retryAt time.Time
		backoff = s.cfg.MinBackoff
	)
	for {
		s.mu.Lock()
		cur := s.cur
		s.mu.Unlock()

		var (
			failedCh <-chan struct{}
			retryCh  <-chan time.Time
			timer    *time.Timer
		)
		if wait := time.Until(retryAt); wait > 0 {
			timer = time.NewTimer(wait)
			retryCh = timer.C
		} else if cur != nil {
			failedCh = cur.Failed()
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-tick.C:
		case <-s.wake:
		case <-failedCh:
		case <-retryCh:
		}
		if timer != nil {
			timer.Stop()
		}
		if time.Now().Before(retryAt) {
			continue
		}

		s.mu.Lock()
		cur, since, pending := s.cur, s.curSince, s.pending
		s.mu.Unlock()

		var reason string
		switch {
		case pending != nil:
			reason = ReasonRotate
		case cur != nil && isClosed(cur.Failed()):
			reason = ReasonRefreshFailed
		case s.stale(since):
			reason = ReasonStale
		default:
			continue
		}

		if err := s.replace(ctx, reason, pending); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.cfg.Logf("relay: re-allocation (%s) failed, retrying in %s: %v", reason, backoff, err)
			retryAt = time.Now().Add(backoff)
			backoff = min(backoff*2, s.cfg.MaxBackoff)
			continue
		}
		retryAt, backoff = time.Time{}, s.cfg.MinBackoff
	}
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (s *Supervisor) stale(since time.Time) bool {
	ref := s.cfg.LastReceive()
	if since.After(ref) {
		ref = since
	}
	return time.Since(ref) > s.cfg.StaleAfter
}

func (s *Supervisor) replace(ctx context.Context, reason string, pending *Config) error {
	var rc Config
	switch {
	case pending != nil:
		rc = *pending
	case s.cfg.Creds != nil:
		var err error
		if rc, err = s.cfg.Creds(ctx); err != nil {
			return fmt.Errorf("fetching TURN credentials: %w", err)
		}
	default:
		s.mu.Lock()
		rc = s.lastCfg
		s.mu.Unlock()
	}
	r, err := s.allocate(ctx, rc)
	if err != nil {
		return err
	}
	s.install(r, rc)
	s.mu.Lock()
	if s.pending == pending {
		s.pending = nil
	}
	s.mu.Unlock()
	s.cfg.Logf("relay: swapped (%s), new relayed address %s", reason, r.RelayedAddr())
	if s.cfg.OnSwap != nil {
		s.cfg.OnSwap(reason)
	}
	return nil
}
