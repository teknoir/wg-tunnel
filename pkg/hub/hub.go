package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Config holds the hub settings. Zero values select the documented defaults,
// except WGListenPort where 0 means "any free port" (tests).
type Config struct {
	// Namespace is the hub namespace (HUB_NAMESPACE).
	Namespace string
	// PodIP is advertised as the WireGuard endpoint host.
	PodIP string
	// WGListenPort is the UDP port of the WireGuard socket (api.HubWGPort in production).
	WGListenPort int
	// Endpoint overrides the advertised "ip:port" (default PodIP:<listen port>).
	Endpoint string
	// ClientIPHeader names a header with the real client address set by a
	// trusted proxy (e.g. X-Envoy-External-Address). Empty: use the peer address.
	ClientIPHeader string

	SessionTTL     time.Duration // default 3m
	RenewAfter     time.Duration // default 60s
	MaxAge         time.Duration // default 12h
	TURNTTL        time.Duration // default 30m
	TURNRotateLeft time.Duration // rotate TURN credentials on renew below this much remaining life (default 15m)
	ReapInterval   time.Duration // default 10s
	DialTimeout    time.Duration // default 10s
	Quarantine     time.Duration // IP quarantine (default 5m)
	// FlushGrace is how long the WireGuard peer of a session ended by the hub
	// stays installed after its spliced connections were closed, so that the
	// FIN/RST reaches the other side (default 300ms).
	FlushGrace time.Duration

	MaxSessions         int // default 5000
	MaxPerNamespace     int // default 200
	MaxPerSubjectDevice int // default 5
	MaxConnsPerSession  int // default 16
	ReplayCacheSize     int // default 10000

	// Rate limits: tokens per second and burst, per source IP and per subject,
	// applied to enroll and session-create requests before any allocation.
	IPRate       float64 // default 5
	IPBurst      int     // default 40
	SubjectRate  float64 // default 0.5
	SubjectBurst int     // default 10

	Logger *slog.Logger
	Now    func() time.Time
}

func (c *Config) applyDefaults() {
	if c.Namespace == "" {
		c.Namespace = api.HubNamespace
	}
	dur := func(p *time.Duration, d time.Duration) {
		if *p <= 0 {
			*p = d
		}
	}
	num := func(p *int, d int) {
		if *p <= 0 {
			*p = d
		}
	}
	dur(&c.SessionTTL, 3*time.Minute)
	dur(&c.RenewAfter, 60*time.Second)
	dur(&c.MaxAge, 12*time.Hour)
	dur(&c.TURNTTL, 30*time.Minute)
	dur(&c.TURNRotateLeft, 15*time.Minute)
	dur(&c.ReapInterval, 10*time.Second)
	dur(&c.DialTimeout, 10*time.Second)
	dur(&c.Quarantine, 5*time.Minute)
	dur(&c.FlushGrace, 300*time.Millisecond)
	num(&c.MaxSessions, 5000)
	num(&c.MaxPerNamespace, 200)
	num(&c.MaxPerSubjectDevice, 5)
	num(&c.MaxConnsPerSession, 16)
	num(&c.ReplayCacheSize, 10000)
	num(&c.IPBurst, 40)
	num(&c.SubjectBurst, 10)
	if c.IPRate <= 0 {
		c.IPRate = 5
	}
	if c.SubjectRate <= 0 {
		c.SubjectRate = 0.5
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Hub is the session broker and WireGuard gateway.
type Hub struct {
	cfg  Config
	deps Deps
	log  *slog.Logger
	now  func() time.Time

	tunnel  Tunnel
	hubAddr netip.Addr
	ipam    *ipam
	met     *metrics

	ipLimit    *limiter
	subjLimit  *limiter
	renewLimit *limiter
	replay     *replayCache

	// mu guards the session registry below.
	mu      sync.Mutex
	byID    map[string]*session
	byIP    map[netip.Addr]*session
	byWG    map[[32]byte]*session
	devices map[devKey]*session
	clients map[devKey]map[string]*session
	perNS   map[string]int
	perSubj map[string]int

	pendMu  sync.Mutex
	pending map[devKey]struct{}
	wake    chan struct{}

	tunnelServing atomic.Bool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
}

// New creates a hub, brings up the WireGuard device (unless deps.Tunnel is
// given) and starts the enforcement worker and the session reaper. Call
// ServeTunnel to open the in-tunnel listeners and Handler for the HTTP API.
func New(cfg Config, deps Deps) (*Hub, error) {
	cfg.applyDefaults()
	switch {
	case deps.Policy == nil, deps.Flags == nil, deps.Identity == nil, deps.Users == nil, deps.Authz == nil, deps.TURN == nil:
		return nil, errors.New("hub: Policy, Flags, Identity, Users, Authz and TURN are required")
	}
	log := cfg.Logger
	tun := deps.Tunnel
	if tun == nil {
		var err error
		if tun, err = NewWGTunnel(cfg.WGListenPort, log); err != nil {
			return nil, err
		}
	}
	hubAddr := netip.MustParseAddr(api.HubAddress)
	prefix := netip.MustParsePrefix(api.OverlayPrefix)
	pool, err := newIPAM(prefix.Addr(), hubAddr, prefix.Bits(), cfg.Quarantine, cfg.Now)
	if err != nil {
		_ = tun.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		cfg: cfg, deps: deps, log: log, now: cfg.Now,
		tunnel: tun, hubAddr: hubAddr, ipam: pool, met: newMetrics(),
		ipLimit:    newLimiter(cfg.IPRate, cfg.IPBurst, 50000, cfg.Now),
		subjLimit:  newLimiter(cfg.SubjectRate, cfg.SubjectBurst, 50000, cfg.Now),
		renewLimit: newLimiter(0.5, 5, 50000, cfg.Now),
		replay:     newReplayCache(cfg.ReplayCacheSize, cfg.Now),
		byID:       map[string]*session{},
		byIP:       map[netip.Addr]*session{},
		byWG:       map[[32]byte]*session{},
		devices:    map[devKey]*session{},
		clients:    map[devKey]map[string]*session{},
		perNS:      map[string]int{},
		perSubj:    map[string]int{},
		pending:    map[devKey]struct{}{},
		wake:       make(chan struct{}, 1),
		ctx:        ctx, cancel: cancel,
	}
	deps.Policy.Subscribe(h.notify)
	deps.Flags.Subscribe(h.notify)
	h.wg.Add(2)
	go h.enforcer()
	go h.reaper()
	return h, nil
}

// WGPort returns the UDP port of the WireGuard socket.
func (h *Hub) WGPort() int { return h.tunnel.ListenPort() }

// Endpoint is the WireGuard endpoint handed to sessions.
func (h *Hub) Endpoint() string {
	if h.cfg.Endpoint != "" {
		return h.cfg.Endpoint
	}
	return net.JoinHostPort(h.cfg.PodIP, strconv.Itoa(h.tunnel.ListenPort()))
}

// Ready reports whether the informers are synced and the data plane is up.
func (h *Hub) Ready() bool {
	return h.deps.Policy.HasSynced() && h.deps.Flags.HasSynced() && h.tunnel.Up() && h.tunnelServing.Load()
}

// Close ends all sessions and stops the hub.
func (h *Hub) Close() error {
	h.closeOnce.Do(func() {
		h.cancel()
		h.wg.Wait()
		h.mu.Lock()
		// byWG also holds sessions that were detached but whose peer removal
		// is still pending (grace period).
		all := make([]*session, 0, len(h.byWG))
		for _, s := range h.byWG {
			all = append(all, s)
		}
		for _, s := range all {
			h.detachLocked(s)
		}
		h.mu.Unlock()
		// Close every stream first, give the FIN/RST a moment to leave, then
		// remove the peers.
		for _, s := range all {
			s.closeConns()
		}
		if len(all) > 0 && h.tunnel.Up() {
			time.Sleep(min(h.cfg.FlushGrace, 100*time.Millisecond))
		}
		for _, s := range all {
			h.finalize(s)
		}
		_ = h.tunnel.Close()
	})
	return nil
}

// notify is the change callback of the policy and flag sources. It only queues
// the device; the enforcer goroutine applies it within microseconds.
func (h *Hub) notify(ns, device string) {
	h.pendMu.Lock()
	h.pending[devKey{ns, device}] = struct{}{}
	h.pendMu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

func (h *Hub) enforcer() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-h.wake:
		}
		h.pendMu.Lock()
		keys := make([]devKey, 0, len(h.pending))
		for k := range h.pending {
			keys = append(keys, k)
		}
		clear(h.pending)
		h.pendMu.Unlock()
		for _, k := range keys {
			h.enforce(k)
		}
	}
}

// enforce re-evaluates a device after a policy or flag change and tears down
// whatever is no longer allowed.
func (h *Hub) enforce(k devKey) {
	eff := computeEffective(h.deps.Policy, h.deps.Flags, k.ns, k.device)

	h.mu.Lock()
	dev := h.devices[k]
	clients := make([]*session, 0, len(h.clients[k]))
	for _, c := range h.clients[k] {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	if !eff.Active {
		if dev == nil && len(clients) == 0 {
			return
		}
		ended, conns := 0, 0
		// Every spliced stream is registered on its device session; fall back
		// to the clients' counts when the device session is already gone.
		if dev != nil {
			conns = dev.connCount()
		} else {
			for _, c := range clients {
				conns += c.connCount()
			}
		}
		// Device first: closes every spliced stream to it (its peer follows
		// after the flush grace).
		if dev != nil && h.endSession(dev, eff.Reason) {
			ended++
		}
		for _, c := range clients {
			if h.endSession(c, eff.Reason) {
				ended++
			}
		}
		if ended > 0 {
			h.met.revocations.WithLabelValues(eff.Reason).Inc()
			h.logRevoke(k, eff.Reason, eff.Detail, "", slog.Int("sessions_ended", ended), slog.Int("connections_closed", conns))
		}
		return
	}

	// Still active: an identity pinned for an older generation is void, and a
	// narrowed port list ends the sessions that used a removed port.
	if dev != nil && eff.Policy.EnrollmentGeneration > dev.generation {
		if h.endSession(dev, api.ReasonReenroll) {
			h.met.revocations.WithLabelValues(api.ReasonReenroll).Inc()
			h.logRevoke(k, api.ReasonReenroll, "enrollment reset", dev.id)
		}
	}
	for _, c := range clients {
		if !portAllowed(eff.Policy.AllowedPorts, c.targetPort) {
			if h.endSession(c, api.ReasonPortNotAllowed) {
				h.met.revocations.WithLabelValues(api.ReasonPortNotAllowed).Inc()
				h.logRevoke(k, api.ReasonPortNotAllowed, "port removed from policy", c.id)
			}
		}
	}
}

// logRevoke writes the decision line of an enforcement action.
func (h *Hub) logRevoke(k devKey, reason, detail, session string, extra ...slog.Attr) {
	h.met.decisions.WithLabelValues("revoke", "revoke", reason).Inc()
	attrs := []slog.Attr{
		slog.String("op", "revoke"), slog.String("decision", "revoke"), slog.String("reason", reason),
		slog.String("kind", ""), slog.String("ns", k.ns), slog.String("device", k.device),
		slog.String("subject", ""), slog.String("session", session), slog.String("remote", ""),
		slog.String("detail", detail),
	}
	h.log.LogAttrs(context.Background(), slog.LevelWarn, "decision", append(attrs, extra...)...)
}

func (h *Hub) reaper() {
	defer h.wg.Done()
	t := time.NewTicker(h.cfg.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
			h.reap()
		}
	}
}

// reap removes expired sessions and housekeeps the caches.
func (h *Hub) reap() {
	now := h.now()
	var dead []*session
	h.mu.Lock()
	for _, s := range h.byID {
		if now.After(s.expiry()) || now.Sub(s.createdAt) > h.cfg.MaxAge {
			dead = append(dead, s)
		}
	}
	h.mu.Unlock()
	for _, s := range dead {
		reason := "expired"
		if now.Sub(s.createdAt) > h.cfg.MaxAge {
			reason = api.ReasonSessionMaxAge
		}
		if h.endSession(s, reason) {
			h.logEnd(s, "reap", reason)
		}
	}
	h.replay.Sweep()
	h.ipam.Sweep()
}

// logEnd logs the end of a session (one decision line).
func (h *Hub) logEnd(s *session, op, reason string) {
	h.met.decisions.WithLabelValues(op, "end", reason).Inc()
	h.log.LogAttrs(context.Background(), slog.LevelInfo, "decision",
		slog.String("op", op), slog.String("decision", "end"), slog.String("reason", reason),
		slog.String("kind", s.kind), slog.String("ns", s.ns), slog.String("device", s.device),
		slog.String("subject", s.subjectLabel()), slog.String("session", s.id), slog.String("remote", s.remote))
}

// sessionCounts returns the live sessions by kind (tests and diagnostics).
func (h *Hub) sessionCounts() (devices, clients int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	devices = len(h.devices)
	for _, m := range h.clients {
		clients += len(m)
	}
	return devices, clients
}

// MetricsHandler serves the Prometheus metrics.
func (h *Hub) MetricsHandler() http.Handler { return h.met.handler() }
