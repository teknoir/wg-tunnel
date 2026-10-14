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
	// BackstageSA is the full username ("system:serviceaccount:<ns>:<name>") of
	// the Backstage backend, the only caller of the status listener.
	BackstageSA string
	// ClientIPHeader names a header with the real client address set by a
	// trusted proxy (e.g. X-Envoy-External-Address). Per-source rate limits
	// apply only to requests that carry a parseable address in it: behind a
	// service mesh or a load balancer that hides client addresses the peer
	// address is the same for everyone and must not be used as a limiter key.
	// A value that is loopback, private, CGNAT, link-local or unspecified is a
	// proxy or NAT hop, not a client, and is ignored the same way.
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
	// P2PGrantTTL is the lifetime of a plane-B grant on the device, restarted
	// by every push (default api.DefaultGrantTTL seconds). A client renewal
	// re-pushes once half of it has passed.
	P2PGrantTTL time.Duration
	// P2PPushTimeout bounds one grant push to the agent (default 3 s).
	P2PPushTimeout time.Duration

	MaxSessions         int // new client sessions are refused at this many sessions in total (default 5000); devices only at twice that
	MaxPerNamespace     int // client sessions per teamspace (default 200); device sessions are exempt
	MaxPerSubjectDevice int // client sessions of one user per device (default 5)
	MaxPerSubject       int // client sessions of one user across all devices (default 20)
	MaxConnsPerSession  int // default 16
	ReplayCacheSize     int // default 10000
	ReplayPerSubject    int // replay entries per subject (default 128)

	// Rate limits: tokens per second and burst, per source IP and per subject,
	// applied to enroll and session-create requests before any allocation.
	IPRate       float64 // default 5; only for requests with a trusted client address
	IPBurst      int     // default 40
	SubjectRate  float64 // default 0.5
	SubjectBurst int     // default 10
	// GlobalRate/GlobalBurst are the generous per-endpoint backstop shared by
	// all callers (default 50 rps, burst 200).
	GlobalRate  float64
	GlobalBurst int

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
	dur(&c.P2PGrantTTL, api.DefaultGrantTTL*time.Second)
	dur(&c.P2PPushTimeout, 3*time.Second)
	num(&c.MaxSessions, 5000)
	num(&c.MaxPerNamespace, 200)
	num(&c.MaxPerSubjectDevice, 5)
	num(&c.MaxPerSubject, 20)
	num(&c.ReplayPerSubject, 128)
	num(&c.GlobalBurst, 200)
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
	if c.GlobalRate <= 0 {
		c.GlobalRate = 50
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

	// instance names this hub process in the grant sets it pushes: a restarted
	// hub starts its sequence numbers over and the agents drop the old pairs.
	instance string

	tunnel  Tunnel
	hubAddr netip.Addr
	ipam    *ipam
	met     *metrics

	ipLimit     *limiter
	globalLimit *limiter
	subjLimit   *limiter
	renewLimit  *limiter
	replay      *replayCache
	nonces      *nonceStore

	// mu guards the session registry below.
	mu      sync.Mutex
	byID    map[string]*session
	byIP    map[netip.Addr]*session
	byWG    map[[32]byte]*session
	devices map[devKey]*session
	clients map[devKey]map[string]*session
	perNS   map[string]int // client sessions per teamspace
	perSubj map[string]int // client sessions per (user, device)
	// perSubjAll counts client sessions per user across all devices.
	perSubjAll map[string]int

	pendMu  sync.Mutex
	pending map[devKey]struct{}
	voiding map[devKey]struct{} // devices whose pin is being voided
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
	instance, err := newID()
	if err != nil {
		_ = tun.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		cfg: cfg, deps: deps, log: log, now: cfg.Now, instance: instance,
		tunnel: tun, hubAddr: hubAddr, ipam: pool, met: newMetrics(),
		ipLimit:     newLimiter(cfg.IPRate, cfg.IPBurst, 50000, cfg.Now),
		globalLimit: newLimiter(cfg.GlobalRate, cfg.GlobalBurst, 64, cfg.Now),
		subjLimit:   newLimiter(cfg.SubjectRate, cfg.SubjectBurst, 50000, cfg.Now),
		renewLimit:  newLimiter(0.5, 5, 50000, cfg.Now),
		replay:      newReplayCache(cfg.ReplayCacheSize, cfg.ReplayPerSubject, cfg.Now),
		nonces:      newNonceStore(cfg.Now),
		byID:        map[string]*session{},
		byIP:        map[netip.Addr]*session{},
		byWG:        map[[32]byte]*session{},
		devices:     map[devKey]*session{},
		clients:     map[devKey]map[string]*session{},
		perNS:       map[string]int{},
		perSubj:     map[string]int{},
		perSubjAll:  map[string]int{},
		pending:     map[devKey]struct{}{},
		voiding:     map[devKey]struct{}{},
		wake:        make(chan struct{}, 1),
		ctx:         ctx, cancel: cancel,
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
	if eff.VoidReason != "" {
		// Sticky revocation: whatever device-controller does or does not see, a
		// device that was ever flagged needs a NEW identity afterwards. It runs
		// beside the enforcer: a slow API server must never delay the teardown
		// of this or any other device.
		h.voidPinAsync(k, eff.VoidReason)
	}

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

	// Still active: the device session must belong to the current enrollment
	// (epoch and generation), to the identity an admin approved, and must
	// expose the ports the policy allows now; a narrowed port list ends the
	// client sessions that used a removed port.
	if dev != nil {
		reason, detail := "", ""
		switch {
		case eff.Policy.EnrollmentGeneration != dev.generation || eff.Policy.EnrollmentEpoch != dev.epoch:
			reason, detail = api.ReasonReenroll, "enrollment reset"
		case !activated(dev.identityView(), eff.Policy):
			reason, detail = api.ReasonPendingApproval, "identity approval changed"
		case !samePorts(eff.Policy.AllowedPorts, dev.ports):
			reason, detail = reasonPortsChanged, "allowed ports changed"
		}
		if reason != "" && h.endSession(dev, reason) {
			h.met.revocations.WithLabelValues(reason).Inc()
			h.logRevoke(k, reason, detail, dev.id)
		}
	}
	// The services of a live agent follow the policy (pushed over its control
	// port, or by ending its session if it cannot take a push).
	live := h.deviceSession(k.ns, k.device)
	if live != nil {
		h.syncServices(live, eff.Policy)
	}
	h.syncP2P(k, eff.Policy, live, clients)
	// A client session whose port or service is gone or was redefined ends,
	// and its spliced connections with it.
	for _, c := range clients {
		if den := h.serviceDenialLive(c, eff.Policy); den != nil {
			if h.endSession(c, den.reason) {
				h.met.revocations.WithLabelValues(den.reason).Inc()
				h.logRevoke(k, den.reason, den.msg, c.id)
			}
		}
	}
}

// reasonPortsChanged ends a device session whose allowed-port set changed, so
// that the agent reconnects and exposes the new set (log and metric label only;
// not a wire reason).
const reasonPortsChanged = "ports_changed"

// voidPinAsync starts voidPin unless one is already running for the device.
func (h *Hub) voidPinAsync(k devKey, reason string) {
	h.pendMu.Lock()
	if _, busy := h.voiding[k]; busy {
		h.pendMu.Unlock()
		return
	}
	h.voiding[k] = struct{}{}
	h.pendMu.Unlock()
	h.wg.Add(1) // the enforcer, which calls this, is itself counted: Close cannot be past Wait
	go func() {
		defer h.wg.Done()
		defer func() {
			h.pendMu.Lock()
			delete(h.voiding, k)
			h.pendMu.Unlock()
		}()
		h.voidPin(k, reason)
	}()
}

// voidPin marks the device's identity pin void. A failure is retried until it
// works (or the hub stops): the pin must never outlive a flag.
func (h *Hub) voidPin(k devKey, reason string) {
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()
	changed, err := h.deps.Identity.Void(ctx, k.ns, k.device, reason, h.now())
	if err != nil {
		h.log.Error("voiding the identity pin failed; retrying", "ns", k.ns, "device", k.device, "err", err)
		time.AfterFunc(2*time.Second, func() {
			if h.ctx.Err() == nil {
				h.notify(k.ns, k.device)
			}
		})
		return
	}
	if changed {
		h.met.revocations.WithLabelValues("identity_voided").Inc()
		h.log.LogAttrs(context.Background(), slog.LevelWarn, "identity pin voided",
			slog.String("ns", k.ns), slog.String("device", k.device), slog.String("reason", reason))
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

// SessionCounts returns the live sessions by kind (tests and diagnostics).
func (h *Hub) SessionCounts() (devices, clients int) { return h.sessionCounts() }

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
