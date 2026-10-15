package wgclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/teknoir/wg-tunnel/internal/wgdev"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/relay"
	"github.com/teknoir/wg-tunnel/pkg/turnbind"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Session is one live tunnel session. All methods are safe for concurrent use.
type Session struct {
	opts    Options
	log     *slog.Logger
	pubB64  string
	posture api.Posture

	hubHex   string
	address  netip.Addr
	direct   bool
	renewURL string
	closeURL string

	p2pc *p2pClient // plane B (nil: none)

	tnet *netstack.Net
	dev  *device.Device
	bind *turnbind.Bind
	sup  *relay.Supervisor
	pc   net.PacketConn // direct UDP socket, owned by the session

	httpInit   sync.Once
	tunnelHTTP *http.Client

	ctx    context.Context
	cancel context.CancelFunc

	started  time.Time
	swapMu   sync.Mutex
	lastSwap time.Time
	// lastRenewOK is the time of the last successful renewal: the answer came
	// through the tunnel, so the tunnel was alive then.
	lastRenewOK time.Time

	mu      sync.Mutex
	resp    api.SessionResponse
	expires time.Time
	tracked map[io.Closer]struct{}
	err     error
	ended   bool

	endOnce sync.Once
	done    chan struct{}
}

// Create asks the hub for a session and brings the tunnel up. ctx bounds only
// Create itself (including the WireGuard handshake); the session lives until
// Close, a denial, or its expiry. A hub refusal is returned as *Error.
func Create(ctx context.Context, opts Options) (*Session, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	log := opts.logger()
	priv, pub, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	defer priv.Zero()
	pubB64 := pub.Base64()

	var (
		path    string
		body    any
		posture api.Posture
		prep    *p2pPrep
	)
	switch opts.Kind {
	case api.KindDevice:
		req := *opts.DeviceRequest
		req.WGPublicKey = pubB64
		path, body, posture = api.DeviceSessionPath, req, req.Posture
	default:
		req := *opts.ClientRequest
		req.WGPublicKey = pubB64
		req.Direct = opts.Direct
		if prep = opts.prepareP2P(ctx); prep != nil {
			req.P2P = prep.offer()
		}
		path, body, posture = api.ClientSessionPath, req, req.Posture
	}
	defer func() { prep.close() }() // closed already (nil) once plane B took over

	token, err := opts.Credential(ctx, pubB64)
	if err != nil {
		return nil, fmt.Errorf("wgclient: obtaining credential: %w", err)
	}
	var resp api.SessionResponse
	if err := doJSON(ctx, opts.httpClient(), hubEndpoint(opts.HubURL, path), token, body, &resp); err != nil {
		return nil, err
	}
	if err := checkResponse(opts, &resp); err != nil {
		return nil, err
	}

	s := &Session{
		opts: opts, log: log, pubB64: pubB64, posture: posture,
		resp: resp, expires: resp.ExpiresAt,
		direct:   opts.Direct || resp.TURN == nil,
		renewURL: "http://" + net.JoinHostPort(api.HubAddress, strconv.Itoa(api.HubAPIPort)) + api.RenewPath,
		closeURL: "http://" + net.JoinHostPort(api.HubAddress, strconv.Itoa(api.HubAPIPort)) + api.CloseSessionPath,
		tracked:  map[io.Closer]struct{}{},
		done:     make(chan struct{}),
		started:  time.Now(),
	}
	s.address = netip.MustParseAddr(resp.Address)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if err := s.up(ctx, &priv); err != nil {
		// The hub already registered the session. If the tunnel came up
		// (ctx ended right after the handshake) the in-tunnel close frees the
		// hub's slot at once; without a tunnel there is no way to tell the
		// hub, which then reaps the session when it expires unrenewed.
		if s.dev != nil && s.handshook() {
			s.notifyClose()
		}
		s.end(nil)
		return nil, err
	}
	// Plane B comes up after plane A: its failure never fails the session.
	s.initP2P(prep, resp)
	prep = nil
	log.Info("wireguard session established", "session", resp.SessionID, "kind", resp.Kind,
		"address", resp.Address, "transport", s.transportName(), "expires", resp.ExpiresAt.Format(time.RFC3339))
	go func() {
		err := s.renewLoop()
		if err != nil {
			s.log.Warn("wireguard session ended", "session", s.resp.SessionID, "reason", ReasonOf(err), "error", err.Error())
		}
		s.end(err)
	}()
	return s, nil
}

func (s *Session) transportName() string {
	if s.direct {
		return "direct"
	}
	return "turn"
}

// checkResponse validates everything the hub told us before it is used to
// configure WireGuard.
func checkResponse(o Options, r *api.SessionResponse) error {
	bad := func(what string) error { return fmt.Errorf("wgclient: hub response: %s", what) }
	if r.Kind != o.Kind {
		return bad("wrong session kind")
	}
	if r.HubAddress != api.HubAddress {
		return bad("unexpected hub address")
	}
	if _, err := wgkey.ParsePublic(r.HubPublicKey); err != nil {
		return bad("invalid hub public key")
	}
	addr, err := netip.ParseAddr(r.Address)
	if err != nil || !addr.Is4() || !netip.MustParsePrefix(api.OverlayPrefix).Contains(addr) || addr == netip.MustParseAddr(api.HubAddress) {
		return bad("invalid session address")
	}
	if _, err := netip.ParseAddrPort(r.HubEndpoint); err != nil {
		return bad("invalid hub endpoint")
	}
	if r.MTU != 0 && (r.MTU < 576 || r.MTU > 1500) {
		return bad("invalid MTU")
	}
	if r.RenewAfterSeconds <= 0 {
		return bad("missing renewal interval")
	}
	if !o.Direct {
		if r.TURN == nil {
			return bad("no TURN credentials (is this an in-cluster hub? use direct mode)")
		}
		if _, err := turnServer(r.TURN.URLs, o.TURNServerOverride); err != nil {
			return bad(err.Error())
		}
		if r.TURN.Username == "" {
			return bad("empty TURN username")
		}
	}
	if o.Kind == api.KindClient {
		if r.SplicePort < 0 || r.SplicePort > 65535 {
			return bad("invalid splice port")
		}
	}
	for _, p := range r.AllowedPorts {
		if p < 1 || p > 65535 {
			return bad("invalid allowed port")
		}
	}
	return nil
}

// relayConfig converts TURN credentials to a relay.Config.
func (s *Session) relayConfig(t *api.TURNCredentials) (relay.Config, error) {
	server, err := turnServer(t.URLs, s.opts.TURNServerOverride)
	if err != nil {
		return relay.Config{}, err
	}
	peer, err := netip.ParseAddrPort(s.resp.HubEndpoint)
	if err != nil {
		return relay.Config{}, err
	}
	return relay.Config{
		Server: server, Username: t.Username, Password: t.Password,
		Realm: s.opts.Realm, Peer: netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()),
	}, nil
}

// up builds the netstack and WireGuard device, installs the transport and
// waits for the first handshake.
func (s *Session) up(ctx context.Context, priv *wgkey.PrivateKey) error {
	mtu := s.resp.MTU
	if mtu == 0 {
		mtu = api.MTU
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{s.address}, nil, mtu)
	if err != nil {
		return fmt.Errorf("wgclient: creating netstack: %w", err)
	}
	s.tnet = tnet
	s.bind = turnbind.New(nil)
	s.dev = device.NewDevice(tun, s.bind, &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { s.log.Warn("wireguard", "msg", fmt.Sprintf(f, a...)) },
	})
	hubHex, err := wgkey.Base64ToHex(s.resp.HubPublicKey)
	if err != nil {
		return err
	}
	s.hubHex = hubHex
	if err := s.dev.IpcSet("private_key=" + priv.Hex() + "\n"); err != nil {
		return fmt.Errorf("wgclient: configuring WireGuard: %w", err)
	}
	if err := s.dev.Up(); err != nil {
		return fmt.Errorf("wgclient: bringing WireGuard up: %w", err)
	}

	// The transport goes in before the peer is configured, so the very first
	// handshake initiation has somewhere to go.
	if s.direct {
		pc, err := net.ListenPacket("udp", ":0") //nolint:noctx // plain local socket.
		if err != nil {
			return fmt.Errorf("wgclient: opening UDP socket: %w", err)
		}
		s.pc = pc
		s.bind.Swap(pc)
	} else {
		rc, err := s.relayConfig(s.resp.TURN)
		if err != nil {
			return err
		}
		sup, err := relay.NewSupervisor(relay.SupervisorConfig{
			Bind: s.bind, Initial: &rc, StaleAfter: s.opts.StaleAfter,
			OnSwap: s.onSwap,
			Logf:   func(f string, a ...any) { s.log.Debug("relay", "msg", fmt.Sprintf(f, a...)) },
		})
		if err != nil {
			return err
		}
		s.sup = sup
		// ctx bounds only Create: the supervisor must outlive it (callers
		// cancel the Create context as soon as Create returns), so it runs on
		// the session's context, which ctx may cancel only while Start runs.
		sctx, cancelStart := context.WithCancel(s.ctx)
		stop := context.AfterFunc(ctx, cancelStart)
		err = sup.Start(sctx)
		if !stop() && err == nil {
			err = ctx.Err() // ctx ended right after Start: the supervisor is cancelled
		}
		if err != nil {
			cancelStart()
			return fmt.Errorf("wgclient: TURN relay: %w", err)
		}
	}

	peer := "public_key=" + hubHex + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=" + api.HubAddress + "/32\n" +
		"endpoint=" + s.resp.HubEndpoint + "\n" +
		"persistent_keepalive_interval=" + strconv.Itoa(api.PersistentKeepalive) + "\n"
	if err := s.dev.IpcSet(peer); err != nil {
		return fmt.Errorf("wgclient: configuring hub peer: %w", err)
	}
	return s.waitHandshake(ctx)
}

func (s *Session) onSwap(reason string) {
	s.swapMu.Lock()
	s.lastSwap = time.Now()
	s.swapMu.Unlock()
	if reason == relay.ReasonInitial {
		return // the peer is not configured yet
	}
	s.log.Info("relay swapped", "session", s.resp.SessionID, "reason", reason)
	if err := turnbind.Nudge(s.dev, s.hubHex, api.PersistentKeepalive); err != nil {
		s.log.Warn("keepalive nudge failed", "error", err.Error())
	}
}

func (s *Session) waitHandshake(ctx context.Context) error {
	deadline := time.NewTimer(s.opts.handshakeTimeout())
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if s.handshook() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wgclient: waiting for the WireGuard handshake: %w", ctx.Err())
		case <-deadline.C:
			return ErrHandshakeTimeout
		case <-tick.C:
		}
	}
}

// handshook reports whether the hub peer has completed a handshake.
func (s *Session) handshook() bool {
	out, err := s.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && v != "0" {
			return true
		}
	}
	return false
}

// renewLoop renews the session and returns why it ended: nil when the session
// was closed locally.
func (s *Session) renewLoop() error {
	s.mu.Lock()
	next := time.Duration(s.resp.RenewAfterSeconds) * time.Second
	s.mu.Unlock()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case <-timer.C:
		}
		rr, err := s.renew()
		if s.ctx.Err() != nil {
			return nil
		}
		if err == nil {
			s.swapMu.Lock()
			s.lastRenewOK = time.Now()
			s.swapMu.Unlock()
			s.mu.Lock()
			s.expires = rr.ExpiresAt
			if rr.RenewAfterSeconds > 0 {
				s.resp.RenewAfterSeconds = rr.RenewAfterSeconds
			}
			next = time.Duration(s.resp.RenewAfterSeconds) * time.Second
			s.mu.Unlock()
			timer.Reset(next)
			continue
		}
		var he *Error
		if errors.As(err, &he) && he.Denial() {
			return err
		}
		if derr := s.deadTunnel(err); derr != nil {
			return derr
		}
		s.mu.Lock()
		expired := time.Now().After(s.expires)
		s.mu.Unlock()
		if expired {
			return fmt.Errorf("%w: %v", ErrExpired, err)
		}
		s.log.Warn("renewal failed, will retry", "session", s.resp.SessionID, "error", err.Error())
		timer.Reset(s.opts.renewRetry())
	}
}

// lastActivity is the latest sign of life of the tunnel: the last WireGuard
// packet received, the last successful renewal (the hub never sends
// keepalives, so on an idle tunnel the renewal response is the only traffic),
// the last relay re-allocation (a recovering relay gets the same grace as a
// fresh one) or the start of the session.
func (s *Session) lastActivity() time.Time {
	t := s.started
	if s.bind != nil {
		if r := s.bind.LastReceive(); r.After(t) {
			t = r
		}
	}
	s.swapMu.Lock()
	if s.lastSwap.After(t) {
		t = s.lastSwap
	}
	if s.lastRenewOK.After(t) {
		t = s.lastRenewOK
	}
	s.swapMu.Unlock()
	return t
}

// deadTunnel decides whether a failed renewal means the tunnel itself is dead:
// the failure is at the transport level (not an HTTP answer from the hub, not a
// failure to obtain the credential) and nothing at all arrived through
// WireGuard for more than DeadAfter (2 * PersistentKeepalive). It then returns
// the error that ends the session at once, instead of retrying until the
// session expires minutes later.
func (s *Session) deadTunnel(err error) error {
	var he *Error
	var ce *credentialError
	if errors.As(err, &he) || errors.As(err, &ce) {
		return nil
	}
	silent := time.Since(s.lastActivity())
	if silent <= s.deadLimit() {
		return nil
	}
	return fmt.Errorf("%w: no WireGuard packet received for %s and the renewal failed: %v",
		ErrTunnelDead, silent.Round(time.Second), err)
}

// deadLimit is how long the tunnel may be silent before a failed renewal ends
// the session. It is DeadAfter, but never less than what one failed renewal
// plus its retry needs to elapse after the last successful one (renewAfter +
// renewTimeout + renewRetry): with the product defaults (60 s renewals, 15 s
// timeout, 5 s retry, 50 s DeadAfter) a single blip or timeout must not end an
// idle session that would have recovered.
func (s *Session) deadLimit() time.Duration {
	s.mu.Lock()
	renewAfter := time.Duration(s.resp.RenewAfterSeconds) * time.Second
	s.mu.Unlock()
	return max(s.opts.deadAfter(), renewAfter+s.opts.renewTimeout()+s.opts.renewRetry())
}

// credentialError marks a failure to obtain the bearer credential, which says
// nothing about the tunnel.
type credentialError struct{ err error }

func (e *credentialError) Error() string { return "obtaining credential: " + e.err.Error() }
func (e *credentialError) Unwrap() error { return e.err }

// renew performs one renewal with a fresh credential and applies TURN rotation.
func (s *Session) renew() (*api.RenewResponse, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.renewTimeout())
	defer cancel()
	token, err := s.opts.Credential(ctx, s.pubB64)
	if err != nil {
		return nil, &credentialError{err}
	}
	s.httpOnce()
	var rr api.RenewResponse
	if err := doJSON(ctx, s.tunnelHTTP, s.renewURL, token, api.RenewRequest{Posture: s.posture, Path: s.Path()}, &rr); err != nil {
		return nil, err
	}
	if s.opts.OnRenew != nil {
		s.opts.OnRenew(&rr)
	}
	if rr.TURN != nil && s.sup != nil {
		rc, err := s.relayConfig(rr.TURN)
		if err != nil {
			return nil, fmt.Errorf("hub rotated TURN credentials: %w", err)
		}
		if err := s.sup.Rotate(rc); err != nil {
			return nil, err
		}
		s.log.Info("TURN credentials rotated", "session", s.resp.SessionID)
	}
	s.log.Debug("session renewed", "session", s.resp.SessionID, "expires", rr.ExpiresAt.Format(time.RFC3339))
	return &rr, nil
}

// httpOnce lazily builds the HTTP client that dials through the tunnel.
func (s *Session) httpOnce() {
	s.httpInit.Do(func() {
		s.tunnelHTTP = &http.Client{
			Timeout: s.opts.renewTimeout(),
			Transport: &http.Transport{
				DialContext:       s.tnet.DialContext,
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
}

// Response returns the hub's session response (a copy).
func (s *Session) Response() api.SessionResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.resp
	r.AllowedPorts = append([]int(nil), r.AllowedPorts...)
	r.SSHHostKeys = append([]string(nil), r.SSHHostKeys...)
	r.ExpiresAt = s.expires
	return r
}

// Done is closed once the session has ended and been torn down.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended: nil while it runs and after a local Close,
// otherwise the hub's denial (*Error), ErrExpired, or a transport error.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// RelaySwaps counts TURN relay installs, including the first (0 in direct mode).
func (s *Session) RelaySwaps() uint64 {
	if s.sup == nil {
		return 0
	}
	return s.bind.Swaps()
}

// Dial opens a TCP connection to the device through the hub (client sessions
// only). The connection is closed when the session ends.
func (s *Session) Dial(ctx context.Context) (net.Conn, error) {
	if s.opts.Kind != api.KindClient {
		return nil, errors.New("wgclient: Dial needs a client session")
	}
	port := s.resp.SplicePort
	if port == 0 {
		port = api.HubSplicePort
	}
	c, err := s.tnet.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, s: s}
	if !s.track(tc) {
		_ = c.Close()
		return nil, ErrSessionClosed
	}
	return tc, nil
}

// Listen listens on the session's overlay address (device sessions only).
func (s *Session) Listen(port int) (net.Listener, error) {
	if s.opts.Kind != api.KindDevice {
		return nil, errors.New("wgclient: Listen needs a device session")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("wgclient: port %d out of range", port)
	}
	l, err := s.tnet.ListenTCPAddrPort(netip.AddrPortFrom(s.address, uint16(port)))
	if err != nil {
		return nil, err
	}
	tl := &trackedListener{Listener: l, s: s}
	if !s.track(tl) {
		_ = l.Close()
		return nil, ErrSessionClosed
	}
	return tl, nil
}

func (s *Session) track(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return false
	}
	s.tracked[c] = struct{}{}
	return true
}

func (s *Session) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.tracked, c)
	s.mu.Unlock()
}

// Close ends the session: it tells the hub (best effort), closes every
// connection and listener, and tears down WireGuard, the relay and the
// netstack. It is idempotent.
func (s *Session) Close() error {
	s.mu.Lock()
	already := s.ended
	s.mu.Unlock()
	if !already {
		s.notifyClose()
	}
	s.end(nil)
	return nil
}

// notifyClose tells the hub to end the session now. Failure is fine: the hub
// reaps sessions that stop renewing.
func (s *Session) notifyClose() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.httpOnce()
	_ = doJSON(ctx, s.tunnelHTTP, s.closeURL, "", nil, nil)
}

// end tears the session down exactly once and waits for the teardown.
func (s *Session) end(err error) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		s.err, s.ended = err, true
		open := make([]io.Closer, 0, len(s.tracked))
		for c := range s.tracked {
			open = append(open, c)
		}
		s.mu.Unlock()
		s.cancel()
		for _, c := range open {
			_ = c.Close()
		}
		if s.dev != nil {
			wgdev.Close(s.dev)
		}
		if s.sup != nil {
			_ = s.sup.Close()
		}
		if s.pc != nil {
			_ = s.pc.Close()
		}
		if s.p2pc != nil {
			s.p2pc.close()
		}
		close(s.done)
	})
	<-s.done
}

type trackedConn struct {
	net.Conn
	s    *Session
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.s.untrack(c) })
	return c.Conn.Close()
}

// CloseWrite half-closes the connection (the netstack TCP conn supports it).
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

type trackedListener struct {
	net.Listener
	s    *Session
	once sync.Once
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, s: l.s}
	if !l.s.track(tc) {
		_ = c.Close()
		return nil, ErrSessionClosed
	}
	return tc, nil
}

func (l *trackedListener) Close() error {
	l.once.Do(func() { l.s.untrack(l) })
	return l.Listener.Close()
}
