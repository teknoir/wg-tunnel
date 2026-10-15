package agent

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Timeouts of the connect listener.
const (
	preambleTimeout = 5 * time.Second
	answerTimeout   = 5 * time.Second
)

// capabilities are what this agent advertises in DeviceSessionRequest.
// baseCapabilities are always advertised by this agent version.
func baseCapabilities() []string { return []string{api.CapServices, api.CapControl} }

// implicitSSH is the always-present ssh service.
var implicitSSH = api.ServiceSpec{ID: api.ServiceSSHID, Kind: api.ServiceKindSSH, Protocol: api.ProtocolTCP, Description: "SSH"}

// connectServer is the plane-A connect listener of one device session
// (api.AgentConnectPort) plus the set of services it serves. The set is
// replaced as a whole: by the session response and by the hub's control RPC.
type connectServer struct {
	log     *slog.Logger
	policy  *TargetPolicy
	dialTO  time.Duration
	perSvc  int           // concurrent connections per service
	perPair int           // concurrent plane-B connections per pair
	global  chan struct{} // concurrent connections in total
	hubAddr netip.Addr
	// preambleTO bounds the wait for the preamble line.
	preambleTO time.Duration

	mu     sync.Mutex
	specs  map[string]api.ServiceSpec
	active map[*activeConn]struct{}
	counts map[string]int
	pairs  map[string]int
	// countsB counts the plane-B connections per service (subset of counts).
	countsB map[string]int
	closed  bool
}

type activeConn struct {
	spec api.ServiceSpec
	// pair is the plane-B pair the connection belongs to ("" on plane A).
	pair  string
	close func()
}

func newConnectServer(log *slog.Logger, policy *TargetPolicy, dialTimeout time.Duration, perService, global int) *connectServer {
	return &connectServer{
		log: log, policy: policy, dialTO: dialTimeout, perSvc: perService, perPair: min(DefaultMaxConnsPerPair, perService),
		global:  make(chan struct{}, global),
		hubAddr: netip.MustParseAddr(api.HubAddress), preambleTO: preambleTimeout,
		specs:   map[string]api.ServiceSpec{api.ServiceSSHID: implicitSSH},
		active:  map[*activeConn]struct{}{},
		counts:  map[string]int{},
		pairs:   map[string]int{},
		countsB: map[string]int{},
	}
}

// SetServices replaces the served set. Invalid specs are dropped (the agent
// fails closed rather than refusing the hub's whole update). Open relays whose
// service is gone, or now reaches somewhere else, are closed at once.
func (s *connectServer) SetServices(in []api.ServiceSpec) {
	valid, dropped := svc.Sanitize(in)
	for _, err := range dropped {
		s.log.Warn("ignoring an invalid service", "error", err.Error())
	}
	next := map[string]api.ServiceSpec{api.ServiceSSHID: implicitSSH}
	for _, sp := range valid {
		if sp.ID == api.ServiceSSHID {
			continue // fixed; the implicit one is the only ssh service
		}
		next[sp.ID] = sp
	}
	var stale []*activeConn
	s.mu.Lock()
	s.specs = next
	for c := range s.active {
		if cur, ok := next[c.spec.ID]; !ok || !svc.Equivalent(cur, c.spec) {
			stale = append(stale, c)
		}
	}
	s.mu.Unlock()
	for _, c := range stale {
		s.log.Info("closing a connection: its service was removed or changed", "service", c.spec.ID)
		c.close()
	}
}

// Services returns the served set (including ssh), for tests and status.
func (s *connectServer) Services() []api.ServiceSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]api.ServiceSpec, 0, len(s.specs))
	for _, sp := range s.specs {
		out = append(out, sp)
	}
	return out
}

// Active is the number of relayed connections.
func (s *connectServer) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// reserve looks the service up and takes one of its connection slots (and,
// on plane B, one of the pair's).
func (s *connectServer) reserve(id, pair string) (api.ServiceSpec, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.specs[id]
	switch {
	case s.closed:
		return sp, api.ReasonServiceUnknown
	case !ok:
		return sp, api.ReasonServiceUnknown
	case s.perSvc > 0 && s.counts[id] >= s.perSvc:
		return sp, api.ReasonSessionLimit
	case pair != "" && s.perPair > 0 && s.pairs[pair] >= s.perPair:
		return sp, api.ReasonSessionLimit
	case pair != "" && s.perSvc > 0 && s.countsB[id] >= s.perSvc-s.perSvc/4:
		// plane B keeps out of the last quarter of the service's slots
		return sp, api.ReasonSessionLimit
	}
	s.counts[id]++
	if pair != "" {
		s.pairs[pair]++
		s.countsB[id]++
	}
	return sp, ""
}

func (s *connectServer) release(id, pair string) {
	s.mu.Lock()
	if s.counts[id] > 0 {
		s.counts[id]--
	}
	if pair != "" && s.countsB[id] > 0 {
		s.countsB[id]--
	}
	if pair != "" && s.pairs[pair] > 0 {
		s.pairs[pair]--
		if s.pairs[pair] == 0 {
			delete(s.pairs, pair)
		}
	}
	s.mu.Unlock()
}

// ClosePair closes every plane-B connection of the pair at once and returns
// how many it closed. New connections of a removed pair are refused by the
// grant check, so this only has to end the live ones.
func (s *connectServer) ClosePair(pair string) int {
	var victims []*activeConn
	s.mu.Lock()
	for c := range s.active {
		if c.pair == pair {
			victims = append(victims, c)
		}
	}
	s.mu.Unlock()
	for _, c := range victims {
		c.close()
	}
	return len(victims)
}

// register tracks a relay, unless its service changed while it was dialling.
func (s *connectServer) register(c *activeConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.specs[c.spec.ID]
	if s.closed || !ok || !svc.Equivalent(cur, c.spec) {
		return false
	}
	s.active[c] = struct{}{}
	return true
}

func (s *connectServer) unregister(c *activeConn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

// Close refuses new connections and closes every relay.
func (s *connectServer) Close() {
	s.mu.Lock()
	s.closed = true
	all := make([]*activeConn, 0, len(s.active))
	for c := range s.active {
		all = append(all, c)
	}
	s.mu.Unlock()
	for _, c := range all {
		c.close()
	}
}

// Serve accepts connections until ln is closed.
func (s *connectServer) Serve(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c)
		}()
	}
}

func (s *connectServer) answer(c net.Conn, resp api.ConnectResponse) {
	_ = c.SetWriteDeadline(time.Now().Add(answerTimeout))
	_ = connectproto.WriteResponse(c, resp)
	_ = c.SetWriteDeadline(time.Time{})
}

// handle serves one plane-A connection: only the hub's overlay address may
// connect, and it vouches for the service (it checked the user).
func (s *connectServer) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err != nil || ap.Addr().Unmap() != s.hubAddr {
		// Plane A has exactly one peer, the hub.
		s.log.Warn("connect from an address other than the hub", "remote", c.RemoteAddr().String())
		return
	}
	br, req, ok := s.readPreamble(c)
	if !ok {
		return
	}
	s.relay(ctx, c, br, req, "", nil)
}

// handleB serves one plane-B connection. WireGuard's cryptokey routing makes
// the source address trustworthy (a peer can only send from its allowed /32),
// and this handler accepts only sources that are the client address of a live
// grant, and only the services that grant lists. Plane A and plane B have
// separate handlers on purpose: nothing a plane-B peer sends is ever treated
// as the hub's word.
func (s *connectServer) handleB(ctx context.Context, c net.Conn, grants *GrantStore) {
	defer func() { _ = c.Close() }()
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	g, ok := grants.ByClientAddress(ap.Addr())
	if !ok {
		s.log.Warn("plane B connect from an address without a grant", "remote", ap.String())
		return
	}
	br, req, ok := s.readPreamble(c)
	if !ok {
		return
	}
	if !slices.Contains(g.Services, req.Service) {
		s.log.Warn("plane B connect refused: service not granted", "pair", g.PairID, "service", req.Service)
		s.answer(c, api.ConnectResponse{Reason: api.ReasonServiceDenied})
		return
	}
	s.relay(ctx, c, br, req, g.PairID, func() bool { return grants.Allows(g.PairID, req.Service) })
}

// readPreamble reads the ConnectRequest line.
func (s *connectServer) readPreamble(c net.Conn) (*bufio.Reader, api.ConnectRequest, bool) {
	_ = c.SetReadDeadline(time.Now().Add(s.preambleTO))
	br := connectproto.NewReader(c)
	req, err := connectproto.ReadRequest(br)
	if err != nil {
		s.log.Warn("bad connect preamble", "error", err.Error())
		if !errors.Is(err, connectproto.ErrTooLong) && !isTimeout(err) {
			s.answer(c, api.ConnectResponse{Reason: api.ReasonBadRequest})
		}
		return nil, req, false
	}
	_ = c.SetReadDeadline(time.Time{})
	return br, req, true
}

// relay validates the service, dials its target and relays. pair is the
// plane-B pair ("" on plane A); stillAllowed, when set, is checked once more
// after the connection is registered, so that a grant removed meanwhile cannot
// leave a relay behind (the removal closes only registered relays).
func (s *connectServer) relay(ctx context.Context, c net.Conn, br *bufio.Reader, req api.ConnectRequest, pair string, stillAllowed func() bool) {
	select {
	case s.global <- struct{}{}:
	default:
		s.log.Warn("too many concurrent connections; refusing one", "service", req.Service)
		s.answer(c, api.ConnectResponse{Reason: api.ReasonSessionLimit})
		return
	}
	// What this connection holds is given back in reverse order, and BEFORE a
	// refusal is answered: the client may retry, or connect to another
	// service, the moment it reads the answer, and must not find the slots of
	// the connection it was just refused still taken.
	var held []func()
	finish := func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i]()
		}
		held = nil
	}
	defer finish()
	refuse := func(reason string) {
		finish()
		s.answer(c, api.ConnectResponse{Reason: reason})
	}
	held = append(held, func() { <-s.global })

	spec, reason := s.reserve(req.Service, pair)
	if reason != "" {
		s.log.Warn("connect refused", "service", req.Service, "reason", reason, "as", req.As)
		refuse(reason)
		return
	}
	held = append(held, func() { s.release(spec.ID, pair) })

	dctx, cancel := context.WithTimeout(ctx, s.dialTO)
	local, err := s.policy.DialService(dctx, spec, s.dialTO)
	cancel()
	if err != nil {
		// The reason on the wire is coarse; the detail stays in this log.
		reason := api.ReasonInternal
		if errors.Is(err, ErrDenied) {
			reason = api.ReasonServiceDenied
		}
		s.log.Warn("service target refused or unreachable", "service", spec.ID, "reason", reason, "error", err.Error())
		refuse(reason)
		return
	}
	held = append(held, func() { _ = local.Close() })

	ac := &activeConn{spec: spec, pair: pair, close: func() { _ = c.Close(); _ = local.Close() }}
	if !s.register(ac) {
		s.log.Warn("service changed while connecting; refusing", "service", spec.ID)
		refuse(api.ReasonServiceUnknown)
		return
	}
	held = append(held, func() { s.unregister(ac) })
	if stillAllowed != nil && !stillAllowed() {
		s.log.Warn("grant removed while connecting; refusing", "service", spec.ID, "pair", pair)
		refuse(api.ReasonServiceDenied)
		return
	}
	stop := context.AfterFunc(ctx, ac.close) // session over: unblock both copies
	held = append(held, func() { stop() })

	s.answer(c, api.ConnectResponse{OK: true})
	s.log.Debug("relaying connection", "service", spec.ID, "as", req.As, "pair", pair)
	pipe(connectproto.Wrap(c, br), local)
}

// ServeB accepts plane-B connections until ln is closed.
func (s *connectServer) ServeB(ctx context.Context, ln net.Listener, grants *GrantStore, wg *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleB(ctx, c, grants)
		}()
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// serveServices starts the connect and control listeners of a session (the
// phase-1 per-port listeners stay for compatibility, see serve). It returns
// false when a listener cannot be opened: the agent advertised the
// capabilities, so the session is useless to the hub and is ended (the agent
// retries with a new one).
func (a *Agent) serveServices(ctx context.Context, sess serviceSession, resp api.SessionResponse, p2pPriv *wgkey.PrivateKey, holder *grantHolder, wg *sync.WaitGroup) bool {
	connect := newConnectServer(a.log, a.target, a.cfg.DialTimeout, a.cfg.MaxConnsPerService, a.cfg.MaxConns)
	if a.cfg.MaxConnsPerPair > 0 {
		connect.perPair = min(a.cfg.MaxConnsPerPair, a.cfg.MaxConnsPerService)
	}
	connect.SetServices(resp.Services)
	// Plane B, when this agent offers it and the hub accepted the key.
	var pb *planeB
	if a.cfg.P2P && p2pPriv != nil {
		var err error
		if pb, err = a.newPlaneB(resp, *p2pPriv, connect); err != nil {
			a.log.Warn("plane B is not available; clients will use the hub splice", "error", err.Error())
			pb = nil
		}
	}
	var bLn net.Listener
	if pb != nil {
		var err error
		if bLn, err = pb.pl.Listen(api.AgentConnectPort); err != nil {
			a.log.Warn("plane B listener failed; clients will use the hub splice", "error", err.Error())
			pb.close()
			pb = nil
		}
	}
	opts := GrantStoreOptions{Hooks: unavailableHooks()}
	if pb != nil {
		opts.Hooks = pb.hooks()
	}
	grants := NewGrantStore(opts)
	if holder != nil {
		holder.set(grants)
	}
	a.grants.Store(grants)
	control := newControlServer(a.log, connect, grants, pb)
	control.revoke = &revokeTarget{sessionID: resp.SessionID, end: sess.EndWith}

	closePlaneB := func() {
		if pb != nil {
			pb.close()
		}
	}
	connLn, err := sess.Listen(api.AgentConnectPort)
	if err != nil {
		a.log.Error("cannot listen on the connect port", "port", api.AgentConnectPort, "error", err.Error())
		closePlaneB()
		return false
	}
	ctlLn, err := sess.Listen(api.AgentControlPort)
	if err != nil {
		a.log.Error("cannot listen on the control port", "port", api.AgentControlPort, "error", err.Error())
		_ = connLn.Close()
		closePlaneB()
		return false
	}
	if pb != nil {
		pb.serve(ctx, bLn, grants, wg)
		a.pb.Store(pb)
	}
	a.log.Info("serving services", "count", len(connect.Services()), "connect_port", api.AgentConnectPort, "control_port", api.AgentControlPort)
	wg.Add(2)
	go func() {
		defer wg.Done()
		connect.Serve(ctx, connLn, wg)
	}()
	go func() {
		defer wg.Done()
		control.Serve(ctx, ctlLn, wg)
		<-ctx.Done()
		// Session over (or shutting down): fail closed.
		connect.Close()
		grants.DropAll()
		a.grants.CompareAndSwap(grants, nil)
		if pb != nil {
			a.pb.CompareAndSwap(pb, nil)
			pb.close()
		}
	}()
	wg.Add(1)
	go func() { // lease expiry of the plane-B grants (wave B)
		defer wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				grants.Sweep()
			}
		}
	}()
	return true
}

// serviceSession is the part of wgclient.Session serveServices needs.
type serviceSession interface {
	Listen(port int) (net.Listener, error)
	EndWith(err error)
}
