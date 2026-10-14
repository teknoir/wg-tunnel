package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
)

// Timeouts of the connect listener.
const (
	preambleTimeout = 5 * time.Second
	answerTimeout   = 5 * time.Second
)

// capabilities are what this agent advertises in DeviceSessionRequest.
func capabilities() []string { return []string{api.CapServices, api.CapControl} }

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
	global  chan struct{} // concurrent connections in total
	hubAddr netip.Addr
	// preambleTO bounds the wait for the preamble line.
	preambleTO time.Duration

	mu     sync.Mutex
	specs  map[string]api.ServiceSpec
	active map[*activeConn]struct{}
	counts map[string]int
	closed bool
}

type activeConn struct {
	spec  api.ServiceSpec
	close func()
}

func newConnectServer(log *slog.Logger, policy *TargetPolicy, dialTimeout time.Duration, perService, global int) *connectServer {
	return &connectServer{
		log: log, policy: policy, dialTO: dialTimeout, perSvc: perService,
		global:  make(chan struct{}, global),
		hubAddr: netip.MustParseAddr(api.HubAddress), preambleTO: preambleTimeout,
		specs:  map[string]api.ServiceSpec{api.ServiceSSHID: implicitSSH},
		active: map[*activeConn]struct{}{},
		counts: map[string]int{},
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

// reserve looks the service up and takes one of its connection slots.
func (s *connectServer) reserve(id string) (api.ServiceSpec, string) {
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
	}
	s.counts[id]++
	return sp, ""
}

func (s *connectServer) release(id string) {
	s.mu.Lock()
	if s.counts[id] > 0 {
		s.counts[id]--
	}
	s.mu.Unlock()
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

// handle serves one connection: preamble, validation, dial, relay.
func (s *connectServer) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err != nil || ap.Addr().Unmap() != s.hubAddr {
		// Plane A has exactly one peer, the hub.
		s.log.Warn("connect from an address other than the hub", "remote", c.RemoteAddr().String())
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(s.preambleTO))
	br := connectproto.NewReader(c)
	req, err := connectproto.ReadRequest(br)
	if err != nil {
		s.log.Warn("bad connect preamble", "error", err.Error())
		if !errors.Is(err, connectproto.ErrTooLong) && !isTimeout(err) {
			s.answer(c, api.ConnectResponse{Reason: api.ReasonBadRequest})
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	select {
	case s.global <- struct{}{}:
		defer func() { <-s.global }()
	default:
		s.log.Warn("too many concurrent connections; refusing one", "service", req.Service)
		s.answer(c, api.ConnectResponse{Reason: api.ReasonSessionLimit})
		return
	}
	spec, reason := s.reserve(req.Service)
	if reason != "" {
		s.log.Warn("connect refused", "service", req.Service, "reason", reason, "as", req.As)
		s.answer(c, api.ConnectResponse{Reason: reason})
		return
	}
	defer s.release(spec.ID)

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
		s.answer(c, api.ConnectResponse{Reason: reason})
		return
	}
	defer func() { _ = local.Close() }()

	ac := &activeConn{spec: spec, close: func() { _ = c.Close(); _ = local.Close() }}
	if !s.register(ac) {
		s.log.Warn("service changed while connecting; refusing", "service", spec.ID)
		s.answer(c, api.ConnectResponse{Reason: api.ReasonServiceUnknown})
		return
	}
	defer s.unregister(ac)
	stop := context.AfterFunc(ctx, ac.close) // session over: unblock both copies
	defer stop()

	s.answer(c, api.ConnectResponse{OK: true})
	s.log.Debug("relaying connection", "service", spec.ID, "as", req.As)
	pipe(connectproto.Wrap(c, br), local)
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
func (a *Agent) serveServices(ctx context.Context, sess serviceSession, resp api.SessionResponse, wg *sync.WaitGroup) bool {
	connect := newConnectServer(a.log, a.target, a.cfg.DialTimeout, a.cfg.MaxConnsPerService, a.cfg.MaxConns)
	connect.SetServices(resp.Services)
	grants := NewGrantStore(GrantStoreOptions{})
	control := newControlServer(a.log, connect, grants)

	connLn, err := sess.Listen(api.AgentConnectPort)
	if err != nil {
		a.log.Error("cannot listen on the connect port", "port", api.AgentConnectPort, "error", err.Error())
		return false
	}
	ctlLn, err := sess.Listen(api.AgentControlPort)
	if err != nil {
		a.log.Error("cannot listen on the control port", "port", api.AgentControlPort, "error", err.Error())
		_ = connLn.Close()
		return false
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
}
