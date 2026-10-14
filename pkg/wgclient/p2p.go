package wgclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Timing of the client's plane B.
const (
	// p2pGatherTimeout bounds the STUN wait before the session request.
	p2pGatherTimeout = 1500 * time.Millisecond
	// p2pDialTimeout bounds the connect preamble over plane B.
	p2pDialTimeout = 3 * time.Second
	// p2pRetryAfter is how long plane B is skipped after it failed a dial.
	p2pRetryAfter = 30 * time.Second
)

// p2pPrep is what the client prepares before the session request: the plane-B
// key, the socket and the candidates that go into the offer.
type p2pPrep struct {
	priv  wgkey.PrivateKey
	pub   wgkey.PublicKey
	sock  *p2p.Socket
	cands []netip.AddrPort
}

func (pp *p2pPrep) close() {
	if pp == nil {
		return
	}
	pp.priv.Zero()
	_ = pp.sock.Close()
}

// prepareP2P opens the plane-B socket and gathers candidates. Any failure is
// logged and returns nil: the session then simply has no plane B.
func (o Options) prepareP2P(ctx context.Context) *p2pPrep {
	if !o.P2P || o.Kind != api.KindClient || o.Direct {
		return nil
	}
	log := o.logger()
	var conn net.PacketConn
	if o.P2PConn != nil {
		var err error
		if conn, err = o.P2PConn(); err != nil {
			log.Warn("plane B: socket unavailable", "error", err.Error())
			return nil
		}
	}
	sock, err := p2p.OpenSocket(p2p.SocketConfig{
		Conn: conn, Wrap: o.P2PWrapConn, Interfaces: o.P2PInterfaces,
		IncludeLoopback: o.P2PIncludeLoopback, Logger: log,
	})
	if err != nil {
		log.Warn("plane B: socket unavailable", "error", err.Error())
		return nil
	}
	priv, pub, err := wgkey.Generate()
	if err != nil {
		_ = sock.Close()
		return nil
	}
	stun := o.P2PSTUN
	if stun == "" {
		stun, _ = p2p.STUNServerFromHub(o.HubURL)
	}
	if stun != "" {
		if hp, err := p2p.STUNServer(nil, stun); err == nil {
			stun = hp
		}
	}
	gctx, cancel := context.WithTimeout(ctx, p2pGatherTimeout)
	defer cancel()
	cands := sock.Gather(gctx, stun)
	if len(cands) == 0 {
		log.Info("plane B: no candidates; continuing without it")
		priv.Zero()
		_ = sock.Close()
		return nil
	}
	return &p2pPrep{priv: priv, pub: pub, sock: sock, cands: cands}
}

func (pp *p2pPrep) offer() *api.P2POffer {
	return &api.P2POffer{WGPublicKey: pp.pub.Base64(), Candidates: p2p.Strings(pp.cands)}
}

// p2pClient is plane B of one client session.
type p2pClient struct {
	s       *Session
	pl      *p2p.Plane
	grant   api.P2PGrant
	devPub  wgkey.PublicKey
	devAddr netip.Addr
	budget  time.Duration

	punchedAt   atomic.Int64 // unix nanos of the last (re)punch
	skipUntil   atomic.Int64 // unix nanos: plane B is not tried before this
	closeOnce   sync.Once
	directDials atomic.Int64
}

// initP2P turns the hub's answer into a running plane. It never fails the
// session: on any problem plane B is dropped and the splice remains.
func (s *Session) initP2P(pp *p2pPrep, resp api.SessionResponse) {
	if pp == nil {
		return
	}
	g := resp.P2P
	if g == nil {
		s.log.Debug("plane B: the device did not take the pair; using the hub splice")
		pp.close()
		return
	}
	if err := s.checkGrant(pp, resp, g); err != nil {
		s.log.Warn("plane B: ignoring the hub's grant", "error", err.Error())
		pp.close()
		return
	}
	selfA, _ := netip.ParseAddr(resp.Address)
	self, _ := p2p.AddrFor(selfA)
	devPub, _ := wgkey.ParsePublic(g.DeviceWGPublicKey)
	devAddr, _ := netip.ParseAddr(g.DeviceAddress)
	cands, _ := p2p.ParseCandidates(g.DeviceCandidates)
	cands = p2p.ProbeTargets(cands, s.opts.P2PIncludeLoopback)
	pl, err := p2p.NewPlane(p2p.PlaneConfig{
		Socket: pp.sock, PrivateKey: pp.priv, Address: self, Logger: s.log, ProbeInterval: s.opts.P2PProbeInterval,
	})
	if err != nil {
		s.log.Warn("plane B: cannot bring the device up", "error", err.Error())
		pp.close()
		return
	}
	pc := &p2pClient{s: s, pl: pl, grant: *g, devPub: devPub, devAddr: devAddr.Unmap(), budget: s.opts.P2PBudget}
	if err := pl.AddPeer(devPub, pc.devAddr, p2p.PeerOptions{Candidates: cands, Initiator: true, Budget: pc.budget}); err != nil {
		s.log.Warn("plane B: cannot add the device peer", "error", err.Error())
		pl.Close()
		return
	}
	pc.punchedAt.Store(time.Now().UnixNano())
	s.p2pc = pc
	s.log.Info("plane B: probing the device", "pair", g.PairID, "candidates", len(cands))
}

// checkGrant validates everything the hub said about plane B before it is used.
func (s *Session) checkGrant(pp *p2pPrep, resp api.SessionResponse, g *api.P2PGrant) error {
	selfA, err := netip.ParseAddr(resp.Address)
	if err != nil {
		return err
	}
	self, err := p2p.AddrFor(selfA)
	if err != nil {
		return err
	}
	switch {
	case g.PairID == "" || len(g.PairID) > 64:
		return errors.New("invalid pair id")
	case g.ClientAddress != self.String():
		return errors.New("the grant is for another client address")
	case g.TTLSeconds <= 0:
		return errors.New("grant without a lifetime")
	}
	dev, err := netip.ParseAddr(g.DeviceAddress)
	if err != nil || !p2p.ValidPlaneBAddr(dev) || dev.Unmap() == self {
		return errors.New("invalid device address")
	}
	k, err := wgkey.ParsePublic(g.DeviceWGPublicKey)
	if err != nil || k == pp.pub {
		return errors.New("invalid device key")
	}
	if _, err := p2p.ParseCandidates(g.DeviceCandidates); err != nil {
		return err
	}
	return nil
}

func (pc *p2pClient) close() {
	pc.closeOnce.Do(pc.pl.Close)
}

// Path is the current data path of a client session: api.PathDirectLAN or
// api.PathDirect while the plane-B session to the device is established,
// api.PathHub otherwise (device sessions: "").
func (s *Session) Path() string {
	if s.opts.Kind != api.KindClient {
		return ""
	}
	if pc := s.p2pc; pc != nil {
		if st := pc.pl.Status(pc.devPub); st.Established && st.Path != "" {
			return st.Path
		}
	}
	return api.PathHub
}

// P2PStatus is the observable state of a session's plane B.
type P2PStatus struct {
	// Enabled is true when the device accepted the pair.
	Enabled     bool
	Established bool
	Path        string
	Endpoint    netip.AddrPort
	PairID      string
	// DirectDials counts connections made over plane B.
	DirectDials int
}

// P2PStatus reports plane B (zero value: the session has none).
func (s *Session) P2PStatus() P2PStatus {
	pc := s.p2pc
	if pc == nil {
		return P2PStatus{}
	}
	st := pc.pl.Status(pc.devPub)
	return P2PStatus{Enabled: true, Established: st.Established, Path: s.Path(), Endpoint: st.Endpoint, PairID: pc.grant.PairID, DirectDials: int(pc.directDials.Load())}
}

// DialService opens a TCP connection to the session's service on the device.
// With plane B it prefers the direct path: it gives plane B up to
// Options.P2PRace (default api.P2PDialRaceMillis) to establish, dials the
// device's connect port over it and returns that connection; if plane B is
// missing, does not come up in time or fails, it falls back to the hub splice
// (Dial) as in phase 1. After a plane-B failure the direct path is skipped for
// a while, so a blocked UDP path costs one race, not one per connection.
func (s *Session) DialService(ctx context.Context, service string) (net.Conn, error) {
	if s.opts.Kind != api.KindClient {
		return nil, errors.New("wgclient: DialService needs a client session")
	}
	s.mu.Lock()
	bound := s.resp.Service
	s.mu.Unlock()
	if service != "" && bound != "" && service != bound {
		return nil, fmt.Errorf("wgclient: this session is bound to service %q, not %q", bound, service)
	}
	if bound == "" && service != "" {
		return nil, errors.New("wgclient: this session is bound to a raw port, not a named service")
	}
	if c := s.dialDirect(ctx, bound); c != nil {
		return c, nil
	}
	return s.Dial(ctx)
}

func (s *Session) dialDirect(ctx context.Context, service string) net.Conn {
	pc := s.p2pc
	if pc == nil || service == "" {
		return nil
	}
	now := time.Now()
	if now.UnixNano() < pc.skipUntil.Load() {
		return nil
	}
	if !pc.pl.Status(pc.devPub).Established {
		// A punch that ran out of budget is restarted for this dial.
		budget := pc.budget
		if budget <= 0 {
			budget = p2p.DefaultBudget
		}
		if now.Sub(time.Unix(0, pc.punchedAt.Load())) > budget {
			pc.punchedAt.Store(now.UnixNano())
			pc.pl.Punch(pc.devPub, budget)
		}
		race := s.opts.P2PRace
		if race <= 0 {
			race = api.P2PDialRaceMillis * time.Millisecond
		}
		wctx, cancel := context.WithTimeout(ctx, race)
		ok := pc.pl.WaitEstablished(wctx, pc.devPub)
		cancel()
		if !ok {
			s.log.Info("plane B did not come up in time; using the hub splice", "race", race.String())
			pc.skipUntil.Store(time.Now().Add(p2pRetryAfter).UnixNano())
			return nil
		}
	}
	dctx, cancel := context.WithTimeout(ctx, p2pDialTimeout)
	defer cancel()
	raw, err := pc.pl.DialContext(dctx, "tcp", net.JoinHostPort(pc.devAddr.String(), strconv.Itoa(api.AgentConnectPort)))
	if err != nil {
		s.log.Info("plane B dial failed; using the hub splice", "error", err.Error())
		pc.skipUntil.Store(time.Now().Add(p2pRetryAfter).UnixNano())
		return nil
	}
	wrapped, resp, err := connectproto.Handshake(raw, api.ConnectRequest{Service: service}, p2pDialTimeout)
	if err != nil || !resp.OK {
		_ = raw.Close()
		reason := resp.Reason
		if err != nil {
			reason = err.Error()
		}
		s.log.Info("plane B connect refused; using the hub splice", "reason", reason)
		pc.skipUntil.Store(time.Now().Add(p2pRetryAfter).UnixNano())
		return nil
	}
	tc := &trackedConn{Conn: wrapped, s: s}
	if !s.track(tc) {
		_ = raw.Close()
		return nil
	}
	pc.directDials.Add(1)
	return tc
}
