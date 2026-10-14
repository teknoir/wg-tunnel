package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// gatherTimeout bounds the STUN wait of the first candidate gathering.
const gatherTimeout = 1500 * time.Millisecond

// paramsWait bounds how long a grant ack waits for the first gathering.
const paramsWait = 1200 * time.Millisecond

// planeB is the device side of plane B for one device session: a WireGuard
// device on its own UDP socket, one peer per granted client, and the connect
// listener on the device's plane-B address.
type planeB struct {
	log     *slog.Logger
	pl      *p2p.Plane
	connect *connectServer
	pub     wgkey.PublicKey
	addr    netip.Addr
	// grace keeps a removed peer for a moment so that the FIN/RST of its
	// closed connections is delivered.
	grace time.Duration
	// allowLoopback lets loopback candidates through (tests with both ends on
	// one machine).
	allowLoopback bool
}

// newPlaneB opens the socket, brings the plane up and starts gathering
// candidates. The device's plane-B address is derived from its plane-A
// address (see p2p.AddrFor).
func (a *Agent) newPlaneB(resp api.SessionResponse, priv wgkey.PrivateKey, connect *connectServer) (*planeB, error) {
	overlay, err := netip.ParseAddr(resp.Address)
	if err != nil {
		return nil, fmt.Errorf("session address: %w", err)
	}
	addr, err := p2p.AddrFor(overlay)
	if err != nil {
		return nil, err
	}
	var conn net.PacketConn
	if a.cfg.P2PConn != nil {
		if conn, err = a.cfg.P2PConn(); err != nil {
			return nil, fmt.Errorf("plane B socket: %w", err)
		}
	}
	sock, err := p2p.OpenSocket(p2p.SocketConfig{
		Port: a.cfg.P2PPort, Conn: conn, Wrap: a.cfg.P2PWrapConn, Interfaces: a.cfg.P2PInterfaces,
		IncludeLoopback: a.cfg.P2PIncludeLoopback, Logger: a.log,
	})
	if err != nil {
		return nil, err
	}
	pl, err := p2p.NewPlane(p2p.PlaneConfig{
		Socket: sock, PrivateKey: priv, Address: addr, Logger: a.log, ProbeInterval: a.cfg.P2PProbeInterval,
	})
	if err != nil {
		_ = sock.Close()
		return nil, err
	}
	var turnURLs []string
	if resp.TURN != nil {
		turnURLs = resp.TURN.URLs
	}
	stun, serr := p2p.STUNServer(turnURLs, a.cfg.P2PSTUN)
	if serr != nil {
		a.log.Info("no STUN server for plane B; offering host candidates only", "reason", serr.Error())
		stun = ""
	}
	pl.StartGather(stun, gatherTimeout)
	return &planeB{log: a.log, pl: pl, connect: connect, pub: pl.PublicKey(), addr: addr, grace: p2p.DefaultRemoveGrace, allowLoopback: a.cfg.P2PIncludeLoopback}, nil
}

// params returns the plane-B parameters of the GrantAck.
func (pb *planeB) params(ctx context.Context) (pub, addr string, cands []string) {
	cctx, cancel := context.WithTimeout(ctx, paramsWait)
	defer cancel()
	return pb.pub.Base64(), pb.addr.String(), p2p.Strings(pb.pl.Candidates(cctx))
}

// hooks are the GrantStore hooks of this plane. They run under the store's
// lock and never call back into it.
func (pb *planeB) hooks() GrantHooks {
	return GrantHooks{
		Add: func(g api.Grant) error {
			pub, err := wgkey.ParsePublic(g.ClientWGPublicKey)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(g.ClientAddress)
			if err != nil {
				return err
			}
			cands, err := p2p.ParseCandidates(g.ClientCandidates)
			if err != nil {
				return err
			}
			// The candidates are the client's word: never probe this host itself.
			cands = p2p.ProbeTargets(cands, pb.allowLoopback)
			if err := pb.pl.AddPeer(pub, addr, p2p.PeerOptions{Candidates: cands}); err != nil {
				return err
			}
			pb.log.Info("plane B peer granted", "pair", g.PairID, "services", g.Services, "candidates", len(cands))
			return nil
		},
		Remove: func(g api.Grant) {
			n := pb.connect.ClosePair(g.PairID)
			if pub, err := wgkey.ParsePublic(g.ClientWGPublicKey); err == nil {
				pb.pl.RemovePeer(pub, pb.grace)
			}
			pb.log.Info("plane B peer removed", "pair", g.PairID, "connections_closed", n)
		},
	}
}

// unavailableHooks refuse every grant: the agent advertised plane B but could
// not bring it up, so the hub gets no acceptance and keeps to the splice.
func unavailableHooks() GrantHooks {
	return GrantHooks{Add: func(api.Grant) error { return errPlaneBDown }}
}

var errPlaneBDown = fmt.Errorf("plane B is not available on this agent")

// serve runs the connect listener on ln until ctx is done.
func (pb *planeB) serve(ctx context.Context, ln net.Listener, grants *GrantStore, wg *sync.WaitGroup) {
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		defer wg.Done()
		pb.connect.ServeB(ctx, ln, grants, wg)
	}()
}

// close stops the plane.
func (pb *planeB) close() { pb.pl.Close() }

// P2PStatus is the observable state of the agent's plane B.
type P2PStatus struct {
	// Up is true while a device session has a plane B.
	Up bool
	// Peers is the number of installed (granted) client peers.
	Peers int
	// Candidates are the addresses the agent offers.
	Candidates []string
}

// grantHolder lets the session-renewal callback (set when the session is
// created) reach the grant store that serveServices builds afterwards.
type grantHolder struct {
	mu     sync.Mutex
	grants *GrantStore
	log    *slog.Logger
}

func (h *grantHolder) set(g *GrantStore) {
	h.mu.Lock()
	h.grants = g
	h.mu.Unlock()
}

// applyBackstop applies the full grant set a device renewal carried: the
// backstop for a control push that was lost. The same ordering rules apply as
// to a push, so an old or duplicate set is harmless.
func (h *grantHolder) applyBackstop(set api.GrantSet) {
	h.mu.Lock()
	g := h.grants
	h.mu.Unlock()
	if g == nil {
		return
	}
	res, err := g.Apply(set)
	switch {
	case err != nil:
		h.log.Debug("renewal grant set not applied", "error", err.Error())
	case len(res.Added)+len(res.Removed) > 0:
		h.log.Info("renewal grant set changed the grants", "added", len(res.Added), "removed", len(res.Removed))
	}
}
