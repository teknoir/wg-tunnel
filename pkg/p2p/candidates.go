package p2p

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// SocketConfig configures OpenSocket. Zero values select the defaults.
type SocketConfig struct {
	// Port is the UDP port to bind (0: any).
	Port int
	// Conn is an already open socket (the NAT lab and tests open sockets in
	// other network namespaces). Port is ignored then.
	Conn net.PacketConn
	// Wrap lets a test wrap the raw socket (for example to drop packets).
	Wrap func(net.PacketConn) net.PacketConn
	// Interfaces lists the local addresses for host candidates (default: the
	// addresses of all up interfaces). Tests inject fakes.
	Interfaces func() ([]netip.Addr, error)
	// IncludeLoopback also offers loopback addresses as host candidates (tests
	// that run both ends on one machine).
	IncludeLoopback bool
	Logger          *slog.Logger
}

// Socket is the one UDP socket of plane B, with its STUN demultiplexer and
// the candidate gathering.
type Socket struct {
	cfg  SocketConfig
	log  *slog.Logger
	conn *DemuxConn
	port uint16

	mu       sync.Mutex
	srflx    []netip.AddrPort
	stunHost string
	gathered time.Time
}

// OpenSocket opens the plane-B socket.
func OpenSocket(cfg SocketConfig) (*Socket, error) {
	pc := cfg.Conn
	if pc == nil {
		var err error
		if pc, err = net.ListenPacket("udp", ":"+strconv.Itoa(cfg.Port)); err != nil { //nolint:noctx // plain local socket.
			return nil, fmt.Errorf("p2p: opening the UDP socket: %w", err)
		}
	}
	if cfg.Wrap != nil {
		pc = cfg.Wrap(pc)
	}
	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("p2p: the socket is not a UDP socket")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Socket{cfg: cfg, log: cfg.Logger, conn: NewDemuxConn(pc), port: uint16(ua.Port)}, nil
}

// Port is the local UDP port.
func (s *Socket) Port() int { return int(s.port) }

// Conn is the demultiplexing PacketConn the WireGuard bind reads from.
func (s *Socket) Conn() *DemuxConn { return s.conn }

// Close closes the socket.
func (s *Socket) Close() error { return s.conn.Close() }

// Gather learns the server-reflexive address from the STUN server ("host:port",
// empty: none) and returns the candidate list (host candidates first, see
// BuildCandidates). A STUN failure is not an error: host candidates still
// work on the same LAN. ctx bounds the STUN wait.
func (s *Socket) Gather(ctx context.Context, stunServer string) []netip.AddrPort {
	if stunServer != "" {
		if ap, err := s.stunBinding(ctx, stunServer); err != nil {
			s.log.Debug("STUN binding failed", "server", stunServer, "error", err.Error())
		} else {
			s.mu.Lock()
			s.srflx = []netip.AddrPort{ap}
			s.stunHost = stunServer
			s.gathered = time.Now()
			s.mu.Unlock()
		}
	}
	return s.Candidates()
}

// GatheredAt is when the reflexive address was last learned (zero: never).
func (s *Socket) GatheredAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gathered
}

func (s *Socket) stunBinding(ctx context.Context, server string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addr = a.Unmap()
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("resolving %s: %w", host, err)
		}
		addr = ips[0].Unmap()
	}
	return s.conn.Binding(ctx, netip.AddrPortFrom(addr, uint16(p)))
}

// Candidates returns the current candidate list.
func (s *Socket) Candidates() []netip.AddrPort {
	hosts, err := s.hostAddrs()
	if err != nil {
		s.log.Debug("listing interface addresses failed", "error", err.Error())
	}
	s.mu.Lock()
	srflx := slices.Clone(s.srflx)
	s.mu.Unlock()
	return BuildCandidates(hosts, s.port, srflx, api.MaxP2PCandidates)
}

func (s *Socket) hostAddrs() ([]netip.Addr, error) {
	if s.cfg.Interfaces != nil {
		return s.cfg.Interfaces()
	}
	return InterfaceAddrs(s.cfg.IncludeLoopback)
}

// InterfaceAddrs lists the addresses of all up interfaces.
func InterfaceAddrs(includeLoopback bool) ([]netip.Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if ifc.Flags&net.FlagLoopback != 0 && !includeLoopback {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out, nil
}

// hostUsable decides which local addresses are offered: IPv4 (private or
// public) and IPv6 unique-local or global; never link-local (needs a zone),
// multicast or unspecified. Loopback is kept: the interface listing leaves it
// out unless the caller asked for it.
func hostUsable(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

// BuildCandidates assembles the offered list from host addresses (all with
// the socket port) and server-reflexive addresses:
//
//   - unusable and duplicate addresses are dropped;
//   - the cap keeps the server-reflexive candidates first (they are what
//     crosses a NAT), then private host addresses, then public ones;
//   - the result is ordered private host addresses first (the cheapest path,
//     tried by the peer first), then server-reflexive, then public host addresses.
func BuildCandidates(hosts []netip.Addr, port uint16, srflx []netip.AddrPort, limit int) []netip.AddrPort {
	if limit <= 0 {
		limit = api.MaxP2PCandidates
	}
	var private, public []netip.AddrPort
	seen := map[netip.AddrPort]struct{}{}
	add := func(dst *[]netip.AddrPort, ap netip.AddrPort) {
		if _, dup := seen[ap]; dup {
			return
		}
		seen[ap] = struct{}{}
		*dst = append(*dst, ap)
	}
	for _, h := range hosts {
		if !hostUsable(h) {
			continue
		}
		h = h.Unmap()
		ap := netip.AddrPortFrom(h, port)
		if h.IsPrivate() || h.IsLoopback() {
			add(&private, ap)
		} else {
			add(&public, ap)
		}
	}
	var reflexive []netip.AddrPort
	for _, r := range srflx {
		r = netip.AddrPortFrom(r.Addr().Unmap(), r.Port())
		if r.IsValid() && r.Port() != 0 {
			add(&reflexive, r)
		}
	}
	// Apply the cap by priority.
	budget := limit
	take := func(in []netip.AddrPort) []netip.AddrPort {
		if len(in) > budget {
			in = in[:budget]
		}
		budget -= len(in)
		return in
	}
	reflexive = take(reflexive)
	private = take(private)
	public = take(public)
	out := make([]netip.AddrPort, 0, limit)
	out = append(out, private...)
	out = append(out, reflexive...)
	out = append(out, public...)
	return out
}
