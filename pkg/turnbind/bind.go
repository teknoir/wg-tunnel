// Package turnbind provides a wireguard-go conn.Bind on top of a swappable
// net.PacketConn.
//
// WireGuard normally owns a UDP socket. Here the socket is a TURN relayed
// connection (see package relay) that has to be replaced at runtime: the
// allocation can die, its credentials rotate, or the TURN server restarts.
// Bind.Swap installs the new PacketConn without the wireguard device noticing:
// the receive function keeps running, and peers re-learn the endpoint through
// WireGuard roaming (the first authenticated packet from the new relay address
// updates the peer endpoint on the other side).
//
// The Bind does not own the PacketConn. Close and the BindUpdate cycle
// (Close then Open) leave it open; whoever created it closes it, and
// after Swap must close the conn that Swap returns.
package turnbind

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

var (
	_ conn.Bind     = (*Bind)(nil)
	_ conn.Endpoint = Endpoint{}
)

// ErrNoConn is returned by Send while no PacketConn is installed.
var ErrNoConn = errors.New("turnbind: no packet conn installed")

const (
	minBackoff = 25 * time.Millisecond
	maxBackoff = 500 * time.Millisecond
)

// Endpoint is a WireGuard endpoint: the remote ip:port. The source address is
// not tracked (a relayed conn has a single local address).
type Endpoint struct{ ap netip.AddrPort }

// NewEndpoint wraps an address.
func NewEndpoint(ap netip.AddrPort) Endpoint { return Endpoint{ap: ap} }

// AddrPort returns the remote address.
func (e Endpoint) AddrPort() netip.AddrPort { return e.ap }

// ClearSrc implements conn.Endpoint (no source tracking).
func (e Endpoint) ClearSrc() {}

// SrcToString implements conn.Endpoint.
func (e Endpoint) SrcToString() string { return "" }

// DstToString implements conn.Endpoint.
func (e Endpoint) DstToString() string { return e.ap.String() }

// DstToBytes implements conn.Endpoint; used for WireGuard mac2 cookies.
func (e Endpoint) DstToBytes() []byte {
	b, _ := e.ap.MarshalBinary()
	return b
}

// DstIP implements conn.Endpoint.
func (e Endpoint) DstIP() netip.Addr { return e.ap.Addr() }

// SrcIP implements conn.Endpoint.
func (e Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

// ParseEndpoint parses "ip:port" (an IP literal, not a hostname).
func ParseEndpoint(s string) (Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("turnbind: parsing endpoint %q: %w", s, err)
	}
	return Endpoint{ap: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

// state is one installed PacketConn. sig is closed when the state is replaced.
type state struct {
	pc  net.PacketConn
	sig chan struct{}
}

// session is one Open..Close period.
type session struct{ done chan struct{} }

// Bind implements conn.Bind over a swappable net.PacketConn.
type Bind struct {
	mu   sync.Mutex // serialises Open, Close and Swap
	sess *session   // nil when closed

	cur      atomic.Pointer[state]
	open     atomic.Bool
	lastRecv atomic.Int64 // unix nanos
	swaps    atomic.Uint64
}

// New returns a Bind using pc, which may be nil: reads then block and Send fails
// with ErrNoConn until Swap installs a conn.
func New(pc net.PacketConn) *Bind {
	b := &Bind{}
	b.cur.Store(&state{pc: pc, sig: make(chan struct{})})
	return b
}

// Swap atomically replaces the underlying PacketConn and returns the previous
// one (nil if there was none). A receive blocked on the old conn is woken with
// a read deadline, so it moves to the new conn; the caller must still Close the
// returned conn. Swapping in the conn that is already installed is a no-op.
func (b *Bind) Swap(pc net.PacketConn) net.PacketConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.cur.Load()
	if old.pc == pc && pc != nil {
		return nil
	}
	if pc != nil && b.open.Load() {
		_ = pc.SetReadDeadline(time.Time{})
	}
	b.cur.Store(&state{pc: pc, sig: make(chan struct{})})
	b.swaps.Add(1)
	close(old.sig)
	if old.pc != nil {
		_ = old.pc.SetReadDeadline(time.Now()) // wake a blocked reader; best effort
	}
	return old.pc
}

// Swaps counts completed Swap calls.
func (b *Bind) Swaps() uint64 { return b.swaps.Load() }

// LastReceive returns when a packet was last received, or the zero time.
func (b *Bind) LastReceive() time.Time {
	n := b.lastRecv.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// LocalAddr returns the local address of the installed conn, or nil.
func (b *Bind) LocalAddr() net.Addr {
	if pc := b.cur.Load().pc; pc != nil {
		return pc.LocalAddr()
	}
	return nil
}

// Open implements conn.Bind. It may be called again after Close. The port
// argument is ignored (the conn is bound elsewhere); the reported port is the
// installed conn's local port, or 0.
func (b *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sess != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	s := &session{done: make(chan struct{})}
	b.sess = s
	b.open.Store(true)
	var port uint16
	if pc := b.cur.Load().pc; pc != nil {
		_ = pc.SetReadDeadline(time.Time{}) // undo the wake-up done by Close
		if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			port = uint16(ua.Port)
		}
	}
	return []conn.ReceiveFunc{b.receiver(s)}, port, nil
}

// Close implements conn.Bind. The PacketConn stays open. Every receive function
// returned by Open returns net.ErrClosed afterwards. Idempotent.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sess == nil {
		return nil
	}
	close(b.sess.done)
	b.sess = nil
	b.open.Store(false)
	if pc := b.cur.Load().pc; pc != nil {
		_ = pc.SetReadDeadline(time.Now()) // wake the blocked receive
	}
	return nil
}

// SetMark implements conn.Bind; there is no socket to mark.
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize implements conn.Bind.
func (b *Bind) BatchSize() int { return 1 }

// ParseEndpoint implements conn.Bind.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Send implements conn.Bind.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	var dst netip.AddrPort
	switch e := ep.(type) {
	case Endpoint:
		dst = e.ap
	case *Endpoint:
		dst = e.ap
	default:
		return conn.ErrWrongEndpointType
	}
	if !b.open.Load() {
		return net.ErrClosed
	}
	pc := b.cur.Load().pc
	if pc == nil {
		return ErrNoConn
	}
	addr := net.UDPAddrFromAddrPort(dst)
	var firstErr error
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, addr); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// receiver builds the receive function of one session. It returns an error
// only when the session is closed: wireguard-go gives up on other errors after
// a few retries, which would end receiving for good, so read errors are
// retried with backoff until the conn is swapped or the Bind is closed.
func (b *Bind) receiver(s *session) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		backoff := minBackoff
		for {
			select {
			case <-s.done:
				return 0, net.ErrClosed
			default:
			}
			st := b.cur.Load()
			if st.pc == nil {
				select {
				case <-st.sig:
				case <-s.done:
					return 0, net.ErrClosed
				}
				continue
			}
			n, from, err := st.pc.ReadFrom(packets[0])
			select {
			case <-s.done:
				return 0, net.ErrClosed
			default:
			}
			if err != nil {
				if b.cur.Load() != st {
					continue // swapped: read from the new conn
				}
				t := time.NewTimer(backoff)
				select {
				case <-t.C:
				case <-st.sig:
				case <-s.done:
				}
				t.Stop()
				if backoff *= 2; backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			backoff = minBackoff
			ap, ok := addrPortOf(from)
			if !ok {
				continue
			}
			b.lastRecv.Store(time.Now().UnixNano())
			sizes[0] = n
			eps[0] = Endpoint{ap: ap}
			return 1, nil
		}
	}
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		if !ap.IsValid() {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	default:
		if a == nil {
			return netip.AddrPort{}, false
		}
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
}
