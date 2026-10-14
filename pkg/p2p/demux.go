package p2p

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Kind classifies a datagram on the plane-B socket.
type Kind int

// Datagram kinds.
const (
	KindWireGuard Kind = iota
	KindSTUN
	KindProbe
)

// Classify says which consumer a datagram belongs to. STUN is tested first
// (see isSTUN for why a WireGuard packet cannot be mistaken for it), then
// probes; everything else goes to WireGuard, which ignores what it does not
// understand.
func Classify(p []byte) Kind {
	switch {
	case isSTUN(p):
		return KindSTUN
	case isProbe(p):
		return KindProbe
	}
	return KindWireGuard
}

const (
	maxDatagram = 2048
	inQueue     = 256
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, maxDatagram); return &b }}

type dgram struct {
	buf  *[]byte
	n    int
	from net.Addr
}

type stunResult struct {
	ap  netip.AddrPort
	src netip.AddrPort
}

// DemuxConn is a net.PacketConn over a real UDP socket that hands only the
// WireGuard datagrams to ReadFrom. STUN responses and probes are consumed by
// the pump goroutine and delivered to their waiters and handler. It is what
// turnbind.Bind reads from.
type DemuxConn struct {
	pc net.PacketConn

	in     chan dgram
	closed chan struct{}
	once   sync.Once

	dlMu sync.Mutex
	dl   time.Time
	dlCh chan struct{} // closed and replaced whenever the deadline changes

	stunMu sync.Mutex
	stun   map[txID]chan stunResult

	probeMu sync.RWMutex
	probeFn func(p []byte, from netip.AddrPort)
}

// NewDemuxConn wraps pc and starts the pump. Close closes pc as well.
func NewDemuxConn(pc net.PacketConn) *DemuxConn {
	c := &DemuxConn{
		pc: pc, in: make(chan dgram, inQueue), closed: make(chan struct{}),
		dlCh: make(chan struct{}), stun: map[txID]chan stunResult{},
	}
	go c.pump()
	return c
}

// SetProbeHandler installs the function called (from the pump goroutine, so it
// must not block) for every probe datagram.
func (c *DemuxConn) SetProbeHandler(fn func(p []byte, from netip.AddrPort)) {
	c.probeMu.Lock()
	c.probeFn = fn
	c.probeMu.Unlock()
}

func (c *DemuxConn) pump() {
	for {
		bp := bufPool.Get().(*[]byte)
		n, from, err := c.pc.ReadFrom(*bp)
		if err != nil {
			bufPool.Put(bp)
			select {
			case <-c.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				_ = c.Close()
				return
			}
			time.Sleep(10 * time.Millisecond) // transient (for example an ICMP error surfaced by the socket)
			continue
		}
		p := (*bp)[:n]
		switch Classify(p) {
		case KindSTUN:
			c.deliverSTUN(p, from)
			bufPool.Put(bp)
		case KindProbe:
			c.probeMu.RLock()
			fn := c.probeFn
			c.probeMu.RUnlock()
			if ap, ok := addrPortOf(from); ok && fn != nil {
				fn(p, ap)
			}
			bufPool.Put(bp)
		default:
			select {
			case c.in <- dgram{buf: bp, n: n, from: from}:
			default: // the WireGuard reader is behind: drop, as a full socket buffer would
				bufPool.Put(bp)
			}
		}
	}
}

func (c *DemuxConn) deliverSTUN(p []byte, from net.Addr) {
	id, ap, err := parseBindingResponse(p)
	if err != nil {
		return
	}
	src, _ := addrPortOf(from)
	c.stunMu.Lock()
	ch := c.stun[id]
	c.stunMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- stunResult{ap: ap, src: src}:
	default:
	}
}

// ReadFrom implements net.PacketConn for the WireGuard datagrams.
func (c *DemuxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.dlMu.Lock()
		dl, sig := c.dl, c.dlCh
		c.dlMu.Unlock()
		var expire <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			expire = timer.C
		}
		select {
		case d := <-c.in:
			if timer != nil {
				timer.Stop()
			}
			n := copy(p, (*d.buf)[:d.n])
			bufPool.Put(d.buf)
			return n, d.from, nil
		case <-expire:
			return 0, nil, os.ErrDeadlineExceeded
		case <-sig:
			if timer != nil {
				timer.Stop()
			}
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		}
	}
}

// WriteTo implements net.PacketConn.
func (c *DemuxConn) WriteTo(p []byte, addr net.Addr) (int, error) { return c.pc.WriteTo(p, addr) }

// LocalAddr implements net.PacketConn.
func (c *DemuxConn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

// SetDeadline implements net.PacketConn (reads only; writes are not bounded).
func (c *DemuxConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline implements net.PacketConn.
func (c *DemuxConn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.dl = t
	old := c.dlCh
	c.dlCh = make(chan struct{})
	c.dlMu.Unlock()
	close(old)
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (c *DemuxConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

// Close stops the pump and closes the socket. It is idempotent.
func (c *DemuxConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.pc.Close()
	})
	return err
}

// Binding sends a STUN Binding request to server and returns the address the
// server saw (the server-reflexive candidate). It retransmits like RFC 5389
// (100 ms doubling) until ctx ends. A response from any other source is ignored.
func (c *DemuxConn) Binding(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	req, id, err := newBindingRequest()
	if err != nil {
		return netip.AddrPort{}, err
	}
	ch := make(chan stunResult, 1)
	c.stunMu.Lock()
	c.stun[id] = ch
	c.stunMu.Unlock()
	defer func() {
		c.stunMu.Lock()
		delete(c.stun, id)
		c.stunMu.Unlock()
	}()
	dst := net.UDPAddrFromAddrPort(server)
	rto := 100 * time.Millisecond
	for {
		if _, err := c.pc.WriteTo(req, dst); err != nil {
			return netip.AddrPort{}, err
		}
		t := time.NewTimer(rto)
	wait:
		for {
			select {
			case r := <-ch:
				if r.src != netip.AddrPortFrom(server.Addr().Unmap(), server.Port()) {
					continue // not from the server we asked
				}
				t.Stop()
				return netip.AddrPortFrom(r.ap.Addr().Unmap(), r.ap.Port()), nil
			case <-t.C:
				break wait
			case <-ctx.Done():
				t.Stop()
				return netip.AddrPort{}, ctx.Err()
			case <-c.closed:
				t.Stop()
				return netip.AddrPort{}, net.ErrClosed
			}
		}
		if rto < 800*time.Millisecond {
			rto *= 2
		}
	}
}
