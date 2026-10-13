package hub

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// ErrPoolExhausted is returned when no address is free.
var ErrPoolExhausted = errors.New("hub: overlay address pool exhausted")

// ipam allocates session addresses (/32) from the overlay prefix. The network
// address, the hub address and the broadcast address are never handed out.
// A released address is quarantined before it can be allocated again, so a
// late packet from a dead peer cannot be taken for the next session.
type ipam struct {
	mu         sync.Mutex
	base       uint32
	size       uint32 // number of addresses in the prefix
	hub        uint32
	used       map[uint32]struct{}
	quarantine map[uint32]time.Time // free-at
	cursor     uint32               // offset of the next candidate
	qttl       time.Duration
	now        func() time.Time
}

func newIPAM(prefix, hub netip.Addr, bits int, quarantine time.Duration, now func() time.Time) (*ipam, error) {
	if !prefix.Is4() || !hub.Is4() || bits < 8 || bits > 30 {
		return nil, fmt.Errorf("hub: unsupported overlay %s/%d", prefix, bits)
	}
	p := netip.PrefixFrom(prefix, bits).Masked()
	if !p.Contains(hub) {
		return nil, fmt.Errorf("hub: hub address %s outside %s", hub, p)
	}
	base := binary.BigEndian.Uint32(p.Addr().AsSlice())
	return &ipam{
		base:       base,
		size:       uint32(1) << (32 - bits),
		hub:        binary.BigEndian.Uint32(hub.AsSlice()),
		used:       map[uint32]struct{}{},
		quarantine: map[uint32]time.Time{},
		cursor:     1,
		qttl:       quarantine,
		now:        now,
	}, nil
}

func (m *ipam) addr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Alloc returns a free address, scanning round-robin so that freshly released
// addresses are reused as late as possible.
func (m *ipam) Alloc() (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for i := uint32(0); i < m.size; i++ {
		off := (m.cursor + i) % m.size
		if off == 0 || off == m.size-1 { // network, broadcast
			continue
		}
		v := m.base + off
		if v == m.hub {
			continue
		}
		if _, ok := m.used[v]; ok {
			continue
		}
		if until, ok := m.quarantine[v]; ok {
			if now.Before(until) {
				continue
			}
			delete(m.quarantine, v)
		}
		m.used[v] = struct{}{}
		m.cursor = (off + 1) % m.size
		return m.addr(v), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Release returns ip to the pool after the quarantine period. The caller must
// have removed the WireGuard peer first.
func (m *ipam) Release(ip netip.Addr) {
	v := binary.BigEndian.Uint32(ip.AsSlice())
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.used[v]; !ok {
		return
	}
	delete(m.used, v)
	m.quarantine[v] = m.now().Add(m.qttl)
}

// Free returns an address that was never used on the wire (no quarantine).
func (m *ipam) Free(ip netip.Addr) {
	v := binary.BigEndian.Uint32(ip.AsSlice())
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.used, v)
}

// Sweep drops expired quarantine entries and returns the remaining count.
func (m *ipam) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for v, until := range m.quarantine {
		if !now.Before(until) {
			delete(m.quarantine, v)
		}
	}
	return len(m.quarantine)
}

// InUse returns the number of allocated addresses.
func (m *ipam) InUse() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.used)
}
