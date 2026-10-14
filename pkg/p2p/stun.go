package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// Minimal RFC 5389: a Binding request without attributes and the parsing of
// the XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) of a success response. STUNner
// answers unauthenticated Binding requests on its TURN port.
const (
	stunMagic            = 0x2112A442
	stunHeaderLen        = 20
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	stunAttrMapped       = 0x0001
	stunAttrXORMapped    = 0x0020
	stunMaxAttrScanBytes = 548
)

// txID is a STUN transaction ID.
type txID [12]byte

// isSTUN reports whether p looks like a STUN message: the first two bits are
// 00, the magic cookie is at bytes 4..8 and the length field matches the
// datagram. The length check matters: WireGuard messages have zero bytes 1..3
// and a random sender/receiver index at bytes 4..8, so a WireGuard datagram is
// STUN-shaped only if it is exactly 20 bytes (none is; the smallest is 32).
func isSTUN(p []byte) bool {
	if len(p) < stunHeaderLen || p[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(p[4:8]) != stunMagic {
		return false
	}
	n := int(binary.BigEndian.Uint16(p[2:4]))
	return n%4 == 0 && stunHeaderLen+n == len(p)
}

// newBindingRequest returns a Binding request and its transaction ID.
func newBindingRequest() ([]byte, txID, error) {
	var id txID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, id, err
	}
	b := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(b[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:], id[:])
	return b, id, nil
}

// parseBindingResponse extracts the transaction ID and the reflexive address
// from a Binding success response.
func parseBindingResponse(p []byte) (txID, netip.AddrPort, error) {
	var id txID
	if !isSTUN(p) {
		return id, netip.AddrPort{}, errors.New("p2p: not a STUN message")
	}
	if binary.BigEndian.Uint16(p[0:2]) != stunBindingSuccess {
		return id, netip.AddrPort{}, errors.New("p2p: not a Binding success response")
	}
	copy(id[:], p[8:20])
	attrs := p[stunHeaderLen:]
	if len(attrs) > stunMaxAttrScanBytes {
		attrs = attrs[:stunMaxAttrScanBytes]
	}
	var mapped netip.AddrPort
	var haveMapped bool
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		n := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+n > len(attrs) {
			break
		}
		val := attrs[4 : 4+n]
		switch typ {
		case stunAttrXORMapped:
			if ap, ok := decodeAddr(val, true, id); ok {
				return id, ap, nil
			}
		case stunAttrMapped:
			if ap, ok := decodeAddr(val, false, id); ok && !haveMapped {
				mapped, haveMapped = ap, true
			}
		}
		adv := 4 + (n+3)&^3
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	if haveMapped {
		return id, mapped, nil
	}
	return id, netip.AddrPort{}, errors.New("p2p: no mapped address in the response")
}

func decodeAddr(v []byte, xor bool, id txID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	if xor {
		port ^= uint16(stunMagic >> 16)
	}
	switch v[1] {
	case 1: // IPv4
		if len(v) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], v[4:8])
		if xor {
			var m [4]byte
			binary.BigEndian.PutUint32(m[:], stunMagic)
			for i := range a {
				a[i] ^= m[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 2: // IPv6
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], v[4:20])
		if xor {
			var m [16]byte
			binary.BigEndian.PutUint32(m[0:4], stunMagic)
			copy(m[4:], id[:])
			for i := range a {
				a[i] ^= m[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// encodeBindingResponse builds a Binding success response with an
// XOR-MAPPED-ADDRESS; used by test STUN servers and the NAT lab.
func encodeBindingResponse(id txID, ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap()
	var val []byte
	if a.Is4() {
		val = make([]byte, 8)
		val[1] = 1
		raw := a.As4()
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], stunMagic)
		for i := range raw {
			val[4+i] = raw[i] ^ m[i]
		}
	} else {
		val = make([]byte, 20)
		val[1] = 2
		raw := a.As16()
		var m [16]byte
		binary.BigEndian.PutUint32(m[0:4], stunMagic)
		copy(m[4:], id[:])
		for i := range raw {
			val[4+i] = raw[i] ^ m[i]
		}
	}
	binary.BigEndian.PutUint16(val[2:4], ap.Port()^uint16(stunMagic>>16))
	b := make([]byte, stunHeaderLen, stunHeaderLen+4+len(val))
	binary.BigEndian.PutUint16(b[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:], id[:])
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:2], stunAttrXORMapped)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(val)))
	b = append(b, h[:]...)
	b = append(b, val...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-stunHeaderLen))
	return b
}

// ServeSTUN answers Binding requests on pc with the sender's address until pc
// is closed or fails. It is a helper for tests and the NAT lab (the lab runs
// it as the public STUN server); production uses STUNner.
func ServeSTUN(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		p := buf[:n]
		if !isSTUN(p) || binary.BigEndian.Uint16(p[0:2]) != stunBindingRequest {
			continue
		}
		ap, ok := addrPortOf(from)
		if !ok {
			continue
		}
		var id txID
		copy(id[:], p[8:20])
		_, _ = pc.WriteTo(encodeBindingResponse(id, ap), from)
	}
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	if u, ok := a.(*net.UDPAddr); ok {
		ap := u.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
