package p2p

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"

	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Probe wire format (38 bytes). The first byte 'T' (0x54) has the first bits
// 01, so a probe is neither STUN (00) nor WireGuard (first byte 1..4).
//
//	0..3    "TKP\x01"
//	4       type: probePing or probePong
//	5       flags: probeNoSession when the sender has no valid WireGuard session
//	6..13   sender key ID: first 8 bytes of SHA-256 of the sender's public key
//	14..21  nonce
//	22..37  MAC: HMAC-SHA256(pairKey, bytes 0..21) truncated to 16 bytes
//
// pairKey is derived from the X25519 shared secret of the two WireGuard keys
// of the pair, which only the two ends (and the hub, which sees only public
// keys) can compute. A probe thus proves that its sender holds the pair's
// private key. It is still only a hint where to send the handshake: nothing
// trusts an address until a WireGuard handshake completes through it.
const (
	probeLen        = 38
	probePing       = 1
	probePong       = 2
	probeNoSession  = 1 << 0
	probeMACLen     = 16
	probeHeaderLen  = 22
	probeKeyIDLen   = 8
	probeNonceLen   = 8
	probeMagicBytes = "TKP\x01"
)

// keyID identifies a public key in a probe.
type keyID [probeKeyIDLen]byte

func idOf(pub wgkey.PublicKey) keyID {
	h := sha256.Sum256(pub[:])
	var id keyID
	copy(id[:], h[:probeKeyIDLen])
	return id
}

// pairKey derives the probe MAC key of the pair (priv, peer).
func pairKey(priv wgkey.PrivateKey, self, peer wgkey.PublicKey) ([32]byte, error) {
	shared, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		return [32]byte{}, err
	}
	lo, hi := self, peer
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	m := hmac.New(sha256.New, shared)
	m.Write([]byte("teknoir-ztna-p2p-probe-v1"))
	m.Write(lo[:])
	m.Write(hi[:])
	var k [32]byte
	m.Sum(k[:0])
	return k, nil
}

// probe is a parsed probe.
type probe struct {
	typ    byte
	flags  byte
	sender keyID
	nonce  [probeNonceLen]byte
}

func isProbe(p []byte) bool {
	return len(p) == probeLen && string(p[:4]) == probeMagicBytes
}

// parseProbeHeader reads the unauthenticated fields. The caller verifies the
// MAC with the key of the peer named by sender.
func parseProbeHeader(p []byte) (probe, bool) {
	if !isProbe(p) || (p[4] != probePing && p[4] != probePong) {
		return probe{}, false
	}
	var pr probe
	pr.typ, pr.flags = p[4], p[5]
	copy(pr.sender[:], p[6:14])
	copy(pr.nonce[:], p[14:22])
	return pr, true
}

func probeMAC(key [32]byte, header []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(header)
	return m.Sum(nil)[:probeMACLen]
}

// verifyProbe checks the MAC of a datagram that passed parseProbeHeader.
func verifyProbe(key [32]byte, p []byte) bool {
	return hmac.Equal(probeMAC(key, p[:probeHeaderLen]), p[probeHeaderLen:])
}

// buildProbe makes a probe with a fresh nonce, or echoing nonce when non-nil
// (a pong repeats the ping's nonce).
func buildProbe(key [32]byte, self keyID, typ, flags byte, echo *[probeNonceLen]byte) ([]byte, error) {
	b := make([]byte, probeLen)
	copy(b, probeMagicBytes)
	b[4], b[5] = typ, flags
	copy(b[6:14], self[:])
	if echo != nil {
		copy(b[14:22], echo[:])
	} else if _, err := rand.Read(b[14:22]); err != nil {
		return nil, errors.New("p2p: no randomness for a probe")
	}
	copy(b[probeHeaderLen:], probeMAC(key, b[:probeHeaderLen]))
	return b, nil
}
