// Package wgkey generates and converts WireGuard X25519 keys.
//
// WireGuard tools exchange keys as standard base64; the wireguard-go UAPI
// (IPC) wants lowercase hex. Keys are fixed 32-byte arrays.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Size is the length of a WireGuard key in bytes.
const Size = 32

// PrivateKey is a clamped X25519 private key. Its String method is redacted so
// it cannot leak through logging; use Base64 or Hex deliberately.
type PrivateKey [Size]byte

// PublicKey is an X25519 public key.
type PublicKey [Size]byte

// Generate returns a fresh clamped private key and its public key.
func Generate() (PrivateKey, PublicKey, error) {
	var priv PrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("wgkey: reading randomness: %w", err)
	}
	clamp(&priv)
	pub, err := priv.Public()
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}
	return priv, pub, nil
}

func clamp(k *PrivateKey) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public derives the public key.
func (k PrivateKey) Public() (PublicKey, error) {
	p, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return PublicKey{}, fmt.Errorf("wgkey: deriving public key: %w", err)
	}
	var pub PublicKey
	copy(pub[:], p.PublicKey().Bytes())
	return pub, nil
}

// Base64 returns the key in WireGuard's standard base64 format.
func (k PrivateKey) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the lowercase hex form wireguard-go IPC expects.
func (k PrivateKey) Hex() string { return hex.EncodeToString(k[:]) }

// String is redacted on purpose.
func (k PrivateKey) String() string { return "wgkey.PrivateKey(REDACTED)" }

// GoString is redacted on purpose (covers %#v).
func (k PrivateKey) GoString() string { return k.String() }

// Zero overwrites the key material.
func (k *PrivateKey) Zero() { *k = PrivateKey{} }

// Base64 returns the key in WireGuard's standard base64 format.
func (k PublicKey) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the lowercase hex form wireguard-go IPC expects.
func (k PublicKey) Hex() string { return hex.EncodeToString(k[:]) }

// String returns the base64 form (public keys are not secret).
func (k PublicKey) String() string { return k.Base64() }

// ErrInvalidKey is wrapped by every parse error.
var ErrInvalidKey = errors.New("invalid WireGuard key")

func decode(s string, raw func(string) ([]byte, error)) ([Size]byte, error) {
	var out [Size]byte
	b, err := raw(s)
	if err != nil {
		return out, fmt.Errorf("%w: bad encoding", ErrInvalidKey)
	}
	if len(b) != Size {
		return out, fmt.Errorf("%w: want %d bytes, got %d", ErrInvalidKey, Size, len(b))
	}
	copy(out[:], b)
	var zero [Size]byte
	if out == zero {
		return out, fmt.Errorf("%w: all-zero key", ErrInvalidKey)
	}
	return out, nil
}

func b64(s string) ([]byte, error) {
	// encoding/base64 silently skips \r and \n; a key is exactly 44 characters.
	if len(s) != base64.StdEncoding.EncodedLen(Size) {
		return nil, errors.New("bad length")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// ParsePrivate parses a base64 private key. The key is accepted as is (any 32
// non-zero bytes; wireguard-go clamps internally), so keys made by `wg genkey`
// and by Generate both parse.
func ParsePrivate(s string) (PrivateKey, error) {
	k, err := decode(s, b64)
	return PrivateKey(k), err
}

// ParsePublic parses a base64 public key.
func ParsePublic(s string) (PublicKey, error) {
	k, err := decode(s, b64)
	return PublicKey(k), err
}

// ParsePrivateHex parses a hex private key (wireguard-go IPC format).
func ParsePrivateHex(s string) (PrivateKey, error) {
	k, err := decode(s, hex.DecodeString)
	return PrivateKey(k), err
}

// ParsePublicHex parses a hex public key (wireguard-go IPC format).
func ParsePublicHex(s string) (PublicKey, error) {
	k, err := decode(s, hex.DecodeString)
	return PublicKey(k), err
}

// Base64ToHex converts a base64 key (either kind) to hex.
func Base64ToHex(s string) (string, error) {
	k, err := decode(s, b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

// HexToBase64 converts a hex key (either kind) to base64.
func HexToBase64(s string) (string, error) {
	k, err := decode(s, hex.DecodeString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}
