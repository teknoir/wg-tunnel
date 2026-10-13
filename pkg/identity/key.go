// Package identity implements the device identity of the ZTNA tunnel: an
// Ed25519 key generated on the device and never exported, its fingerprint, and
// the device JWTs (see api.DeviceClaims) with their verification.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// KeyFile is the identity key file name inside the identity directory.
	KeyFile = "identity.key"
	// PrevKeyFile is where Rotate keeps the replaced key for audit.
	PrevKeyFile = "identity.key.prev"

	pemType = "PRIVATE KEY"
)

// LoadOrCreate returns the identity key stored in dir, generating and
// persisting a new one if there is none. dir is created with mode 0700 and
// the key file with 0600. An existing key file that is accessible by group or
// others, is a symlink, or is not a regular file is refused (never silently
// "fixed": it may already have been read by someone else).
func LoadOrCreate(dir string) (ed25519.PrivateKey, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, KeyFile)
	priv, err := load(path)
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generating key: %w", err)
	}
	return writeNewKey(dir, priv, path)
}

// Rotate replaces the identity key: a new key becomes identity.key and the old
// one is kept as identity.key.prev (overwriting an older .prev). The new key is
// fully written before the old one is moved aside.
func Rotate(dir string) (ed25519.PrivateKey, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, KeyFile)
	if _, err := load(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("identity: refusing to rotate: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: encoding key: %w", err)
	}
	tmp, err := writeTemp(dir, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Rename(path, filepath.Join(dir, PrevKeyFile)); err != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("identity: keeping previous key: %w", err)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("identity: installing new key: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	return priv, nil
}

func ensureDir(dir string) error {
	if dir == "" {
		return errors.New("identity: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: creating %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("identity: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("identity: %s is writable by group or others (mode %04o)", dir, fi.Mode().Perm())
	}
	return nil
}

func load(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err // fs.ErrNotExist is passed through
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("identity: %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("identity: %s is accessible by group or others (mode %04o); refusing to use it", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: reading %s: %w", path, err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemType {
		return nil, fmt.Errorf("identity: %s is not a PKCS#8 PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parsing %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s holds a %T, want Ed25519", path, k)
	}
	return priv, nil
}

// writeNewKey installs priv at path unless a key appeared meanwhile, in which
// case that key wins and is returned.
func writeNewKey(dir string, priv ed25519.PrivateKey, path string) (ed25519.PrivateKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("identity: encoding key: %w", err)
	}
	tmp, err := writeTemp(dir, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
	if err != nil {
		return nil, err
	}
	// link, not rename: never replace a key that appeared meanwhile.
	linkErr := os.Link(tmp, path)
	if linkErr != nil && !errors.Is(linkErr, fs.ErrExist) {
		// Some filesystems do not support hard links; fall back to rename,
		// accepting a small window in which a concurrent creator could lose.
		if _, serr := os.Lstat(path); serr != nil {
			if rerr := os.Rename(tmp, path); rerr == nil {
				linkErr = nil
			}
		}
	}
	_ = os.Remove(tmp) // no-op after a successful rename
	switch {
	case errors.Is(linkErr, fs.ErrExist):
		return load(path)
	case linkErr != nil:
		if k, err := load(path); err == nil {
			return k, nil
		}
		return nil, fmt.Errorf("identity: installing key: %w", linkErr)
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	return priv, nil
}

// writeTemp creates a 0600 temp file in dir holding data, synced.
func writeTemp(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return "", fmt.Errorf("identity: creating temp file: %w", err)
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("identity: writing key: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("identity: writing key: %w", err)
	}
	return name, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("identity: syncing %s: %w", dir, err)
	}
	return nil
}

// Fingerprint returns "SHA256:" + base64 (raw, unpadded) of SHA-256 of the raw
// public key, the format api.EnrollResponse uses.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// EncodePublicKey returns the base64 (standard, padded) raw public key, as
// carried in api.DeviceClaims.IdentityKey and api.EnrollRequest.IdentityPublicKey.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes a base64 raw Ed25519 public key (padded or not).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, fmt.Errorf("identity: public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func decodeB64(s string) ([]byte, error) {
	if len(s) > 4096 {
		return nil, errors.New("too long")
	}
	if strings.ContainsAny(s, "\r\n") { // encoding/base64 would silently skip them
		return nil, errors.New("contains line breaks")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict()} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}
