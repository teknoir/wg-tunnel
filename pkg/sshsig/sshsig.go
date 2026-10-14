// Package sshsig implements the OpenSSH signature format (PROTOCOL.sshsig,
// "ssh-keygen -Y sign") for the two key types an sshd host key can have here:
// Ed25519 and RSA with rsa-sha2-512. The message hash is always SHA-512.
//
// It is deliberately narrow. ssh-rsa (SHA-1), rsa-sha2-256, ECDSA, security
// keys and certificates are refused when signing and when verifying, so a
// verifier cannot be talked into a weaker algorithm.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	magic        = "SSHSIG"
	version      = 1
	hashAlg      = "sha512"
	minRSABits   = 2048
	maxBlobBytes = 16 << 10

	armorBegin = "-----BEGIN SSH SIGNATURE-----"
	armorEnd   = "-----END SSH SIGNATURE-----"
)

// wire is the binary SSHSIG blob after the six magic bytes.
type wire struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     []byte
}

// signedData is what the key signs (PROTOCOL.sshsig, "Signed data").
type signedData struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          []byte
}

func dataToSign(namespace string, message []byte) []byte {
	h := sha512.Sum512(message)
	return append([]byte(magic), ssh.Marshal(signedData{Namespace: namespace, HashAlgorithm: hashAlg, Hash: h[:]})...)
}

// checkKey accepts Ed25519 and RSA (at least 2048 bits) public keys only.
func checkKey(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return nil
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("sshsig: unsupported RSA key")
		}
		rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < minRSABits {
			return fmt.Errorf("sshsig: RSA keys need at least %d bits", minRSABits)
		}
		return nil
	}
	return fmt.Errorf("sshsig: unsupported key type %q (want ssh-ed25519 or ssh-rsa with rsa-sha2-512)", pub.Type())
}

// Sign returns the binary SSHSIG blob of message in namespace, signed by
// signer. RSA keys sign with rsa-sha2-512.
func Sign(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, errors.New("sshsig: namespace is required")
	}
	pub := signer.PublicKey()
	if err := checkKey(pub); err != nil {
		return nil, err
	}
	data := dataToSign(namespace, message)
	var sig *ssh.Signature
	var err error
	if pub.Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("sshsig: RSA signer cannot select rsa-sha2-512")
		}
		sig, err = as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return nil, fmt.Errorf("sshsig: signing: %w", err)
	}
	if err := checkSigFormat(pub, sig); err != nil {
		return nil, err
	}
	blob := append([]byte(magic), ssh.Marshal(wire{
		Version: version, PublicKey: pub.Marshal(), Namespace: namespace,
		HashAlgorithm: hashAlg, Signature: ssh.Marshal(sig),
	})...)
	return blob, nil
}

func checkSigFormat(pub ssh.PublicKey, sig *ssh.Signature) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		if sig.Format != ssh.KeyAlgoED25519 {
			return fmt.Errorf("sshsig: signature format %q does not match an ed25519 key", sig.Format)
		}
	case ssh.KeyAlgoRSA:
		if sig.Format != ssh.KeyAlgoRSASHA512 {
			return fmt.Errorf("sshsig: RSA signatures must use rsa-sha2-512, got %q", sig.Format)
		}
	}
	return nil
}

// Verify checks a binary SSHSIG blob over message in namespace and returns the
// public key that signed it. Whether that key is the one the caller expects is
// the caller's decision.
func Verify(blob []byte, namespace string, message []byte) (ssh.PublicKey, error) {
	if namespace == "" {
		return nil, errors.New("sshsig: namespace is required")
	}
	if len(blob) > maxBlobBytes {
		return nil, errors.New("sshsig: signature too large")
	}
	if !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, errors.New("sshsig: bad magic")
	}
	var w wire
	if err := ssh.Unmarshal(blob[len(magic):], &w); err != nil {
		return nil, fmt.Errorf("sshsig: malformed signature: %w", err)
	}
	if w.Version != version {
		return nil, fmt.Errorf("sshsig: unsupported version %d", w.Version)
	}
	if w.Namespace != namespace {
		return nil, errors.New("sshsig: wrong namespace")
	}
	if w.HashAlgorithm != hashAlg {
		return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q (want %s)", w.HashAlgorithm, hashAlg)
	}
	pub, err := ssh.ParsePublicKey(w.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: public key: %w", err)
	}
	if err := checkKey(pub); err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(w.Signature, &sig); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	if err := checkSigFormat(pub, &sig); err != nil {
		return nil, err
	}
	if err := pub.Verify(dataToSign(namespace, message), &sig); err != nil {
		return nil, errors.New("sshsig: signature does not verify")
	}
	return pub, nil
}

// Armor wraps a binary blob in the "-----BEGIN SSH SIGNATURE-----" text form
// that ssh-keygen reads and writes.
func Armor(blob []byte) string {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(armorBegin + "\n")
	for len(enc) > 0 {
		n := min(70, len(enc))
		b.WriteString(enc[:n] + "\n")
		enc = enc[n:]
	}
	b.WriteString(armorEnd + "\n")
	return b.String()
}

// Unarmor extracts the binary blob from the armored text form.
func Unarmor(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	body, ok := strings.CutPrefix(s, armorBegin)
	if !ok {
		return nil, errors.New("sshsig: missing armor header")
	}
	body, ok = strings.CutSuffix(strings.TrimSpace(body), armorEnd)
	if !ok {
		return nil, errors.New("sshsig: missing armor footer")
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil {
		return nil, fmt.Errorf("sshsig: armor: %w", err)
	}
	return b, nil
}
