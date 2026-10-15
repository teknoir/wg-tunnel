// Package devicekey creates, seals and opens the per-device Ed25519 device key
// (api.DeviceKeyFile, api.DeviceKeyEnvelope). The device key signs the
// enrollment AttestStatement; its fingerprint is the hub's activation anchor.
//
// Seal runs in device-controller and needs only the device's bootstrap RSA
// public key (Device spec.keys rsa_public). Open runs in the wg-agent with the
// bootstrap RSA private key (/etc/teknoir/rsa_private.pem). The envelope is
// RSA-OAEP-SHA256 over the 32-byte Ed25519 seed, with an OAEP label that binds
// it to one namespace/device/serial, so an envelope cannot be replayed to
// another device or relabelled.
package devicekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
)

// Generate returns a new device key.
func Generate() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("devicekey: generating: %w", err)
	}
	return priv, nil
}

// Fingerprint is the OpenSSH SHA256 fingerprint ("SHA256:<b64>") of the
// device key's public half: the same value the hub records for an SSHSIG
// attestation and device-controller writes to api.AnnotationDeviceKey.
func Fingerprint(pub ed25519.PublicKey) (string, error) {
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("devicekey: public key: %w", err)
	}
	return ssh.FingerprintSHA256(sp), nil
}

// NewSerial returns a random delivery serial for an envelope.
func NewSerial() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("devicekey: serial: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Seal encrypts priv to the device's bootstrap RSA public key (a CERTIFICATE,
// PUBLIC KEY or RSA PUBLIC KEY PEM, at least 2048 bits).
func Seal(rsaPublicPEM []byte, namespace, device, serial string, priv ed25519.PrivateKey) (api.DeviceKeyEnvelope, error) {
	if namespace == "" || device == "" || serial == "" {
		return api.DeviceKeyEnvelope{}, errors.New("devicekey: namespace, device and serial are required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return api.DeviceKeyEnvelope{}, errors.New("devicekey: not an Ed25519 private key")
	}
	pub, err := identity.ParseRSAPublicPEM(rsaPublicPEM)
	if err != nil {
		return api.DeviceKeyEnvelope{}, fmt.Errorf("devicekey: %w", err)
	}
	fp, err := Fingerprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return api.DeviceKeyEnvelope{}, err
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, priv.Seed(), api.DeviceKeyLabel(namespace, device, serial))
	if err != nil {
		return api.DeviceKeyEnvelope{}, fmt.Errorf("devicekey: sealing: %w", err)
	}
	return api.DeviceKeyEnvelope{
		V: api.DeviceKeyEnvelopeVersion, Namespace: namespace, Device: device, Serial: serial,
		Fingerprint: fp, Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts env with the device's bootstrap RSA private key (PKCS#1 or
// PKCS#8 PEM). It refuses an envelope for another namespace/device or with a
// version it does not know, and checks that the opened key has the envelope's
// fingerprint.
func Open(rsaPrivatePEM []byte, namespace, device string, env api.DeviceKeyEnvelope) (ed25519.PrivateKey, error) {
	if env.V != api.DeviceKeyEnvelopeVersion {
		return nil, fmt.Errorf("devicekey: envelope version %d, want %d", env.V, api.DeviceKeyEnvelopeVersion)
	}
	if env.Namespace != namespace || env.Device != device {
		return nil, fmt.Errorf("devicekey: envelope is for %s/%s, not %s/%s", env.Namespace, env.Device, namespace, device)
	}
	if env.Serial == "" {
		return nil, errors.New("devicekey: envelope has no serial")
	}
	key, err := identity.ParseRSAPrivatePEM(rsaPrivatePEM)
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("devicekey: ciphertext: %w", err)
	}
	seed, err := rsa.DecryptOAEP(sha256.New(), nil, key, ct, api.DeviceKeyLabel(namespace, device, env.Serial))
	if err != nil {
		return nil, errors.New("devicekey: envelope does not open with this device's RSA key")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("devicekey: envelope does not hold an Ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	fp, err := Fingerprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if fp != env.Fingerprint {
		return nil, fmt.Errorf("devicekey: opened key is %s, envelope says %s", fp, env.Fingerprint)
	}
	return priv, nil
}

// MarshalOpenSSH encodes priv as an unencrypted "OPENSSH PRIVATE KEY" PEM, the
// format of api.DeviceKeyFile.
func MarshalOpenSSH(priv ed25519.PrivateKey) ([]byte, error) {
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("devicekey: marshal: %w", err)
	}
	return pem.EncodeToMemory(blk), nil
}

// ParseOpenSSH parses an unencrypted OpenSSH Ed25519 private key.
func ParseOpenSSH(b []byte) (ed25519.PrivateKey, error) {
	k, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("devicekey: parse: %w", err)
	}
	switch p := k.(type) {
	case ed25519.PrivateKey:
		return p, nil
	case *ed25519.PrivateKey:
		return *p, nil
	default:
		return nil, fmt.Errorf("devicekey: key is %T, want Ed25519", k)
	}
}
