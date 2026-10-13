package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ErrToken is wrapped by every token verification failure; the hub maps it to
// api.ReasonUnauthenticated. Details in the message are for logs only.
var ErrToken = errors.New("invalid device token")

const (
	maxTokenLen  = 4096
	maxJTILen    = 128
	minRSABits   = 2048
	algIdentity  = "EdDSA"
	algEnrollJWT = "RS256"
)

// claims adapts api.DeviceClaims (stdlib only) to jwt.Claims.
type claims struct{ api.DeviceClaims }

func (c claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}
func (c claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}
func (c claims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c claims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c claims) GetSubject() (string, error)             { return c.Subject, nil }
func (c claims) GetAudience() (jwt.ClaimStrings, error)  { return jwt.ClaimStrings{c.Audience}, nil }

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity: jti: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func newClaims(sub string, ttl time.Duration, now time.Time) (api.DeviceClaims, error) {
	if sub == "" {
		return api.DeviceClaims{}, errors.New("identity: empty subject")
	}
	if ttl < time.Second || ttl > api.MaxDeviceJWTLifetime {
		return api.DeviceClaims{}, fmt.Errorf("identity: ttl %s outside [1s, %s]", ttl, api.MaxDeviceJWTLifetime)
	}
	jti, err := newJTI()
	if err != nil {
		return api.DeviceClaims{}, err
	}
	iat := now.Unix()
	return api.DeviceClaims{
		Issuer: api.DeviceJWTIssuer, Subject: sub, Audience: api.DeviceJWTAudience,
		IssuedAt: iat, ExpiresAt: iat + int64(ttl/time.Second), ID: jti,
	}, nil
}

// MintIdentityJWT signs an EdDSA identity token for a session create or
// renew. wgKey is the base64 WireGuard public key the token is bound to. It
// returns the token and its jti. ttl must be in [1s, api.MaxDeviceJWTLifetime].
func MintIdentityJWT(priv ed25519.PrivateKey, sub, wgKey string, ttl time.Duration) (token, jti string, err error) {
	return MintIdentityJWTAt(priv, sub, wgKey, ttl, time.Now())
}

// MintIdentityJWTAt is MintIdentityJWT with an explicit clock.
func MintIdentityJWTAt(priv ed25519.PrivateKey, sub, wgKey string, ttl time.Duration, now time.Time) (token, jti string, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", "", errors.New("identity: bad Ed25519 private key")
	}
	if wgKey == "" {
		return "", "", errors.New("identity: identity tokens must be bound to a WireGuard key")
	}
	c, err := newClaims(sub, ttl, now)
	if err != nil {
		return "", "", err
	}
	c.WGKey = wgKey
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims{c}).SignedString(priv)
	if err != nil {
		return "", "", fmt.Errorf("identity: signing: %w", err)
	}
	return tok, c.ID, nil
}

// MintEnrollJWT signs an RS256 enrollment token with the legacy device key
// (PKCS#1 or PKCS#8 PEM). identityKeyB64 is the identity public key being
// enrolled (EncodePublicKey). The returned jti is what ProveEnroll must sign.
func MintEnrollJWT(rsaPrivPEM []byte, sub, identityKeyB64 string, ttl time.Duration) (token, jti string, err error) {
	return MintEnrollJWTAt(rsaPrivPEM, sub, identityKeyB64, ttl, time.Now())
}

// MintEnrollJWTAt is MintEnrollJWT with an explicit clock.
func MintEnrollJWTAt(rsaPrivPEM []byte, sub, identityKeyB64 string, ttl time.Duration, now time.Time) (token, jti string, err error) {
	key, err := ParseRSAPrivatePEM(rsaPrivPEM)
	if err != nil {
		return "", "", err
	}
	if _, err := ParsePublicKey(identityKeyB64); err != nil {
		return "", "", err
	}
	c, err := newClaims(sub, ttl, now)
	if err != nil {
		return "", "", err
	}
	c.IdentityKey = identityKeyB64
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims{c}).SignedString(key)
	if err != nil {
		return "", "", fmt.Errorf("identity: signing: %w", err)
	}
	return tok, c.ID, nil
}

// VerifyIdentityJWT verifies an identity token: alg exactly EdDSA, signature
// by pub, iss/aud, subject equal to expectSub, lifetime and clock skew, a
// non-empty jti and a bound WireGuard key (WGKey, returned for the caller to
// compare with the request). Replay protection (jti cache) is the caller's.
func VerifyIdentityJWT(token string, pub ed25519.PublicKey, expectSub string, now time.Time) (*api.DeviceClaims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: no identity key", ErrToken)
	}
	c, err := parse(token, algIdentity, pub)
	if err != nil {
		return nil, err
	}
	if err := checkClaims(c, expectSub, now); err != nil {
		return nil, err
	}
	if c.WGKey == "" || c.IdentityKey != "" {
		return nil, fmt.Errorf("%w: identity token must carry wgk and no idk", ErrToken)
	}
	return c, nil
}

// VerifyEnrollJWT verifies an enrollment token against the device's RSA
// public material (X.509 certificate PEM, or a bare PUBLIC KEY PEM). The
// certificate's validity period is deliberately ignored: only its key matters.
// The token must carry idk (the identity key to pin) and no wgk.
func VerifyEnrollJWT(token string, certPEM []byte, expectSub string, now time.Time) (*api.DeviceClaims, error) {
	pub, err := ParseRSAPublicPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToken, err)
	}
	c, err := parse(token, algEnrollJWT, pub)
	if err != nil {
		return nil, err
	}
	if err := checkClaims(c, expectSub, now); err != nil {
		return nil, err
	}
	if c.IdentityKey == "" || c.WGKey != "" {
		return nil, fmt.Errorf("%w: enrollment token must carry idk and no wgk", ErrToken)
	}
	if _, err := ParsePublicKey(c.IdentityKey); err != nil {
		return nil, fmt.Errorf("%w: idk: %v", ErrToken, err)
	}
	return c, nil
}

func parse(token, alg string, key any) (*api.DeviceClaims, error) {
	if token == "" || len(token) > maxTokenLen {
		return nil, fmt.Errorf("%w: bad length", ErrToken)
	}
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{alg}),
		jwt.WithoutClaimsValidation(), // checkClaims applies stricter, explicit rules
	)
	var c claims
	if _, err := p.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return key, nil }); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToken, err)
	}
	return &c.DeviceClaims, nil
}

func checkClaims(c *api.DeviceClaims, expectSub string, now time.Time) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrToken, fmt.Sprintf(format, a...))
	}
	skew := int64(api.MaxClockSkew / time.Second)
	maxLife := int64(api.MaxDeviceJWTLifetime / time.Second)
	n := now.Unix()
	switch {
	case c.Issuer != api.DeviceJWTIssuer:
		return bad("issuer")
	case c.Audience != api.DeviceJWTAudience:
		return bad("audience")
	case expectSub == "" || c.Subject != expectSub:
		return bad("subject")
	case c.ID == "" || len(c.ID) > maxJTILen:
		return bad("jti")
	case c.IssuedAt <= 0 || c.ExpiresAt <= 0:
		return bad("missing iat or exp")
	case c.ExpiresAt <= c.IssuedAt:
		return bad("exp not after iat")
	case c.ExpiresAt-c.IssuedAt > maxLife:
		return bad("lifetime %ds exceeds %ds", c.ExpiresAt-c.IssuedAt, maxLife)
	case c.IssuedAt > n+skew:
		return bad("issued in the future")
	case c.ExpiresAt < n-skew:
		return bad("expired")
	}
	return nil
}

// ProveEnroll returns the base64 Ed25519 signature the identity key makes over
// api.EnrollProofMessage(sub, jti) to prove possession at enrollment.
func ProveEnroll(priv ed25519.PrivateKey, sub, jti string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, api.EnrollProofMessage(sub, jti)))
}

// VerifyEnrollProof checks a proof made by ProveEnroll.
func VerifyEnrollProof(pub ed25519.PublicKey, sub, jti, proof string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad identity key", ErrToken)
	}
	sig, err := decodeB64(proof)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed enrollment proof", ErrToken)
	}
	if !ed25519.Verify(pub, api.EnrollProofMessage(sub, jti), sig) {
		return fmt.Errorf("%w: enrollment proof does not verify", ErrToken)
	}
	return nil
}

// ParseRSAPrivatePEM parses a PKCS#1 ("RSA PRIVATE KEY") or PKCS#8
// ("PRIVATE KEY") RSA private key.
func ParseRSAPrivatePEM(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("identity: no PEM block in RSA private key")
	}
	var key *rsa.PrivateKey
	switch blk.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parsing PKCS#1 key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parsing PKCS#8 key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identity: PKCS#8 key is %T, want RSA", k)
		}
		key = rk
	default:
		return nil, fmt.Errorf("identity: unsupported PEM type %q for RSA private key", blk.Type)
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("identity: RSA key has %d bits, want at least %d", key.N.BitLen(), minRSABits)
	}
	return key, nil
}

// ParseRSAPublicPEM extracts the RSA public key from the first usable PEM block:
// a CERTIFICATE (the form stored in Device.spec.keys rsa_public), a PUBLIC KEY
// (PKIX) or an RSA PUBLIC KEY (PKCS#1). The key must be at least 2048 bits.
func ParseRSAPublicPEM(b []byte) (*rsa.PublicKey, error) {
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		var pub any
		var err error
		switch blk.Type {
		case "CERTIFICATE":
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(blk.Bytes); err == nil {
				pub = cert.PublicKey
			}
		case "PUBLIC KEY":
			pub, err = x509.ParsePKIXPublicKey(blk.Bytes)
		case "RSA PUBLIC KEY":
			pub, err = x509.ParsePKCS1PublicKey(blk.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("identity: parsing %s: %w", blk.Type, err)
		}
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("identity: %s holds a %T key, want RSA", blk.Type, pub)
		}
		if rk.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("identity: RSA key has %d bits, want at least %d", rk.N.BitLen(), minRSABits)
		}
		return rk, nil
	}
	return nil, errors.New("identity: no certificate or public key PEM block found")
}
