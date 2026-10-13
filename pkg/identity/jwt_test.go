package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

const sub = "teknoir-demo/vdev-01"

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return rsaKey
}

func pkcs1(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func pkcs8(t testing.TB, k *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// cert mimics device-controller: self-signed, valid for one year from `from`.
func cert(t testing.TB, k *rsa.PrivateKey, from time.Time) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "teknoir.ai"},
		NotBefore: from, NotAfter: from.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func spki(t testing.TB, k *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func edKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func isTokenErr(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, ErrToken) {
		t.Errorf("%s: err = %v, want ErrToken", name, err)
	}
}

func TestIdentityJWTRoundTrip(t *testing.T) {
	pub, priv := edKey(t)
	now := time.Now()
	tok, jti, err := MintIdentityJWTAt(priv, sub, "d2dLZXk=", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyIdentityJWT(tok, pub, sub, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != api.DeviceJWTIssuer || c.Audience != api.DeviceJWTAudience || c.Subject != sub ||
		c.WGKey != "d2dLZXk=" || c.IdentityKey != "" || c.ID != jti || len(jti) != 32 ||
		c.IssuedAt != now.Unix() || c.ExpiresAt != now.Unix()+30 {
		t.Fatalf("claims %+v", c)
	}
	// Header is EdDSA and the payload uses the contract's claim names.
	parts := strings.Split(tok, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var h map[string]any
	_ = json.Unmarshal(hdr, &h)
	if h["alg"] != "EdDSA" {
		t.Fatalf("header %v", h)
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	for _, k := range []string{"iss", "sub", "aud", "iat", "exp", "jti", "wgk"} {
		if _, ok := m[k]; !ok {
			t.Errorf("claim %q missing: %v", k, m)
		}
	}
	if _, ok := m["idk"]; ok {
		t.Error("idk must be absent from identity tokens")
	}
	// Unique jti per token.
	_, jti2, _ := MintIdentityJWTAt(priv, sub, "x", time.Second, now)
	if jti2 == jti {
		t.Fatal("jti reused")
	}
	// The unclocked variant works against the real clock.
	tok, _, err = MintIdentityJWT(priv, sub, "x", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIdentityJWT(tok, pub, sub, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestMintIdentityValidation(t *testing.T) {
	_, priv := edKey(t)
	now := time.Now()
	for name, f := range map[string]func() error{
		"no wgk":      func() error { _, _, e := MintIdentityJWTAt(priv, sub, "", time.Second*5, now); return e },
		"no sub":      func() error { _, _, e := MintIdentityJWTAt(priv, "", "k", time.Second*5, now); return e },
		"ttl zero":    func() error { _, _, e := MintIdentityJWTAt(priv, sub, "k", 0, now); return e },
		"ttl sub-sec": func() error { _, _, e := MintIdentityJWTAt(priv, sub, "k", time.Millisecond, now); return e },
		"ttl too big": func() error {
			_, _, e := MintIdentityJWTAt(priv, sub, "k", api.MaxDeviceJWTLifetime+time.Second, now)
			return e
		},
		"bad key": func() error {
			_, _, e := MintIdentityJWTAt(ed25519.PrivateKey("short"), sub, "k", time.Second*5, now)
			return e
		},
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := MintIdentityJWTAt(priv, sub, "k", api.MaxDeviceJWTLifetime, now); err != nil {
		t.Errorf("max lifetime rejected: %v", err)
	}
}

// signRaw signs arbitrary claims, bypassing Mint's safety checks.
func signRaw(t testing.TB, method jwt.SigningMethod, key any, mutate func(m jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	m := jwt.MapClaims{
		"iss": api.DeviceJWTIssuer, "sub": sub, "aud": api.DeviceJWTAudience,
		"iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "abc", "wgk": "k",
	}
	if mutate != nil {
		mutate(m)
	}
	s, err := jwt.NewWithClaims(method, m).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyIdentityRejects(t *testing.T) {
	pub, priv := edKey(t)
	_, otherPriv := edKey(t)
	now := time.Now()
	mk := func(f func(m jwt.MapClaims)) string { return signRaw(t, jwt.SigningMethodEdDSA, priv, f) }

	if _, err := VerifyIdentityJWT(mk(nil), pub, sub, now); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	unix := func(d time.Duration) int64 { return now.Add(d).Unix() }
	cases := map[string]string{
		"wrong issuer":        mk(func(m jwt.MapClaims) { m["iss"] = "evil" }),
		"missing issuer":      mk(func(m jwt.MapClaims) { delete(m, "iss") }),
		"wrong audience":      mk(func(m jwt.MapClaims) { m["aud"] = "other" }),
		"audience array":      mk(func(m jwt.MapClaims) { m["aud"] = []string{api.DeviceJWTAudience} }),
		"wrong subject":       mk(func(m jwt.MapClaims) { m["sub"] = "teknoir-demo/other" }),
		"missing jti":         mk(func(m jwt.MapClaims) { delete(m, "jti") }),
		"empty jti":           mk(func(m jwt.MapClaims) { m["jti"] = "" }),
		"huge jti":            mk(func(m jwt.MapClaims) { m["jti"] = strings.Repeat("a", 200) }),
		"missing wgk":         mk(func(m jwt.MapClaims) { delete(m, "wgk") }),
		"has idk":             mk(func(m jwt.MapClaims) { m["idk"] = "x" }),
		"missing exp":         mk(func(m jwt.MapClaims) { delete(m, "exp") }),
		"missing iat":         mk(func(m jwt.MapClaims) { delete(m, "iat") }),
		"expired":             mk(func(m jwt.MapClaims) { m["iat"] = unix(-5 * time.Minute); m["exp"] = unix(-4 * time.Minute) }),
		"expired beyond skew": mk(func(m jwt.MapClaims) { m["iat"] = unix(-50 * time.Second); m["exp"] = unix(-31 * time.Second) }),
		"iat in future":       mk(func(m jwt.MapClaims) { m["iat"] = unix(31 * time.Second); m["exp"] = unix(61 * time.Second) }),
		"lifetime 61s":        mk(func(m jwt.MapClaims) { m["iat"] = unix(0); m["exp"] = unix(61 * time.Second) }),
		"lifetime 10min":      mk(func(m jwt.MapClaims) { m["exp"] = unix(10 * time.Minute) }),
		"exp before iat":      mk(func(m jwt.MapClaims) { m["exp"] = unix(-time.Second) }),
		"exp equals iat":      mk(func(m jwt.MapClaims) { m["exp"] = m["iat"] }),
		"signed by other key": signRaw(t, jwt.SigningMethodEdDSA, otherPriv, nil),
		"alg none":            signRaw(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, nil),
		"HS256 with pub":      signRaw(t, jwt.SigningMethodHS256, []byte(pub), nil),
		"RS256":               signRaw(t, jwt.SigningMethodRS256, testRSA(t), nil),
		"empty":               "",
		"junk":                "not.a.jwt",
		"too long":            strings.Repeat("a", 5000),
	}
	for name, tok := range cases {
		_, err := VerifyIdentityJWT(tok, pub, sub, now)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		isTokenErr(t, name, err)
	}

	// Tampered payload keeps a valid-looking structure but fails the signature.
	good := mk(nil)
	parts := strings.Split(good, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	body = []byte(strings.Replace(string(body), sub, "teknoir-demo/other", 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(body)
	if _, err := VerifyIdentityJWT(strings.Join(parts, "."), pub, "teknoir-demo/other", now); err == nil {
		t.Error("tampered token accepted")
	}
	// Truncated signature.
	if _, err := VerifyIdentityJWT(good[:len(good)-4], pub, sub, now); err == nil {
		t.Error("truncated token accepted")
	}
	// No expected subject / no key.
	if _, err := VerifyIdentityJWT(good, pub, "", now); err == nil {
		t.Error("empty expectSub accepted")
	}
	if _, err := VerifyIdentityJWT(good, nil, sub, now); err == nil {
		t.Error("nil key accepted")
	}
}

func TestVerifyIdentitySkewBoundaries(t *testing.T) {
	pub, priv := edKey(t)
	now := time.Now()
	mk := func(iat, exp time.Time) string {
		return signRaw(t, jwt.SigningMethodEdDSA, priv, func(m jwt.MapClaims) { m["iat"] = iat.Unix(); m["exp"] = exp.Unix() })
	}
	// 29 s in the future is within skew; 29 s past expiry is within skew.
	if _, err := VerifyIdentityJWT(mk(now.Add(29*time.Second), now.Add(59*time.Second)), pub, sub, now); err != nil {
		t.Errorf("iat +29s rejected: %v", err)
	}
	if _, err := VerifyIdentityJWT(mk(now.Add(-59*time.Second), now.Add(-29*time.Second)), pub, sub, now); err != nil {
		t.Errorf("exp -29s rejected: %v", err)
	}
	// Exactly the maximum lifetime passes.
	if _, err := VerifyIdentityJWT(mk(now, now.Add(api.MaxDeviceJWTLifetime)), pub, sub, now); err != nil {
		t.Errorf("60s lifetime rejected: %v", err)
	}
	// Verifying later (the "now" argument) expires the token.
	tok, _, _ := MintIdentityJWTAt(priv, sub, "k", 30*time.Second, now)
	if _, err := VerifyIdentityJWT(tok, pub, sub, now.Add(61*time.Second)); err == nil {
		t.Error("token valid 61s after expiry")
	}
	if _, err := VerifyIdentityJWT(tok, pub, sub, now.Add(-31*time.Second)); err == nil {
		t.Error("token valid 31s before issue")
	}
}

func TestEnrollJWTRoundTrip(t *testing.T) {
	rk := testRSA(t)
	idPub, idPriv := edKey(t)
	idk := EncodePublicKey(idPub)
	now := time.Now()

	for name, privPEM := range map[string][]byte{"PKCS1": pkcs1(rk), "PKCS8": pkcs8(t, rk)} {
		tok, jti, err := MintEnrollJWTAt(privPEM, sub, idk, 30*time.Second, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Public material as stored in Device.spec.keys (certificate), a bare
		// PUBLIC KEY, and a certificate that expired long ago.
		for pname, pubPEM := range map[string][]byte{
			"cert":          cert(t, rk, now.AddDate(-3, 0, 0)), // expired two years ago
			"cert (valid)":  cert(t, rk, now),
			"PUBLIC KEY":    spki(t, rk),
			"cert + noise":  append([]byte("# comment\n"), cert(t, rk, now)...),
			"key then cert": append(spki(t, rk), cert(t, rk, now)...),
		} {
			c, err := VerifyEnrollJWT(tok, pubPEM, sub, now)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, pname, err)
			}
			if c.IdentityKey != idk || c.WGKey != "" || c.ID != jti || c.Subject != sub {
				t.Fatalf("%s/%s: claims %+v", name, pname, c)
			}
		}
		// Proof of possession.
		proof := ProveEnroll(idPriv, sub, jti)
		if err := VerifyEnrollProof(idPub, sub, jti, proof); err != nil {
			t.Fatalf("proof: %v", err)
		}
	}
}

func TestEnrollJWTHeaderIsRS256(t *testing.T) {
	idPub, _ := edKey(t)
	tok, _, err := MintEnrollJWT(pkcs1(testRSA(t)), sub, EncodePublicKey(idPub), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var h map[string]any
	_ = json.Unmarshal(hdr, &h)
	if h["alg"] != "RS256" {
		t.Fatalf("header %v", h)
	}
}

func TestVerifyEnrollRejects(t *testing.T) {
	rk := testRSA(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idPub, _ := edKey(t)
	idk := EncodePublicKey(idPub)
	edPub, edPriv := edKey(t)
	now := time.Now()
	certPEM := cert(t, rk, now)
	mk := func(method jwt.SigningMethod, key any, f func(m jwt.MapClaims)) string {
		return signRaw(t, method, key, func(m jwt.MapClaims) {
			delete(m, "wgk")
			m["idk"] = idk
			if f != nil {
				f(m)
			}
		})
	}
	if _, err := VerifyEnrollJWT(mk(jwt.SigningMethodRS256, rk, nil), certPEM, sub, now); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	cases := map[string]string{
		"wrong key":        mk(jwt.SigningMethodRS256, other, nil),
		"wrong subject":    mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["sub"] = "x/y" }),
		"wrong issuer":     mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["iss"] = "x" }),
		"wrong audience":   mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["aud"] = "x" }),
		"no idk":           mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { delete(m, "idk") }),
		"idk garbage":      mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["idk"] = "zzz" }),
		"idk wrong length": mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["idk"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) }),
		"has wgk":          mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["wgk"] = "k" }),
		"no jti":           mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { delete(m, "jti") }),
		"expired": mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) {
			m["iat"] = now.Add(-5 * time.Minute).Unix()
			m["exp"] = now.Add(-4 * time.Minute).Unix()
		}),
		"lifetime 5min":   mk(jwt.SigningMethodRS256, rk, func(m jwt.MapClaims) { m["exp"] = now.Add(5 * time.Minute).Unix() }),
		"alg none":        mk(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, nil),
		"HS256 with n":    mk(jwt.SigningMethodHS256, rk.N.Bytes(), nil),
		"HS256 with cert": mk(jwt.SigningMethodHS256, certPEM, nil),
		"RS384":           mk(jwt.SigningMethodRS384, rk, nil),
		"PS256":           mk(jwt.SigningMethodPS256, rk, nil),
		"EdDSA":           mk(jwt.SigningMethodEdDSA, edPriv, nil),
		"junk":            "a.b.c",
	}
	for name, tok := range cases {
		_, err := VerifyEnrollJWT(tok, certPEM, sub, now)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		isTokenErr(t, name, err)
	}
	_ = edPub
	good := mk(jwt.SigningMethodRS256, rk, nil)
	if _, err := VerifyEnrollJWT(good, []byte("not pem"), sub, now); err == nil {
		t.Error("garbage cert accepted")
	} else {
		isTokenErr(t, "garbage cert", err)
	}
	if _, err := VerifyEnrollJWT(good, certPEM, "", now); err == nil {
		t.Error("empty expectSub accepted")
	}
	// An enrollment token is not an identity token and vice versa.
	if _, err := VerifyIdentityJWT(good, edPub, sub, now); err == nil {
		t.Error("enrollment token accepted as identity token")
	}
}

func TestEnrollProof(t *testing.T) {
	pub, priv := edKey(t)
	otherPub, _ := edKey(t)
	proof := ProveEnroll(priv, sub, "jti-1")
	if err := VerifyEnrollProof(pub, sub, "jti-1", proof); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnrollProof(pub, sub, "jti-1", strings.TrimRight(proof, "=")); err != nil {
		t.Errorf("unpadded proof rejected: %v", err)
	}
	for name, f := range map[string]func() error{
		"wrong jti":     func() error { return VerifyEnrollProof(pub, sub, "jti-2", proof) },
		"wrong subject": func() error { return VerifyEnrollProof(pub, "x/y", "jti-1", proof) },
		"wrong key":     func() error { return VerifyEnrollProof(otherPub, sub, "jti-1", proof) },
		"garbage":       func() error { return VerifyEnrollProof(pub, sub, "jti-1", "!!") },
		"short": func() error {
			return VerifyEnrollProof(pub, sub, "jti-1", base64.StdEncoding.EncodeToString([]byte("x")))
		},
		"empty":   func() error { return VerifyEnrollProof(pub, sub, "jti-1", "") },
		"nil key": func() error { return VerifyEnrollProof(nil, sub, "jti-1", proof) },
	} {
		err := f()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		isTokenErr(t, name, err)
	}
	// The signed message is exactly the contract's.
	sig, _ := base64.StdEncoding.DecodeString(proof)
	if !ed25519.Verify(pub, api.EnrollProofMessage(sub, "jti-1"), sig) {
		t.Fatal("proof is not over api.EnrollProofMessage")
	}
	// Domain separation: an identity-JWT signing input cannot double as a proof.
	tok, _, _ := MintIdentityJWT(priv, sub, "k", time.Minute)
	jwtSig := strings.Split(tok, ".")[2]
	raw, _ := base64.RawURLEncoding.DecodeString(jwtSig)
	if err := VerifyEnrollProof(pub, sub, "jti-1", base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("JWT signature accepted as enrollment proof")
	}
}

func TestMintEnrollValidation(t *testing.T) {
	rk := testRSA(t)
	idPub, _ := edKey(t)
	idk := EncodePublicKey(idPub)
	now := time.Now()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, f := range map[string]func() error{
		"bad pem":      func() error { _, _, e := MintEnrollJWTAt([]byte("x"), sub, idk, time.Second*5, now); return e },
		"public pem":   func() error { _, _, e := MintEnrollJWTAt(spki(t, rk), sub, idk, time.Second*5, now); return e },
		"1024 bit key": func() error { _, _, e := MintEnrollJWTAt(pkcs1(small), sub, idk, time.Second*5, now); return e },
		"bad idk":      func() error { _, _, e := MintEnrollJWTAt(pkcs1(rk), sub, "nope", time.Second*5, now); return e },
		"no sub":       func() error { _, _, e := MintEnrollJWTAt(pkcs1(rk), "", idk, time.Second*5, now); return e },
		"ttl too big":  func() error { _, _, e := MintEnrollJWTAt(pkcs1(rk), sub, idk, 2*time.Minute, now); return e },
		"ed25519 pkcs8": func() error {
			_, p := edKey(t)
			der, _ := x509.MarshalPKCS8PrivateKey(p)
			_, _, e := MintEnrollJWTAt(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), sub, idk, time.Second*5, now)
			return e
		},
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRSAPublicPEMRejects(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	edPub, _ := edKey(t)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	for name, in := range map[string][]byte{
		"empty":      nil,
		"junk":       []byte("hello"),
		"1024 bit":   spki(t, small),
		"ed25519":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}),
		"bad cert":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"only other": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("x")}),
	} {
		if _, err := ParseRSAPublicPEM(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// PKCS#1 public key form.
	rk := testRSA(t)
	p1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rk.PublicKey)})
	if _, err := ParseRSAPublicPEM(p1); err != nil {
		t.Errorf("PKCS#1 public key: %v", err)
	}
}
