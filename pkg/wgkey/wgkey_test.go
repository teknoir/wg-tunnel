package wgkey

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGenerateClampedAndConsistent(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		priv, pub, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if priv[0]&7 != 0 || priv[31]&0x80 != 0 || priv[31]&0x40 == 0 {
			t.Fatalf("private key not clamped: %x", priv[:])
		}
		want, err := ecdh.X25519().NewPrivateKey(priv[:])
		if err != nil {
			t.Fatal(err)
		}
		if string(want.PublicKey().Bytes()) != string(pub[:]) {
			t.Fatal("public key does not match private key")
		}
		got, err := priv.Public()
		if err != nil || got != pub {
			t.Fatalf("Public() = %v, %v", got, err)
		}
		if seen[priv.Base64()] {
			t.Fatal("duplicate key generated")
		}
		seen[priv.Base64()] = true
	}
}

// RFC 7748 section 6.1 test vector (Alice).
func TestPublicKnownVector(t *testing.T) {
	priv, err := ParsePrivateHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pub.Hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; got != want {
		t.Fatalf("pub = %s want %s", got, want)
	}
}

func TestBase64HexRoundTrip(t *testing.T) {
	priv, pub, _ := Generate()
	for _, k := range []struct{ b64, hex string }{{priv.Base64(), priv.Hex()}, {pub.Base64(), pub.Hex()}} {
		h, err := Base64ToHex(k.b64)
		if err != nil || h != k.hex {
			t.Fatalf("Base64ToHex = %q, %v want %q", h, err, k.hex)
		}
		b, err := HexToBase64(k.hex)
		if err != nil || b != k.b64 {
			t.Fatalf("HexToBase64 = %q, %v want %q", b, err, k.b64)
		}
	}
	p2, err := ParsePrivate(priv.Base64())
	if err != nil || p2 != priv {
		t.Fatal("ParsePrivate round trip failed")
	}
	q2, err := ParsePublic(pub.Base64())
	if err != nil || q2 != pub {
		t.Fatal("ParsePublic round trip failed")
	}
	p3, err := ParsePrivateHex(priv.Hex())
	if err != nil || p3 != priv {
		t.Fatal("ParsePrivateHex round trip failed")
	}
	q3, err := ParsePublicHex(pub.Hex())
	if err != nil || q3 != pub {
		t.Fatal("ParsePublicHex round trip failed")
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	nonzero := make([]byte, 32)
	nonzero[5] = 9
	cases := map[string]string{
		"empty":        "",
		"short":        base64.StdEncoding.EncodeToString(nonzero[:31]),
		"long":         base64.StdEncoding.EncodeToString(append(nonzero, 1)),
		"not base64":   "!!!!" + strings.Repeat("A", 40),
		"all zero":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"url alphabet": strings.ReplaceAll(base64.StdEncoding.EncodeToString(func() []byte { b := make([]byte, 32); b[0] = 0xfb; b[1] = 0xff; return b }()), "+", "-"),
		"trailing nl":  base64.StdEncoding.EncodeToString(nonzero) + "\n",
		"no padding":   strings.TrimRight(base64.StdEncoding.EncodeToString(nonzero), "="),
	}
	for name, in := range cases {
		if _, err := ParsePublic(in); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ParsePublic(%s): err = %v", name, err)
		}
		if _, err := ParsePrivate(in); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ParsePrivate(%s): err = %v", name, err)
		}
	}
	if _, err := ParsePublicHex("zz"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("bad hex: %v", err)
	}
	if _, err := ParsePublicHex(strings.Repeat("ab", 31)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short hex: %v", err)
	}
	if _, err := Base64ToHex("nope"); err == nil {
		t.Error("Base64ToHex accepted junk")
	}
	if _, err := HexToBase64("nope"); err == nil {
		t.Error("HexToBase64 accepted junk")
	}
}

func TestPrivateKeyIsRedacted(t *testing.T) {
	priv, _, _ := Generate()
	forms := []string{
		fmt.Sprint(priv), fmt.Sprintf("%v", priv), fmt.Sprintf("%+v", priv), fmt.Sprintf("%#v", priv),
		fmt.Sprintf("%s", priv), //nolint:staticcheck // exercising the %s verb on purpose
	}
	for _, s := range forms {
		if strings.Contains(s, priv.Base64()) || strings.Contains(s, priv.Hex()) {
			t.Fatalf("private key leaked in %q", s)
		}
	}
}

func TestZero(t *testing.T) {
	priv, _, _ := Generate()
	priv.Zero()
	if priv != (PrivateKey{}) {
		t.Fatal("Zero did not clear key")
	}
}
