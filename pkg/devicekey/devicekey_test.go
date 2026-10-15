package devicekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// rsaPair returns a PKCS#1 private key PEM and a self-signed CERTIFICATE PEM,
// the forms Device spec.keys rsa_private / rsa_public use.
func rsaPair(t *testing.T) (privPEM, certPEM []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unused"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSealOpenRoundTrip(t *testing.T) {
	privPEM, certPEM := rsaPair(t)
	dk, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(certPEM, "ns", "dev", "s1", dk)
	if err != nil {
		t.Fatal(err)
	}
	if env.V != api.DeviceKeyEnvelopeVersion || !strings.HasPrefix(env.Fingerprint, "SHA256:") {
		t.Fatalf("envelope %+v", env)
	}
	got, err := Open(privPEM, "ns", "dev", env)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(dk) {
		t.Fatal("opened key differs")
	}
	b, err := MarshalOpenSSH(got)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseOpenSSH(b)
	if err != nil || !back.Equal(dk) {
		t.Fatalf("openssh round trip: %v", err)
	}
}

func TestOpenRefusesTampering(t *testing.T) {
	privPEM, certPEM := rsaPair(t)
	otherPriv, _ := rsaPair(t)
	dk, _ := Generate()
	other, _ := Generate()
	otherFP, _ := Fingerprint(other.Public().(ed25519.PublicKey))
	env, err := Seal(certPEM, "ns", "dev", "s1", dk)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (api.DeviceKeyEnvelope, []byte, string, string){
		"other device":    func() (api.DeviceKeyEnvelope, []byte, string, string) { return env, privPEM, "ns", "dev2" },
		"other namespace": func() (api.DeviceKeyEnvelope, []byte, string, string) { return env, privPEM, "ns2", "dev" },
		"other rsa key":   func() (api.DeviceKeyEnvelope, []byte, string, string) { return env, otherPriv, "ns", "dev" },
		"relabelled device": func() (api.DeviceKeyEnvelope, []byte, string, string) {
			e := env
			e.Device = "dev2"
			return e, privPEM, "ns", "dev2"
		},
		"changed serial": func() (api.DeviceKeyEnvelope, []byte, string, string) {
			e := env
			e.Serial = "s2"
			return e, privPEM, "ns", "dev"
		},
		"wrong fingerprint": func() (api.DeviceKeyEnvelope, []byte, string, string) {
			e := env
			e.Fingerprint = otherFP
			return e, privPEM, "ns", "dev"
		},
		"wrong version": func() (api.DeviceKeyEnvelope, []byte, string, string) {
			e := env
			e.V = 2
			return e, privPEM, "ns", "dev"
		},
		"no serial": func() (api.DeviceKeyEnvelope, []byte, string, string) {
			e := env
			e.Serial = ""
			return e, privPEM, "ns", "dev"
		},
	}
	for name, mk := range cases {
		e, k, ns, dev := mk()
		if _, err := Open(k, ns, dev, e); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestSealRefusesBadInput(t *testing.T) {
	_, certPEM := rsaPair(t)
	dk, _ := Generate()
	if _, err := Seal(certPEM, "", "dev", "s", dk); err == nil {
		t.Error("empty namespace sealed")
	}
	if _, err := Seal([]byte("junk"), "ns", "dev", "s", dk); err == nil {
		t.Error("junk RSA key sealed")
	}
}
