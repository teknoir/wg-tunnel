package sshsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Vectors produced by `ssh-keygen -Y sign -n teknoir-test` over "hello vector".
const (
	vecMessage = "hello vector"
	vecNS      = "teknoir-test"
	vecEDKey   = "AAAAC3NzaC1lZDI1NTE5AAAAIDWoqFBCIG4VJjeT6s23tWeIbU8iPOFftK41lmXettk1"
	vecED25519 = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgNaioUEIgbhUmN5Pqzbe1Z4htTy
I84V+0rjWWZd622TUAAAAMdGVrbm9pci10ZXN0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3Nz
aC1lZDI1NTE5AAAAQLKsEY9cW0KvmAi3Qhj5pie5z0aiPheugbcF+o7aMHMPeeIARjPSNh
grZKTA1OeN54GPR7092pMlWCCZZW/EUwQ=
-----END SSH SIGNATURE-----
`
	vecRSA = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAKkImWHhjWypfOC+InpCWH
G2GefAUtsu6Egtpaq5F5oqVJ8Erd1WmyEUzxxPrlE3y/IwexEB6rkdKs/Gfo/fUZoRRwKn
nJxWaHYb1wUAbooAeKRMJvOONubof2VX7QWFTHbTMyNF8q3+XYvhn3vcNPw9pr5y4pfxue
8W1qivk3kU+jIZlRpizKrTLvH6XPrCS8Gbp4dkZNoYdtKj0J+o+NdiS2jzUMHHaJpX++9V
Fp8AON9AMJ1MFd9h8dALBbtn50Wr4y9iBedM/6e/ndN/JUIk77JtiiM6mnmC4Re3S6A7o6
4y8Y621xBip4mZ6pGGCofcxw4yhNQzEPE1uHi0tz8AAAAMdGVrbm9pci10ZXN0AAAAAAAA
AAZzaGE1MTIAAAEUAAAADHJzYS1zaGEyLTUxMgAAAQBgZ3XwpVf1bLbeqaUc4HHAU0hk5l
QlqAnWsgHlo9RaE9Mh+eY+T4s0TxBA+VFnM0j7HyN4BkONQfQjM/abGNXQ0x78qlAlXW6Y
8DthxP6c9hxH4btk5lqaSziaofXBQLviDwa8EA4z0clLElnbp7aDrwLeyIzkzo6+XeefHC
omaMXx/QPLgbT40JYDSJmGlUaNq/9zJpB6PkkI9AqEn/BuECQ0BfZG3dBqGf50Kkf68x0g
HYb79rjmL2T3v2sY+gtQwsLmd3GpLCzSjjLcbTd+0YbUN69Od73ORhvTplWpZbaUTrSde/
7oi9ZlW1+A0vEYOvpPzHrp63DpF7luikEz
-----END SSH SIGNATURE-----
`
)

func TestVerifyOpenSSHVectors(t *testing.T) {
	for name, armored := range map[string]string{"ed25519": vecED25519, "rsa": vecRSA} {
		t.Run(name, func(t *testing.T) {
			blob, err := Unarmor(armored)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := Verify(blob, vecNS, []byte(vecMessage))
			if err != nil {
				t.Fatal(err)
			}
			if name == "ed25519" && ssh.FingerprintSHA256(pub) != "SHA256:kd5yB+0SX/5h3j+GOX43IW1MiEkaS9j+LvtnGuIo+0M" {
				t.Fatalf("fingerprint %s", ssh.FingerprintSHA256(pub))
			}
			if _, err := Verify(blob, vecNS+"x", []byte(vecMessage)); err == nil {
				t.Error("wrong namespace accepted")
			}
			if _, err := Verify(blob, vecNS, []byte(vecMessage+"!")); err == nil {
				t.Error("wrong message accepted")
			}
			if _, err := Verify(blob, vecNS, nil); err == nil {
				t.Error("empty message accepted")
			}
		})
	}
}

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa1024":
		key, err = rsa.GenerateKey(rand.Reader, 1024)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			s := newSigner(t, kind)
			blob, err := Sign(s, "ns", []byte("message"))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := Verify(blob, "ns", []byte("message"))
			if err != nil {
				t.Fatal(err)
			}
			if ssh.FingerprintSHA256(pub) != ssh.FingerprintSHA256(s.PublicKey()) {
				t.Fatal("verify returned another key")
			}
			if _, err := Verify(blob, "other", []byte("message")); err == nil {
				t.Error("wrong namespace verified")
			}
			if _, err := Verify(blob, "ns", []byte("messagf")); err == nil {
				t.Error("wrong message verified")
			}
			// Any single flipped byte must fail (or at least never verify).
			for i := range blob {
				bad := append([]byte(nil), blob...)
				bad[i] ^= 0x01
				if _, err := Verify(bad, "ns", []byte("message")); err == nil {
					t.Fatalf("flipped byte %d still verifies", i)
				}
			}
			if _, err := Verify(append(append([]byte(nil), blob...), 0), "ns", []byte("message")); err == nil {
				t.Error("trailing byte accepted")
			}
			if _, err := Verify(blob[:len(blob)-1], "ns", []byte("message")); err == nil {
				t.Error("truncated blob accepted")
			}
		})
	}
}

func TestSignRefusesUnsupportedKeys(t *testing.T) {
	if _, err := Sign(newSigner(t, "ecdsa"), "ns", []byte("m")); err == nil {
		t.Error("ecdsa signer accepted")
	}
	if _, err := Sign(newSigner(t, "rsa1024"), "ns", []byte("m")); err == nil {
		t.Error("1024-bit RSA signer accepted")
	}
	if _, err := Sign(newSigner(t, "ed25519"), "", []byte("m")); err == nil {
		t.Error("empty namespace accepted")
	}
}

// build assembles an SSHSIG blob by hand so tests can produce what a hostile
// signer would.
func build(version uint32, pub ssh.PublicKey, ns, hash string, sig *ssh.Signature) []byte {
	return append([]byte(magic), ssh.Marshal(wire{
		Version: version, PublicKey: pub.Marshal(), Namespace: ns, HashAlgorithm: hash, Signature: ssh.Marshal(sig),
	})...)
}

func TestVerifyRefusesWeakVariants(t *testing.T) {
	msg := []byte("message")
	rs := newSigner(t, "rsa")
	as := rs.(ssh.AlgorithmSigner)

	signRSA := func(alg, hash string, ns string) []byte {
		t.Helper()
		var data []byte
		if hash == "sha512" {
			data = dataToSign(ns, msg)
		} else {
			// A correct sha256 SSHSIG signed-data, to prove the refusal is about the algorithm.
			data = append([]byte(magic), ssh.Marshal(signedData{Namespace: ns, HashAlgorithm: hash, Hash: make([]byte, 32)})...)
		}
		sig, err := as.SignWithAlgorithm(rand.Reader, data, alg)
		if err != nil {
			t.Fatal(err)
		}
		return build(1, rs.PublicKey(), ns, hash, sig)
	}
	if _, err := Verify(signRSA(ssh.KeyAlgoRSASHA512, "sha512", "ns"), "ns", msg); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, blob := range map[string][]byte{
		"ssh-rsa SHA1":   signRSA(ssh.KeyAlgoRSA, "sha512", "ns"),
		"rsa-sha2-256":   signRSA(ssh.KeyAlgoRSASHA256, "sha512", "ns"),
		"sha256 hashalg": signRSA(ssh.KeyAlgoRSASHA512, "sha256", "ns"),
	} {
		if _, err := Verify(blob, "ns", msg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	ed := newSigner(t, "ed25519")
	sig, err := ed.Sign(rand.Reader, dataToSign("ns", msg))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(build(1, ed.PublicKey(), "ns", "sha512", sig), "ns", msg); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := Verify(build(2, ed.PublicKey(), "ns", "sha512", sig), "ns", msg); err == nil {
		t.Error("version 2 accepted")
	}

	ec := newSigner(t, "ecdsa")
	esig, err := ec.Sign(rand.Reader, dataToSign("ns", msg))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(build(1, ec.PublicKey(), "ns", "sha512", esig), "ns", msg); err == nil {
		t.Error("ecdsa accepted")
	}

	weak := newSigner(t, "rsa1024")
	wsig, err := weak.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, dataToSign("ns", msg), ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(build(1, weak.PublicKey(), "ns", "sha512", wsig), "ns", msg); err == nil {
		t.Error("1024-bit RSA accepted")
	}

	// A signature in the key's format but made by another key.
	other := newSigner(t, "ed25519")
	osig, _ := other.Sign(rand.Reader, dataToSign("ns", msg))
	if _, err := Verify(build(1, ed.PublicKey(), "ns", "sha512", osig), "ns", msg); err == nil {
		t.Error("signature of another key accepted")
	}
	if _, err := Verify(nil, "ns", msg); err == nil {
		t.Error("empty blob accepted")
	}
	if _, err := Verify([]byte("SSHSIG"), "ns", msg); err == nil {
		t.Error("magic only accepted")
	}
	huge := make([]byte, maxBlobBytes+1)
	copy(huge, magic)
	binary.BigEndian.PutUint32(huge[6:], 1)
	if _, err := Verify(huge, "ns", msg); err == nil {
		t.Error("oversized blob accepted")
	}
}

func TestArmorRoundTrip(t *testing.T) {
	blob, err := Sign(newSigner(t, "ed25519"), "ns", []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unarmor(Armor(blob))
	if err != nil || string(got) != string(blob) {
		t.Fatalf("armor round trip: %v", err)
	}
	for _, bad := range []string{"", "xx", "-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----"} {
		if _, err := Unarmor(bad); err == nil {
			t.Errorf("Unarmor(%q) succeeded", bad)
		}
	}
}

func keygen(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	return t.TempDir()
}

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCrossSignedByOpenSSH has ssh-keygen sign and checks our Verify.
func TestCrossSignedByOpenSSH(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			dir := keygen(t)
			key := filepath.Join(dir, "k")
			if out, err := run(t, "", "-q", "-t", kind, "-b", "3072", "-N", "", "-f", key); err != nil {
				t.Fatalf("ssh-keygen: %v: %s", err, out)
			}
			msgFile := filepath.Join(dir, "msg")
			msg := []byte("teknoir-ztna-attest-v1\nns/dev\nSHA256:abc\nepoch\n3\nnonce")
			if err := os.WriteFile(msgFile, msg, 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := run(t, "", "-q", "-Y", "sign", "-f", key, "-n", "cross-ns", msgFile); err != nil {
				t.Fatalf("ssh-keygen -Y sign: %v: %s", err, out)
			}
			armored, err := os.ReadFile(msgFile + ".sig")
			if err != nil {
				t.Fatal(err)
			}
			blob, err := Unarmor(string(armored))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := Verify(blob, "cross-ns", msg)
			if err != nil {
				t.Fatalf("our Verify rejects an OpenSSH signature: %v", err)
			}
			pubFile, _ := os.ReadFile(key + ".pub")
			want, _, _, _, err := ssh.ParseAuthorizedKey(pubFile)
			if err != nil {
				t.Fatal(err)
			}
			if ssh.FingerprintSHA256(pub) != ssh.FingerprintSHA256(want) {
				t.Error("verified key is not the signing key")
			}
		})
	}
}

// TestCrossCheckedByOpenSSH signs here and has ssh-keygen check the result.
func TestCrossCheckedByOpenSSH(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			dir := keygen(t)
			key := filepath.Join(dir, "k")
			if out, err := run(t, "", "-q", "-t", kind, "-b", "3072", "-N", "", "-f", key); err != nil {
				t.Fatalf("ssh-keygen: %v: %s", err, out)
			}
			raw, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.ParsePrivateKey(raw)
			if err != nil {
				t.Fatal(err)
			}
			msg := "statement to check"
			blob, err := Sign(signer, "cross-ns", []byte(msg))
			if err != nil {
				t.Fatal(err)
			}
			sigFile := filepath.Join(dir, "sig")
			if err := os.WriteFile(sigFile, []byte(Armor(blob)), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := run(t, msg, "-Y", "check-novalidate", "-n", "cross-ns", "-s", sigFile); err != nil {
				t.Fatalf("ssh-keygen -Y check-novalidate rejects our signature: %v: %s", err, out)
			}
			if _, err := run(t, msg+"x", "-Y", "check-novalidate", "-n", "cross-ns", "-s", sigFile); err == nil {
				t.Error("ssh-keygen accepted a different message")
			}
			if _, err := run(t, msg, "-Y", "check-novalidate", "-n", "other-ns", "-s", sigFile); err == nil {
				t.Error("ssh-keygen accepted a different namespace")
			}
		})
	}
}
