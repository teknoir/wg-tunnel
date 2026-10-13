package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tmp returns a fresh 0700 directory (t.TempDir honours the umask, which on
// dev machines makes it group-writable).
func tmp(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestLoadOrCreate(t *testing.T) {
	dir := filepath.Join(tmp(t), "wg-agent")
	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != ed25519.PrivateKeySize {
		t.Fatalf("key size %d", len(k1))
	}
	if m := mode(t, dir); m != 0o700 {
		t.Fatalf("dir mode %04o", m)
	}
	if m := mode(t, filepath.Join(dir, KeyFile)); m != 0o600 {
		t.Fatalf("key mode %04o", m)
	}
	k2, err := LoadOrCreate(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reload: %v equal=%v", err, k1.Equal(k2))
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != KeyFile {
		t.Fatalf("stray files in identity dir: %v", ents)
	}
	// The stored form is a standard PKCS#8 PEM.
	b, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatal("not PKCS#8 PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOrCreateRefusesUnsafeFiles(t *testing.T) {
	for _, m := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o707} {
		dir := tmp(t)
		if _, err := LoadOrCreate(dir); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, KeyFile)
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(dir); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("mode %04o accepted: %v", m, err)
		}
		if _, err := Rotate(dir); err == nil {
			t.Errorf("Rotate accepted mode %04o", m)
		}
		// Not silently repaired.
		if got := mode(t, p); got != m {
			t.Errorf("mode changed from %04o to %04o", m, got)
		}
	}
}

func TestLoadOrCreateRefusesBadContent(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_ = other
	cases := map[string]func(dir string){
		"garbage": func(dir string) { os.WriteFile(filepath.Join(dir, KeyFile), []byte("hello"), 0o600) },
		"empty":   func(dir string) { os.WriteFile(filepath.Join(dir, KeyFile), nil, 0o600) },
		"wrong type": func(dir string) {
			os.WriteFile(filepath.Join(dir, KeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600)
		},
		"directory": func(dir string) { os.Mkdir(filepath.Join(dir, KeyFile), 0o700) },
		"symlink": func(dir string) {
			real := filepath.Join(dir, "real")
			os.WriteFile(real, []byte("x"), 0o600)
			os.Symlink(real, filepath.Join(dir, KeyFile))
		},
	}
	for name, setup := range cases {
		dir := tmp(t)
		setup(dir)
		if _, err := LoadOrCreate(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An RSA key in the identity file is not an identity.
	dir := tmp(t)
	der, _ := x509.MarshalPKCS8PrivateKey(testRSA(t))
	os.WriteFile(filepath.Join(dir, KeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	if _, err := LoadOrCreate(dir); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("RSA identity accepted: %v", err)
	}
}

func TestEnsureDir(t *testing.T) {
	if _, err := LoadOrCreate(""); err == nil {
		t.Error("empty dir accepted")
	}
	d := t.TempDir()
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(d); err == nil {
		t.Error("world-writable dir accepted")
	}
	f := filepath.Join(tmp(t), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := LoadOrCreate(f); err == nil {
		t.Error("file as dir accepted")
	}
	// Pre-existing 0755 directory (created by an init container) is fine.
	d2 := t.TempDir()
	os.Chmod(d2, 0o755)
	if _, err := LoadOrCreate(d2); err != nil {
		t.Errorf("0755 dir rejected: %v", err)
	}
}

func TestLoadOrCreateConcurrent(t *testing.T) {
	dir := tmp(t)
	const n = 12
	keys := make([]ed25519.PrivateKey, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = LoadOrCreate(dir)
		}()
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if !keys[i].Equal(keys[0]) {
			t.Fatal("concurrent callers got different keys")
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("stray files: %v", ents)
	}
}

func TestRotate(t *testing.T) {
	dir := tmp(t)
	old, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Rotate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Equal(old) {
		t.Fatal("Rotate returned the same key")
	}
	got, err := LoadOrCreate(dir)
	if err != nil || !got.Equal(fresh) {
		t.Fatal("identity.key does not hold the new key")
	}
	prev, err := load(filepath.Join(dir, PrevKeyFile))
	if err != nil || !prev.Equal(old) {
		t.Fatalf("identity.key.prev does not hold the old key: %v", err)
	}
	if m := mode(t, filepath.Join(dir, PrevKeyFile)); m != 0o600 {
		t.Fatalf("prev mode %04o", m)
	}
	// A second rotation overwrites .prev with the previous generation.
	third, err := Rotate(dir)
	if err != nil {
		t.Fatal(err)
	}
	prev2, _ := load(filepath.Join(dir, PrevKeyFile))
	if !prev2.Equal(fresh) || third.Equal(fresh) {
		t.Fatal("second rotation did not shift keys")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("stray files: %v", ents)
	}
	// Rotate with no existing key just creates one.
	d2 := tmp(t)
	k, err := Rotate(d2)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := LoadOrCreate(d2); !again.Equal(k) {
		t.Fatal("Rotate on empty dir did not persist")
	}
	if _, err := os.Stat(filepath.Join(d2, PrevKeyFile)); err == nil {
		t.Fatal("no .prev expected without an old key")
	}
}

func TestFingerprintAndPublicKeyEncoding(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fp := Fingerprint(pub)
	sum := sha256.Sum256(pub)
	if want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]); fp != want {
		t.Fatalf("fingerprint %q want %q", fp, want)
	}
	if strings.HasSuffix(fp, "=") || len(fp) != len("SHA256:")+43 {
		t.Fatalf("fingerprint format %q", fp)
	}
	// Fixed vector: 32 zero bytes.
	// sha256(32 zero bytes) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
	if got := Fingerprint(make(ed25519.PublicKey, 32)); got != "SHA256:Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU" {
		t.Errorf("fingerprint of zero key: %s", got)
	}
	enc := EncodePublicKey(pub)
	for _, s := range []string{enc, strings.TrimRight(enc, "=")} {
		back, err := ParsePublicKey(s)
		if err != nil || !back.Equal(pub) {
			t.Fatalf("ParsePublicKey(%q): %v", s, err)
		}
	}
	for _, bad := range []string{"", "!!", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33)), enc + "\n", strings.Repeat("A", 5000)} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%.20q) accepted", bad)
		}
	}
}
