package knownhosts

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	xkh "golang.org/x/crypto/ssh/knownhosts"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

func authorized(t testing.TB, pub any, comment string) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + comment
}

func hostKeys(t testing.TB) (ed, ec, rs string) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return authorized(t, edPub, " root@vdev-01"), authorized(t, &ecKey.PublicKey, ""), authorized(t, &rsaKey.PublicKey, " host")
}

func TestWriteProducesUsableKnownHosts(t *testing.T) {
	ed, ec, rs := hostKeys(t)
	path := filepath.Join(t.TempDir(), "sub", "known_hosts")
	alias := api.KnownHostsAlias("teknoir-demo", "vdev-01")
	if err := Write(path, alias, []string{ed, ec, rs}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("stat: %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 3 || f[0] != alias {
			t.Fatalf("line %q is not '<alias> <type> <base64>'", l)
		}
	}
	if strings.Contains(string(b), "root@vdev-01") || strings.Contains(string(b), " host") {
		t.Fatal("comments must not be written")
	}
	// ssh's own known_hosts parser accepts the file and matches each key
	// for the alias (this is what StrictHostKeyChecking=yes consults).
	cb, err := xkh.New(path)
	if err != nil {
		t.Fatal(err)
	}
	addr := &fakeAddr{alias + ":22"}
	for _, raw := range []string{ed, ec, rs} {
		k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(raw))
		if err := cb(alias+":22", addr, k); err != nil {
			t.Errorf("key %s not trusted for alias: %v", k.Type(), err)
		}
	}
	// A different key for the same alias is rejected.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	ok, _ := ssh.NewPublicKey(other)
	if err := cb(alias+":22", addr, ok); err == nil {
		t.Error("unknown key trusted")
	}
	// ...and the alias is the only host the file speaks for.
	k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(ed))
	if err := cb("other.host:22", &fakeAddr{"other.host:22"}, k); err == nil {
		t.Error("key trusted for another host")
	}
}

type fakeAddr struct{ s string }

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string  { return a.s }

func TestWriteReplacesAtomically(t *testing.T) {
	ed, ec, _ := hostKeys(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("old content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, "a.b.c", []string{ed}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "old content") || !strings.HasPrefix(string(b), "a.b.c ssh-ed25519 ") {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// Failed writes leave the previous file untouched and no temp files behind.
	if err := Write(path, "a.b.c", []string{ed, "garbage"}); err == nil {
		t.Fatal("garbage accepted")
	}
	b2, _ := os.ReadFile(path)
	if string(b2) != string(b) {
		t.Fatal("failed write modified the file")
	}
	_ = Write(path, "a.b.c", []string{ec})
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("stray files: %v", ents)
	}
}

func TestFormatRejects(t *testing.T) {
	ed, _, _ := hostKeys(t)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(caPriv)
	hostPub, _, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewPublicKey(hostPub)
	cert := &ssh.Certificate{Key: hk, CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	for name, keys := range map[string][]string{
		"none":          nil,
		"empty":         {},
		"empty string":  {""},
		"garbage":       {"garbage"},
		"bad base64":    {"ssh-ed25519 !!!!"},
		"truncated":     {ed[:len(ed)/2]},
		"options":       {`command="rm -rf /" ` + ed},
		"two lines":     {ed + "\n" + ed},
		"trailing line": {ed + "\n"},
		"certificate":   {certLine},
		"too many":      make([]string, 17),
	} {
		if name == "trailing line" {
			// A single trailing newline is harmless (what .pub files have).
			if _, err := Format("a.b", keys); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if name == "too many" {
			for i := range keys {
				keys[i] = ed
			}
		}
		if _, err := Format("a.b", keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAliasValidation(t *testing.T) {
	ed, _, _ := hostKeys(t)
	for _, ok := range []string{"vdev-01.teknoir-demo.ztna.teknoir", "a", "A_b.c-d9"} {
		if _, err := Format(ok, []string{ed}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a,b", "*.x", "a?b", "!a", "@cert-authority", "|1|x", "a\nb", "a/b", "a:22", "[a]:22", strings.Repeat("a", 254)} {
		if _, err := Format(bad, []string{ed}); err == nil {
			t.Errorf("alias %.20q accepted", bad)
		}
		if err := Write(filepath.Join(t.TempDir(), "kh"), bad, []string{ed}); err == nil {
			t.Errorf("Write accepted alias %.20q", bad)
		}
	}
}

func TestFormatDeduplicatesAndNormalises(t *testing.T) {
	ed, _, _ := hostKeys(t)
	out, err := Format("a.b", []string{ed, ed + " other-comment", "  " + ed + "  "})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "\n"); n != 1 {
		t.Fatalf("expected deduplication, got %q", out)
	}
}

func TestWriteIntoUnwritableLocation(t *testing.T) {
	ed, _, _ := hostKeys(t)
	file := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(file, nil, 0o600)
	if err := Write(filepath.Join(file, "known_hosts"), "a.b", []string{ed}); err == nil {
		t.Fatal("writing below a regular file succeeded")
	}
}
