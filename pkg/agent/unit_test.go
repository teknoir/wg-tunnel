package agent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	b := Backoff{Min: 2 * time.Second, Max: 5 * time.Minute}
	full := func() float64 { return 1 }
	low := func() float64 { return 0 }
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second, 256 * time.Second, 300 * time.Second, 300 * time.Second}
	for n, w := range want {
		if got := b.delay(n, full); got != w {
			t.Errorf("delay(%d) with full jitter = %s, want %s", n, got, w)
		}
		if got := b.delay(n, low); got != w/2 {
			t.Errorf("delay(%d) with no jitter = %s, want %s", n, got, w/2)
		}
	}
	for i := 0; i < 1000; i++ {
		d := b.delay(3, randFloat)
		if d < 8*time.Second || d > 16*time.Second {
			t.Fatalf("jittered delay %s outside [8s,16s]", d)
		}
	}
	if d := b.delay(1_000_000, full); d != b.Max {
		t.Errorf("huge failure count: %s", d)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ConfigFromEnv(env(map[string]string{"DEVICE_ID": "d1", "NAMESPACE": "ns", "DOMAIN": "teknoir.cloud"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.HubURL != "https://wg-device.teknoir.cloud:8084" || c.RSAKeyPath != DefaultRSAKey || c.IdentityDir != DefaultIdentityDir ||
		c.SSHHostKeysGlob != DefaultHostKeysGlob || c.ForwardHost != "127.0.0.1" || c.MaxConns != 32 ||
		c.Backoff.Min != 2*time.Second || c.Backoff.Max != 5*time.Minute || c.TURNServer != "" {
		t.Fatalf("defaults: %+v", c)
	}
	c, err = ConfigFromEnv(env(map[string]string{
		"DEVICE_ID": "d1", "NAMESPACE": "ns", "HUB_URL": "http://hub:8080", "RSA_KEY": "/k", "IDENTITY_DIR": "/i",
		"SSH_HOST_KEYS_GLOB": "/g*", "FORWARD_HOST": "10.0.0.5", "TURN_SERVER": "192.168.2.166:3478",
	}))
	if err != nil || c.HubURL != "http://hub:8080" || c.RSAKeyPath != "/k" || c.IdentityDir != "/i" || c.SSHHostKeysGlob != "/g*" ||
		c.ForwardHost != "10.0.0.5" || c.TURNServer != "192.168.2.166:3478" {
		t.Fatalf("overrides: %+v, %v", c, err)
	}
	bad := []map[string]string{
		{},
		{"DEVICE_ID": "d1"},
		{"DEVICE_ID": "d1", "NAMESPACE": "ns"}, // neither HUB_URL nor DOMAIN
		{"DEVICE_ID": "d/1", "NAMESPACE": "ns", "DOMAIN": "x.y"}, // slash in id
		{"DEVICE_ID": "d1", "NAMESPACE": "ns", "DOMAIN": "x.y", "TURN_SERVER": "nohostport"},
		{"DEVICE_ID": "d1", "NAMESPACE": "ns", "DOMAIN": "x.y", "CA_FILE": "/does/not/exist.pem"}, // explicit CA must exist
	}
	for i, m := range bad {
		if _, err := ConfigFromEnv(env(m)); err == nil {
			t.Errorf("case %d accepted: %v", i, m)
		}
	}
}

func TestCAFile(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HTTPClient(junk, true); err == nil {
		t.Error("accepted a CA file without certificates")
	}
	if _, err := HTTPClient(filepath.Join(dir, "missing.pem"), false); err != nil {
		t.Errorf("missing default CA file must be fine: %v", err)
	}
}

func TestParseLogLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"": slog.LevelInfo, "INFO": slog.LevelInfo, "debug": slog.LevelDebug, "warn": slog.LevelWarn, "error": slog.LevelError} {
		if got, err := ParseLogLevel(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseLogLevel("loud"); err == nil {
		t.Error("accepted loud")
	}
}

func TestReadHostKeys(t *testing.T) {
	dir := t.TempDir()
	a := writeHostKey(t, filepath.Join(dir, "ssh_host_a_key.pub"), " root@box\n")
	b := writeHostKey(t, filepath.Join(dir, "ssh_host_b_key.pub"), "\n")
	// Duplicate of a (different comment), garbage, options-prefixed, oversized.
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_c_key.pub"), []byte(a+" other comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_d_key.pub"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_e_key.pub"), []byte("command=\"x\" "+a+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_f_key.pub"), []byte(strings.Repeat("a", 20_000)), 0o644); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := ReadHostKeys(filepath.Join(dir, "ssh_host_*_key.pub"), log)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v, want [%s %s]", got, a, b)
	}
	if got := ReadHostKeys(filepath.Join(dir, "nothing_*"), log); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := ReadHostKeys("[", log); got != nil {
		t.Fatalf("bad glob: %v", got)
	}
}

func TestInitDir(t *testing.T) {
	uid := os.Getuid()
	root := t.TempDir()
	dir := filepath.Join(root, "var", "lib", "wg-agent")

	if err := InitDir(dir, uid); err != nil { // creates parents and dir
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("dir: %v %v", fi, err)
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != uid || int(st.Gid) != uid {
			t.Fatalf("owner %d:%d, want %d:%d", st.Uid, st.Gid, uid, uid)
		}
	}
	check()

	// Idempotent; also repairs a loose mode and keeps existing files.
	if err := os.WriteFile(filepath.Join(dir, "identity.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InitDir(dir, uid); err != nil {
		t.Fatal(err)
	}
	check()
	if b, _ := os.ReadFile(filepath.Join(dir, "identity.key")); string(b) != "x" {
		t.Fatal("existing file touched")
	}

	// A symlink at dir is refused, whatever it points to.
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := InitDir(link, uid); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink accepted: %v", err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Fatal("symlink target was modified")
	}
	// A symlink inside the directory is neither followed nor chowned.
	if err := os.Symlink(target, filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := InitDir(dir, uid); err != nil {
		t.Fatal(err)
	}
	// Bad arguments.
	if err := InitDir("relative/dir", uid); err == nil {
		t.Error("relative dir accepted")
	}
	if err := InitDir(dir, -1); err == nil {
		t.Error("negative uid accepted")
	}
	f := filepath.Join(root, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitDir(f, uid); err == nil {
		t.Error("regular file accepted as directory")
	}
}
