package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// TestE2EConnectRelaysAndPinsHostKey runs wg-connect's run() as ssh would run
// it as a ProxyCommand, against the real hub, TURN server and agent: the bytes
// on stdin come back on stdout from the device side (the fake sshd), the
// known_hosts file holds the host key the AGENT reported, and a compromised
// device ends the connection at once.
func TestE2EConnectRelaysAndPinsHostKey(t *testing.T) {
	r := e2erig.New(t, e2erig.Options{})
	r.StartAgent()
	r.WaitDeviceUp(1)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "keycloak-token")
	if err := os.WriteFile(tokenFile, []byte(r.UserToken(e2erig.AliceEmail)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(dir, "ssh", "known_hosts")
	args := []string{
		"--hub-url", r.HubURL, "--namespace", e2erig.NS, "--device", e2erig.DeviceName,
		"--port", strconv.Itoa(r.Echo.Port), "--keycloak-token-file", tokenFile,
		"--known-hosts-file", knownHosts,
	}

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	var stderr lockedBuf
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, args, stdinR, stdoutW, &stderr) }()

	// stdin -> tunnel -> hub -> device -> fake sshd -> and all the way back.
	out := bufio.NewReader(stdoutR)
	for _, line := range []string{"SSH-2.0-e2e-client\n", strings.Repeat("x", 50_000) + "\n"} {
		if _, err := stdinW.Write([]byte(line)); err != nil {
			t.Fatalf("writing to the ProxyCommand's stdin: %v (stderr: %s)", err, stderr.String())
		}
		got := make(chan string, 1)
		go func() { s, _ := out.ReadString('\n'); got <- s }()
		select {
		case s := <-got:
			if s != line {
				t.Fatalf("echo mismatch: %d bytes back, want %d (stderr: %s)", len(s), len(line), stderr.String())
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("no echo through wg-connect (stderr: %s)", stderr.String())
		}
	}

	// known_hosts: written before any byte flowed, with the host key the agent
	// reported, under the HostKeyAlias ssh is told to use; strict checking
	// with it accepts that key and rejects any other.
	alias := api.KnownHostsAlias(e2erig.NS, e2erig.DeviceName)
	data, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatalf("known_hosts not written: %v", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != alias || fields[1]+" "+fields[2] != r.HostKey {
		t.Fatalf("known_hosts = %q, want %q for %s", data, r.HostKey, alias)
	}
	if st, err := os.Stat(knownHosts); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode: %v %v", st, err)
	}
	check, err := knownhosts.New(knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	reported, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("100.96.0.1"), Port: 22}
	if err := check(alias+":22", addr, reported); err != nil {
		t.Fatalf("strict host key checking rejects the reported key: %v", err)
	}
	other := mustOtherKey(t)
	if err := check(alias+":22", addr, other); err == nil {
		t.Fatal("strict host key checking accepted a different key")
	}

	// Compromise the device: the ProxyCommand ends at once and the connection
	// to ssh is closed.
	t0 := time.Now()
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	select {
	case code := <-exit:
		t.Logf("wg-connect exited with %d %v after the device was flagged (stderr: %q)", code, time.Since(t0).Round(time.Millisecond), stderr.String())
	case <-time.After(3 * time.Second):
		t.Fatalf("wg-connect still running 3s after the device was flagged (stderr: %s)", stderr.String())
	}
	if time.Since(t0) > time.Second+500*time.Millisecond {
		t.Fatalf("took %v", time.Since(t0))
	}
	_ = stdinW.Close()
	if strings.Contains(stderr.String(), "eyJ") {
		t.Fatal("stderr contains a token")
	}
}

func mustOtherKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	// A well-formed ed25519 key that is not the device's.
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
