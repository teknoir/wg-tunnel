package wgclient_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/fakehub"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

func TestDeviceAndClientThroughTURN(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	var dn, cn atomic.Int64
	dev := create(t, r.deviceOpts(deviceCred(&dn)))
	echoOn(t, dev, 22)

	dr := dev.Response()
	if dr.Kind != api.KindDevice || dr.TURN == nil || len(dr.AllowedPorts) != 1 || dr.AllowedPorts[0] != 22 {
		t.Fatalf("device response: %+v", dr)
	}
	if dev.RelaySwaps() != 1 {
		t.Fatalf("device relay swaps = %d, want 1", dev.RelaySwaps())
	}
	if got := r.hub.HostKeys(testNS, testDevice); len(got) != 1 || !strings.HasPrefix(got[0], "ssh-ed25519 ") {
		t.Fatalf("hub saw host keys %v", got)
	}

	cli := create(t, r.clientOpts(counter("cli", &cn)))
	cr := cli.Response()
	if cr.SplicePort != api.HubSplicePort || cr.TargetPort != 22 || len(cr.SSHHostKeys) != 1 {
		t.Fatalf("client response: %+v", cr)
	}
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	for _, m := range []string{"hello", strings.Repeat("x", 100_000)} {
		if err := roundTrip(c, m); err != nil {
			t.Fatalf("round trip (%d bytes): %v", len(m), err)
		}
	}
	// Half-close: the echo server sees EOF and closes, so reads end cleanly.
	if cw, ok := c.(interface{ CloseWrite() error }); !ok || cw.CloseWrite() != nil {
		t.Fatal("conn does not support CloseWrite")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("expected EOF after half-close, got %d %v", n, err)
	}
}

func TestDeviceCannotDialAndClientCannotListen(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	var n atomic.Int64
	dev := create(t, r.deviceOpts(deviceCred(&n)))
	cli := create(t, r.clientOpts(counter("c", &n)))
	if _, err := dev.Dial(ctxT(t)); err == nil {
		t.Error("device session allowed Dial")
	}
	if _, err := cli.Listen(22); err == nil {
		t.Error("client session allowed Listen")
	}
}

func TestDirectSession(t *testing.T) {
	// No TURN secret: the hub mints no TURN credentials at all.
	r := &rig{hub: fakehub.New(t, fakehub.Options{})}
	r.hub.AddDevice(testNS, testDevice, fakehub.DeviceSpec{SkipAuth: true, AllowedPorts: []int{22}})
	var n atomic.Int64
	do := r.deviceOpts(deviceCred(&n))
	do.Direct, do.TURNServerOverride = true, ""
	dev := create(t, do)
	echoOn(t, dev, 22)
	if dev.Response().TURN != nil || dev.RelaySwaps() != 0 {
		t.Fatalf("direct session used TURN: %+v", dev.Response().TURN)
	}
	co := r.clientOpts(counter("c", &n))
	co.Direct, co.TURNServerOverride = true, ""
	cli := create(t, co)
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c, "direct"); err != nil {
		t.Fatal(err)
	}

	// Without Direct, a hub that offers no TURN credentials is an error.
	nd := r.clientOpts(counter("c", &n))
	if _, err := wgclient.Create(ctxT(t), nd); err == nil || !strings.Contains(err.Error(), "TURN") {
		t.Fatalf("expected a no-TURN error, got %v", err)
	}
}

func TestRenewRotatesTURNWithoutDroppingStream(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second, RotateTURNOnRenew: true})
	var dn, cn atomic.Int64
	dev := create(t, r.deviceOpts(deviceCred(&dn)))
	echoOn(t, dev, 22)
	cli := create(t, r.clientOpts(counter("cli", &cn)))
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c, "before"); err != nil {
		t.Fatal(err)
	}

	// Keep the same TCP stream busy while both sides rotate at least twice.
	deadline := time.Now().Add(6 * time.Second)
	i := 0
	for time.Now().Before(deadline) && (cli.RelaySwaps() < 3 || dev.RelaySwaps() < 3) {
		i++
		if err := roundTrip(c, "ping"); err != nil {
			t.Fatalf("stream broke after %d pings (client swaps %d, device swaps %d): %v", i, cli.RelaySwaps(), dev.RelaySwaps(), err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cli.RelaySwaps() < 3 || dev.RelaySwaps() < 3 {
		t.Fatalf("relays did not rotate: client %d, device %d", cli.RelaySwaps(), dev.RelaySwaps())
	}
	if err := roundTrip(c, "after"); err != nil {
		t.Fatalf("stream broke after rotation: %v", err)
	}
	select {
	case <-cli.Done():
		t.Fatalf("client session ended: %v", cli.Err())
	case <-dev.Done():
		t.Fatalf("device session ended: %v", dev.Err())
	default:
	}
}

func TestRenewDenialEndsSessionAndClosesConns(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second})
	var dn, cn atomic.Int64
	dev := create(t, r.deviceOpts(deviceCred(&dn)))
	echoOn(t, dev, 22)
	cli := create(t, r.clientOpts(counter("cli", &cn)))
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c, "alive"); err != nil {
		t.Fatal(err)
	}
	var deny atomic.Bool
	r.hub.SetOnRenew(func(call fakehub.Call) *fakehub.Denial {
		if call.Kind == api.KindClient && deny.Load() {
			return &fakehub.Denial{Status: 403, Reason: api.ReasonDeviceRevoked}
		}
		return nil
	})
	deny.Store(true)

	// A blocked Read returns as soon as the session ends.
	readErr := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); readErr <- err }()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read returned data")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Dial'ed connection stayed open after the renewal was denied")
	}
	select {
	case <-cli.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed")
	}
	var we *wgclient.Error
	if !errors.As(cli.Err(), &we) || we.Reason != api.ReasonDeviceRevoked || we.Status != 403 {
		t.Fatalf("Err() = %v", cli.Err())
	}
	if wgclient.ReasonOf(cli.Err()) != api.ReasonDeviceRevoked {
		t.Fatal("ReasonOf")
	}
	if _, err := cli.Dial(ctxT(t)); !errors.Is(err, wgclient.ErrSessionClosed) && err == nil {
		t.Fatalf("Dial after end: %v", err)
	}
	// The device session is unaffected.
	select {
	case <-dev.Done():
		t.Fatal("device session ended")
	default:
	}
}

func TestRenewalsFailingUntilExpiryEndSession(t *testing.T) {
	// The hub forgets the device session: its peer is gone, so renewals time
	// out. They are retried until the session's expiry, then the session ends.
	r := newRig(t, fakehub.Options{RenewAfter: time.Second, TTL: 3 * time.Second})
	var n atomic.Int64
	o := r.deviceOpts(deviceCred(&n))
	o.RenewTimeout = 400 * time.Millisecond
	dev := create(t, o)
	for _, id := range r.hub.SessionIDs(api.KindDevice) {
		r.hub.KillSession(id)
	}
	select {
	case <-dev.Done():
		if !errors.Is(dev.Err(), wgclient.ErrExpired) {
			t.Fatalf("Err() = %v", dev.Err())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("session did not end after its expiry")
	}
}

func TestCredentialIsFreshForEveryCall(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second})
	var n, dn atomic.Int64
	create(t, r.deviceOpts(deviceCred(&dn)))
	var pubs []string
	cred := func(_ context.Context, pub string) (string, error) {
		pubs = append(pubs, pub) // calls are sequential per session
		return counter("tok", &n)(context.Background(), pub)
	}
	cli := create(t, r.clientOpts(cred))
	// create + at least 2 renewals
	eventually(t, 10*time.Second, "two renewals", func() bool { return n.Load() >= 3 })
	_ = cli.Close()

	seen := map[string]bool{}
	for _, c := range r.hub.Calls() {
		if c.Kind != api.KindClient {
			continue
		}
		if seen[c.Bearer] {
			t.Errorf("bearer %q was reused", c.Bearer)
		}
		seen[c.Bearer] = true
	}
	var creates, renews int
	for _, c := range r.hub.Calls() {
		if c.Kind != api.KindClient {
			continue
		}
		switch c.Path {
		case api.ClientSessionPath:
			creates++
		case api.RenewPath:
			renews++
		}
	}
	if got := int(n.Load()); creates != 1 || renews < 2 || got < creates+renews || got > creates+renews+1 {
		t.Fatalf("Credential called %d times for %d creates and %d renewals", n.Load(), creates, renews)
	}
	for _, p := range pubs {
		if p != pubs[0] || p == "" {
			t.Fatalf("Credential saw different or empty WireGuard keys: %v", pubs)
		}
	}
}

func TestCredentialErrorFailsCreate(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	o := r.clientOpts(func(context.Context, string) (string, error) { return "", errors.New("no token") })
	if _, err := wgclient.Create(ctxT(t), o); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("got %v", err)
	}
	o.Credential = func(context.Context, string) (string, error) { return "has space", nil }
	if _, err := wgclient.Create(ctxT(t), o); err == nil {
		t.Fatal("accepted a credential that cannot be a header value")
	}
}

func TestCloseNotifiesHub(t *testing.T) {
	r := newRig(t, fakehub.Options{})
	var n, dn atomic.Int64
	create(t, r.deviceOpts(deviceCred(&dn)))
	cli := create(t, r.clientOpts(counter("c", &n)))
	if len(r.hub.SessionIDs(api.KindClient)) != 1 {
		t.Fatal("hub has no client session")
	}
	if err := cli.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cli.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	if cli.Err() != nil {
		t.Fatalf("Err after Close = %v", cli.Err())
	}
	eventually(t, 15*time.Second, "hub to drop the session", func() bool { return len(r.hub.SessionIDs(api.KindClient)) == 0 })
	_ = cli.Close() // idempotent
}

func TestLogsNeverContainSecrets(t *testing.T) {
	r := newRig(t, fakehub.Options{RenewAfter: time.Second, RotateTURNOnRenew: true})
	var buf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var dn, cn atomic.Int64
	do := r.deviceOpts(deviceCred(&dn))
	do.Logger = logger
	dev := create(t, do)
	co := r.clientOpts(counter("clitok", &cn))
	co.Logger = logger
	cli := create(t, co)
	pass := cli.Response().TURN.Password
	devPass := dev.Response().TURN.Password
	eventually(t, 10*time.Second, "renewals", func() bool { return cn.Load() >= 3 && dn.Load() >= 3 })
	// Provoke error logging too.
	r.hub.SetOnRenew(func(fakehub.Call) *fakehub.Denial { return &fakehub.Denial{Status: 403, Reason: api.ReasonForbidden} })
	select {
	case <-cli.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("no denial")
	}
	_ = cli.Close()
	_ = dev.Close()

	logs := buf.String()
	if !strings.Contains(logs, "wireguard session established") {
		t.Fatalf("logger not used:\n%s", logs)
	}
	secrets := []string{}
	for _, c := range r.hub.Calls() {
		secrets = append(secrets, c.Bearer) // every device JWT and client token the hub received
	}
	if len(secrets) < 6 {
		t.Fatalf("expected many bearers to check, got %d", len(secrets))
	}
	for _, secret := range append(secrets, "eyJ", pass, devPass, "Authorization", "Bearer", "wgPublicKey", "sshHostKeys", "AAAAC3NzaC1lZDI1NTE5", turnSecret) {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("log output contains a secret (%d bytes starting %.4q)", len(secret), secret)
		}
	}
}

func TestDeadTunnelEndsSessionBeforeExpiry(t *testing.T) {
	// The hub drops the peer (no FIN/RST can reach us). The in-tunnel renewal
	// fails at the transport level and nothing arrives through WireGuard, so
	// the session ends with ErrTunnelDead long before its 3 minute TTL.
	r := newRig(t, fakehub.Options{RenewAfter: time.Second})
	var dn, cn atomic.Int64
	dev := create(t, r.deviceOpts(deviceCred(&dn)))
	echoOn(t, dev, 22)
	o := r.clientOpts(counter("cli", &cn))
	o.RenewTimeout = 400 * time.Millisecond
	o.DeadAfter = 1500 * time.Millisecond
	cli := create(t, o)
	c, err := cli.Dial(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := roundTrip(c, "alive"); err != nil {
		t.Fatal(err)
	}
	// Drop only the peer, silently: no spliced connection is closed first.
	r.hub.DropPeerSilently(r.hub.SessionIDs(api.KindClient)[0])
	t0 := time.Now()
	select {
	case <-cli.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("session did not end although the tunnel is dead")
	}
	if !errors.Is(cli.Err(), wgclient.ErrTunnelDead) {
		t.Fatalf("Err() = %v", cli.Err())
	}
	if time.Since(t0) > 15*time.Second {
		t.Fatalf("took %v", time.Since(t0))
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the Dial'ed connection survived the session")
	}
}

func TestSlowRenewalWithLiveTunnelDoesNotEndSession(t *testing.T) {
	// A transport-level failure alone is not enough: while packets keep
	// arriving, the session is retried.
	r := newRig(t, fakehub.Options{RenewAfter: time.Second})
	var dn, cn atomic.Int64
	create(t, r.deviceOpts(deviceCred(&dn)))
	o := r.clientOpts(counter("cli", &cn))
	o.DeadAfter = time.Hour
	o.RenewTimeout = 300 * time.Millisecond
	cli := create(t, o)
	r.hub.DropPeerSilently(r.hub.SessionIDs(api.KindClient)[0])
	select {
	case <-cli.Done():
		t.Fatalf("session ended: %v", cli.Err())
	case <-time.After(3 * time.Second):
	}
}

func TestRelaySupervisorOutlivesCreateContext(t *testing.T) {
	// Create's context bounds only Create; callers cancel it right after. The
	// relay supervisor must keep running (with a short StaleAfter an idle
	// tunnel re-allocates its relay again and again).
	r := newRig(t, fakehub.Options{})
	var n atomic.Int64
	o := r.deviceOpts(deviceCred(&n))
	o.StaleAfter = 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	s, err := wgclient.Create(ctx, o)
	cancel() // as wg-connect does
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	eventually(t, 15*time.Second, "the relay to be re-allocated after Create's context ended", func() bool { return s.RelaySwaps() >= 3 })
}
