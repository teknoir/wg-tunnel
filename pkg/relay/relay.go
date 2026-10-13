// Package relay allocates a TURN relayed UDP connection (to a STUNner gateway)
// and keeps it alive.
//
// # Supervision
//
// pion/turn refreshes the allocation and its permissions on timers but only
// LOGS failures; nothing returns an error to the caller. After a TURN server
// restart or a credential expiry the relayed conn simply goes quiet. A Relay
// therefore exposes Failed(), which is closed when pion logs a refresh
// failure (detected through a logger hook), and the Supervisor in this package
// combines that signal with a receive-staleness check and credential rotation
// to replace the relay under a turnbind.Bind. Callers must run a Supervisor
// (or implement the same) rather than trust a bare Relay for long-lived use.
package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// DefaultRealm is the realm STUNner uses unless configured otherwise.
const DefaultRealm = "stunner.l7mp.io"

// Config describes one allocation.
type Config struct {
	// Server is the TURN server "host:port" (UDP).
	Server string
	// Username and Password are TURN-REST credentials (see pkg/turncred).
	Username string
	Password string
	// Realm defaults to DefaultRealm. Like any TURN client, pion adopts the
	// realm the server announces in its 401 challenge, so this only matters for
	// servers that do not announce one.
	Realm string
	// Peer is the only address the relay talks to (the hub's WireGuard
	// endpoint). A permission for it is created up front, so inbound packets
	// from the peer are accepted before the first outbound one.
	Peer netip.AddrPort
	// RTO is the STUN retransmission timeout (default 200 ms, doubling).
	RTO time.Duration
}

func (c Config) validate() error {
	switch {
	case c.Server == "":
		return errors.New("relay: empty TURN server")
	case c.Username == "":
		return errors.New("relay: empty TURN username")
	case !c.Peer.IsValid():
		return errors.New("relay: invalid peer address")
	}
	return nil
}

// Relay is a TURN relayed net.PacketConn. Close releases the allocation, the
// turn.Client and the local UDP socket.
type Relay struct {
	net.PacketConn // the relayed conn (pion UDPConn)

	client *turn.Client
	sock   net.PacketConn
	peer   netip.AddrPort
	cfg    Config

	failed    chan struct{}
	failOnce  sync.Once
	failErr   error
	failMu    sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// Allocate resolves cfg.Server, creates a UDP socket, allocates a relay and a
// permission for cfg.Peer. It honours ctx, including during STUN retransmits.
func Allocate(ctx context.Context, cfg Config) (*Relay, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Realm == "" {
		cfg.Realm = DefaultRealm
	}
	if cfg.RTO == 0 {
		cfg.RTO = 200 * time.Millisecond
	}

	server, network, err := resolve(ctx, cfg.Server)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenPacket(network, ":0") //nolint:noctx // plain local socket, no blocking.
	if err != nil {
		return nil, fmt.Errorf("relay: opening UDP socket: %w", err)
	}

	r := &Relay{sock: sock, peer: cfg.Peer, cfg: cfg, failed: make(chan struct{})}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server,
		TURNServerAddr: server,
		Conn:           sock,
		Username:       cfg.Username,
		Password:       cfg.Password,
		Realm:          cfg.Realm,
		RTO:            cfg.RTO,
		LoggerFactory:  &watchFactory{r: r},
	})
	if err != nil {
		_ = sock.Close()
		return nil, fmt.Errorf("relay: creating TURN client: %w", err)
	}
	r.client = client
	if err := client.Listen(); err != nil {
		_ = sock.Close()
		return nil, fmt.Errorf("relay: starting TURN client: %w", err)
	}

	type result struct {
		pc  net.PacketConn
		err error
	}
	done := make(chan result, 1)
	go func() {
		pc, err := client.Allocate()
		if err == nil {
			r.PacketConn = pc
			err = client.CreatePermission(net.UDPAddrFromAddrPort(cfg.Peer))
		}
		done <- result{pc, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			_ = r.teardown(res.pc)
			return nil, fmt.Errorf("relay: allocating on %s: %w", cfg.Server, res.err)
		}
		return r, nil
	case <-ctx.Done():
		client.Close() // aborts pending transactions so Allocate returns
		_ = sock.Close()
		res := <-done
		_ = r.teardown(res.pc)
		return nil, fmt.Errorf("relay: allocating on %s: %w", cfg.Server, ctx.Err())
	}
}

func resolve(ctx context.Context, hostport string) (addr, network string, err error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", fmt.Errorf("relay: bad TURN server %q: %w", hostport, err)
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return hostport, networkFor(ip), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		return "", "", fmt.Errorf("relay: resolving %q: %w", host, err)
	}
	pick := ips[0]
	for _, ip := range ips { // prefer IPv4
		if ip.Unmap().Is4() {
			pick = ip
			break
		}
	}
	pick = pick.Unmap()
	return net.JoinHostPort(pick.String(), port), networkFor(pick), nil
}

func networkFor(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return "udp4"
	}
	return "udp6"
}

// teardown releases whatever was set up, in the order pion needs: the relayed
// conn first (it sends the deallocating refresh through the socket).
func (r *Relay) teardown(relayed net.PacketConn) error {
	var errs []error
	if relayed != nil {
		if err := relayed.Close(); err != nil && !strings.Contains(err.Error(), "already closed") {
			errs = append(errs, err)
		}
	}
	if r.client != nil {
		r.client.Close()
	}
	if r.sock != nil {
		if err := r.sock.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close deallocates the relay and closes the TURN client and the UDP socket.
// It is idempotent and safe to call concurrently.
func (r *Relay) Close() error {
	r.closeOnce.Do(func() { r.closeErr = r.teardown(r.PacketConn) })
	return r.closeErr
}

// RelayedAddr is the transport address on the TURN server that peers send to
// (this is what the peer must use as the client's endpoint).
func (r *Relay) RelayedAddr() netip.AddrPort {
	if ua, ok := r.LocalAddr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// Peer returns the peer the relay was permitted for.
func (r *Relay) Peer() netip.AddrPort { return r.peer }

// Config returns the configuration the relay was allocated with.
func (r *Relay) Config() Config { return r.cfg }

// Failed is closed when pion reports that refreshing the allocation or its
// permissions failed. The relay must then be considered unreliable.
func (r *Relay) Failed() <-chan struct{} { return r.failed }

// Err returns the first refresh failure observed, or nil.
func (r *Relay) Err() error {
	r.failMu.Lock()
	defer r.failMu.Unlock()
	return r.failErr
}

func (r *Relay) markFailed(err error) {
	r.failOnce.Do(func() {
		r.failMu.Lock()
		r.failErr = err
		r.failMu.Unlock()
		close(r.failed)
	})
}

// watchFactory hands pion a logger that discards output but reports refresh
// failures to the Relay.
type watchFactory struct{ r *Relay }

func (f *watchFactory) NewLogger(string) logging.LeveledLogger { return watchLogger{r: f.r} }

type watchLogger struct{ r *Relay }

func (l watchLogger) Trace(string)          {}
func (l watchLogger) Tracef(string, ...any) {}
func (l watchLogger) Debug(string)          {}
func (l watchLogger) Debugf(string, ...any) {}
func (l watchLogger) Info(string)           {}
func (l watchLogger) Infof(string, ...any)  {}
func (l watchLogger) Warn(msg string)       { l.check(msg) }
func (l watchLogger) Warnf(format string, args ...any) {
	l.check(fmt.Sprintf(format, args...))
}
func (l watchLogger) Error(msg string) { l.check(msg) }
func (l watchLogger) Errorf(format string, args ...any) {
	l.check(fmt.Sprintf(format, args...))
}

func (l watchLogger) check(msg string) {
	// pion: "Failed to refresh allocation: ...", "Failed to refresh permissions: ...",
	// "Fail to refresh permissions: ...", "Refresh allocation: 438 but no nonce.".
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "refresh") && (strings.Contains(lower, "fail") || strings.Contains(lower, "no nonce")) {
		l.r.markFailed(errors.New(msg))
	}
}
