package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/teknoir/wg-tunnel/internal/wgdev"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// wgTunnel is wireguard-go on a gVisor netstack: no TUN device, no
// capabilities. The hub owns api.HubAddress on the netstack; every session is
// a peer with a single /32 allowed address. The netstack does not forward, so
// peers have no L3 path to each other.
type wgTunnel struct {
	dev    *device.Device
	tnet   *netstack.Net
	pub    wgkey.PublicKey
	port   int
	closed atomic.Bool
}

var _ Tunnel = (*wgTunnel)(nil)

// NewWGTunnel creates the hub's WireGuard device with an ephemeral private key
// that exists only in memory. listenPort 0 picks a free UDP port (tests). The
// socket is bound by wireguard-go's default bind (all addresses); the hub
// never dials out over the underlay.
func NewWGTunnel(listenPort int, logger *slog.Logger) (Tunnel, error) {
	hubIP, err := netip.ParseAddr(api.HubAddress)
	if err != nil {
		return nil, err
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{hubIP}, nil, api.MTU)
	if err != nil {
		return nil, fmt.Errorf("hub: creating netstack: %w", err)
	}
	priv, pub, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	defer priv.Zero()
	if logger == nil {
		logger = slog.Default()
	}
	wgLog := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			logger.Warn("wireguard", "msg", strings.TrimSpace(fmt.Sprintf(format, args...)))
		},
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), wgLog)
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", priv.Hex(), listenPort)
	if err := dev.IpcSet(cfg); err != nil {
		wgdev.Close(dev)
		return nil, fmt.Errorf("hub: configuring wireguard: %w", err)
	}
	if err := dev.Up(); err != nil {
		wgdev.Close(dev)
		return nil, fmt.Errorf("hub: bringing wireguard up: %w", err)
	}
	port, err := listenPortOf(dev)
	if err != nil {
		wgdev.Close(dev)
		return nil, err
	}
	return &wgTunnel{dev: dev, tnet: tnet, pub: pub, port: port}, nil
}

func listenPortOf(dev *device.Device) (int, error) {
	out, err := dev.IpcGet()
	if err != nil {
		return 0, fmt.Errorf("hub: reading wireguard state: %w", err)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("hub: wireguard did not report a listen port")
}

func (t *wgTunnel) PublicKey() wgkey.PublicKey { return t.pub }
func (t *wgTunnel) ListenPort() int            { return t.port }
func (t *wgTunnel) Up() bool                   { return !t.closed.Load() }

func (t *wgTunnel) AddPeer(pub wgkey.PublicKey, ip netip.Addr) error {
	cfg := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", pub.Hex(), ip)
	if err := t.dev.IpcSet(cfg); err != nil {
		return fmt.Errorf("hub: adding peer: %w", err)
	}
	return nil
}

func (t *wgTunnel) RemovePeer(pub wgkey.PublicKey) error {
	if err := t.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pub.Hex())); err != nil {
		return fmt.Errorf("hub: removing peer: %w", err)
	}
	return nil
}

func (t *wgTunnel) Listen(addr netip.AddrPort) (net.Listener, error) {
	return t.tnet.ListenTCPAddrPort(addr)
}

func (t *wgTunnel) DialContext(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return t.tnet.DialContextTCPAddrPort(ctx, addr)
}

func (t *wgTunnel) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	wgdev.Close(t.dev)
	return nil
}
