// Package wgtest builds wireguard-go devices on gVisor netstack for tests.
package wgtest

import (
	"fmt"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Node is one WireGuard device with its own netstack.
type Node struct {
	Dev  *device.Device
	Net  *netstack.Net
	Priv wgkey.PrivateKey
	Pub  wgkey.PublicKey
	Addr netip.Addr
}

// NewNode creates and brings up a device that owns addr on its netstack and
// uses bind for transport.
func NewNode(t testing.TB, bind conn.Bind, addr netip.Addr) *Node {
	t.Helper()
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1280)
	if err != nil {
		t.Fatalf("wgtest: CreateNetTUN: %v", err)
	}
	priv, pub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", priv.Hex())); err != nil {
		t.Fatalf("wgtest: set private key: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("wgtest: Up: %v", err)
	}
	t.Cleanup(dev.Close)
	return &Node{Dev: dev, Net: tnet, Priv: priv, Pub: pub, Addr: addr}
}

// AddPeer adds peer with a single allowed /32 (or /128). endpoint may be empty.
func (n *Node) AddPeer(t testing.TB, peer wgkey.PublicKey, allowed netip.Addr, endpoint string, keepaliveSeconds int) {
	t.Helper()
	cfg := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/%d\n", peer.Hex(), allowed, allowed.BitLen())
	if endpoint != "" {
		cfg += fmt.Sprintf("endpoint=%s\n", endpoint)
	}
	if keepaliveSeconds > 0 {
		cfg += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepaliveSeconds)
	}
	if err := n.Dev.IpcSet(cfg); err != nil {
		t.Fatalf("wgtest: add peer: %v", err)
	}
}
