// Package wgdev holds helpers for wireguard-go devices on a gVisor netstack.
package wgdev

import "golang.zx2c4.com/wireguard/device"

// Close stops every peer before closing the device. device.Close closes the
// netstack TUN (and its packet channel) before it removes the peers, so a peer
// receive routine that is still writing a packet into the stack can make the
// stack's reply send on the closed channel: a data race, and a "send on closed
// channel" panic. Peer.Stop waits for those routines, so after RemoveAllPeers
// none is left to write.
func Close(dev *device.Device) {
	if dev == nil {
		return
	}
	dev.RemoveAllPeers()
	dev.Close()
}
