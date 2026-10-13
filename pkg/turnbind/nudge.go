package turnbind

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

// Nudge makes the device send a keepalive to the peer immediately, so the
// remote side re-learns our endpoint after a Swap instead of waiting up to a
// keepalive interval. wireguard-go sends one when persistent keepalive is
// turned on (0 to non-zero), so this switches it off and on again.
// peerPublicHex is the peer key in hex; seconds is the keepalive interval to restore.
func Nudge(dev *device.Device, peerPublicHex string, seconds int) error {
	if seconds <= 0 {
		return fmt.Errorf("turnbind: nudge needs a positive keepalive interval, got %d", seconds)
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=0\n", peerPublicHex)); err != nil {
		return fmt.Errorf("turnbind: nudge: %w", err)
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=%d\n", peerPublicHex, seconds)); err != nil {
		return fmt.Errorf("turnbind: nudge: %w", err)
	}
	return nil
}
