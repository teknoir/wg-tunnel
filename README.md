# wg-tunnel

Zero-trust WireGuard tunnels for Teknoir devices, relayed through
[STUNner](https://github.com/l7mp/stunner) (TURN). This runs as an
alternative to the SSH reverse tunnels and stays separate from them.

- `cmd/wg-hub`: session broker and WireGuard gateway. It runs wireguard-go on a
  gVisor netstack, unprivileged. It authenticates every session, applies policy
  per connection, and splices TCP from clients to devices. It revokes
  immediately when a device is flagged.
- `cmd/wg-agent`: device agent. It uses an on-device Ed25519 identity, opens
  connections from the device side over TURN, and exposes only the allowed ports.
- `cmd/wg-connect`: stdio proxy for `ssh -o ProxyCommand=...` (WG web terminal).
- `pkg/wgclient`: client library used by `tnctl ssh --wireguard`.
- `pkg/api`: the wire contract (standard library only).

Design: `plans/wireguard-ztna-tunnel.md` in the Teknoir workspace.
