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

## Libraries

- `pkg/wgkey`: X25519 key generation, wg base64 and wireguard-go hex conversion.
- `pkg/turncred`: TURN-REST credentials identical to STUNner's.
- `pkg/turnbind`: wireguard-go `conn.Bind` over a swappable `net.PacketConn`.
- `pkg/relay`: pion/turn relay allocation and the supervisor that re-allocates and swaps it.
- `pkg/identity`: device Ed25519 identity key file, device JWTs (EdDSA identity, RS256 enrollment), enrollment proof.
- `pkg/knownhosts`: writes the known_hosts file for the device's SSH host keys.

## Development

`make test` (race detector), `make vet`, `make lint` (golangci-lint v2).
`internal/turntest` and `internal/wgtest` provide an in-process TURN server and
WireGuard netstack nodes for tests.
