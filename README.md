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
- `pkg/wgclient`: creates and keeps one tunnel session (fresh WG key, TURN relay with
  supervisor, in-tunnel renewal with a fresh credential, `Dial`/`Listen`). The
  `Credential` callback receives the session's WireGuard public key so device
  identity tokens can bind it (`wgk`).
- `pkg/agent`: the wg-agent loop (identity, enrollment, session, port forwarding, backoff).

## wg-agent

`wg-agent init --dir D --uid U` (init container, root) prepares the identity directory.
`wg-agent run` is configured by environment: `DEVICE_ID`, `NAMESPACE`, `DOMAIN`
(or `HUB_URL`, default `https://wg-device.<DOMAIN>:8084`), `RSA_KEY`
(`/etc/teknoir/rsa_private.pem`), `IDENTITY_DIR` (`/var/lib/teknoir/wg-agent`),
`SSH_HOST_KEYS_GLOB` (`/etc/ssh/ssh_host_*_key.pub`), `FORWARD_HOST` (`127.0.0.1`),
`TURN_SERVER` (host:port override), `CA_FILE` (extra CAs added to the system
roots; `/etc/teknoir/roots.pem` if present) and `LOG_LEVEL`.

## wg-connect

ssh ProxyCommand: `wg-connect --hub-url U --namespace NS --device D
(--sa-token-file F --on-behalf-of EMAIL | --keycloak-token-file F)
--known-hosts-file K [--port 22] [--direct] [--turn-server HOST:PORT] [--ca-file F]`.
Token files are re-read for every create and renewal; tokens never go in argv or env.

## Development

`make test` (race detector), `make vet`, `make lint` (golangci-lint v2).
`internal/turntest` and `internal/wgtest` provide an in-process TURN server and
WireGuard netstack nodes for tests; `internal/fakehub` is a minimal test double of
the hub (session, enrollment and renewal API plus a TCP splice) for client-side tests.
