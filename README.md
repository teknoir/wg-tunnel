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

## wg-hub

`pkg/hub` is the broker; `cmd/wg-hub` wires it to Kubernetes with client-go. All
decision logic sits behind small interfaces (`PolicySource`, `DeviceFlags`,
`IdentityStore`, `UserAuthenticator`, `SADelegation`, `Authorizer`,
`TURNMinter`, `Tunnel`), so it is tested with in-memory fakes plus a real
wireguard-go data plane on loopback. The `k8s_*.go` files hold the client-go
implementations (ConfigMap informer for policy, metadata-only Device informer,
identity ConfigMaps with optimistic concurrency, TokenReview, SubjectAccessReview,
TURN secret).

A device is reachable only while the policy entry is `active`, the Device exists,
`ztna.teknoir.org/wireguard=enabled` and neither `compromised` nor
`health-check-failed` is `true`. Every policy or annotation change re-evaluates
the device at once and tears down its sessions and spliced connections.

| Environment | Meaning | Default |
|---|---|---|
| `POD_IP` | advertised WireGuard endpoint host (downward API) | required |
| `DOMAIN` | derives `TURN_URLS`, `KEYCLOAK_ISSUER` when unset | |
| `HUB_NAMESPACE` | policy, identity ConfigMaps and delegating SAs | `teknoir-ztna` |
| `HTTP_ADDR` / `METRICS_ADDR` | outside API / Prometheus | `:8080` / `:9090` |
| `TURN_URLS` | comma-separated TURN URLs returned to sessions | `turn:turn.<DOMAIN>:3478?transport=udp` |
| `TURN_SECRET_REF` | `namespace/name` of the Secret holding key `secret` | `stunner-system/stunner-auth-secret` |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_JWKS_URL` | access-token issuer and key set | `https://auth.<DOMAIN>/auth/realms/master` |
| `ALLOWED_AZP` | accepted Keycloak `azp` values | `teknoir-cli` |
| `CLIENT_IP_HEADER` | trusted proxy header with the real client IP (optional) | peer address |
| `LOG_LEVEL` | slog level | `info` |

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
