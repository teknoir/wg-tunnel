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
| `FLUSH_GRACE` | how long a revoked session's WireGuard peer stays after its streams were closed, so the FIN/RST reaches the client and the device | `300ms` |
| `LOG_LEVEL` | slog level | `info` |

On every teardown the hub started itself (policy or flag change, device
replacement, maximum age, reaper, a denied renewal) it does this in order:
detach the session (no new connections or renewals), close its spliced streams
on both sides, keep the peers for `FLUSH_GRACE`, remove the peer, then release
the address to quarantine. A client that is still connected therefore sees its
`Dial`ed connection end within milliseconds. If the tunnel itself dies (peer
gone, relay lost), `pkg/wgclient` ends the session with `ErrTunnelDead` when a
renewal fails at the transport level and nothing arrived through WireGuard for
more than twice the persistent keepalive.

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

## Images

One `Dockerfile` with two targets, built with CGO off and pinned base images
(`golang:1.26-alpine`, `gcr.io/distroless/static-debian12:nonroot`, both by
digest), running as uid 65532. The Go toolchain cross-compiles, so no emulation
is needed to build for other architectures.

```
make docker-hub                                   # ghcr.io/teknoir/wg-hub:<version>, linux/amd64, loaded locally
make docker-agent PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
docker run --rm ghcr.io/teknoir/wg-hub:<version> --help
```

`wg-hub` is published for amd64 and arm64, `wg-agent` for amd64, arm64 and
arm/v7. The agent's `init` subcommand needs uid 0 (the init container sets
`runAsUser: 0`); the agent itself runs as 65532. `.github/workflows/build.yml`
runs `go vet` and `go test -race ./...`, then pushes
`ghcr.io/teknoir/wg-hub` and `ghcr.io/teknoir/wg-agent` tagged `sha-<7>`,
`<branch>-<timestamp>`, `<branch>` (and `latest` on main; the git tag itself for tag pushes).

## Development

`make test` (race detector), `make vet`, `make lint` (golangci-lint v2).
`internal/turntest` and `internal/wgtest` provide an in-process TURN server and
WireGuard netstack nodes for tests; `internal/fakehub` is a minimal test double of
the hub (session, enrollment and renewal API plus a TCP splice) for client-side tests.

`e2e/` runs the whole system in one process (about 15 s): a pion TURN server with
STUNner-style TURN-REST authentication, the real hub on wireguard-go with the
in-memory doubles of `internal/hubtest`, the real agent with a generated RSA
device key and a temporary identity directory, real client sessions with Keycloak
tokens from a local JWKS server, and a TCP echo server as the fake sshd.
`internal/e2erig` assembles it; `cmd/wg-connect/e2e_test.go` drives the
ProxyCommand through it and checks the known_hosts file. Scenarios: enrollment
and echo over TURN on both legs; device marked compromised (client connection
fails within 1 s, new sessions `device_revoked`, agent backs off); flag cleared
with an enrollment reset (new identity fingerprint, access returns); user loses
access (next connection refused, renewal denied); TURN restart (relays
recover); log hygiene over all logs.
