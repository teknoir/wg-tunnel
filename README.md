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
implementations (ConfigMap informers for policy and flags, identity ConfigMaps
with optimistic concurrency, TokenReview, SubjectAccessReview, TURN secret).
The hub needs no access to Device objects: `wg-hub flags-watcher` (a separate
Deployment with its own ServiceAccount and no ingress) is the only component
that reads them, metadata only, and mirrors the three switches into
`ztna-flags-<teamspace>.<device>` ConfigMaps (written only on change; deleted
when the Device is gone). A missing flags entry means "not enabled".

A device is reachable only while the policy entry is `active`, the flags entry
says the Device exists, `ztna.teknoir.org/wireguard=enabled` and neither
`compromised` nor `health-check-failed` is `true` (`api.FlagSet` parses the
values everywhere). Every policy or flag change re-evaluates the device at once
and tears down its sessions and spliced connections.

Device identity:

- Enrollment pins the first identity per enrollment epoch (a random value the
  controller writes each time it opens a window); the pin is valid only for that
  exact epoch and generation. Pinning is not trust: a device session needs the
  fingerprint an admin approved (`PolicyEntry.ApprovedFingerprint`), otherwise
  the hub answers `pending_approval` (the agent logs its fingerprint and keeps
  asking, staying enrolled).
- When the hub sees a `compromised` or `health-check-failed` flag it voids the pin
  in the identity ConfigMap for good, whether or not device-controller noticed.
  Re-admission needs a new enrollment window (new epoch) and a new identity.
- Callers who have not proven a credential only ever hear `unauthenticated`; the
  specific reasons (`reenroll`, `pending_approval`, ...) go to authenticated devices.

Listeners: `HTTP_ADDR` (8080) is the outside API behind the ingress gateways and
serves Keycloak users and devices only. `INTERNAL_HTTP_ADDR` (8081) is not
routed by any VirtualService and additionally accepts service-account
delegation (`onBehalfOf`, TokenReview audience `teknoir-ztna`, SA labelled
`app.kubernetes.io/managed-by=device-controller` and annotated for the device)
and `direct` UDP sessions. Keycloak renewals must present a freshly issued token
(another `jti`, not older than the last accepted one).

Limits: per-IP rate limits apply only to requests that carry a parseable address
in `CLIENT_IP_HEADER` (behind servicelb or a sidecar the peer address is the
same for everybody); a global per-endpoint backstop (50 rps, burst 200) always
applies. Device sessions are exempt from the per-teamspace cap, which counts
client sessions only; there is also a per-user cap across devices (20) and, for
delegated sessions, the budget is per (service account, email).

| Environment | Meaning | Default |
|---|---|---|
| `POD_IP` | advertised WireGuard endpoint host (downward API) | required |
| `DOMAIN` | derives `TURN_URLS`, `KEYCLOAK_ISSUER` when unset | |
| `HUB_NAMESPACE` | policy, identity ConfigMaps and delegating SAs | `teknoir-ztna` |
| `HTTP_ADDR` / `INTERNAL_HTTP_ADDR` / `METRICS_ADDR` | outside API / internal API / Prometheus | `:8080` / `:8081` / `:9090` |
| `TURN_URLS` | comma-separated TURN URLs returned to sessions | `turn:turn.<DOMAIN>:3478?transport=udp` |
| `TURN_SECRET_REF` | `namespace/name` of the Secret holding key `secret` | `stunner-system/stunner-auth-secret` |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_JWKS_URL` | access-token issuer and key set | `https://auth.<DOMAIN>/auth/realms/master` |
| `ALLOWED_AZP` | accepted Keycloak `azp` values | `teknoir-cli` |
| `CLIENT_IP_HEADER` | trusted proxy header with the real client IP; without it there is no per-IP limit | none |
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
more than `DeadAfter` (twice the persistent keepalive, at least one renewal cycle
plus its retry) since the last packet or the last successful renewal.

`wg-hub flags-watcher` takes `HUB_NAMESPACE`, `LOG_LEVEL` and `METRICS_ADDR`
(`/healthz`, `/readyz`, `/metrics`); it needs get/list/watch on Devices
(cluster-wide, metadata only) and create/update/delete on ConfigMaps in the hub
namespace.

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
roots; `/etc/teknoir/roots.pem` if present), `ATTEST_EXCHANGE` (see below) and `LOG_LEVEL`.

### Host-key attestation and automatic activation

`wg-agent attestor --state /var/lib/teknoir/wg-agent --exchange /run/wg-attest --hostkeys /etc/ssh`
is a sidecar run as root with **all capabilities dropped** (root owns the 0600
host keys, so no DAC capability is needed), a read-only `/etc/ssh` and no
socket. `NAMESPACE` and `DEVICE_ID` come from its own environment.

- The agent (with `ATTEST_EXCHANGE=/run/wg-attest`) asks the hub for a
  single-use nonce (`api.AttestChallengePath`), writes `request.json`
  `{nonce, epoch, generation}` into the shared exchange directory and waits up to
  15 s for `response.json`. The attestor polls once a second, accepts only a
  regular file of at most 4 KiB owned by uid 65532, reads the identity PUBLIC
  key from `identity.pub` in the state directory, signs `api.AttestStatement`
  with the ed25519 host key (RSA host key with `rsa-sha2-512` only when there is
  no ed25519 one; SSHSIG, `pkg/sshsig`) and writes `response.json` (0644,
  atomically). One signature per 10 s.
- The agent verifies the signature locally and sends it in the `EnrollRequest`
  with capability `attest-v1`. Without `ATTEST_EXCHANGE` it enrolls like a
  phase-1 agent; against a hub without the challenge endpoint it enrolls without
  attestation. If the attestor says it cannot sign (no host key), the agent
  enrolls unattested, and if it does not answer at all the enrollment is retried.
- The hub verifies the attestation against the CURRENT epoch and generation, the
  enrolling identity and a nonce it issued to that identity key. It records
  `AttestedHostKey` (`SHA256:<b64>` of the key blob) on the identity. An agent
  that advertises `attest-v1` without a valid attestation is refused
  (`attest_required`).
- **Activation rule** (`identityUsable`, one function for session create, renew
  and enforcement): an identity is usable iff it is not voided, its epoch and
  generation are the policy's, and either its fingerprint is the approved one
  (`activatedBy: approval`) or `activationMode != "manual"`, `forceManualGeneration
  < enrollmentGeneration`, `!duplicateHostKey`, `trustedHostKey != ""` and the
  attested host key equals `trustedHostKey` (`activatedBy: host-key`). The hub
  records `activatedBy`/`activatedAt` once.
- **Pin displacement**: an enrollment attested by the trusted host key replaces an
  existing pin of the same epoch that is not attested by it and not approved by
  an admin (the displaced fingerprint is voided for good and counted as a
  conflict).

The state directory is `0711` (the attestor is "other" to it) and `identity.pub`
is `0644`; `identity.key` stays `0600`. The exchange directory must be writable
by uid 65532 and by root without capabilities, e.g. a default `emptyDir` (0777).
`test/smoke-attestor.sh` checks all of this under the device capability set.

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
