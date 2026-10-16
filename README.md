# wg-tunnel

WireGuard is the Teknoir platform's **Tunneling**: zero-trust, device-initiated
WireGuard tunnels to Teknoir devices, relayed through
[STUNner](https://github.com/l7mp/stunner) (TURN). It is on by default and
activates itself during device bootstrap, with no manual step. Users reach
devices with `tnctl ssh <device>`, `tnctl port-forward <device> [local:]<service-id>`
and `tnctl ansible`; `tnctl` picks WireGuard by itself and falls back to the
legacy SSH tunnel (deadend, reverse-tunnel-app) only where WireGuard is not yet
deployed. As of this writing that is production (teknoir.online) and airgapped
installs; staging (teknoir.cloud) uses WireGuard. There is no SOCKS proxy and no
arbitrary `host:port` forwarding over WireGuard, only the services a device
publishes.

Network needs on the device: outbound HTTPS to `wg.<domain>` and UDP 3478 to the
TURN relay.

Technical names keep the internal project name: namespace `teknoir-ztna`,
annotations `ztna.teknoir.org/*`, and the `ztna-*` ConfigMaps and images.

- `cmd/wg-hub`: session broker and WireGuard gateway. It runs wireguard-go on a
  gVisor netstack, unprivileged. It authenticates every session, applies policy
  per connection, and splices TCP from clients to devices. It revokes
  immediately when a device is flagged.
- `cmd/wg-agent`: device agent. It uses an on-device Ed25519 identity, opens
  connections from the device side over TURN, and exposes only the allowed ports.
- `cmd/wg-gateway`: web gateway of a device (second container of the per-device
  `wgt-` pod): an HTTP reverse proxy that publishes the device's web services to
  browsers through the ingress, over the tunnel.
- `cmd/wg-connect`: stdio proxy for `ssh -o ProxyCommand=...` (WG web terminal).
- `pkg/wgclient`: client library used by `tnctl ssh`, `tnctl port-forward` and `tnctl ansible`.
- `pkg/api`: the wire contract (standard library only).

Design: `plans/wireguard-ztna-tunnel.md` in the Teknoir workspace (historical name).

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
| `STATUS_ADDR` | listener for the Backstage live status and admin API (the chart sets `:8082`); off when empty | off |
| `BACKSTAGE_SA` | full username of the Backstage service account (`system:serviceaccount:<ns>:<name>`), required with `STATUS_ADDR` | |
| `STATUS_AUDIENCE` | audience of the projected token the Backstage backend presents on the status listener | `teknoir-ztna-status` (`api.StatusTokenAudience`) |
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

### Status and admin listener (`STATUS_ADDR`)

A separate port (`api.HubStatusPort`, 8082) for the Backstage backend only; 8081
is unchanged and no VirtualService routes to it. The caller sends a projected
ServiceAccount token whose audience is `api.StatusTokenAudience`
(`teknoir-ztna-status`, overridable with `STATUS_AUDIENCE`), NOT its automounted
API-server token: the hub runs a TokenReview for that audience only and requires
the review to confirm it, so a compromised hub (or its logs) never holds a token
the API server would accept as Backstage. The username must equal `BACKSTAGE_SA`
exactly: a missing or invalid token (including an API-server token) is 401, any
other identity 403. An AuthorizationPolicy in front admits only the Backstage SA
as well. **Deployment:** the Backstage backend pod needs a projected
`serviceAccountToken` volume with that audience (short `expirationSeconds`) and
must send that token; until it does, every status call is refused.

- `GET /v1/status/devices/<ns>/<device>` returns `api.DeviceLiveStatus`: whether
  the device is connected and since when, the last WireGuard handshake of its
  peer, transport (`turn`), agent version and capabilities, whether the
  identity waits for an admin, the hub's own record of the identity pin
  (`identity`: fingerprint, attested key (the device key) and type, enrollment
  epoch and generation, activation source and time, voided, conflicts,
  replacements; taken from the identity
  store, never from the Device CR, whose status device editors can write; the
  admin actions of Backstage compare against it), and its client sessions (subject, service,
  software, path, since, bytes). `BytesIn` is client to device, `BytesOut` device
  to client; both are counted while the stream runs. `Path` is what the client
  reported on its last renewal (`api.RenewRequest.Path`), `hub` by default.
  A gateway session lists the users with an open connection, comma separated.
  Unknown device: 404.
- `GET /v1/status/devices/<ns>/<device>/k3s-services` returns `api.K3sServiceList`
  for the console's "Add service" dialog; see "k3s Service discovery".
- `POST /v1/admin/sessions/<id>/end` ends a client session like a revocation
  (streams closed, peer removed after the flush grace) and logs a decision
  `op=admin_end` with the requester from the header `api.StatusRequesterHeader` (`X-Ztna-Requester`, an email,
  else `unknown`) and the Backstage identity. Device sessions cannot be ended
  here (404).

### Delegated gateway sessions (`software: web-gateway`)

The web gateway holds one delegated session per web service, not per user. It
creates a client session on the internal API with its service account token,
`software: web-gateway`, `direct: true` and NO `onBehalfOf`; the hub verifies the
token and the SA's device binding (`DelegateVerifier`) and marks the session
`perConn`. Each spliced connection then starts with one `api.ConnectRequest`
line to the hub (`{"service":"web","as":"alice@example.com"}`): the service must
be the session's, `as` a lowercase email. The hub runs the SubjectAccessReview
for that user, dials the agent with the same line (`as` is only logged there),
and answers the client with one `api.ConnectResponse` line before any byte is
relayed (`reason` is an `api.Reason*` code on refusal). The quota of such a
session allows one per service id (32). Renewals take the SA token and no user.

The session is shared by every user of the service, so its connection cap is its
own (`Config.MaxConnsPerConnSession`, default 256, instead of the 16 of a
one-user session); the gateway bounds each user (16 open connections, upgraded
ones included). A WebSocket or an event stream is one connection for hours, so
the hub authorizes the users of OPEN connections again: on every renewal of the
gateway session (about once a minute) and every `UserRecheckInterval` (60 s) it
runs the SubjectAccessReview for each distinct end user that has a connection
and closes the connections of a user who is denied. An unavailable authorizer
closes nothing (the next round asks again).

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
- `pkg/agent`: the wg-agent loop (identity, enrollment, session, port forwarding, backoff), the services connect/control listeners, target validation and the `GrantStore`.
- `pkg/svc`: shape validation of `api.ServiceSpec` (shared with device-controller).

## wg-agent

`wg-agent init --dir D --uid U` (init container, root) prepares the identity directory.
`wg-agent run` is configured by environment: `DEVICE_ID`, `NAMESPACE`, `DOMAIN`
(or `HUB_URL`, default `https://wg-device.<DOMAIN>:8084`), `RSA_KEY`
(`/etc/teknoir/rsa_private.pem`), `IDENTITY_DIR` (`/var/lib/teknoir/wg-agent`),
`SSH_HOST_KEYS_GLOB` (`/etc/ssh/ssh_host_*_key.pub`), `FORWARD_HOST` (`127.0.0.1`),
`TURN_SERVER` (host:port override), `CA_FILE` (extra CAs added to the system
roots; `/etc/teknoir/roots.pem` if present), `DEVICE_KEY_FILE`
(`/etc/teknoir/ztna_device_key`), `DEVICE_KEY_ENVELOPE`
(`/run/ztna-device-key/envelope.json`), `ATTEST_EXCHANGE` (deprecated, see below) and `LOG_LEVEL`.

### Device key and automatic activation (rev 3)

The bootstrap of a device is a trusted process, so a bootstrapped device needs
no hands-on step to get WireGuard: it holds a per-device **device key** (Ed25519,
`pkg/devicekey`) whose fingerprint device-controller writes to the policy as
`trustedHostKey` (the wire name is kept; the meaning is now the device key). An
identity that the device key attested activates by itself.

- **Where the key comes from.** Either the trusted bootstrap installs it as
  `/etc/teknoir/ztna_device_key` (OpenSSH Ed25519, 0440, owner 65532:root;
  `DEVICE_KEY_FILE`; source `bootstrap` or `vdevice`), or device-controller
  generates one, **seals it to the device's bootstrap RSA key** (RSA-OAEP-SHA256
  over the 32-byte seed, label `api.DeviceKeyLabel(ns, device, serial)`,
  `api.DeviceKeyEnvelope`) and ships the envelope in the device's MQTT config as
  the ConfigMap `wg-agent-device-key`, mounted read-only and optional at
  `/run/ztna-device-key/envelope.json` (`DEVICE_KEY_ENVELOPE`; source `mqtt`).
  Nobody types or compares anything, and the private key is stored nowhere in
  the cloud.
- **The agent** loads the bootstrap file; if the envelope's fingerprint is not
  already stored it opens the envelope with `RSA_KEY` (`/etc/teknoir/rsa_private.pem`),
  checks namespace, device and fingerprint and writes `<IDENTITY_DIR>/device_key`
  (0600, atomic). It collects every device key it holds (bootstrap and delivered,
  deduplicated, at most 2), fetches one single-use nonce per key
  (`api.AttestChallengePath`), signs `api.AttestStatement` **in-process**
  (SSHSIG, `pkg/sshsig`) with each, and enrolls with capabilities `attest-v1` and
  `device-key-v1`. No sidecar, no shared directory. It never logs key material,
  only fingerprints. Against a hub without the challenge endpoint it enrolls
  without attestation.
- **Re-attestation.** The agent remembers the set of key fingerprints it
  attested with. A poller (`DeviceKeyPoll`, 15 s) re-reads the key file and the
  envelope; when the set changes, the agent enrolls the SAME identity again,
  also while a session is active (the hub accepts it idempotently and records
  the attestation). That is how a pending pin activates when the key arrives
  later, an approved pin records a first key, and a rotation (a new trusted key
  and a new envelope) activates the identity again. A pending identity is also
  attested again at start and every `ReattestInterval` (60 s) as long as the
  hub holds it back, also when the set is unchanged: the hub records ONE
  attestation per pin (the key trusted at that moment), so a pin that fell back to
  pending because trust moved to another key the agent holds is attested again
  until the hub records that key.
- The hub verifies each attestation against the CURRENT epoch and generation,
  the enrolling identity and a nonce it issued to that identity key, and records
  `AttestedHostKey` (`SHA256:<b64>`; the name is kept) on the pin, preferring the
  trusted key when several signed. An agent that advertises `attest-v1` without a
  valid attestation is refused (`attest_required`). While the policy trusts a
  device key, an enrollment with no attestation at all is refused too, whatever
  the agent advertised: a holder of the legacy enrollment key could otherwise pin
  an unattested identity that an admin might approve by hand. An identity pinned
  before the key was trusted can still be approved, activated by re-attesting, or
  displaced.
- **Window bypass.** With a device key trusted that activates identities (not
  shared with another device, `activationMode` not `manual`, the generation not
  forced manual) the hub issues attestation nonces outside the enrollment window
  and admits an enrollment attested by that key without one; an unattested or
  differently attested enrollment is still refused (`enroll_closed`). Pin
  displacement and replacement below follow the same rule: the device key admits
  an identity only where the identity would itself become usable.
- **A flagged device's key is not trusted again.** When a pin is voided because
  the device was flagged compromised or failed its health check, the key that
  attested it is stored in the identity (`distrustedKeys`, bounded like
  `voidedFingerprints`) and carried over whenever the pin is replaced or
  displaced, and never cleared. While the policy trusts a listed key, the hub
  refuses every enrollment that carries an attestation by a listed key, beside
  any other (`attest_required`), and issues no nonce outside the window for it.
  Once the policy trusts a rotated key that is not listed, an attestation by an
  old key can neither activate nor displace anything and is not refused, so an
  agent that still holds the old key beside the new one enrolls; trusting a
  listed key again later is refused the same way. This applies where the key
  would activate an identity; in a generation
  forced to manual or with manual activation an admin decides anyway. device-controller
  rotates the key when it clears the flag; a hub that did not wait for that would
  let whoever caused the flag enroll in the gap.
- **Budgets**: enrollment and challenge rate limits, replay partitions and the
  outstanding-nonce caps (8) are per (device, identity key), with a generous
  per-device bucket (and 64 nonces) behind them, so a squatter holding the
  enrollment key drains its own budget and cannot starve the real device. The
  identity keys of a device other than its pinned one hold at most 16 nonces
  together (the oldest is dropped), so identity keys minted at will, also outside
  the window, cannot crowd out the pinned identity. An
  unattested enrollment of another identity than the pinned one is counted as a
  conflict even though it is refused.
- **Activation rule** (`identityUsable`, one function for session create, renew
  and enforcement): an identity is usable iff it is not voided, its epoch and
  generation are the policy's, and either its fingerprint is the approved one
  (`activatedBy: approval`) or `activationMode != "manual"`, `forceManualGeneration
  < enrollmentGeneration`, `!duplicateHostKey`, `trustedHostKey != ""` and the
  attested key equals `trustedHostKey` (`activatedBy: device-key`; entries marked
  `host-key` before rev 3 stay valid). The hub records `activatedBy`/`activatedAt`
  once, so an approved pin that later also gets a device key stays `approval`.
- **Pin displacement**: an enrollment attested by the trusted device key replaces
  an existing pin of the same epoch that is not attested by it and not approved
  by an admin (the displaced fingerprint is voided for good and counted as a
  conflict). This also holds with `activationMode: manual` or a generation forced
  to manual (the new pin then waits for an admin): a squatter must not lock the
  real device out. A key shared with another device displaces nothing.
- **Pin replacement**: an enrollment attested by the trusted device key also
  replaces a pin that IS trusted (attested by the key, or approved) when the
  device has **no live session**: the device lost its identity (re-image) and the
  device key proves it is the same device. The old fingerprint is voided,
  `replacements`, `lastReplacedAt` and `lastReplacedFingerprint` are recorded and
  the new identity activates. While the device is online the same enrollment is
  today's `enroll_conflict`. A voided identity that comes back (the pod moved
  from node A to B and back) and proves the trusted device key is answered
  `reenroll`, not `enroll_conflict`: the agent generates a new identity and
  enrolls it (and the console shows no squatting). Without the key it stays a
  conflict.
- The live status (`api.LiveIdentity`) reports `activatedBy`, `activatedAt`,
  `replacements`, `lastReplacedAt`, `current` (the pin is of the policy's current
  epoch and generation) and `agentCapabilities`.

A device key is only as strong as how it got to the device. A bootstrap key is
written by the trusted bootstrap; an MQTT-delivered key is as strong as the
device's RSA key and the MQTT channel during delivery (the envelope is sealed to
the RSA key, but whoever holds that key and can read the config topic can open
it). Rotating the key (an admin action in the console) delivers a new one.

### Legacy host-key attestor (deprecated)

`wg-agent attestor --state /var/lib/teknoir/wg-agent --exchange /run/wg-attest --hostkeys /etc/ssh`
is the pre-rev-3 sidecar, run as root with **all capabilities dropped** (root
owns the 0600 host keys, so no DAC capability is needed), a read-only `/etc/ssh`
and no socket. It is deprecated and will be removed one release after
device-controller stops deploying it. The agent uses it (with
`ATTEST_EXCHANGE=/run/wg-attest`) only while the device holds **no device key**;
as soon as a device key exists the agent signs with that and ignores the sidecar.

- The agent asks the hub for a nonce, writes `request.json` `{nonce, epoch,
  generation}` into the shared exchange directory and waits up to 15 s for
  `response.json`. The attestor polls once a second, accepts only a regular file
  of at most 4 KiB owned by uid 65532, reads the identity PUBLIC key from
  `identity.pub` in the state directory, signs `api.AttestStatement` with the
  ed25519 host key (RSA host key with `rsa-sha2-512` only when there is no
  ed25519 one) and writes `response.json` (0644, atomically). One signature per
  10 s. If the attestor says it cannot sign (no host key), the agent enrolls
  unattested, and if it does not answer at all the enrollment is retried.
- With an exchange directory the state directory is `0711` (the attestor is
  "other" to it) and `identity.pub` is `0644`; `identity.key` stays `0600`. The
  exchange directory must be writable by uid 65532 and by root without
  capabilities, e.g. a default `emptyDir` (0777). Without `ATTEST_EXCHANGE` the
  agent sets the state directory back to `0700`.
  `test/smoke-attestor.sh` checks all of this under the device capability set.

### Services (phase 2)

The agent advertises `services-v1` and `control-v1` and serves, on its overlay
address (reachable only from the hub), a connect listener on `api.AgentConnectPort`
and a control listener on `api.AgentControlPort`. The phase-1 per-port listeners
(`AllowedPorts`) stay. A dialer writes one JSON line (`api.ConnectRequest`,
at most 1 KiB, 5 s), the agent answers one line (`api.ConnectResponse`) and then
relays bytes with half-close; at most 128 connections per service
(`MaxConnsPerService`, 256 in total) so that one shared web-gateway session
fits, and per plane-B pair at most 16 (`MaxConnsPerPair`); plane B as a whole
leaves a quarter of a service's slots to the hub splice.

The agent never dials a host or port taken from the caller: it looks the service
up in its **current** set (the session response, replaced by the hub's control RPC
`api.ControlServicesPath`) and validates the target again on **every** dial:

| Kind | Target | Refused |
|---|---|---|
| `ssh` (implicit) | `FORWARD_HOST:SSH_PORT` (127.0.0.1:22); the spec is ignored | |
| `external` | IP literal and port | loopback (the ssh target excepted), 169.254/16, fe80::/10, multicast, unspecified, addresses inside the service CIDR or the pod CIDR (`CLUSTER_CIDR`, default `10.42.0.0/16`: in-cluster targets must be `internal` services), and the control-plane ports 6443, 10250, 10255, 2379, 2380, 10257, 10259 on ANY address (the other nodes of a multi-node Robot are not known to the agent; internal services additionally refuse the node's own addresses there) |
| `internal` | `<svc>.<ns>`, resolved as `<svc>.<ns>.svc.<CLUSTER_DOMAIN>.` (A records only) | any address outside `SERVICE_CIDR` (headless services, pod IPs), an answer through a CNAME (ExternalName), `kube-system`, `default/kubernetes` |

`SERVICE_CIDR` (comma-separated, default `10.43.0.0/16`, the k3s default),
`CLUSTER_CIDR`, `CLUSTER_DOMAIN` (`cluster.local`) and `SSH_PORT` (`22`) configure it.
Internal services are trusted at the Service level: the agent checks the
ClusterIP, not the endpoints behind it. The agent's own overlay ports
(`api.AgentConnectPort`, `api.AgentControlPort`) are never raw ports: the hub drops them
from `AllowedPorts` and answers `port_not_allowed` to a raw-port client session
for them (the control port trusts the hub's overlay address). Internal
services need the pod's cluster DNS (`dnsPolicy: ClusterFirstWithHostNet` for a
host-network pod). A refusal is `service_denied` on the wire (`internal` for an
unreachable target, `session_limit` at a cap); the detail is only in the agent's log.

The hub routes a connection to the agent by service id, so it also checks that
the live agent was TOLD the policy's current definition of the service (what the
last session response or control push carried): while an edited service has not
been applied, new connections are refused as `device_offline` (retryable) and no
plane-B grant is made, instead of reaching the old target. A client session also
re-checks its service after it was registered, before plane B is granted.

`POST api.ControlGrantsPath` takes a versioned `api.GrantSet` (see `GrantStore` in
`pkg/agent/grants.go`): `(hubInstance, seq)` ordering, tombstones for removed
pairs, relative TTLs on the agent's monotonic clock, a changed hub instance drops
every pair. The `GrantHooks` install and remove the plane-B peers (see below).

Tests that need an external service on a loopback listener use the
`Config.AllowTarget` test hook (never settable from the environment); the e2e rig
lets exactly its echo servers through.

### k3s Service discovery

The apps of a Robot (a k3s HelmChart, a GitOps app, anything applied on the
device) create their Services on the device, so the cloud cannot read them from
the Device manifest. The console's "Add service" dialog therefore asks for
them on demand, through the agent. The list is informational: a service that
is picked is still validated as an `internal` ServiceSpec by device-controller,
Backstage and the agent on every dial (see "Services (phase 2)").

```
Backstage -- GET /v1/status/devices/<ns>/<device>/k3s-services --> hub (8082)
hub       -- GET api.ControlK3sServicesPath over plane A --------> agent
agent     -- GET /api/v1/services?limit=500 ---------------------> Kubernetes API
```

- **Agent** (`k3s-discovery-v1`, `pkg/agent/k3sdiscovery.go`): the control
  listener answers `GET api.ControlK3sServicesPath` with an `api.K3sServiceList`,
  for the hub's overlay address only (same check as the other control routes).
  It lists Services cluster-wide with its own ServiceAccount, using plain
  `net/http` and the in-cluster configuration (`KUBERNETES_SERVICE_HOST`,
  `KUBERNETES_SERVICE_PORT`, the token at
  `/var/run/secrets/kubernetes.io/serviceaccount/token`, read on every call, and
  the CA `ca.crt` next to it). One page of at most `api.MaxK3sServices` (500)
  Services; `truncated` is set when the API server has more. Only metadata is
  returned: namespace, name, type, clusterIP and the ports (name, port,
  protocol, appProtocol; at most `api.MaxK3sServicePorts` (32) per Service), never
  annotations, labels, selectors or Endpoints. The list is sorted by namespace and
  name, cached for 10 s (concurrent callers share one request) and the call has a
  5 s timeout. The ServiceAccount needs `get` and `list` on `services`
  (cluster-wide); device-controller ships that RBAC with the agent. Without a
  token, or when the API server answers 401/403, the agent still answers 200,
  with `error` set ("the agent has no permission to list Services yet") and an
  empty list; the same holds when it runs outside a cluster or cannot reach the
  API server.
- **Hub** (`pkg/hub/k3sdiscovery.go`): the route is on the status listener and
  authenticated and authorized exactly like `GET /v1/status/devices/<ns>/<device>`
  (TokenReview for `api.StatusTokenAudience`, username must be `BACKSTAGE_SA`;
  unknown device 404). Each call is logged as a decision `op=k3s_services` with the
  requester from `X-Ztna-Requester` and the Backstage identity. A device that
  cannot answer is still a 200 with `error` and an empty list: "the device is
  offline" (no live session), "the device agent is too old to list services" (no
  `k3s-discovery-v1`), "the device did not answer in time" (5 s) or "the device
  agent gave an answer the hub could not accept" (non-200, unreadable JSON or an
  answer over 4 MiB). The agent is a device and is not trusted: the hub checks the
  list again before it leaves (at most 500 Services of at most 32 ports; Services
  with an empty, oversized or control-character name are dropped, as are ports
  outside 1..65535; type, protocol and clusterIP are reduced to known values and
  valid addresses; the agent's `error` text is stripped of control characters and
  cut to 300 bytes), and sets `observedAt` from its own clock, since device
  clocks are not trusted. Backstage should show `error` as is and treat the list
  as a convenience, not as permission.

### Peer-to-peer (plane B, "P2P-lite")

Plane A (client to hub to device, over TURN) stays the control channel and the
fallback. Plane B is an end-to-end WireGuard session between a client and a
device, found by hole punching, in `pkg/p2p`:

- **One UDP socket per side**, with a separate wireguard-go device on a gVisor
  netstack (MTU `api.P2PMTU`). A demultiplexer in front of the WireGuard bind
  splits the socket's datagrams into STUN responses (RFC 5389: first bits 00,
  magic cookie at bytes 4..8, consistent length; no WireGuard message can match),
  punch probes and WireGuard. Endpoints are raw `ip:port`; roaming does the rest.
- **Candidates**: host (all up interface addresses, IPv4 and non-link-local IPv6),
  server-reflexive (STUN Binding to the TURN host, port 3478) and nothing else,
  at most `api.MaxP2PCandidates`, private first. The agent takes the STUN server
  from the session's TURN URL (`P2P_STUN` overrides it); the client needs its
  address before it has a session, so it derives `turn.<domain>:3478` from
  `https://wg.<domain>` (`Options.P2PSTUN` / `--stun-server` override).
- **Punching**: both sides send a 38-byte authenticated probe to every candidate
  of the other every 150 ms (500 ms after 3 s) for up to 20 s. A probe carries a
  MAC under a key derived from the X25519 secret of the two plane-B keys, so only
  the pair can make one. The first valid probe from an address moves the
  WireGuard endpoint there and the **client** (the initiator) starts the
  handshake. This replaces "cycle the peer endpoint and nudge the keepalive":
  wireguard-go sends at most one handshake initiation per peer per 5 s
  (`RekeyTimeout`), so cycling would try one candidate per 5 s. A probe is a hint;
  nothing trusts an address before a WireGuard handshake completes through it.
  A responder that loses its session (peer removed and re-added) says so in its
  probes and the initiator starts over at once.
- **Addresses**: a session's plane-B address is its plane-A address with the
  network part replaced (`100.96.x.y` becomes `100.97.x.y`, `p2p.AddrFor`), so
  the plane-A IPAM and its quarantine cover plane B and no address can be reused
  while an old pair might still hold it.
- **Hub**: on a client session request with `P2P` (Keycloak users only, never
  delegated or direct sessions; a named service; `PolicyEntry.P2P`; an agent with
  `p2p-v1`, `control-v1` and a plane-B key) the hub validates the offer, adds the
  pair to the device's **full** grant set (`hubInstance` random per process, `seq`
  per device session, taken in the same critical section as the membership
  snapshot), pushes it with a 3 s timeout and returns `SessionResponse.P2P` only
  if the device acknowledges the pair with the key and address the hub expects.
  The lease is the grant TTL (`Config.P2PGrantTTL`, default 90 s): each client
  renewal restarts it and re-pushes once half has passed; the device's renewal
  response carries the full set (`RenewResponse.Grants`, remaining leases only)
  as the backstop for a lost push. A client session that ends, a service that
  goes away, a policy that turns plane B off and a revoked device each push the
  new set at once.
- **Agent**: `GrantHooks.Add` installs the peer (`allowed_ip` = the client's /32)
  and starts probing; `Remove` closes the pair's connections and removes the
  peer after 250 ms (so the FIN/RST is delivered). The plane-B connect listener
  on `deviceB:2224` has its own handler: it serves only sources that are the
  client address of a live grant, only that grant's services, with the same
  target validation as plane A, per-pair connection caps, and a re-check of the
  grant after registering. Probe targets never include loopback, link-local or
  unspecified addresses (a candidate is the client's word).
- **Client**: `Options.P2P` (`wg-connect --p2p`). `Session.DialService` gives
  plane B `api.P2PDialRaceMillis` to establish, dials `deviceB:2224` with the
  `ConnectRequest` preamble and otherwise falls back to the hub splice (`Dial`);
  after a failure plane B is skipped for 30 s (doubling per failure in a row, at
  most 5 min); a dial the caller cancelled or timed out is no failure, and the
  WireGuard handshake a dial failed on stops counting as established.
  A pong is believed only as the answer to a ping this side sent in the last
  10 s (once per address it was sent to), so a captured pong cannot be replayed
  to steer the endpoint. A device session that ends or is replaced drops the
  clients' pairs on the hub at once (a revocation still pushes one empty grant
  set while the peer is installed); a client whose pair vanished falls back to the
  splice. `Session.Path()` reports
  `direct-lan`, `direct` or `hub` and is sent in every renewal. A plane-B problem
  never ends the session.

NAT expectations (measured in `test/natlab`): endpoint-independent mapping on
both sides punches a direct path; endpoint-dependent mapping on both sides (or
on one) falls back to the hub. No UPnP, no birthday attack, no hub relay.

Environment of the agent: `P2P=on|off` (default on), `P2P_PORT` (default 0, any),
`P2P_STUN` (`host:port`). The agent needs only an unprivileged UDP socket and the
interface listing: `test/smoke-p2p-k3d.sh` runs two probes as uid 65532 with all
capabilities dropped and a read-only root on the throwaway k3d cluster.

## wg-gateway

`pkg/gateway` is the proxy, `cmd/wg-gateway` its main. Flags:
`--hub-url http://wg-hub.<ns>.svc.cluster.local:8081 --namespace NS --device D
--sa-token-file /var/run/ztna/token --listen :8090` (`--idle-timeout`, `--log-level`).

The ingress (oauth2-proxy via ext_authz, then the per-service VirtualService)
routes a service host to port 8090 and sets `X-Ztna-Service: <id>`; an
AuthorizationPolicy admits only the ingress gateway's principal, so
`X-Auth-Request-Email` is trusted. Per request:

1. no valid `X-Auth-Request-Email`: 403; `X-Ztna-Service` not a valid service
   id: 404; the upstream is never derived from the request.
2. CSRF: unsafe methods (anything but GET/HEAD/OPTIONS) and WebSocket upgrades
   need `Origin` equal to `https://<Host>`, else 403.
3. The session of that service is taken from a pool (one per service id,
   created lazily and shared by all users, closed after 15 minutes without
   requests, rebuilt when the hub ends it or the tunnel is found dead).
4. The request is scrubbed: every platform login cookie (any name containing
   `oauth2`, such as the real `_teknoir_oauth2_proxy` and its `_csrf` and
   `_0`/`_1` variants; names starting with `_teknoir`, `KEYCLOAK_`,
   `AUTH_SESSION_ID`; plus the comma list in `--strip-cookies` / `STRIP_COOKIES`,
   all case-insensitive), `Authorization`,
   `Proxy-Authorization`, `X-Forwarded-Access-Token`, all `X-Auth-Request-*`,
   oauth2-proxy's `X-Forwarded-User/Email/Groups/Preferred-Username` and
   `X-Ztna-Service` are removed; `X-Forwarded-Host/Proto/For` are set (the
   ingress's `X-Forwarded-For` chain is kept and extended); `Host` is kept.
5. Every upstream connection is dialled with `Session.DialAs(ctx, email)` and
   carries one user: the Transports are per (service, user), so a connection is
   never shared between users. A connection is authorized when it is opened;
   keep-alive connections are therefore recycled after `ConnMaxAge` (30 s), the
   delay after which a revoked user is checked again. Open WebSockets and
   streams are cut by the hub, which authorizes the users of open connections
   again at every renewal of the session (see above). A user may hold at most
   `--max-conns-per-user` (16) connections to a service, upgraded ones
   included, until they close; the excess waits up to 5 s, then answers 503.
6. Responses: a `Set-Cookie` with a platform login cookie name (as above) is
   dropped and the `Domain`
   attribute of the others removed (host-only cookies). WebSockets and
   streaming responses pass through.
7. Hub refusals become pages: `forbidden` 403, `device_offline` 503, session
   limits 503 with `Retry-After`, an unknown service 404, anything else 502 (a
   small HTML page for browsers, text otherwise; reason codes are not shown).

Logs are one JSON line per request (method, path without query, service, user,
status, bytes, outcome); headers, cookies and tokens are never logged.
`/healthz` and `/readyz` (token file readable) answer only requests WITHOUT
`X-Ztna-Service`, so a device application's own `/healthz` is still proxied.

Known parity risk with the legacy tunnels: the device's JavaScript runs on a
host that is same-site with Backstage.

## wg-connect

ssh ProxyCommand: `wg-connect --hub-url U --namespace NS --device D
(--sa-token-file F --on-behalf-of EMAIL | --keycloak-token-file F)
--known-hosts-file K [--service ssh | --port 22] [--direct] [--p2p [--stun-server HOST:PORT]] [--turn-server HOST:PORT] [--ca-file F]`.
Token files are re-read for every create and renewal; tokens never go in argv or env.

## Images

One `Dockerfile` with three targets (`wg-hub`, `wg-agent`, `wg-gateway`), built with CGO off and pinned base images
(`golang:1.26-alpine`, `gcr.io/distroless/static-debian12:nonroot`, both by
digest), running as uid 65532. The Go toolchain cross-compiles, so no emulation
is needed to build for other architectures.

```
make docker-hub                                   # ghcr.io/teknoir/wg-hub:<version>, linux/amd64, loaded locally
make docker-agent PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
docker run --rm ghcr.io/teknoir/wg-hub:<version> --help
```

`wg-hub` and `wg-gateway` are published for amd64 and arm64, `wg-agent` for
amd64, arm64 and arm/v7. The agent's `init` subcommand needs uid 0 (the init container sets
`runAsUser: 0`); the agent itself runs as 65532. `.github/workflows/build.yml`
runs `go vet` and `go test -race ./...`, then pushes
`ghcr.io/teknoir/wg-hub`, `wg-agent` and `wg-gateway` tagged `sha-<7>`,
`<branch>-<timestamp>`, `<branch>` (and `latest` on main; the git tag itself for tag pushes).

## Development

`make test` (race detector), `make vet`, `make lint` (golangci-lint v2).
The NAT lab (Linux network namespaces, needs root, only touches `wgt-*`
namespaces and interfaces): `go test -c -tags natlab -o /tmp/natlab.test ./test/natlab
&& sudo /tmp/natlab.test -test.v`; `sudo test/natlab/natlab.sh down` removes it if a run
was killed. `test/smoke-p2p-k3d.sh` is the k3d smoke test of plane B.
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
recover); log hygiene over all logs. `e2e/gateway_test.go`: a browser-like request
through the real web gateway, hub, agent and an HTTP app (scrubbing both ways, CSRF,
WebSocket, a second user on the shared session, per-connection access loss, live status,
admin end and recovery, idle close).
