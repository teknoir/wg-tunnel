// Package api is the wire contract between the wg-hub (session broker and
// WireGuard gateway), the device agent (wg-agent), user clients (tnctl,
// wg-connect) and device-controller, which writes the access policy.
//
// It depends on the standard library only, so device-controller and tnctl can
// import it without pulling in WireGuard, gVisor or pion.
package api

import (
	"fmt"
	"strings"
	"time"
)

// Overlay network. The hub is the only peer of every client and every device;
// clients never get L3 reachability to devices (the hub splices TCP).
const (
	// OverlayPrefix is the pool the hub allocates session addresses (/32) from.
	OverlayPrefix = "100.96.0.0/16"
	// HubAddress is the hub's own overlay address. Every session peers only with it.
	HubAddress = "100.96.0.1"
	// HubAPIPort is the in-tunnel HTTP API port on HubAddress (renewals).
	HubAPIPort = 80
	// HubSplicePort is where a client session dials (HubAddress:HubSplicePort);
	// the hub splices the TCP stream to the session's bound device and port.
	HubSplicePort = 2222
	// MTU of every WireGuard netstack interface; leaves room for TURN
	// ChannelData (4B) + outer IPv4/IPv6 + UDP + WireGuard overhead on a 1500 path.
	MTU = 1280
	// PersistentKeepalive in seconds, set by clients and devices (never by the hub).
	PersistentKeepalive = 25
)

// HTTP API paths. Enrollment and session creation are served outside the
// tunnel (users: https://wg.<domain>, devices: https://wg-device.<domain>:8084,
// in-cluster: http://wg-hub.teknoir-ztna.svc:8080). Renewal and close are served
// inside the tunnel on HubAddress:HubAPIPort: the source IP identifies the
// session (cryptokey routing, /32 AllowedIPs) AND every renewal re-authenticates
// with a fresh credential of the same kind as the one that created the session.
const (
	DeviceEnrollPath  = "/v1/device/enroll"  // POST, Bearer <device RSA JWT (enrollment)>, EnrollRequest
	DeviceSessionPath = "/v1/device/session" // POST, Bearer <device identity JWT (EdDSA)>, DeviceSessionRequest
	ClientSessionPath = "/v1/client/session" // POST, Bearer <Keycloak token (azp teknoir-cli)> or <SA token + OnBehalfOf>, ClientSessionRequest
	RenewPath         = "/v1/renew"          // POST in-tunnel, same Bearer kind as the session, RenewRequest
	CloseSessionPath  = "/v1/close"          // POST in-tunnel, empty body; ends the session
	HealthzPath       = "/healthz"
)

// Session kinds.
const (
	KindDevice = "device"
	KindClient = "client"
)

// Device JWTs. Two keys, two token kinds:
//   - Enrollment JWT: RS256, signed with the legacy device key
//     /etc/teknoir/rsa_private.pem. That key is widely exposed (Backstage
//     catalog, tnctl), so it is accepted ONLY on DeviceEnrollPath, only inside
//     the policy's enrollment window, and only if no identity is pinned yet.
//   - Identity JWT: EdDSA (Ed25519), signed with the agent's identity key, which
//     the agent generates on the device and never exports. Required for
//     sessions and renewals once the identity is pinned.
const (
	DeviceJWTIssuer      = "wg-agent"
	DeviceJWTAudience    = "teknoir-ztna"
	MaxDeviceJWTLifetime = 60 * time.Second
	MaxClockSkew         = 30 * time.Second
)

// DeviceClaims are the claims of both device JWT kinds. Sub is
// "<namespace>/<device>". WGKey (session/renew tokens) binds the token to the
// WireGuard public key in the request; IdentityKey (enrollment tokens) binds it
// to the identity key being enrolled.
type DeviceClaims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    string `json:"aud"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	ID          string `json:"jti"`
	WGKey       string `json:"wgk,omitempty"`
	IdentityKey string `json:"idk,omitempty"`
}

// EnrollRequest pins the agent identity key (base64 raw Ed25519 public key).
// Proof is base64 Ed25519 signature over EnrollProofMessage(sub, jti) made with
// the identity private key (proof of possession).
type EnrollRequest struct {
	IdentityPublicKey string  `json:"identityPublicKey"`
	Proof             string  `json:"proof"`
	Posture           Posture `json:"posture"`
	// Capabilities the agent supports (CapAttest => an unattested enrollment
	// from this agent is shown as suspicious).
	Capabilities []string `json:"capabilities,omitempty"`
	// HostKeyAttestations (CapAttest) over AttestStatement for this identity.
	HostKeyAttestations []HostKeyAttestation `json:"hostKeyAttestations,omitempty"`
}

// EnrollProofMessage is the byte string the identity key signs at enrollment.
func EnrollProofMessage(subject, jti string) []byte {
	return []byte("teknoir-ztna-enroll-v1\n" + subject + "\n" + jti)
}

// EnrollResponse is returned with 201 (newly pinned) or 200 (same key already pinned).
type EnrollResponse struct {
	Fingerprint          string    `json:"fingerprint"` // "SHA256:<base64 raw>" of the identity public key
	EnrollmentGeneration int64     `json:"enrollmentGeneration"`
	EnrolledAt           time.Time `json:"enrolledAt"`
}

// DeviceSubject formats the device JWT subject.
func DeviceSubject(namespace, device string) string { return namespace + "/" + device }

// Posture is SELF-REPORTED client context. It is advisory: the hub uses it
// only for compatibility gating (minimum versions) and audit, never as a
// security signal. Software is "wg-agent", "tnctl" or "web-terminal".
type Posture struct {
	Software string `json:"software"`
	Version  string `json:"version"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// TURNCredentials are TURN-REST (time-windowed) credentials for the STUNner
// gateway: Username is "<unix-expiry>:<namespace>/<id>", Password is
// base64(HMAC-SHA1(shared secret, Username)).
type TURNCredentials struct {
	// URLs such as "turn:turn.teknoir.cloud:3478?transport=udp".
	URLs      []string  `json:"urls"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// DeviceSessionRequest is posted by wg-agent. WGPublicKey is base64 (wg format),
// freshly generated per session and never persisted.
type DeviceSessionRequest struct {
	WGPublicKey string `json:"wgPublicKey"`
	// Capabilities (Cap*) the agent supports; absent = phase-1 agent.
	Capabilities []string `json:"capabilities,omitempty"`
	// P2PWGPublicKey is the agent's plane-B key for this device session (CapP2P).
	P2PWGPublicKey string  `json:"p2pWgPublicKey,omitempty"`
	Posture        Posture `json:"posture"`
	// SSHHostKeys are the device's sshd host public keys in authorized_keys
	// format ("ssh-ed25519 AAAA..."), read by the agent from /etc/ssh/*.pub.
	// The hub hands them to clients so ssh runs with StrictHostKeyChecking=yes.
	SSHHostKeys []string `json:"sshHostKeys,omitempty"`
}

// ClientSessionRequest is posted by tnctl / wg-connect. A client session is
// bound to exactly one (namespace, device, port).
type ClientSessionRequest struct {
	Namespace   string  `json:"namespace"`
	Device      string  `json:"device"`
	Port        int     `json:"port"`
	WGPublicKey string  `json:"wgPublicKey"`
	Posture     Posture `json:"posture"`
	// OnBehalfOf is set only by a delegating service account (the per-device WG
	// web terminal in the hub namespace): the end-user email that ingress
	// (oauth2-proxy) authenticated. The hub authorizes THIS email with a
	// SubjectAccessReview; the SA itself must be bound to (Namespace, Device).
	OnBehalfOf string `json:"onBehalfOf,omitempty"`
	// Direct asks for direct UDP to HubEndpoint (in-cluster clients); no TURN
	// credentials are minted.
	Direct bool `json:"direct,omitempty"`
	// Service is the service ID (phase 2). Empty = Port 22 = "ssh".
	Service string `json:"service,omitempty"`
	// P2P is set by clients that can do plane B (tnctl); the hub answers with
	// SessionResponse.P2P if the device accepted the pair.
	P2P *P2POffer `json:"p2p,omitempty"`
}

// SessionResponse is returned on 201 Created for both session kinds.
type SessionResponse struct {
	SessionID string `json:"sessionId"`
	Kind      string `json:"kind"`
	// Address is the session's overlay address (no prefix length; it is a /32).
	Address string `json:"address"`
	// HubAddress is api.HubAddress; HubPublicKey is base64 (wg format).
	HubAddress   string `json:"hubAddress"`
	HubPublicKey string `json:"hubPublicKey"`
	// HubEndpoint is the UDP ip:port of the hub's WireGuard socket as reachable
	// from the STUNner dataplane (the TURN peer address) and from in-cluster
	// clients that use direct UDP.
	HubEndpoint string `json:"hubEndpoint"`
	// TURN is nil only for in-cluster sessions that asked for direct UDP.
	TURN              *TURNCredentials `json:"turn,omitempty"`
	ExpiresAt         time.Time        `json:"expiresAt"`
	RenewAfterSeconds int              `json:"renewAfterSeconds"`
	MTU               int              `json:"mtu"`
	// Device sessions: ports the agent must expose on Address (forwarded to 127.0.0.1).
	AllowedPorts []int `json:"allowedPorts,omitempty"`
	// Client sessions: dial HubAddress:SplicePort; the hub splices to Device:TargetPort.
	SplicePort int `json:"splicePort,omitempty"`
	TargetPort int `json:"targetPort,omitempty"`
	// Device sessions (CapServices): the device's services.
	Services []ServiceSpec `json:"services,omitempty"`
	// Client sessions: the granted service and, if any, the plane-B grant.
	Service string    `json:"service,omitempty"`
	P2P     *P2PGrant `json:"p2p,omitempty"`
	// Client sessions: the device's SSH host keys as reported by its
	// identity-authenticated agent. Clients write them to a known_hosts file
	// under HostKeyAlias = KnownHostsAlias(ns, device).
	SSHHostKeys []string `json:"sshHostKeys,omitempty"`
}

// KnownHostsAlias is the ssh HostKeyAlias clients use for a device.
func KnownHostsAlias(namespace, device string) string {
	return device + "." + namespace + ".ztna.teknoir"
}

// RenewRequest is posted in-tunnel to http://HubAddress:HubAPIPort/v1/renew.
type RenewRequest struct {
	Posture Posture `json:"posture"`
	// Path is the client's current data path to the device for live status
	// (PathDirectLAN | PathDirect | PathHub). Client-reported: informational.
	Path string `json:"path,omitempty"`
}

// RenewResponse extends the session. TURN is set only when the hub rotated the
// TURN credentials; the client must then move to a new relay allocation.
type RenewResponse struct {
	ExpiresAt         time.Time        `json:"expiresAt"`
	RenewAfterSeconds int              `json:"renewAfterSeconds"`
	TURN              *TURNCredentials `json:"turn,omitempty"`
	// Grants (device sessions with CapP2P) is the full current plane-B grant
	// set: the backstop for a lost control push. Applied with the same
	// (HubInstance, Seq) ordering as a control push.
	Grants *GrantSet `json:"grants,omitempty"`
}

// Error is the JSON body of every 4xx/5xx. Reason is one of the Reason* codes.
type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Reason, e.Message) }

// Denial reasons. Clients treat every reason as terminal for the session and
// back off before creating a new one.
const (
	ReasonUnauthenticated = "unauthenticated"  // missing/invalid/expired token
	ReasonNotEnrolled     = "not_enrolled"     // no identity pinned: enroll first
	ReasonReenroll        = "reenroll"         // enrollment was reset: generate a NEW identity and enroll
	ReasonEnrollClosed    = "enroll_closed"    // enrollment window closed (admin must reset enrollment)
	ReasonEnrollConflict  = "enroll_conflict"  // a different identity is already pinned
	ReasonSessionLimit    = "session_limit"    // per-subject/per-device session cap reached
	ReasonPendingApproval = "pending_approval" // identity pinned, waiting for an admin to approve its fingerprint
	ReasonServiceUnknown  = "service_unknown"  // requested service is not defined for the device
	ReasonServiceDenied   = "service_denied"   // service target refused by validation on the agent
	ReasonP2PUnavailable  = "p2p_unavailable"  // device cannot do plane B (capability, opt-out, timeout)
	ReasonAttestRequired  = "attest_required"  // agent advertised CapAttest but sent no valid attestation
	ReasonReplay          = "replay"           // device JWT jti reused
	ReasonForbidden       = "forbidden"        // user lacks access to the teamspace
	ReasonDeviceUnknown   = "device_unknown"   // no policy entry
	ReasonDeviceDisabled  = "device_disabled"  // WireGuard not enabled for the device
	ReasonDeviceRevoked   = "device_revoked"   // compromised / health check failed
	ReasonDeviceOffline   = "device_offline"   // no live device session to splice to
	ReasonPortNotAllowed  = "port_not_allowed" // requested port not in AllowedPorts
	ReasonPosture         = "posture"          // client software/version rejected
	ReasonSessionUnknown  = "session_unknown"  // renew for an unknown/ended session
	ReasonSessionMaxAge   = "session_max_age"  // session exceeded its maximum lifetime
	ReasonRateLimited     = "rate_limited"
	ReasonBadRequest      = "bad_request"
	ReasonInternal        = "internal"
)

// Policy store, written only by device-controller into the hub's namespace
// (a ValidatingAdmissionPolicy denies every other writer). One ConfigMap per
// device; the entry is under PolicyDataKey.
const (
	PolicyConfigMapPrefix = "ztna-policy-"               // + <teamspace>.<device>
	PolicyLabel           = "ztna.teknoir.org/policy"    // = "true"
	PolicyTeamspaceLabel  = "ztna.teknoir.org/teamspace" // = <teamspace>
	PolicyDeviceLabel     = "ztna.teknoir.org/device"    // = <device>
	PolicyDataKey         = "policy.json"
)

// Identity store, written only by the hub (TOFU enrollment pins). One
// ConfigMap per device; device-controller reads it to show the fingerprint.
const (
	IdentityConfigMapPrefix = "ztna-identity-"            // + <teamspace>.<device>
	IdentityLabel           = "ztna.teknoir.org/identity" // = "true"
	IdentityDataKey         = "identity.json"
)

// Device annotations: the operator-facing switches set from the Backstage UI.
// The hub ALSO watches these directly (metadata-only) so revocation does not
// depend on device-controller being healthy: either source revoking wins.
const (
	AnnotationWireGuard         = "ztna.teknoir.org/wireguard"           // "enabled" | absent
	AnnotationWebTerminal       = "ztna.teknoir.org/web-terminal"        // "enabled" | absent
	AnnotationCompromised       = "ztna.teknoir.org/compromised"         // "true" | absent
	AnnotationHealthCheckFailed = "ztna.teknoir.org/health-check-failed" // "true" | absent
	AnnotationReason            = "ztna.teknoir.org/reason"              // free text
	AnnotationReenroll          = "ztna.teknoir.org/reenroll"            // RFC3339 request time; a newer value resets enrollment
	AnnotationApprovedIdentity  = "ztna.teknoir.org/approved-identity"   // identity fingerprint approved by an admin
)

// MaxVoidedFingerprints bounds IdentityEntry.VoidedFingerprints.
const MaxVoidedFingerprints = 32

// MaxDistrustedKeys bounds IdentityEntry.DistrustedKeys.
const MaxDistrustedKeys = 32

// FlagSet is the single parser for boolean device annotations, used by the
// hub, the flags watcher and device-controller alike.
func FlagSet(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "true") }

// Flags store, written only by the flags watcher (`wg-hub flags-watcher`, its
// own ServiceAccount, no ingress), which is the only component allowed to read
// Device objects. The internet-facing hub reads these ConfigMaps instead of
// Devices, so it never has access to device keys.
const (
	FlagsConfigMapPrefix = "ztna-flags-"            // + <teamspace>.<device>
	FlagsLabel           = "ztna.teknoir.org/flags" // = "true"
	FlagsDataKey         = "flags.json"
)

// FlagsEntry mirrors the security-relevant Device annotations.
type FlagsEntry struct {
	Device            string    `json:"device"`
	Namespace         string    `json:"namespace"`
	Exists            bool      `json:"exists"`
	WireGuard         bool      `json:"wireguard"`
	Compromised       bool      `json:"compromised"`
	HealthCheckFailed bool      `json:"healthCheckFailed"`
	ObservedAt        time.Time `json:"observedAt"`
}

// FlagsConfigMapName returns the flags ConfigMap name for a device.
func FlagsConfigMapName(teamspace, device string) string {
	return FlagsConfigMapPrefix + teamspace + "." + device
}

// Policy states.
const (
	StateActive   = "active"
	StateRevoked  = "revoked"
	StateDisabled = "disabled"
)

// Revocation reasons.
const (
	RevokeCompromised       = "compromised"
	RevokeHealthCheckFailed = "health_check_failed"
)

// PolicyEntry is the JSON value stored under PolicyDataKey.
type PolicyEntry struct {
	Device    string   `json:"device"`
	Namespace string   `json:"namespace"`
	State     string   `json:"state"`
	Reasons   []string `json:"reasons,omitempty"`
	// Note is the free-text reason entered by the operator in the UI.
	Note string `json:"note,omitempty"`
	// Services (phase 2) the device exposes; only delivered to CapServices
	// agents. AllowedPorts stays [22] for phase-1 agents.
	Services []ServiceSpec `json:"services,omitempty"`
	// P2P is false when the device opted out (AnnotationP2P=disabled).
	P2P bool `json:"p2p"`
	// ActivationMode is "automatic" or "manual". ForceManualGeneration >= the
	// current generation forces manual activation (set when a compromised or
	// health flag was cleared, until an admin re-enables automatic).
	ActivationMode        string `json:"activationMode,omitempty"`
	ForceManualGeneration int64  `json:"forceManualGeneration,omitempty"`
	// TrustedHostKey is the SHA256 fingerprint ("SHA256:<b64>") of the key whose
	// attestation activates an identity automatically. Since rev 3 it is the
	// device's WireGuard device key (AnnotationDeviceKey, set by device-controller
	// from the trusted bootstrap or an MQTT delivery, never by a person); the
	// wire name is kept for compatibility. DuplicateHostKey is set when the same
	// key is trusted for more than one device in the teamspace (cloned image):
	// then automatic activation is refused. TrustedKeySource is a
	// DeviceKeySource* value, TrustedKeySetAt when device-controller set the key.
	TrustedHostKey   string    `json:"trustedHostKey,omitempty"`
	DuplicateHostKey bool      `json:"duplicateHostKey,omitempty"`
	TrustedKeySource string    `json:"trustedKeySource,omitempty"`
	TrustedKeySetAt  time.Time `json:"trustedKeySetAt,omitempty"`
	// RSAPublicCert (PEM) verifies ENROLLMENT JWTs only.
	RSAPublicCert string `json:"rsaPublicCert"`
	AllowedPorts  []int  `json:"allowedPorts"`
	// EnrollmentGeneration increases on every enrollment reset (and whenever a
	// compromised/health flag is cleared). A pinned identity with a lower
	// generation is void: the agent must create a NEW identity and enroll.
	EnrollmentGeneration int64 `json:"enrollmentGeneration"`
	// EnrollmentEpoch is a random value the controller generates every time it
	// opens an enrollment window (new generation, re-enable, device recreate).
	// It never repeats, so a pin is valid only if its epoch AND generation equal
	// the policy's exactly.
	EnrollmentEpoch string `json:"enrollmentEpoch"`
	// EnrollUntil closes the TOFU window for this generation.
	EnrollUntil time.Time `json:"enrollUntil"`
	// ApprovedFingerprint is the identity fingerprint an admin approved in the
	// UI (annotation AnnotationApprovedIdentity). A pinned identity is usable
	// for sessions only when its fingerprint equals this value; until then the
	// hub answers ReasonPendingApproval. This closes the TOFU race against
	// holders of the (widely exposed) legacy RSA key.
	ApprovedFingerprint string    `json:"approvedFingerprint,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

// IdentityEntry is the JSON value stored under IdentityDataKey.
type IdentityEntry struct {
	Device               string    `json:"device"`
	Namespace            string    `json:"namespace"`
	IdentityPublicKey    string    `json:"identityPublicKey"` // base64 raw Ed25519
	Fingerprint          string    `json:"fingerprint"`
	EnrollmentGeneration int64     `json:"enrollmentGeneration"`
	EnrollmentEpoch      string    `json:"enrollmentEpoch"`
	EnrolledAt           time.Time `json:"enrolledAt"`
	// Voided is set by the hub when it observes a compromised/health-check
	// flag for the device: a voided pin is never accepted again (sticky
	// revocation that does not depend on device-controller).
	Voided       bool      `json:"voided,omitempty"`
	VoidedReason string    `json:"voidedReason,omitempty"`
	VoidedAt     time.Time `json:"voidedAt,omitempty"`
	// VoidedFingerprints is the bounded history (newest last, max
	// MaxVoidedFingerprints) of every identity ever voided for this device. It
	// is carried over whenever a pin is replaced, and the hub refuses to pin
	// any listed fingerprint again, in any epoch.
	VoidedFingerprints []string `json:"voidedFingerprints,omitempty"`
	// DistrustedKeys is the bounded list (newest last, max MaxDistrustedKeys)
	// of attestation keys ("SHA256:<b64>") that signed a pin voided because the
	// device was flagged compromised or failed its health check. Whoever caused
	// the flag may hold such a key, so the hub refuses every enrollment that
	// carries an attestation by one (attest_required) while the policy trusts a
	// listed key. It is carried over whenever a pin is replaced or displaced and
	// never cleared: a key on it is not trusted for this device again.
	DistrustedKeys []string `json:"distrustedKeys,omitempty"`
	// Attestation (CapAttest): the key that signed this identity's
	// AttestStatement ("SHA256:<b64>", key type), and the agent's capabilities.
	// Since rev 3 the signing key is the device key (CapDeviceKey); older agents
	// signed with the SSH host key. The wire names are kept.
	AttestedHostKey     string   `json:"attestedHostKey,omitempty"`
	AttestedHostKeyType string   `json:"attestedHostKeyType,omitempty"`
	AgentCapabilities   []string `json:"agentCapabilities,omitempty"`
	// ActivatedBy is an ActivatedBy* value once usable.
	ActivatedBy string    `json:"activatedBy,omitempty"`
	ActivatedAt time.Time `json:"activatedAt,omitempty"`
	// Replacements counts pins replaced without an admin because a new
	// identity attested by the trusted device key arrived while the device was
	// offline (re-image, lost state). The replaced fingerprint is voided.
	Replacements            int       `json:"replacements,omitempty"`
	LastReplacedAt          time.Time `json:"lastReplacedAt,omitempty"`
	LastReplacedFingerprint string    `json:"lastReplacedFingerprint,omitempty"`
	// Conflicts counts rejected enrollments with a DIFFERENT key for this
	// generation (possible key theft); surfaced in the UI.
	Conflicts      int       `json:"conflicts,omitempty"`
	LastConflictAt time.Time `json:"lastConflictAt,omitempty"`
}

// PolicyConfigMapName returns the policy ConfigMap name for a device.
func PolicyConfigMapName(teamspace, device string) string {
	return PolicyConfigMapPrefix + teamspace + "." + device
}

// IdentityConfigMapName returns the identity ConfigMap name for a device.
func IdentityConfigMapName(teamspace, device string) string {
	return IdentityConfigMapPrefix + teamspace + "." + device
}

// Deployment constants shared by the hub, device-controller and the charts.
const (
	HubNamespace   = "teknoir-ztna"
	HubServiceName = "wg-hub" // headless; HubEndpoint is the hub pod IP
	HubHTTPPort    = 8080     // outside-tunnel API reachable via ingress (users, devices)
	// HubInternalPort is NOT routed by any VirtualService: SA delegation
	// (OnBehalfOf) and Direct sessions are accepted only here, from pods in
	// HubNamespace (AuthorizationPolicy).
	HubInternalPort = 8081
	HubWGPort       = 51820 // WireGuard UDP; the only STUNner backend port
	// UserHostPrefix: https://wg.<domain> (443, oauth2-proxy lets teknoir-cli bearer tokens through).
	UserHostPrefix = "wg"
	// DeviceHostPrefix: https://wg-device.<domain>:8084 (public gateway, no edge auth; hub authenticates).
	DeviceHostPrefix = "wg-device"
	DevicePort       = 8084
	// TURNHostPrefix: turn:turn.<domain>:3478?transport=udp
	TURNHostPrefix = "turn"
	TURNPort       = 3478

	// Keycloak tokens are accepted only when azp is one of these clients:
	// browser tokens (azp "teknoir") are forwarded to every upstream behind
	// oauth2-proxy and must never be accepted.
	KeycloakAllowedAZP = "teknoir-cli"

	// Delegating service accounts (the per-device WG web terminal) live in
	// HubNamespace and carry these annotations; the hub verifies the SA token
	// with a TokenReview for SATokenAudience and binds it to exactly this device.
	SATokenAudience       = "teknoir-ztna"
	SAAnnotationNamespace = "ztna.teknoir.org/namespace"
	SAAnnotationDevice    = "ztna.teknoir.org/device"
)

// ---------------------------------------------------------------------------
// Phase 2 (plans/ztna-phase2.md): services, hub->agent control, peer-to-peer,
// host-key attestation, live status.
// ---------------------------------------------------------------------------

// Agent capabilities, advertised in DeviceSessionRequest.Capabilities. The hub
// uses a phase-2 feature with an agent only if the agent advertises it; phase-1
// agents get exactly the phase-1 behaviour (ssh on port 22 only).
const (
	CapServices = "services-v1" // connect listener on AgentConnectPort with ConnectRequest preamble
	CapControl  = "control-v1"  // control listener on AgentControlPort (hub -> agent RPC)
	CapAttest   = "attest-v1"   // attestation at enrollment (AttestStatement over SSHSIG)
	// CapDeviceKey: the agent holds a device key (bootstrap file or MQTT
	// envelope) and signs AttestStatement with it in-process. Implies CapAttest.
	CapDeviceKey = "device-key-v1"
	CapP2P       = "p2p-v1" // direct end-to-end WireGuard (plane B)
)

// Overlay ports on the agent (plane A, reachable only from the hub: the
// agent's only A peer is the hub).
const (
	AgentConnectPort = 2224 // ConnectRequest line, then raw bytes to the service target
	AgentControlPort = 2225 // HTTP: ControlGrantsPath, ControlServicesPath, ControlRevokePath
	// HubStatusPort serves read-only live status and admin actions to the
	// Backstage backend only: Bearer = a projected ServiceAccount token with
	// audience StatusTokenAudience, verified with a TokenReview for that
	// audience; the username must equal the configured Backstage
	// ServiceAccount; separate AuthorizationPolicy. Never routed.
	HubStatusPort = 8082
)

// Device annotations added in phase 2. All ztna.teknoir.org/* annotations are
// writable only by the Backstage backend (after its admin checks) and
// device-controller (ValidatingAdmissionPolicy on devices.teknoir.org).
const (
	AnnotationServices   = "ztna.teknoir.org/services"   // JSON []ServiceSpec (admin)
	AnnotationP2P        = "ztna.teknoir.org/p2p"        // "disabled" | absent = enabled
	AnnotationActivation = "ztna.teknoir.org/activation" // "manual" | absent = automatic (admin)
	// Deprecated (rev 3): an admin-trusted SSH host key. device-controller
	// ignores it; activation is anchored on AnnotationDeviceKey.
	AnnotationTrustedHostKey = "ztna.teknoir.org/trusted-host-key"
)

// Device key (rev 3, zero-touch activation). The device key is a per-device
// Ed25519 key that only the trusted bootstrap or device-controller creates.
// Its fingerprint is the activation anchor (PolicyEntry.TrustedHostKey): an
// identity whose AttestStatement is signed by it activates with no admin step.
//
// Delivery paths, strongest first:
//   - bootstrap: the bootstrap script writes DeviceKeyFile (source "bootstrap",
//     or "vdevice" for virtual-device cloud-init);
//   - mqtt: device-controller generates a key, seals it to the device's
//     bootstrap RSA key (DeviceKeyEnvelope) and ships it in the device's MQTT
//     config as the ConfigMap DeviceKeyConfigMap; the agent opens it with
//     /etc/teknoir/rsa_private.pem and keeps it as DeliveredDeviceKeyFile. The
//     ConfigMap is removed from the config once the hub shows an attestation
//     by that key. The private key is stored nowhere in the cloud.
//
// Device annotations (written only by device-controller, except
// AnnotationRotateDeviceKey, which an admin sets through Backstage).
const (
	AnnotationDeviceKey       = "ztna.teknoir.org/device-key"        // "SHA256:<b64>" of the device key
	AnnotationDeviceKeySource = "ztna.teknoir.org/device-key-source" // DeviceKeySource*
	AnnotationDeviceKeySetAt  = "ztna.teknoir.org/device-key-set-at" // RFC3339, when device-controller set it
	AnnotationRotateDeviceKey = "ztna.teknoir.org/rotate-device-key" // RFC3339 request time (admin); newer than set-at => new MQTT key

	DeviceKeySourceBootstrap = "bootstrap"
	DeviceKeySourceVirtual   = "vdevice"
	DeviceKeySourceMQTT      = "mqtt"

	// DeviceKeyFile is the bootstrap-installed device key: OpenSSH Ed25519
	// private key, mode 0440, owner 65532:root (next to rsa_private.pem).
	DeviceKeyFile = "/etc/teknoir/ztna_device_key"
	// DeviceKeyConfigMap (namespace default on the device) carries the sealed
	// envelope under DeviceKeyEnvelopeKey; the agent mounts it (optional) at
	// DeviceKeyMountDir.
	DeviceKeyConfigMap   = "wg-agent-device-key"
	DeviceKeyEnvelopeKey = "envelope.json"
	DeviceKeyMountDir    = "/run/ztna-device-key"
	// DeliveredDeviceKeyFile is where the agent keeps an opened envelope key,
	// inside its identity state directory, mode 0600, OpenSSH format.
	DeliveredDeviceKeyFile = "device_key"

	DeviceKeyEnvelopeVersion = 1
	DeviceKeyLabelTag        = "teknoir-ztna-device-key-v1"
)

// DeviceKeyEnvelope is a device key sealed to the device's bootstrap RSA key.
// Ciphertext is base64 RSA-OAEP-SHA256 over the 32-byte Ed25519 seed with the
// label DeviceKeyLabel(Namespace, Device, Serial). Fingerprint is the device
// key's "SHA256:<b64>"; the opener must check it against the opened key.
type DeviceKeyEnvelope struct {
	V           int    `json:"v"`
	Namespace   string `json:"namespace"`
	Device      string `json:"device"`
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	Ciphertext  string `json:"ciphertext"`
}

// DeviceKeyLabel is the OAEP label that binds an envelope to one device and
// one delivery.
func DeviceKeyLabel(namespace, device, serial string) []byte {
	return []byte(fmt.Sprintf("%s\n%s/%s\n%s", DeviceKeyLabelTag, namespace, device, serial))
}

// Service kinds.
const (
	ServiceKindSSH      = "ssh"      // 127.0.0.1:22, implicit, always present
	ServiceKindExternal = "external" // IP:port on the device's networks
	ServiceKindInternal = "internal" // k3s Service <name>.<namespace>:port on the device
	ServiceSSHID        = "ssh"
	ProtocolTCP         = "tcp"
	ProtocolHTTP        = "http"
	MaxServices         = 32
)

// ServiceSpec is one reachable service on a device. ID is a DNS label (<=20).
// Target: for external an IP literal (no DNS); for internal "<svc>.<namespace>"
// (resolved by the agent to an A record inside the service CIDR only; CNAMEs and
// ExternalName refused; namespaces kube-system and default/kubernetes refused).
// Validated by device-controller and re-validated by the agent on every dial.
type ServiceSpec struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Target      string `json:"target,omitempty"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol"`
	Web         bool   `json:"web,omitempty"` // published as a browser URL (http only)
	Description string `json:"description,omitempty"`
}

// ConnectRequest is the single JSON line a dialer writes to the agent's
// connect listener (plane A from the hub, plane B from a granted client).
// As is the end user on whose behalf a delegating in-cluster client (web
// gateway) connects; the hub sets it, the agent only logs it.
type ConnectRequest struct {
	Service string `json:"service"`
	As      string `json:"as,omitempty"`
}

// ConnectResponse is the single JSON line the agent answers before relaying
// bytes (OK) or closing (Reason set).
type ConnectResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Control RPC paths on http://<device overlay IP>:AgentControlPort.
const (
	ControlGrantsPath   = "/v1/control/grants"   // POST GrantSet -> GrantAck
	ControlServicesPath = "/v1/control/services" // POST ServicesUpdate -> 204
	ControlRevokePath   = "/v1/control/revoke"   // POST RevokeNotice -> 204 (409: not the current session)
)

// RevokeNotice is the hub telling a device agent, over plane A, that it is
// about to end the named device session. It is sent best effort and BEFORE the
// hub removes the device's WireGuard peer, so the agent can act at once instead
// of finding out when a renewal fails and the tunnel is declared dead. The
// agent ends the named session with Reason (an api.Reason* code: reenroll
// rotates the identity and enrolls again without a back-off, the others take
// the agent's normal denial path). Only for agents that advertised CapControl.
// A notice for any other session is answered 409 and ignored. The hub's ending
// of the session does not depend on the notice being delivered.
type RevokeNotice struct {
	Reason    string `json:"reason"`
	SessionID string `json:"sessionId"`
	Detail    string `json:"detail,omitempty"`
}

// Grant authorizes one client's plane-B peer on the device. TTL is relative:
// the agent expires it on its monotonic clock from receipt (device clocks are
// not trusted). Services lists service IDs the pair may reach.
type Grant struct {
	PairID            string   `json:"pairId"`
	ClientWGPublicKey string   `json:"clientWgPublicKey"`
	ClientAddress     string   `json:"clientAddress"` // plane-B /32
	ClientCandidates  []string `json:"clientCandidates,omitempty"`
	Services          []string `json:"services"`
	TTLSeconds        int      `json:"ttlSeconds"`
}

// GrantSet is the full desired grant list (not a delta). The agent applies it
// only if (HubInstance, Seq) is newer than the last applied set; a changed
// HubInstance drops all pairs first. Removed PairIDs are tombstoned by the agent
// and never re-added.
type GrantSet struct {
	HubInstance string  `json:"hubInstance"`
	Seq         uint64  `json:"seq"`
	Grants      []Grant `json:"grants"`
}

// GrantAck returns the device's plane-B parameters for the pairs it accepted.
type GrantAck struct {
	DeviceWGPublicKey string   `json:"deviceWgPublicKey"`
	DeviceAddress     string   `json:"deviceAddress"` // plane-B /32
	DeviceCandidates  []string `json:"deviceCandidates"`
	Accepted          []string `json:"accepted"` // pair IDs
}

// ServicesUpdate pushes the device's current services (policy changed).
type ServicesUpdate struct {
	Services []ServiceSpec `json:"services"`
}

// P2P plane B addressing (separate from plane A).
const (
	P2PPrefix         = "100.97.0.0/16"
	P2PMTU            = 1280
	MaxP2PCandidates  = 8
	DefaultGrantTTL   = 90 // seconds
	P2PDialRaceMillis = 2500
)

// P2POffer is sent by a client that can do plane B.
type P2POffer struct {
	WGPublicKey string   `json:"wgPublicKey"`
	Candidates  []string `json:"candidates"` // "ip:port", host + server-reflexive, <= MaxP2PCandidates
}

// P2PGrant is returned to the client when the device accepted the pair.
type P2PGrant struct {
	PairID            string   `json:"pairId"`
	ClientAddress     string   `json:"clientAddress"`
	DeviceAddress     string   `json:"deviceAddress"`
	DeviceWGPublicKey string   `json:"deviceWgPublicKey"`
	DeviceCandidates  []string `json:"deviceCandidates"`
	TTLSeconds        int      `json:"ttlSeconds"`
}

// Attestation (CapAttest). The agent fetches a single-use nonce and signs the
// statement (SSHSIG, namespace AttestNamespace) with its device key
// (CapDeviceKey, in-process). Pre-rev-3 agents had an attestor sidecar sign
// with the SSH host key; the hub verifies both the same way.
const (
	AttestChallengePath = "/v1/device/attest-challenge" // POST, Bearer enroll JWT -> AttestChallenge
	AttestNamespace     = "teknoir-ztna-attest-v1@teknoir.ai"
	AttestStatementTag  = "teknoir-ztna-attest-v1"
)

// AttestChallenge binds an attestation to this enrollment window.
type AttestChallenge struct {
	Nonce                string    `json:"nonce"`
	EnrollmentEpoch      string    `json:"enrollmentEpoch"`
	EnrollmentGeneration int64     `json:"enrollmentGeneration"`
	ExpiresAt            time.Time `json:"expiresAt"`
}

// AttestStatement returns the exact bytes the host key signs.
func AttestStatement(namespace, device, identityFingerprint, epoch string, generation int64, nonce string) []byte {
	return []byte(fmt.Sprintf("%s\n%s/%s\n%s\n%s\n%d\n%s", AttestStatementTag, namespace, device, identityFingerprint, epoch, generation, nonce))
}

// HostKeyAttestation is one SSHSIG signature (base64 of the binary SSHSIG blob,
// which embeds the public key) over AttestStatement.
type HostKeyAttestation struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// Activation sources recorded on the identity entry.
const (
	ActivatedByApproval  = "approval"   // admin approved the identity fingerprint
	ActivatedByDeviceKey = "device-key" // attested by the trusted device key (zero-touch)
	// Deprecated: entries activated before rev 3 by an admin-trusted SSH host key.
	ActivatedByHostKey = "host-key"
)

// Live status (HubStatusPort, Backstage backend only).
const (
	StatusDevicePath    = "/v1/status/devices/" // GET /v1/status/devices/<ns>/<device> -> DeviceLiveStatus
	AdminEndSessionPath = "/v1/admin/sessions/" // POST /v1/admin/sessions/<id>/end
	PathDirectLAN       = "direct-lan"
	PathDirect          = "direct"
	PathHub             = "hub"
)

// DeviceLiveStatus is the hub's live view of one device.
type DeviceLiveStatus struct {
	Connected       bool                `json:"connected"`
	ConnectedSince  time.Time           `json:"connectedSince,omitempty"`
	LastHandshake   time.Time           `json:"lastHandshake,omitempty"`
	Transport       string              `json:"transport,omitempty"` // "turn" | "direct-udp"
	AgentVersion    string              `json:"agentVersion,omitempty"`
	Capabilities    []string            `json:"capabilities,omitempty"`
	NAT             string              `json:"nat,omitempty"` // "easy" | "hard" | "unknown"
	Sessions        []ClientSessionInfo `json:"sessions"`
	IdentityPending bool                `json:"identityPending"`
	// Identity is the hub-owned identity pin (never the Device CR status,
	// which device editors can write). Admin actions (trust host key, approve
	// identity) must compare against these values.
	Identity *LiveIdentity `json:"identity,omitempty"`
}

// LiveIdentity is the current pin as the hub stores it.
type LiveIdentity struct {
	Fingerprint          string    `json:"fingerprint"`
	AttestedHostKey      string    `json:"attestedHostKey,omitempty"`
	AttestedHostKeyType  string    `json:"attestedHostKeyType,omitempty"`
	EnrollmentGeneration int64     `json:"enrollmentGeneration"`
	EnrollmentEpoch      string    `json:"enrollmentEpoch"`
	EnrolledAt           time.Time `json:"enrolledAt"`
	ActivatedBy          string    `json:"activatedBy,omitempty"`
	ActivatedAt          time.Time `json:"activatedAt,omitempty"`
	Voided               bool      `json:"voided,omitempty"`
	Conflicts            int       `json:"conflicts,omitempty"`
	Replacements         int       `json:"replacements,omitempty"`
	LastReplacedAt       time.Time `json:"lastReplacedAt,omitempty"`
	// Current is true when the pin is of the policy's current enrollment epoch
	// AND generation, i.e. the pin the activation rule evaluates (it can still
	// be voided or pending). A pin that is not current belongs to an older
	// enrollment and must be replaced by a new enrollment.
	Current bool `json:"current"`
	// AgentCapabilities are the capabilities the enrolling agent advertised
	// (IdentityEntry.AgentCapabilities).
	AgentCapabilities []string `json:"agentCapabilities,omitempty"`
}

// StatusTokenAudience is the audience of the projected ServiceAccount token
// the Backstage backend presents on HubStatusPort. The hub's TokenReview
// requires exactly this audience, so the hub never receives a token the API
// server would accept on Backstage's behalf.
const StatusTokenAudience = "teknoir-ztna-status"

// StatusRequesterHeader carries the end user (email) behind a Backstage admin
// action on HubStatusPort, for the hub's audit log.
const StatusRequesterHeader = "X-Ztna-Requester"

// ClientSessionInfo is one client session as shown in the console. Subject is
// redacted by the Backstage backend for non-admin viewers.
type ClientSessionInfo struct {
	ID       string    `json:"id"`
	Subject  string    `json:"subject"`
	Service  string    `json:"service"`
	Software string    `json:"software"` // tnctl | web-terminal | web-gateway
	Path     string    `json:"path"`     // PathDirectLAN | PathDirect | PathHub
	Since    time.Time `json:"since"`
	BytesIn  int64     `json:"bytesIn"`
	BytesOut int64     `json:"bytesOut"`
}
