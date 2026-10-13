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
	WGPublicKey string  `json:"wgPublicKey"`
	Posture     Posture `json:"posture"`
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
}

// RenewResponse extends the session. TURN is set only when the hub rotated the
// TURN credentials; the client must then move to a new relay allocation.
type RenewResponse struct {
	ExpiresAt         time.Time        `json:"expiresAt"`
	RenewAfterSeconds int              `json:"renewAfterSeconds"`
	TURN              *TURNCredentials `json:"turn,omitempty"`
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
