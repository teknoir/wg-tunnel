package hub

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Sentinel errors returned by the authenticators. The HTTP layer maps them to
// status codes: ErrUnauthenticated 401, ErrForbidden 403, ErrUnavailable 503.
// Any other error from an authenticator is treated as ErrUnauthenticated.
var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
	// ErrUnavailable marks an infrastructure failure (API server, JWKS endpoint
	// unreachable). The hub fails closed but does not tear down live sessions
	// because of it.
	ErrUnavailable = errors.New("backend unavailable")
)

// PolicySource serves the access policy written by device-controller.
type PolicySource interface {
	// Get returns the policy entry of a device.
	Get(ns, device string) (api.PolicyEntry, bool)
	// Subscribe registers fn, called after the entry of (ns, device) was
	// added, changed or removed. fn must not block.
	Subscribe(fn func(ns, device string))
	// HasSynced reports whether the initial listing is complete.
	HasSynced() bool
}

// DeviceFlags serves the operator switches (wireguard, compromised, health)
// that the flags watcher mirrors from the Device annotations into the flags
// store. The hub never reads Device objects itself.
type DeviceFlags interface {
	// Flags returns the mirrored switches of a device. ok is false when the
	// flags store has no entry; the hub then treats the device as NOT enabled
	// (fail closed), exactly like an entry with Exists == false.
	Flags(ns, device string) (e api.FlagsEntry, ok bool)
	// Subscribe registers fn, called after a relevant change; fn must not block.
	Subscribe(fn func(ns, device string))
	HasSynced() bool
}

// IdentityStore persists the TOFU identity pins.
type IdentityStore interface {
	// Get returns the pin of a device, if any.
	Get(ctx context.Context, ns, device string) (api.IdentityEntry, bool, error)
	// Pin stores entry unless a pin for the SAME enrollment epoch and
	// generation exists (first wins per epoch, voided or not). It returns the
	// entry that is in effect afterwards and whether entry was written
	// (created == true). A pin of any other epoch or generation is void and is
	// replaced.
	Pin(ctx context.Context, entry api.IdentityEntry) (current api.IdentityEntry, created bool, err error)
	// RecordConflict counts a rejected enrollment with a different key.
	RecordConflict(ctx context.Context, ns, device string, at time.Time) error
	// Void marks the pin of a device void for good (sticky revocation): it is
	// never accepted again, whatever the policy says. It is a no-op (false)
	// when nothing is pinned or the pin is already void.
	Void(ctx context.Context, ns, device, reason string, at time.Time) (changed bool, err error)
	// Update atomically applies fn to the stored entry of a device (optimistic
	// concurrency; fn may run more than once). fn returns the entry to store,
	// or nil to leave the entry as it is. current is the entry in effect
	// afterwards; found is false (and fn is not called) when nothing is
	// pinned; wrote reports whether fn's result was stored. The hub uses it
	// for attestation records, activation and pin displacement.
	Update(ctx context.Context, ns, device string, fn func(cur api.IdentityEntry) *api.IdentityEntry) (current api.IdentityEntry, found, wrote bool, err error)
}

// UserIdentity is an authenticated end user.
type UserIdentity struct {
	// Email is lowercase and verified.
	Email string
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
	// TokenID (jti) and IssuedAt (iat) identify the token; renewals must
	// present a different, not older token than the previously accepted one.
	TokenID  string
	IssuedAt time.Time
	// LegacyAudience is true when the token lacks the hub audience and was
	// accepted anyway (audience mode "transition").
	LegacyAudience bool
}

// UserAuthenticator verifies Keycloak access tokens.
type UserAuthenticator interface {
	Authenticate(ctx context.Context, token string) (UserIdentity, error)
}

// SAIdentity is an authenticated, device-bound delegating service account.
type SAIdentity struct {
	// Name of the service account in the hub namespace.
	Name string
}

// SADelegation verifies a delegating service account token (the per-device WG
// web terminal): the token is valid for api.SATokenAudience, the SA lives in
// the hub namespace, is annotated for exactly (ns, device), and onBehalfOf is
// empty (a gateway session: its users are named per connection) or a
// syntactically valid lowercase email.
type SADelegation interface {
	Verify(ctx context.Context, token, ns, device, onBehalfOf string) (SAIdentity, error)
}

// DelegateVerifier is implemented by an SADelegation that also accepts the web
// gateway: the same token and device-binding checks, without an asserted user
// (each spliced connection names and is authorized for its own user).
type DelegateVerifier interface {
	VerifyDelegate(ctx context.Context, token, ns, device string) (SAIdentity, error)
}

// Authorizer answers whether a user may open an exec-class session in a
// teamspace (SubjectAccessReview create pods/exec).
type Authorizer interface {
	CanExec(ctx context.Context, email, ns string) (bool, error)
}

// TURNMinter mints TURN-REST credentials for a session.
type TURNMinter interface {
	Mint(ns, sessionID string) (*api.TURNCredentials, error)
}

// Tunnel is the WireGuard data plane: wireguard-go on a netstack. The hub
// never dials out through the underlay; it only dials overlay addresses.
type Tunnel interface {
	PublicKey() wgkey.PublicKey
	// ListenPort is the UDP port the WireGuard socket listens on.
	ListenPort() int
	// AddPeer installs a peer whose only allowed address is ip/32.
	AddPeer(pub wgkey.PublicKey, ip netip.Addr) error
	// RemovePeer removes the peer synchronously.
	RemovePeer(pub wgkey.PublicKey) error
	// Listen listens on the overlay (netstack).
	Listen(addr netip.AddrPort) (net.Listener, error)
	// DialContext dials an overlay address.
	DialContext(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// Up reports whether the device is running.
	Up() bool
	Close() error
}

// Deps are the collaborators of a Hub.
type Deps struct {
	Policy   PolicySource
	Flags    DeviceFlags
	Identity IdentityStore
	Users    UserAuthenticator
	SA       SADelegation
	Authz    Authorizer
	// Org serves the per-teamspace org documents of the org gate. Required
	// unless Config.OrgGateMode is "off".
	Org  OrgSource
	TURN TURNMinter
	// Status verifies the Backstage service account token of the status
	// listener (optional: without it StatusHandler refuses everything).
	Status StatusAuthenticator
	// Tunnel is optional; New creates the wireguard-go tunnel when nil.
	Tunnel Tunnel
}
