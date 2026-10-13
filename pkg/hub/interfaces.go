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

// DeviceFlags serves the operator switches on the Device objects (metadata
// only: annotations).
type DeviceFlags interface {
	// Annotations returns the relevant annotations of the Device and whether
	// the Device exists.
	Annotations(ns, device string) (map[string]string, bool)
	// Subscribe registers fn, called after a relevant change; fn must not block.
	Subscribe(fn func(ns, device string))
	HasSynced() bool
}

// IdentityStore persists the TOFU identity pins.
type IdentityStore interface {
	// Get returns the pin of a device, if any.
	Get(ctx context.Context, ns, device string) (api.IdentityEntry, bool, error)
	// Pin stores entry unless a pin for the same or a newer enrollment
	// generation exists. It returns the entry that is in effect afterwards
	// and whether entry was written (created == true). A pin with a lower
	// generation is void and is replaced.
	Pin(ctx context.Context, entry api.IdentityEntry) (current api.IdentityEntry, created bool, err error)
	// RecordConflict counts a rejected enrollment with a different key.
	RecordConflict(ctx context.Context, ns, device string, at time.Time) error
}

// UserIdentity is an authenticated end user.
type UserIdentity struct {
	// Email is lowercase and verified.
	Email string
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
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
// a syntactically valid lowercase email.
type SADelegation interface {
	Verify(ctx context.Context, token, ns, device, onBehalfOf string) (SAIdentity, error)
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
	TURN     TURNMinter
	// Tunnel is optional; New creates the wireguard-go tunnel when nil.
	Tunnel Tunnel
}
