// Package hub implements the wg-hub: the session broker and WireGuard gateway
// of the ZTNA tunnel.
//
// The hub terminates every WireGuard tunnel on a gVisor netstack in its own
// process (no TUN device, no NET_ADMIN). Devices and clients are peers of the
// hub only; clients never get an L3 path to devices. The hub accepts a client's
// TCP connection on its overlay address, re-authorizes it, dials the device
// session's overlay address and splices the two streams.
//
// The hub is built around small interfaces (PolicySource, DeviceFlags,
// IdentityStore, UserAuthenticator, SADelegation, Authorizer, TURNMinter and
// Tunnel) so that all decision logic is unit-testable without Kubernetes.
// The k8s_*.go files hold the client-go implementations.
//
// Nothing in this package logs bearer tokens, TURN passwords, Authorization
// headers or request bodies.
package hub
