// Package p2p is plane B of the ZTNA tunnel: an end-to-end WireGuard session
// between a client and a device, established by hole punching, next to the
// hub-relayed plane A (see plans/ztna-phase2.md, "P2P-lite").
//
// Each side runs a separate wireguard-go device on a gVisor netstack over ONE
// plain UDP socket (Socket). A small demultiplexer in front of the WireGuard
// bind splits the datagrams of that socket into
//
//   - STUN Binding responses (RFC 5389: first two bits 00, magic cookie at
//     bytes 4..8, consistent length), used to learn the server-reflexive
//     address;
//   - punch probes (see probe.go), used to find an address pair that works;
//   - everything else, which is WireGuard.
//
// Endpoints are raw ip:port pairs: WireGuard's own roaming locks in whatever
// address an authenticated packet arrives from. There are no virtual
// endpoints, no multipath bind and no relay on this plane; the hub-spliced
// plane A stays the fallback.
//
// # Why probes and not just endpoint cycling
//
// wireguard-go sends at most one handshake initiation per peer every
// RekeyTimeout (5 s), and an endpoint change does not reset that. Cycling the
// peer endpoint through the candidates and nudging the keepalive would try one
// candidate per 5 s. The Puncher therefore sends tiny authenticated probes to
// ALL candidates at once, every 150 ms, which opens the NAT mappings in both
// directions and tells each side which address works; only then is the WireGuard
// peer pointed at that address and nudged (its first initiation of the pair,
// so it is not rate limited). A probe is advisory: the endpoint is trusted only
// once a WireGuard handshake completes, exactly as before.
package p2p
