package p2p

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

var (
	overlayPrefix = netip.MustParsePrefix(api.OverlayPrefix)
	p2pPrefix     = netip.MustParsePrefix(api.P2PPrefix)
)

// AddrFor maps a plane-A overlay address (api.OverlayPrefix) to the plane-B
// address of the same session (api.P2PPrefix): the host part is kept, the
// network part is replaced. The hub allocates plane-A addresses with its IPAM
// and quarantine, so plane-B addresses are unique and quarantined the same way
// without a second allocator. The contract carries no plane-B address in the
// session response, so hub and agent agree on this derivation instead.
func AddrFor(a netip.Addr) (netip.Addr, error) {
	a = a.Unmap()
	if !a.Is4() || !overlayPrefix.Contains(a) {
		return netip.Addr{}, fmt.Errorf("p2p: %s is not in the overlay network %s", a, api.OverlayPrefix)
	}
	b := a.As4()
	base := p2pPrefix.Addr().As4()
	// Both prefixes are /16: keep the last two octets.
	return netip.AddrFrom4([4]byte{base[0], base[1], b[2], b[3]}), nil
}

// ValidPlaneBAddr reports whether a is a usable plane-B address.
func ValidPlaneBAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && p2pPrefix.Contains(a)
}

// ParseCandidate parses "ip:port" and rejects addresses that are never a
// valid peer: unspecified, multicast, broadcast, port 0. Loopback and private
// addresses are valid (same-host and LAN candidates).
func ParseCandidate(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("p2p: candidate %q is not ip:port", s)
	}
	a := ap.Addr().Unmap()
	switch {
	case ap.Port() == 0:
		return netip.AddrPort{}, errors.New("p2p: candidate port is 0")
	case a.IsUnspecified(), a.IsMulticast(), a.IsInterfaceLocalMulticast(), a.IsLinkLocalMulticast():
		return netip.AddrPort{}, fmt.Errorf("p2p: candidate %s is unspecified or multicast", s)
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.AddrPort{}, errors.New("p2p: candidate is the broadcast address")
	case a.Zone() != "":
		return netip.AddrPort{}, errors.New("p2p: candidate has a zone")
	}
	return netip.AddrPortFrom(a, ap.Port()), nil
}

// ParseCandidates validates a candidate list: at most api.MaxP2PCandidates,
// each valid, duplicates removed. A nil list is valid and empty.
func ParseCandidates(in []string) ([]netip.AddrPort, error) {
	if len(in) > api.MaxP2PCandidates {
		return nil, fmt.Errorf("p2p: %d candidates (maximum %d)", len(in), api.MaxP2PCandidates)
	}
	out := make([]netip.AddrPort, 0, len(in))
	seen := map[netip.AddrPort]struct{}{}
	for _, s := range in {
		ap, err := ParseCandidate(s)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[ap]; dup {
			continue
		}
		seen[ap] = struct{}{}
		out = append(out, ap)
	}
	return out, nil
}

// ProbeTargets drops the candidates a peer may not make this side send to,
// whoever vouched for them: a candidate comes from the other end of the pair
// (a client, in the device's case), and a probe is a UDP datagram sent to it.
// Loopback, link-local and unspecified addresses are never a remote peer's
// address (they would point the probe at this very host or its metadata
// services), so they are dropped unless allowLoopback is set (tests that run
// both ends on one machine). Private LAN addresses stay: they are what makes a
// same-LAN direct path possible.
func ProbeTargets(in []netip.AddrPort, allowLoopback bool) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		a := ap.Addr().Unmap()
		switch {
		case a.IsUnspecified(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
			continue
		case a.IsLoopback() && !allowLoopback:
			continue
		}
		out = append(out, ap)
	}
	return out
}

// Strings renders candidates as "ip:port".
func Strings(in []netip.AddrPort) []string {
	out := make([]string, 0, len(in))
	for _, ap := range in {
		out = append(out, ap.String())
	}
	return out
}

// PathOf classifies the established endpoint: PathDirectLAN for private,
// unique-local, loopback and link-local addresses, PathDirect otherwise.
func PathOf(ep netip.AddrPort) string {
	a := ep.Addr().Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return api.PathDirectLAN
	}
	return api.PathDirect
}

// STUNServer picks the STUN server for a session: the override if set, else
// the host of the first usable TURN URL (STUNner answers Binding requests on
// the TURN port). The result is "host:port"; the host may be a name.
func STUNServer(turnURLs []string, override string) (string, error) {
	if override != "" {
		return withPort(override)
	}
	for _, raw := range turnURLs {
		rest, ok := strings.CutPrefix(raw, "turn:")
		if !ok {
			continue
		}
		rest = strings.TrimPrefix(rest, "//")
		rest, query, _ := strings.Cut(rest, "?")
		if query != "" {
			if q, err := url.ParseQuery(query); err == nil {
				if tr := q.Get("transport"); tr != "" && tr != "udp" {
					continue
				}
			}
		}
		if hp, err := withPort(rest); err == nil {
			return hp, nil
		}
	}
	return "", errors.New("p2p: no usable STUN/TURN server")
}

// STUNServerFromHub derives the STUN server of a hub URL when no session exists
// yet (the client needs its server-reflexive address BEFORE it creates the
// session): https://wg.<domain> maps to turn.<domain>:3478. It returns false
// for hosts that do not follow the naming scheme (set an override then).
func STUNServerFromHub(hubURL string) (string, bool) {
	u, err := url.Parse(hubURL)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	domain, ok := strings.CutPrefix(host, api.UserHostPrefix+".")
	if !ok || domain == "" || !strings.Contains(domain, ".") {
		return "", false
	}
	return net.JoinHostPort(api.TURNHostPrefix+"."+domain, strconv.Itoa(api.TURNPort)), true
}

func withPort(hostport string) (string, error) {
	if hostport == "" {
		return "", errors.New("p2p: empty server")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.Trim(hostport, "[]"), strconv.Itoa(api.TURNPort)
	}
	if host == "" {
		return "", errors.New("p2p: empty server host")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("p2p: bad server port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}
