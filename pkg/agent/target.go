package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
)

// Errors of target validation. The connect listener maps ErrDenied to
// api.ReasonServiceDenied and everything else to api.ReasonInternal.
var (
	ErrDenied      = errors.New("service target denied")
	ErrUnreachable = errors.New("service target unreachable")
)

func denied(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, a...))
}

// Resolver is the part of net.Resolver the internal-service lookup needs.
// *net.Resolver satisfies it; tests use a fake.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Defaults of TargetPolicy.
const (
	// DefaultServiceCIDR is the k3s default service network.
	DefaultServiceCIDR = "10.43.0.0/16"
	// DefaultClusterCIDR is the k3s default pod network.
	DefaultClusterCIDR = "10.42.0.0/16"
	// DefaultClusterDomain is the k3s default cluster DNS domain.
	DefaultClusterDomain = "cluster.local"
	// DefaultSSHPort is the sshd port the implicit ssh service reaches.
	DefaultSSHPort = 22
)

// protectedNodePorts are control-plane ports of a k3s node: the API server
// (6443), kubelet (10250, 10255), etcd (2379, 2380) and the controller manager
// and scheduler (10257, 10259). No external service may use them on ANY
// address (the other nodes of a multi-node Robot are not known to the agent),
// and no service of any kind may reach them on one of this node's addresses.
var protectedNodePorts = map[uint16]bool{6443: true, 10250: true, 10255: true, 2379: true, 2380: true, 10257: true, 10259: true}

// TargetPolicy decides where a service may connect. The agent validates the
// target of a service on EVERY dial, whatever the hub or the policy said
// before: this is the last line against an open proxy into the device.
//
// Rules:
//   - ssh: fixed to SSHHost:SSHPort (127.0.0.1:22); the spec's target is ignored.
//   - external: an IP literal; never loopback (except that explicit ssh
//     target), link-local (169.254/16, fe80::/10), multicast, unspecified,
//     inside the service CIDR or the pod CIDR (in-cluster targets must be
//     internal services, where the kube-system/kubernetes refusals apply), and
//     never on a control-plane port (6443, 10250, 10255, 2379, 2380, 10257,
//     10259) of ANY address.
//   - internal: "<svc>.<ns>", resolved to A records only through Resolver using
//     the fully qualified name <svc>.<ns>.svc.<ClusterDomain>.; every address
//     must lie inside a service CIDR (so headless services and pod IPs are
//     refused), the answer must not come through a CNAME (ExternalName), and
//     kube-system and default/kubernetes are refused.
type TargetPolicy struct {
	// ServiceCIDRs are the cluster's service networks (default 10.43.0.0/16).
	ServiceCIDRs []netip.Prefix
	// ClusterCIDRs are the cluster's pod networks (default 10.42.0.0/16);
	// external services may not point into them.
	ClusterCIDRs  []netip.Prefix
	ClusterDomain string
	// SSHHost and SSHPort are the implicit ssh service's target.
	SSHHost netip.Addr
	SSHPort int
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// NodeIPs lists the node's own addresses; it is called on every dial.
	// Default: the addresses of all network interfaces.
	NodeIPs func() []netip.Addr
	// AllowTarget is a TEST HOOK, never set in production: targets for which
	// it returns true skip the loopback refusal (and only that one), so that
	// tests can use listeners on 127.0.0.1 as external services.
	AllowTarget func(netip.AddrPort) bool
}

// ParseServiceCIDRs parses a comma-separated list of prefixes.
func ParseServiceCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("service CIDR %q: %w", part, err)
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("no service CIDR given")
	}
	return out, nil
}

func (p *TargetPolicy) applyDefaults() {
	if len(p.ServiceCIDRs) == 0 {
		p.ServiceCIDRs = []netip.Prefix{netip.MustParsePrefix(DefaultServiceCIDR)}
	}
	if len(p.ClusterCIDRs) == 0 {
		p.ClusterCIDRs = []netip.Prefix{netip.MustParsePrefix(DefaultClusterCIDR)}
	}
	if p.ClusterDomain == "" {
		p.ClusterDomain = DefaultClusterDomain
	}
	if !p.SSHHost.IsValid() {
		p.SSHHost = netip.MustParseAddr("127.0.0.1")
	}
	if p.SSHPort == 0 {
		p.SSHPort = DefaultSSHPort
	}
	if p.Resolver == nil {
		p.Resolver = net.DefaultResolver
	}
	if p.NodeIPs == nil {
		p.NodeIPs = interfaceIPs
	}
}

// interfaceIPs returns the addresses of all network interfaces of the host.
func interfaceIPs() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

func (p *TargetPolicy) inServiceCIDR(a netip.Addr) bool {
	for _, c := range p.ServiceCIDRs {
		if c.Contains(a) {
			return true
		}
	}
	return false
}

func (p *TargetPolicy) inClusterCIDR(a netip.Addr) bool {
	for _, c := range p.ClusterCIDRs {
		if c.Contains(a) {
			return true
		}
	}
	return false
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	broadcast   = netip.MustParseAddr("255.255.255.255")
)

// checkAddr applies the address rules common to all kinds.
func (p *TargetPolicy) checkAddr(ap netip.AddrPort, isSSH bool) error {
	a := ap.Addr().Unmap()
	switch {
	case !a.IsValid(), a.Zone() != "":
		return denied("invalid address")
	case ap.Port() == 0:
		return denied("invalid port")
	case a.IsUnspecified(), thisNetwork.Contains(a), a == broadcast:
		return denied("unspecified address")
	case a.IsMulticast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return denied("multicast address")
	case a.IsLinkLocalUnicast():
		return denied("link-local address")
	case a.IsLoopback():
		if isSSH || (p.AllowTarget != nil && p.AllowTarget(netip.AddrPortFrom(a, ap.Port()))) {
			break
		}
		return denied("loopback address")
	}
	if protectedNodePorts[ap.Port()] {
		for _, n := range p.NodeIPs() {
			if n.Unmap() == a {
				return denied("control-plane port %d of this node", ap.Port())
			}
		}
		if a.IsLoopback() { // an allowed loopback target must not reach the node's control plane either
			return denied("control-plane port %d of this node", ap.Port())
		}
	}
	return nil
}

// Resolve validates spec and returns the address to dial. It is called for
// every connection; nothing is cached.
func (p *TargetPolicy) Resolve(ctx context.Context, spec api.ServiceSpec) (netip.AddrPort, error) {
	switch spec.Kind {
	case api.ServiceKindSSH:
		ap := netip.AddrPortFrom(p.SSHHost, uint16(p.SSHPort))
		// The ssh target is fixed by configuration, not by the policy; it is
		// the one loopback target allowed by default.
		return ap, p.checkAddr(ap, true)
	case api.ServiceKindExternal:
		return p.resolveExternal(spec)
	case api.ServiceKindInternal:
		return p.resolveInternal(ctx, spec)
	}
	return netip.AddrPort{}, denied("unknown service kind %q", spec.Kind)
}

func (p *TargetPolicy) resolveExternal(spec api.ServiceSpec) (netip.AddrPort, error) {
	if spec.Port < 1 || spec.Port > 65535 {
		return netip.AddrPort{}, denied("port out of range")
	}
	a, err := netip.ParseAddr(spec.Target)
	if err != nil || a.Zone() != "" {
		return netip.AddrPort{}, denied("target is not an IP address literal")
	}
	a = a.Unmap()
	ap := netip.AddrPortFrom(a, uint16(spec.Port))
	if err := p.checkAddr(ap, false); err != nil {
		return netip.AddrPort{}, err
	}
	if protectedNodePorts[ap.Port()] {
		return netip.AddrPort{}, denied("control-plane port %d is not available to external services", ap.Port())
	}
	if p.inServiceCIDR(a) {
		return netip.AddrPort{}, denied("address is inside the service network; use an internal service")
	}
	if p.inClusterCIDR(a) {
		return netip.AddrPort{}, denied("address is inside the pod network; use an internal service")
	}
	return ap, nil
}

func (p *TargetPolicy) resolveInternal(ctx context.Context, spec api.ServiceSpec) (netip.AddrPort, error) {
	if spec.Port < 1 || spec.Port > 65535 {
		return netip.AddrPort{}, denied("port out of range")
	}
	name, ns, err := svc.SplitInternal(spec.Target)
	if err != nil {
		return netip.AddrPort{}, denied("%v", err)
	}
	if err := svc.InternalDenied(name, ns); err != nil {
		return netip.AddrPort{}, denied("%v", err)
	}
	fqdn := name + "." + ns + ".svc." + strings.Trim(p.ClusterDomain, ".") + "."
	ips, err := p.Resolver.LookupIP(ctx, "ip4", fqdn)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: resolving %s: %v", ErrUnreachable, name+"."+ns, err)
	}
	var first netip.Addr
	n := 0
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok || ip.To4() == nil {
			continue // A records only
		}
		a = a.Unmap()
		if !p.inServiceCIDR(a) {
			return netip.AddrPort{}, denied("%s resolves outside the service network (headless service or pod address)", name+"."+ns)
		}
		if n == 0 {
			first = a
		}
		n++
	}
	if n == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: %s has no A record", ErrUnreachable, name+"."+ns)
	}
	// An ExternalName service (or anything else that answers through a CNAME)
	// would redirect the dial to a name the policy never saw. The canonical
	// name of a plain Service is the queried name itself.
	cname, err := p.Resolver.LookupCNAME(ctx, fqdn)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: resolving %s: %v", ErrUnreachable, name+"."+ns, err)
	}
	if !sameDNSName(cname, fqdn) {
		return netip.AddrPort{}, denied("%s is answered through a CNAME (ExternalName services are refused)", name+"."+ns)
	}
	ap := netip.AddrPortFrom(first, uint16(spec.Port))
	if err := p.checkAddr(ap, false); err != nil {
		return netip.AddrPort{}, err
	}
	return ap, nil
}

func sameDNSName(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
	return norm(a) == norm(b)
}

// DialService validates spec and connects to its target.
func (p *TargetPolicy) DialService(ctx context.Context, spec api.ServiceSpec, timeout time.Duration) (net.Conn, error) {
	ap, err := p.Resolve(ctx, spec)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ap.Addr().String(), strconv.Itoa(int(ap.Port()))))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return c, nil
}
