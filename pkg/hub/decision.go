package hub

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// dctx collects the log fields of one request. It never holds credentials.
type dctx struct {
	op      string
	kind    string
	ns      string
	device  string
	subject string
	session string
	remote  string
	// service is the service id of a client request or connection (phase 2).
	service string
	// internal is true for requests served on api.HubInternalPort.
	internal bool
}

// log writes the single decision line of a request and counts it.
func (h *Hub) logDecision(d *dctx, decision, reason, detail string) {
	h.met.decisions.WithLabelValues(d.op, decision, reason).Inc()
	lvl := slog.LevelInfo
	if decision == "deny" {
		lvl = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("op", d.op),
		slog.String("decision", decision),
		slog.String("reason", reason),
		slog.String("kind", d.kind),
		slog.String("ns", d.ns),
		slog.String("device", d.device),
		slog.String("subject", d.subject),
		slog.String("session", d.session),
		slog.String("remote", d.remote),
	}
	if d.service != "" {
		attrs = append(attrs, slog.String("service", d.service))
	}
	if detail != "" {
		attrs = append(attrs, slog.String("detail", detail))
	}
	h.log.LogAttrs(context.Background(), lvl, "decision", attrs...)
}

// clientIP returns the address used for logs and per-source rate limits.
// trusted is true only when the configured ClientIPHeader carried a parseable
// address; otherwise the peer address is returned (for logs only), because
// behind a mesh sidecar or a load balancer it is the same for every caller.
func (h *Hub) clientIP(r *http.Request) (ip string, trusted bool) {
	if hdr := h.cfg.ClientIPHeader; hdr != "" {
		first, _, _ := strings.Cut(r.Header.Get(hdr), ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil && publicClientAddr(a.Unmap()) {
			return a.Unmap().String(), true
		}
	}
	return remoteIP(r.RemoteAddr), false
}

// cgnat is the shared address space of RFC 6598 (100.64.0.0/10).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicClientAddr reports whether a can plausibly be a real client address.
// Loopback, private (RFC 1918 and ULA), CGNAT, link-local, multicast and
// unspecified addresses are what a proxy or a NAT hop (k3s servicelb, a mesh
// sidecar, the node itself) shows instead of the caller. Keying a limiter on
// one of them would let a single caller exhaust the budget of everybody, so
// such a value is treated like no trusted address at all: only the global
// backstop applies.
func publicClientAddr(a netip.Addr) bool {
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsPrivate(),
		a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return false
	case a.Is4() && cgnat.Contains(a):
		return false
	}
	return true
}

func remoteIP(remote string) string {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().String()
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
