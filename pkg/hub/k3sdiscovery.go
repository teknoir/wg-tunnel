package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// k3s Service discovery (api.CapK3sDiscovery), hub side. Backstage asks, on
// behalf of an administrator who opened "Add service", which Services the
// device's k3s cluster has. The hub asks the live agent over plane A (the
// control RPC, like the grant push) and passes the answer on after checking
// it again: the agent is the device, and the device is not trusted.

const (
	// maxK3sAnswerBody bounds the agent's answer. It equals the agent's own cap
	// on the Kubernetes API answer, which is larger than the mapped list.
	maxK3sAnswerBody = 8 << 20

	k3sMaxNameLen        = 253 // a DNS-1123 subdomain, also the longest allowed label value
	k3sMaxTypeLen        = 32
	k3sMaxPortNameLen    = 63
	k3sMaxProtocolLen    = 16
	k3sMaxAppProtocolLen = 317 // a qualified name: 253-byte prefix, '/', 63-byte name
	k3sMaxErrorLen       = 300
)

// k3sAgentTimeout bounds the call to the agent (a variable for tests).
var k3sAgentTimeout = 5 * time.Second

// Plain-English reasons in api.K3sServiceList.Error that the hub itself gives.
const (
	k3sErrOffline    = "the device is offline"
	k3sErrOldAgent   = "the device agent is too old to list services"
	k3sErrNoAnswer   = "the device did not answer in time"
	k3sErrBadAnswer  = "the device agent gave an answer the hub could not accept"
	k3sErrAgentError = "the device agent could not list the services"
)

// handleK3sServices serves GET api.StatusDevicePath<ns>/<device>/k3s-services.
// A device that cannot answer (offline, old agent, no permission, no reply) is
// still a 200 with Error set and an empty list, so the console can say why;
// 4xx and 5xx are for the caller (authentication, unknown device).
func (h *Hub) handleK3sServices(w http.ResponseWriter, r *http.Request, d *dctx, user string) *denial {
	ns, device := r.PathValue("ns"), r.PathValue("device")
	if !validLabel(ns) || !validLabel(device) {
		return deny(api.ReasonBadRequest, "invalid namespace or device")
	}
	d.ns, d.device = ns, device
	if _, ok := h.deps.Policy.Get(ns, device); !ok {
		return &denial{status: http.StatusNotFound, reason: api.ReasonDeviceUnknown, msg: "no such device"}
	}
	requester := r.Header.Get(api.StatusRequesterHeader)
	if !ValidEmail(requester) {
		requester = "unknown"
	}
	res, outcome := h.k3sServices(r.Context(), ns, device)
	h.met.decisions.WithLabelValues(d.op, "allow", outcome).Inc()
	h.log.LogAttrs(context.Background(), slog.LevelInfo, "decision",
		slog.String("op", d.op), slog.String("decision", "allow"), slog.String("reason", outcome),
		slog.String("ns", ns), slog.String("device", device), slog.String("remote", d.remote),
		slog.Int("services", len(res.Services)), slog.String("requester", requester), slog.String("via", user))
	writeJSON(w, http.StatusOK, res)
	return nil
}

// k3sServices returns the device's Services and the outcome label for the log
// and the metric: ok, offline, old_agent, agent_error, unreachable, bad_answer.
func (h *Hub) k3sServices(ctx context.Context, ns, device string) (api.K3sServiceList, string) {
	fail := func(msg string) api.K3sServiceList {
		return api.K3sServiceList{Services: []api.K3sService{}, ObservedAt: h.now().UTC(), Error: msg}
	}
	dev := h.deviceSession(ns, device)
	switch {
	case dev == nil:
		return fail(k3sErrOffline), "offline"
	case !dev.hasCap(api.CapK3sDiscovery) || !dev.hasCap(api.CapControl):
		return fail(k3sErrOldAgent), "old_agent"
	}
	raw, err := h.getK3sServices(ctx, dev)
	if err != nil {
		h.log.Warn("k3s Service discovery failed", "ns", ns, "device", device, "err", err)
		if errors.Is(err, errK3sAnswer) {
			return fail(k3sErrBadAnswer), "bad_answer"
		}
		return fail(k3sErrNoAnswer), "unreachable"
	}
	res := sanitizeK3sList(raw, h.now())
	if res.Error != "" {
		return res, "agent_error"
	}
	return res, "ok"
}

var errK3sAnswer = errors.New("unacceptable answer")

// getK3sServices asks the agent over plane A, the way pushGrants does.
func (h *Hub) getK3sServices(ctx context.Context, dev *session) (api.K3sServiceList, error) {
	ctx, cancel := context.WithTimeout(ctx, k3sAgentTimeout)
	defer cancel()
	addr := netip.AddrPortFrom(dev.ip, api.AgentControlPort)
	cl := &http.Client{
		Timeout: k3sAgentTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return h.tunnel.DialContext(ctx, addr)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr.String()+api.ControlK3sServicesPath, nil)
	if err != nil {
		return api.K3sServiceList{}, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return api.K3sServiceList{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return api.K3sServiceList{}, fmt.Errorf("%w: agent answered %d", errK3sAnswer, resp.StatusCode)
	}
	// One byte more than the bound tells an oversized answer from one that fits.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxK3sAnswerBody+1))
	if err != nil {
		return api.K3sServiceList{}, err
	}
	if len(body) > maxK3sAnswerBody {
		return api.K3sServiceList{}, fmt.Errorf("%w: answer larger than %d bytes", errK3sAnswer, maxK3sAnswerBody)
	}
	var list api.K3sServiceList
	if err := json.Unmarshal(body, &list); err != nil {
		return api.K3sServiceList{}, fmt.Errorf("%w: %v", errK3sAnswer, err)
	}
	return list, nil
}

// sanitizeK3sList re-validates an agent's list before it reaches Backstage:
// the caps of the contract, sane strings, and the hub's own clock for
// ObservedAt (device clocks are not trusted). A Service that does not
// validate is dropped, a bad field of a Service is cleared; the console never
// sees control characters or oversized strings from a device. The agent's
// Error replaces the list (it is plain text for people, so it is bounded and
// stripped of control characters too).
func sanitizeK3sList(in api.K3sServiceList, now time.Time) api.K3sServiceList {
	out := api.K3sServiceList{Services: []api.K3sService{}, ObservedAt: now.UTC()}
	if in.Error != "" {
		out.Error = cleanK3sText(in.Error, k3sMaxErrorLen)
		if out.Error == "" {
			out.Error = k3sErrAgentError
		}
		return out
	}
	out.Truncated = in.Truncated
	for _, s := range in.Services {
		if len(out.Services) >= api.MaxK3sServices {
			out.Truncated = true
			break
		}
		if !k3sText(s.Namespace, k3sMaxNameLen) || !k3sText(s.Name, k3sMaxNameLen) || s.Namespace == "" || s.Name == "" {
			continue
		}
		c := api.K3sService{Namespace: s.Namespace, Name: s.Name}
		if slices.Contains([]string{"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"}, s.Type) {
			c.Type = s.Type
		}
		if s.ClusterIP == "None" {
			c.ClusterIP = s.ClusterIP
		} else if ip, err := netip.ParseAddr(s.ClusterIP); err == nil {
			c.ClusterIP = ip.String()
		}
		for _, p := range s.Ports {
			if len(c.Ports) >= api.MaxK3sServicePorts {
				break
			}
			if p.Port < 1 || p.Port > 65535 || !k3sText(p.Name, k3sMaxPortNameLen) {
				continue
			}
			cp := api.K3sServicePort{Name: p.Name, Port: p.Port}
			if k3sText(p.AppProtocol, k3sMaxAppProtocolLen) {
				// Only a protocol hint for the console: an unusable one is
				// dropped, the port stays.
				cp.AppProtocol = p.AppProtocol
			}
			if slices.Contains([]string{"TCP", "UDP", "SCTP"}, p.Protocol) {
				cp.Protocol = p.Protocol
			}
			c.Ports = append(c.Ports, cp)
		}
		out.Services = append(out.Services, c)
	}
	return out
}

// k3sText reports whether s is valid UTF-8 without control characters and at
// most limit bytes. The empty string is fine.
func k3sText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// cleanK3sText makes free text from a device safe to show: control characters
// and invalid bytes dropped, cut to at most limit bytes at a character boundary.
func cleanK3sText(s string, limit int) string {
	out := make([]rune, 0, len(s))
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if n += utf8.RuneLen(r); n > limit {
			break
		}
		out = append(out, r)
	}
	return string(out)
}
