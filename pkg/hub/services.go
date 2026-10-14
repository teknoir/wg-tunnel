package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/svc"
)

// reasonServicesChanged ends a device session whose agent cannot be told about
// a services change (log and metric label; the wire reason is service_unknown
// or forbidden, see staleDenialReason).
const reasonServicesChanged = "services_changed"

const (
	maxCaps          = 16
	maxCapLen        = 32
	servicePushTries = 3
	servicePushWait  = 500 * time.Millisecond
	servicePushTO    = 5 * time.Second
)

var knownCaps = []string{api.CapServices, api.CapControl, api.CapAttest, api.CapP2P}

// sanitizeCaps keeps the capabilities this hub knows, once each. An unknown
// capability is ignored: it can only ever enable a feature the hub has.
func sanitizeCaps(in []string) []string {
	var out []string
	for _, c := range in {
		if len(c) > maxCapLen || !slices.Contains(knownCaps, c) || slices.Contains(out, c) {
			continue
		}
		if len(out) >= maxCaps {
			break
		}
		out = append(out, c)
	}
	return out
}

func (s *session) hasCap(c string) bool { return slices.Contains(s.caps, c) }

// policyServices are the services the policy defines beyond the implicit ssh:
// valid, unique, at most api.MaxServices.
func policyServices(pol api.PolicyEntry) []api.ServiceSpec {
	valid, _ := svc.Sanitize(pol.Services)
	return slices.DeleteFunc(valid, func(sp api.ServiceSpec) bool { return sp.ID == api.ServiceSSHID })
}

// servicesOf returns the services a device session's agent was last told.
func (s *session) servicesOf() []api.ServiceSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.services)
}

// serviceDenial checks that client session s may still reach its service (or
// legacy port) given the effective policy. agentKnown says whether devSvc, "the
// device's agent speaks services-v1", is known; callers pass the live device
// session's capability, or the one the client session was created against when
// the device is offline.
//
//   - legacy raw port (no service): the port must be in AllowedPorts;
//   - ssh: implicit for a services-v1 agent; for a phase-1 agent it is port 22
//     and must be in AllowedPorts;
//   - any other service: it must still exist in the policy with the same
//     target, and the agent must speak services-v1.
func serviceDenial(s *session, pol api.PolicyEntry, agentKnown, devSvc bool) *denial {
	switch s.service {
	case "":
		if !portAllowed(pol.AllowedPorts, s.targetPort) {
			return deny(api.ReasonPortNotAllowed, "port is no longer allowed")
		}
	case api.ServiceSSHID:
		if agentKnown && !devSvc && !portAllowed(pol.AllowedPorts, 22) {
			return deny(api.ReasonPortNotAllowed, "port is no longer allowed")
		}
	default:
		cur, ok := svc.Find(policyServices(pol), s.service)
		if !ok {
			return deny(api.ReasonServiceUnknown, "service is no longer defined")
		}
		if !svc.Equivalent(cur, s.svcSpec) {
			return deny(api.ReasonServiceUnknown, "service definition changed")
		}
		if agentKnown && !devSvc {
			return deny(api.ReasonServiceUnknown, "the device agent does not support services")
		}
	}
	return nil
}

// serviceDenialLive is serviceDenial against the device's live session, or
// against what the client session was created with when the device is offline.
func (h *Hub) serviceDenialLive(s *session, pol api.PolicyEntry) *denial {
	devSvc := s.agentSvc
	if dev := h.deviceSession(s.ns, s.device); dev != nil {
		devSvc = dev.hasCap(api.CapServices)
	}
	return serviceDenial(s, pol, true, devSvc)
}

// resolveRequest maps a client session request to the service it names. It
// returns the service id ("" for a legacy raw port), the port the session is
// bound to (22 for ssh, 0 for other services) and the policy spec.
func resolveRequest(req api.ClientSessionRequest, pol api.PolicyEntry) (service string, port int, spec api.ServiceSpec, den *denial) {
	switch {
	case req.Service == "" && req.Port == 22, req.Service == api.ServiceSSHID:
		if req.Port != 0 && req.Port != 22 {
			return "", 0, spec, deny(api.ReasonBadRequest, "the ssh service is port 22")
		}
		return api.ServiceSSHID, 22, spec, nil
	case req.Service == "":
		if req.Port < 1 || req.Port > 65535 {
			return "", 0, spec, deny(api.ReasonBadRequest, "invalid namespace, device or port")
		}
		return "", req.Port, spec, nil
	}
	if !svc.ValidID(req.Service) || req.Port != 0 {
		return "", 0, spec, deny(api.ReasonBadRequest, "invalid service")
	}
	cur, ok := svc.Find(policyServices(pol), req.Service)
	if !ok {
		return "", 0, spec, deny(api.ReasonServiceUnknown, "service is not defined for this device")
	}
	return req.Service, 0, cur, nil
}

// syncServices makes sure dev's agent serves the policy's current services.
// It never blocks: the push runs in its own goroutine, one per device session.
//
//   - an agent without services-v1 has nothing to sync;
//   - an agent without control-v1 cannot be told: its session ends and the next
//     one carries the new set in the session response;
//   - otherwise the set is pushed (control RPC over the tunnel); when the push
//     keeps failing the session ends the same way.
func (h *Hub) syncServices(dev *session, pol api.PolicyEntry) {
	if !dev.hasCap(api.CapServices) {
		return
	}
	want := policyServices(pol)
	dev.mu.Lock()
	if svc.Same(dev.services, want) {
		dev.mu.Unlock()
		return
	}
	if !dev.hasCap(api.CapControl) {
		dev.mu.Unlock()
		if h.endSession(dev, reasonServicesChanged) {
			h.met.revocations.WithLabelValues(reasonServicesChanged).Inc()
			h.logRevoke(dev.key(), reasonServicesChanged, "agent cannot take a services update", dev.id)
		}
		return
	}
	if dev.pushing {
		dev.pushDirty = true
		dev.mu.Unlock()
		return
	}
	dev.pushing = true
	dev.mu.Unlock()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.pushServices(dev)
	}()
}

// pushServices pushes until the agent has what the policy says now.
func (h *Hub) pushServices(dev *session) {
	k := dev.key()
	for {
		dev.mu.Lock()
		dev.pushDirty = false
		dev.mu.Unlock()
		eff := computeEffective(h.deps.Policy, h.deps.Flags, k.ns, k.device)
		want := policyServices(eff.Policy)
		current := h.deviceSession(k.ns, k.device) == dev // not under dev.mu: h.mu is taken before s.mu elsewhere
		dev.mu.Lock()
		if !eff.Active || !current || svc.Same(dev.services, want) {
			if dev.pushDirty { // the policy changed while we looked: look again
				dev.mu.Unlock()
				continue
			}
			dev.pushing = false
			dev.mu.Unlock()
			return
		}
		dev.mu.Unlock()

		var err error
		for attempt := range servicePushTries {
			if attempt > 0 {
				select {
				case <-h.ctx.Done():
					return
				case <-time.After(servicePushWait * time.Duration(attempt)):
				}
			}
			if err = h.postServices(dev, want); err == nil {
				break
			}
			h.log.Warn("pushing services to the agent failed", "ns", k.ns, "device", k.device, "attempt", attempt+1, "err", err)
		}
		if err != nil {
			// The agent cannot be reached over its control port: end the
			// session, so that it reconnects and gets the set in the response.
			dev.mu.Lock()
			dev.pushing = false
			dev.mu.Unlock()
			if h.endSession(dev, reasonServicesChanged) {
				h.met.revocations.WithLabelValues(reasonServicesChanged).Inc()
				h.logRevoke(k, reasonServicesChanged, "services push failed", dev.id)
			}
			return
		}
		dev.mu.Lock()
		dev.services = slices.Clone(want)
		dev.mu.Unlock()
		h.log.Info("services pushed to the agent", "ns", k.ns, "device", k.device, "session", dev.id, "count", len(want))
		// Loop: the policy may have changed again meanwhile.
	}
}

// postServices calls the agent's control RPC through the tunnel.
func (h *Hub) postServices(dev *session, specs []api.ServiceSpec) error {
	if specs == nil {
		specs = []api.ServiceSpec{}
	}
	body, err := json.Marshal(api.ServicesUpdate{Services: specs})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(h.ctx, servicePushTO)
	defer cancel()
	addr := netip.AddrPortFrom(dev.ip, api.AgentControlPort)
	cl := &http.Client{
		Timeout: servicePushTO,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return h.tunnel.DialContext(ctx, addr)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr.String()+api.ControlServicesPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent answered %d", resp.StatusCode)
	}
	return nil
}
