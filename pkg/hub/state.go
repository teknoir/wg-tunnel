package hub

import (
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// effective is the hub's view of whether a device may be reached right now.
type effective struct {
	// Active is true only when every source agrees.
	Active bool
	// State is api.StateActive, api.StateRevoked or api.StateDisabled.
	State string
	// Reason is the most specific api.Reason*; empty when active.
	Reason string
	// Detail is a short log-safe explanation.
	Detail string
	// Policy is the policy entry (zero value when none exists).
	Policy api.PolicyEntry
}

func flagTrue(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "true") }

// computeEffective combines the policy entry (device-controller) with the
// Device annotations (operator switches, watched directly) and fails closed:
// a device is active only if the policy entry exists and is active, the
// Device exists, WireGuard is enabled and neither the compromised nor the
// health-check-failed flag is set. Either source revoking wins.
func computeEffective(pol PolicySource, flags DeviceFlags, ns, device string) effective {
	entry, havePolicy := pol.Get(ns, device)
	ann, exists := flags.Annotations(ns, device)

	revoked := func(detail string) effective {
		return effective{State: api.StateRevoked, Reason: api.ReasonDeviceRevoked, Detail: detail, Policy: entry}
	}
	if exists {
		switch {
		case flagTrue(ann[api.AnnotationCompromised]):
			return revoked(api.RevokeCompromised)
		case flagTrue(ann[api.AnnotationHealthCheckFailed]):
			return revoked(api.RevokeHealthCheckFailed)
		}
	}
	if !havePolicy {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceUnknown, Detail: "no policy entry"}
	}
	switch entry.State {
	case api.StateRevoked:
		return revoked("policy revoked")
	case api.StateActive:
	default:
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceDisabled, Detail: "policy " + entry.State, Policy: entry}
	}
	if !exists {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceUnknown, Detail: "device does not exist", Policy: entry}
	}
	if ann[api.AnnotationWireGuard] != "enabled" {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceDisabled, Detail: "wireguard not enabled", Policy: entry}
	}
	return effective{Active: true, State: api.StateActive, Policy: entry}
}

func portAllowed(ports []int, p int) bool {
	for _, a := range ports {
		if a == p {
			return true
		}
	}
	return false
}
