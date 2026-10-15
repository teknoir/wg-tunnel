package hub

import (
	"slices"

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
	// VoidReason is set (api.RevokeCompromised or api.RevokeHealthCheckFailed)
	// when a compromised or health-check flag is in force; the enforcer then
	// voids the device's identity pin for good.
	VoidReason string
	// Policy is the policy entry (zero value when none exists).
	Policy api.PolicyEntry
}

// computeEffective combines the policy entry (device-controller) with the
// mirrored Device flags (operator switches, written by the flags watcher) and
// fails closed: a device is active only if the policy entry exists and is
// active, the flags entry exists and says the Device exists, WireGuard is
// enabled and neither the compromised nor the health-check-failed flag is
// set. Either source revoking wins. A missing flags entry means "not enabled".
func computeEffective(pol PolicySource, flags DeviceFlags, ns, device string) effective {
	entry, havePolicy := pol.Get(ns, device)
	fl, haveFlags := flags.Flags(ns, device)
	exists := haveFlags && fl.Exists

	revoked := func(detail, void string) effective {
		return effective{State: api.StateRevoked, Reason: api.ReasonDeviceRevoked, Detail: detail, VoidReason: void, Policy: entry}
	}
	if exists {
		switch {
		case fl.Compromised:
			return revoked(api.RevokeCompromised, api.RevokeCompromised)
		case fl.HealthCheckFailed:
			return revoked(api.RevokeHealthCheckFailed, api.RevokeHealthCheckFailed)
		}
	}
	if !havePolicy {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceUnknown, Detail: "no policy entry"}
	}
	switch entry.State {
	case api.StateRevoked:
		void := ""
		switch {
		case slices.Contains(entry.Reasons, api.RevokeCompromised):
			void = api.RevokeCompromised
		case slices.Contains(entry.Reasons, api.RevokeHealthCheckFailed):
			void = api.RevokeHealthCheckFailed
		}
		return revoked("policy revoked", void)
	case api.StateActive:
	default:
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceDisabled, Detail: "policy " + entry.State, Policy: entry}
	}
	if !exists {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceUnknown, Detail: "device does not exist", Policy: entry}
	}
	if !fl.WireGuard {
		return effective{State: api.StateDisabled, Reason: api.ReasonDeviceDisabled, Detail: "wireguard not enabled", Policy: entry}
	}
	return effective{Active: true, State: api.StateActive, Policy: entry}
}

// reservedPort: the agent's overlay ports of the connect and control
// listeners are never raw-forwardable. The control port trusts its caller by
// the hub's overlay address, so a client that reached it through a raw-port
// session would speak as the hub (grants, services).
func reservedPort(p int) bool { return p == api.AgentConnectPort || p == api.AgentControlPort }

func portAllowed(ports []int, p int) bool {
	return !reservedPort(p) && slices.Contains(ports, p)
}

// validPorts keeps the forwardable TCP ports in 1..65535 (the agent's reserved
// ports are dropped), deduplicated and sorted.
func validPorts(ports []int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p >= 1 && p <= 65535 && !reservedPort(p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// samePorts compares two port sets regardless of order.
func samePorts(a, b []int) bool {
	return slices.Equal(validPorts(a), validPorts(b))
}

// pinCurrent reports whether pin is valid for pol: same enrollment epoch AND
// generation, and not voided. Anything else is a void pin and the agent must
// enroll a NEW identity.
func pinCurrent(pin api.IdentityEntry, pol api.PolicyEntry) bool {
	return !pin.Voided && pin.EnrollmentGeneration == pol.EnrollmentGeneration && pin.EnrollmentEpoch == pol.EnrollmentEpoch
}

// sameEpoch reports whether pin belongs to the policy's current enrollment
// window (epoch and generation), voided or not.
func sameEpoch(pin api.IdentityEntry, pol api.PolicyEntry) bool {
	return pin.EnrollmentGeneration == pol.EnrollmentGeneration && pin.EnrollmentEpoch == pol.EnrollmentEpoch
}

// identityView is the part of a device identity the activation rule looks at:
// a stored pin, or the snapshot a live device session keeps of the pin it was
// created from.
type identityView struct {
	Fingerprint     string
	AttestedHostKey string
	Voided          bool
	Epoch           string
	Generation      int64
}

func viewOfPin(pin api.IdentityEntry) identityView {
	return identityView{
		Fingerprint: pin.Fingerprint, AttestedHostKey: pin.AttestedHostKey,
		Voided: pin.Voided, Epoch: pin.EnrollmentEpoch, Generation: pin.EnrollmentGeneration,
	}
}

func (s *session) identityView() identityView {
	return identityView{Fingerprint: s.fingerprint, AttestedHostKey: s.attestedKey, Epoch: s.epoch, Generation: s.generation}
}

// identityUsable is THE activation rule, used for session creation, renewal
// and enforcement. An identity is usable for sessions iff it is not voided,
// its epoch and generation are the policy's, and either
//   - an admin approved exactly this identity fingerprint (api.ActivatedByApproval), or
//   - automatic activation is on (the activation mode is not "manual", the
//     generation is not forced manual, the trusted device key is not shared
//     with another device) and the identity was enrolled with an attestation
//     made by exactly the device key the policy trusts (api.ActivatedByDeviceKey;
//     entries activated before rev 3 keep their stored api.ActivatedByHostKey).
//
// by is the activation source when ok.
func identityUsable(v identityView, pol api.PolicyEntry) (ok bool, by string) {
	if v.Voided || v.Fingerprint == "" ||
		v.Generation != pol.EnrollmentGeneration || v.Epoch != pol.EnrollmentEpoch {
		return false, ""
	}
	if pol.ApprovedFingerprint != "" && v.Fingerprint == pol.ApprovedFingerprint {
		return true, api.ActivatedByApproval
	}
	if pol.ActivationMode != "manual" &&
		pol.ForceManualGeneration < pol.EnrollmentGeneration &&
		!pol.DuplicateHostKey &&
		pol.TrustedHostKey != "" &&
		v.AttestedHostKey == pol.TrustedHostKey {
		return true, api.ActivatedByDeviceKey
	}
	return false, ""
}

func activated(v identityView, pol api.PolicyEntry) bool {
	ok, _ := identityUsable(v, pol)
	return ok
}
