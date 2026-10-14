// Package svc validates the shape of api.ServiceSpec values. It is shared by
// the hub (which sanitizes the policy before it reaches an agent), the agent
// (which re-validates on receipt and again on every dial, see pkg/agent) and
// device-controller (which validates the services annotation). It depends on
// the standard library and pkg/api only.
//
// Shape validation is purely syntactic: it never resolves names and never
// looks at the machine. The dial-time rules (loopback, link-local, node
// ports, service CIDR, CNAME) need the device and live in pkg/agent.
package svc

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// MaxIDLen is the longest service ID (a DNS label, kept short for host names).
const MaxIDLen = 20

// MaxDescriptionLen bounds ServiceSpec.Description.
const MaxDescriptionLen = 200

var (
	labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,18}[a-z0-9])?$`)
	// k8sLabelRE is an RFC 1123 label (up to 63 characters).
	k8sLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// ValidID reports whether id is a service ID: a lowercase DNS label of at
// most MaxIDLen characters.
func ValidID(id string) bool { return len(id) <= MaxIDLen && labelRE.MatchString(id) }

// SplitInternal splits an internal target "<service>.<namespace>".
func SplitInternal(target string) (name, namespace string, err error) {
	name, namespace, ok := strings.Cut(target, ".")
	if !ok || !k8sLabelRE.MatchString(name) || !k8sLabelRE.MatchString(namespace) {
		return "", "", fmt.Errorf("internal target %q must be <service>.<namespace>", target)
	}
	return name, namespace, nil
}

// InternalDenied reports why a k3s Service is never reachable through a
// service: kube-system and the kubernetes API service (default/kubernetes).
func InternalDenied(name, namespace string) error {
	switch {
	case namespace == "kube-system":
		return errors.New("services in kube-system are not reachable")
	case namespace == "default" && name == "kubernetes":
		return errors.New("the kubernetes API service is not reachable")
	}
	return nil
}

// ValidateSpec checks one service. The ssh service is implicit; an explicit
// ssh entry must be the fixed one (kind ssh, id ssh, port 22 or unset).
func ValidateSpec(s api.ServiceSpec) error {
	if !ValidID(s.ID) {
		return fmt.Errorf("service id %q must be a DNS label of at most %d characters", s.ID, MaxIDLen)
	}
	if len(s.Description) > MaxDescriptionLen {
		return fmt.Errorf("service %s: description is too long", s.ID)
	}
	if s.Protocol != api.ProtocolTCP && s.Protocol != api.ProtocolHTTP {
		return fmt.Errorf("service %s: protocol must be %q or %q", s.ID, api.ProtocolTCP, api.ProtocolHTTP)
	}
	if s.Web && s.Protocol != api.ProtocolHTTP {
		return fmt.Errorf("service %s: only http services can be published as web", s.ID)
	}
	switch s.Kind {
	case api.ServiceKindSSH:
		if s.ID != api.ServiceSSHID {
			return fmt.Errorf("service %s: the ssh kind is only valid for the id %q", s.ID, api.ServiceSSHID)
		}
		if s.Port != 0 && s.Port != 22 || s.Web {
			return fmt.Errorf("service %s: ssh is fixed to port 22", s.ID)
		}
	case api.ServiceKindExternal:
		if s.ID == api.ServiceSSHID {
			return fmt.Errorf("service id %q is reserved", s.ID)
		}
		if err := validPort(s); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(s.Target)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("service %s: external target must be an IP address literal", s.ID)
		}
	case api.ServiceKindInternal:
		if s.ID == api.ServiceSSHID {
			return fmt.Errorf("service id %q is reserved", s.ID)
		}
		if err := validPort(s); err != nil {
			return err
		}
		name, ns, err := SplitInternal(s.Target)
		if err != nil {
			return fmt.Errorf("service %s: %w", s.ID, err)
		}
		if err := InternalDenied(name, ns); err != nil {
			return fmt.Errorf("service %s: %w", s.ID, err)
		}
	default:
		return fmt.Errorf("service %s: unknown kind %q", s.ID, s.Kind)
	}
	return nil
}

func validPort(s api.ServiceSpec) error {
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("service %s: port %d out of range", s.ID, s.Port)
	}
	return nil
}

// ValidateSet checks a whole set: every spec valid, IDs unique, at most
// api.MaxServices entries.
func ValidateSet(specs []api.ServiceSpec) error {
	if len(specs) > api.MaxServices {
		return fmt.Errorf("at most %d services are allowed", api.MaxServices)
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if err := ValidateSpec(s); err != nil {
			return err
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate service id %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}

// Sanitize returns the valid, unique specs of in (at most api.MaxServices),
// dropping the rest, for receivers that must fail closed rather than reject a
// whole update. dropped lists the problems.
func Sanitize(in []api.ServiceSpec) (out []api.ServiceSpec, dropped []error) {
	seen := map[string]bool{}
	for _, s := range in {
		if len(out) >= api.MaxServices {
			dropped = append(dropped, fmt.Errorf("more than %d services; the rest are ignored", api.MaxServices))
			break
		}
		if err := ValidateSpec(s); err != nil {
			dropped = append(dropped, err)
			continue
		}
		if seen[s.ID] {
			dropped = append(dropped, fmt.Errorf("duplicate service id %q", s.ID))
			continue
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out, dropped
}

// Equivalent reports whether two specs reach the same place in the same way
// (description and the web flag do not matter to an open connection).
func Equivalent(a, b api.ServiceSpec) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Target == b.Target && a.Port == b.Port && a.Protocol == b.Protocol
}

// Find returns the spec with the given id.
func Find(specs []api.ServiceSpec, id string) (api.ServiceSpec, bool) {
	for _, s := range specs {
		if s.ID == id {
			return s, true
		}
	}
	return api.ServiceSpec{}, false
}

// Same reports whether two sets are equal as sets of equivalent specs.
func Same(a, b []api.ServiceSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		y, ok := Find(b, x.ID)
		if !ok || !Equivalent(x, y) || x.Web != y.Web || x.Description != y.Description {
			return false
		}
	}
	return true
}
