package hub

import (
	"testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

func TestComputeEffective(t *testing.T) {
	active := api.PolicyEntry{Namespace: "ns", Device: "d", State: api.StateActive}
	enabled := map[string]string{api.AnnotationWireGuard: "enabled"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range enabled {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name       string
		policy     *api.PolicyEntry
		pol        func(api.PolicyEntry) api.PolicyEntry
		ann        map[string]string
		exists     bool
		wantActive bool
		wantReason string
		wantState  string
	}{
		{name: "active", policy: &active, ann: enabled, exists: true, wantActive: true, wantState: api.StateActive},
		{name: "no policy", ann: enabled, exists: true, wantReason: api.ReasonDeviceUnknown, wantState: api.StateDisabled},
		{name: "device missing", policy: &active, exists: false, wantReason: api.ReasonDeviceUnknown, wantState: api.StateDisabled},
		{name: "wireguard annotation absent", policy: &active, ann: map[string]string{}, exists: true, wantReason: api.ReasonDeviceDisabled, wantState: api.StateDisabled},
		{name: "wireguard annotation wrong", policy: &active, ann: map[string]string{api.AnnotationWireGuard: "true"}, exists: true, wantReason: api.ReasonDeviceDisabled, wantState: api.StateDisabled},
		{name: "compromised", policy: &active, ann: with(map[string]string{api.AnnotationCompromised: "true"}), exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "health failed", policy: &active, ann: with(map[string]string{api.AnnotationHealthCheckFailed: "true"}), exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "compromised case-insensitive", policy: &active, ann: with(map[string]string{api.AnnotationCompromised: " True "}), exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "compromised false is not set", policy: &active, ann: with(map[string]string{api.AnnotationCompromised: "false"}), exists: true, wantActive: true, wantState: api.StateActive},
		{name: "compromised even without wireguard annotation", policy: &active, ann: map[string]string{api.AnnotationCompromised: "true"}, exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "compromised even without policy", ann: with(map[string]string{api.AnnotationCompromised: "true"}), exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "policy revoked", policy: &active, pol: func(p api.PolicyEntry) api.PolicyEntry { p.State = api.StateRevoked; return p }, ann: enabled, exists: true, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
		{name: "policy disabled", policy: &active, pol: func(p api.PolicyEntry) api.PolicyEntry { p.State = api.StateDisabled; return p }, ann: enabled, exists: true, wantReason: api.ReasonDeviceDisabled, wantState: api.StateDisabled},
		{name: "policy unknown state fails closed", policy: &active, pol: func(p api.PolicyEntry) api.PolicyEntry { p.State = "bogus"; return p }, ann: enabled, exists: true, wantReason: api.ReasonDeviceDisabled, wantState: api.StateDisabled},
		{name: "policy revoked beats missing device", policy: &active, pol: func(p api.PolicyEntry) api.PolicyEntry { p.State = api.StateRevoked; return p }, exists: false, wantReason: api.ReasonDeviceRevoked, wantState: api.StateRevoked},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol, flags := newFakePolicy(), newFakeFlags()
			if tc.policy != nil {
				p := *tc.policy
				if tc.pol != nil {
					p = tc.pol(p)
				}
				pol.Set(p)
			}
			if tc.exists {
				flags.Set("ns", "d", tc.ann)
			}
			got := computeEffective(pol, flags, "ns", "d")
			if got.Active != tc.wantActive || got.Reason != tc.wantReason || got.State != tc.wantState {
				t.Fatalf("got active=%v reason=%q state=%q (%s), want active=%v reason=%q state=%q",
					got.Active, got.Reason, got.State, got.Detail, tc.wantActive, tc.wantReason, tc.wantState)
			}
		})
	}
}
