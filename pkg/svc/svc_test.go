package svc

import (
	"strings"
	"testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

func TestValidateSpec(t *testing.T) {
	ext := func(id, target string, port int) api.ServiceSpec {
		return api.ServiceSpec{ID: id, Kind: api.ServiceKindExternal, Target: target, Port: port, Protocol: api.ProtocolTCP}
	}
	in := func(id, target string, port int) api.ServiceSpec {
		return api.ServiceSpec{ID: id, Kind: api.ServiceKindInternal, Target: target, Port: port, Protocol: api.ProtocolHTTP, Web: true}
	}
	tests := []struct {
		name string
		spec api.ServiceSpec
		want string // substring of the error, empty = valid
	}{
		{"external ok", ext("cam", "192.168.1.20", 554), ""},
		{"external v6 ok", ext("cam6", "fd00::1", 80), ""},
		{"external hostname", ext("cam", "camera.local", 554), "IP address literal"},
		{"external zone", ext("cam", "fe80::1%eth0", 554), "IP address literal"},
		{"external no port", ext("cam", "10.0.0.1", 0), "out of range"},
		{"external big port", ext("cam", "10.0.0.1", 70000), "out of range"},
		{"internal ok", in("grafana", "grafana.monitoring", 3000), ""},
		{"internal fqdn refused", in("grafana", "grafana.monitoring.svc.cluster.local", 3000), "must be <service>.<namespace>"},
		{"internal no ns", in("grafana", "grafana", 3000), "must be <service>.<namespace>"},
		{"internal kube-system", in("dns", "kube-dns.kube-system", 53), "kube-system"},
		{"internal kubernetes", in("api", "kubernetes.default", 443), "kubernetes API"},
		{"internal default other ok", in("web", "web.default", 80), ""},
		{"ssh ok", api.ServiceSpec{ID: "ssh", Kind: api.ServiceKindSSH, Protocol: api.ProtocolTCP}, ""},
		{"ssh other port", api.ServiceSpec{ID: "ssh", Kind: api.ServiceKindSSH, Port: 2222, Protocol: api.ProtocolTCP}, "fixed to port 22"},
		{"ssh kind other id", api.ServiceSpec{ID: "shell", Kind: api.ServiceKindSSH, Protocol: api.ProtocolTCP}, "only valid for the id"},
		{"ssh id reserved", ext("ssh", "10.0.0.1", 22), "reserved"},
		{"bad id upper", ext("Cam", "10.0.0.1", 80), "DNS label"},
		{"bad id long", ext(strings.Repeat("a", 21), "10.0.0.1", 80), "DNS label"},
		{"bad kind", api.ServiceSpec{ID: "x", Kind: "weird", Protocol: api.ProtocolTCP}, "unknown kind"},
		{"bad protocol", api.ServiceSpec{ID: "x", Kind: api.ServiceKindExternal, Target: "10.0.0.1", Port: 1, Protocol: "udp"}, "protocol"},
		{"web needs http", api.ServiceSpec{ID: "x", Kind: api.ServiceKindExternal, Target: "10.0.0.1", Port: 1, Protocol: api.ProtocolTCP, Web: true}, "only http"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSpec(tc.spec)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestSetAndSanitize(t *testing.T) {
	a := api.ServiceSpec{ID: "a", Kind: api.ServiceKindExternal, Target: "10.0.0.1", Port: 80, Protocol: api.ProtocolTCP}
	bad := api.ServiceSpec{ID: "BAD", Kind: api.ServiceKindExternal}
	if err := ValidateSet([]api.ServiceSpec{a, a}); err == nil {
		t.Fatal("duplicate ids accepted")
	}
	out, dropped := Sanitize([]api.ServiceSpec{a, bad, a})
	if len(out) != 1 || len(dropped) != 2 {
		t.Fatalf("out %v dropped %v", out, dropped)
	}
	many := make([]api.ServiceSpec, 0, 40)
	for i := range 40 {
		s := a
		s.ID = "s" + strings.Repeat("x", i%10) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		many = append(many, s)
	}
	if err := ValidateSet(many); err == nil {
		t.Fatal("more than MaxServices accepted")
	}
	if !Same(out, []api.ServiceSpec{a}) || Same(out, nil) {
		t.Fatal("Same")
	}
	b := a
	b.Port = 81
	if Equivalent(a, b) || !Equivalent(a, a) {
		t.Fatal("Equivalent")
	}
}
