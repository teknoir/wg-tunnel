package hub

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics are per Hub instance (own registry) so tests can run many hubs.
type metrics struct {
	reg         *prometheus.Registry
	sessions    *prometheus.GaugeVec
	creates     *prometheus.CounterVec
	decisions   *prometheus.CounterVec
	revocations *prometheus.CounterVec
	conns       prometheus.Gauge
	connsTotal  prometheus.Counter
	bytes       *prometheus.CounterVec
	orgGate     *prometheus.CounterVec

	leader          prometheus.Gauge
	handovers       *prometheus.CounterVec
	handoverNotices *prometheus.CounterVec
	rolePatchErrors prometheus.Counter
	userTokens      *prometheus.CounterVec
}

func newMetrics() *metrics {
	m := &metrics{
		reg: prometheus.NewRegistry(),
		sessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wghub_sessions_active", Help: "Live sessions by kind.",
		}, []string{"kind"}),
		creates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_session_creates_total", Help: "Sessions created by kind.",
		}, []string{"kind"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_decisions_total", Help: "Access decisions by operation, outcome and reason.",
		}, []string{"op", "decision", "reason"}),
		revocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_revocations_total", Help: "Enforcement actions that tore sessions down, by reason.",
		}, []string{"reason"}),
		conns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wghub_spliced_connections", Help: "Currently spliced TCP connections.",
		}),
		connsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wghub_spliced_connections_total", Help: "Spliced TCP connections since start.",
		}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_spliced_bytes_total", Help: "Bytes spliced, by direction.",
		}, []string{"direction"}),
		orgGate: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_org_gate_total", Help: "Org gate decisions by mode, decision (allow, deny, would_deny) and reason.",
		}, []string{"mode", "decision", "reason"}),
		leader: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wghub_leader", Help: "1 while this replica serves (it holds the lease, or leader election is off), 0 on a hot standby.",
		}),
		handovers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_handover_total", Help: "Planned handovers by result (successor: another replica took the lease, no_successor, not_leader).",
		}, []string{"result"}),
		handoverNotices: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_handover_notices_total", Help: "Hub-handover notices to device agents by result (delivered, delivered_legacy: an agent that refused hub_handover took a device_unknown notice instead, failed, skipped).",
		}, []string{"result"}),
		rolePatchErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wghub_role_patch_errors_total", Help: "Failed updates of this pod's hub-role label and deletion-cost annotation.",
		}),
		userTokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wghub_user_tokens_total", Help: "Keycloak tokens presented on create and renew, by whether they carry the hub audience (ztna) or not (legacy).",
		}, []string{"op", "audience"}),
	}
	m.reg.MustRegister(m.sessions, m.creates, m.decisions, m.revocations, m.conns, m.connsTotal, m.bytes, m.orgGate,
		m.leader, m.handovers, m.handoverNotices, m.rolePatchErrors, m.userTokens)
	// Make zero series visible.
	m.sessions.WithLabelValues("device").Set(0)
	m.sessions.WithLabelValues("client").Set(0)
	for _, r := range []string{"delivered", "delivered_legacy", "failed", "skipped"} {
		m.handoverNotices.WithLabelValues(r)
	}
	for _, r := range []string{"successor", "no_successor", "not_leader"} {
		m.handovers.WithLabelValues(r)
	}
	for _, op := range []string{"create", "renew"} {
		for _, aud := range []string{audienceZTNA, audienceLegacy} {
			m.userTokens.WithLabelValues(op, aud)
		}
	}
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
