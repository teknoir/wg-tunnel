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
	}
	m.reg.MustRegister(m.sessions, m.creates, m.decisions, m.revocations, m.conns, m.connsTotal, m.bytes)
	// Make zero series visible.
	m.sessions.WithLabelValues("device").Set(0)
	m.sessions.WithLabelValues("client").Set(0)
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
