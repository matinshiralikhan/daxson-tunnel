// Package metrics provides Prometheus metrics for Daxson.
//
// Exposed metrics:
//
//	daxson_connections_total{direction}     - cumulative connections established
//	daxson_sessions_active                  - currently active mux sessions
//	daxson_streams_active                   - currently active streams
//	daxson_reconnects_total                 - client reconnect events
//	daxson_auth_failures_total              - server auth failures
//	daxson_proxy_accepts_total{proxy_type}  - inbound proxy connections accepted
//	daxson_dials_total{addr,port}           - outbound dials from server
//	daxson_bytes_sent_total                 - bytes sent through tunnel
//	daxson_bytes_recv_total                 - bytes received through tunnel
package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Metrics holds all Prometheus metric objects.
type Metrics struct {
	connectionsTotal *prometheus.CounterVec
	sessionsActive   prometheus.Gauge
	streamsActive    prometheus.Gauge
	reconnectsTotal  prometheus.Counter
	authFailures     prometheus.Counter
	proxyAccepts     *prometheus.CounterVec
	dialsTotal       *prometheus.CounterVec
	bytesSent        prometheus.Counter
	bytesRecv        prometheus.Counter
}

// New creates and registers all metrics. Call once at startup.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)

	return &Metrics{
		connectionsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "daxson_connections_total",
			Help: "Total tunnel connections established.",
		}, []string{"direction"}),

		sessionsActive: factory.NewGauge(prometheus.GaugeOpts{
			Name: "daxson_sessions_active",
			Help: "Number of currently active mux sessions.",
		}),

		streamsActive: factory.NewGauge(prometheus.GaugeOpts{
			Name: "daxson_streams_active",
			Help: "Number of currently active tunnel streams.",
		}),

		reconnectsTotal: factory.NewCounter(prometheus.CounterOpts{
			Name: "daxson_reconnects_total",
			Help: "Total client reconnect events.",
		}),

		authFailures: factory.NewCounter(prometheus.CounterOpts{
			Name: "daxson_auth_failures_total",
			Help: "Total authentication failures.",
		}),

		proxyAccepts: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "daxson_proxy_accepts_total",
			Help: "Total inbound proxy connections accepted.",
		}, []string{"proxy_type"}),

		dialsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "daxson_dials_total",
			Help: "Total outbound dials from server.",
		}, []string{"addr"}),

		bytesSent: factory.NewCounter(prometheus.CounterOpts{
			Name: "daxson_bytes_sent_total",
			Help: "Total bytes sent through the tunnel.",
		}),

		bytesRecv: factory.NewCounter(prometheus.CounterOpts{
			Name: "daxson_bytes_recv_total",
			Help: "Total bytes received through the tunnel.",
		}),
	}
}

// RecordConnect records an outbound connection (client side).
func (m *Metrics) RecordConnect() {
	m.connectionsTotal.WithLabelValues("outbound").Inc()
}

// RecordAccept records an inbound connection (server side).
func (m *Metrics) RecordAccept() {
	m.connectionsTotal.WithLabelValues("inbound").Inc()
}

// RecordReconnect records a client reconnect event.
func (m *Metrics) RecordReconnect() { m.reconnectsTotal.Inc() }

// RecordAuthFailure records a server-side auth failure.
func (m *Metrics) RecordAuthFailure() { m.authFailures.Inc() }

// RecordSessionOpen increments the active session gauge.
func (m *Metrics) RecordSessionOpen() { m.sessionsActive.Inc() }

// RecordSessionClose decrements the active session gauge.
func (m *Metrics) RecordSessionClose() { m.sessionsActive.Dec() }

// RecordStreamOpen increments the active stream gauge.
func (m *Metrics) RecordStreamOpen() { m.streamsActive.Inc() }

// RecordStreamClose decrements the active stream gauge.
func (m *Metrics) RecordStreamClose() { m.streamsActive.Dec() }

// RecordProxyAccept records an inbound proxy connection.
func (m *Metrics) RecordProxyAccept(proxyType string) {
	m.proxyAccepts.WithLabelValues(proxyType).Inc()
}

// RecordDial records a server-side outbound dial.
func (m *Metrics) RecordDial(addr string, port uint16) {
	label := fmt.Sprintf("%s:%d", addr, port)
	if len(label) > 64 {
		label = label[:64]
	}
	m.dialsTotal.WithLabelValues(label).Inc()
}

// AddBytesSent adds n to the bytes-sent counter.
func (m *Metrics) AddBytesSent(n int64) { m.bytesSent.Add(float64(n)) }

// AddBytesRecv adds n to the bytes-received counter.
func (m *Metrics) AddBytesRecv(n int64) { m.bytesRecv.Add(float64(n)) }

// Serve starts the Prometheus HTTP server on addr.
func Serve(ctx context.Context, addr string, log *zap.Logger) {
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n")) //nolint:errcheck
	})

	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Info("metrics server listening", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server error", zap.Error(err))
		}
	}()

	go func() {
		<-ctx.Done()
		srv.Close() //nolint:errcheck
	}()
}
