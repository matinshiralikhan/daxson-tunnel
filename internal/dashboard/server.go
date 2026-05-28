// Package dashboard provides the Daxson management HTTP panel.
//
// It exposes a REST API at /api/v1/ and serves a single-page HTML dashboard
// at /. The server binds to localhost only and is not exposed publicly.
//
// Endpoints:
//
//	GET  /                          — embedded SPA dashboard
//	GET  /api/v1/status             — server health + device count
//	GET  /api/v1/sessions           — active session snapshots
//	GET  /api/v1/devices            — registered device list
//	DELETE /api/v1/devices/{id}     — revoke device
//	GET  /api/v1/invites            — invite list
//	POST /api/v1/invites            — create invite
//	DELETE /api/v1/invites/{id}     — revoke invite
//	GET  /api/v1/transport-stats    — transport effectiveness
//	GET  /api/v1/probes             — recent probe events
package dashboard

import (
	"context"
	_ "embed"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/internal/telemetry"
	"github.com/daxson/tunnel/pkg/identity"
)

//go:embed ui.html
var uiHTML []byte

// Server is the dashboard HTTP server.
type Server struct {
	addr      string
	reg       *registry.Registry
	collector *telemetry.Collector
	serverKey *identity.KeyPair
	version   string
	log       *zap.Logger
	httpSrv   *http.Server
}

// New creates a dashboard Server.
func New(
	addr string,
	reg *registry.Registry,
	collector *telemetry.Collector,
	serverKey *identity.KeyPair,
	version string,
	log *zap.Logger,
) *Server {
	return &Server{
		addr:      addr,
		reg:       reg,
		collector: collector,
		serverKey: serverKey,
		version:   version,
		log:       log,
	}
}

// Start begins serving the dashboard and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Serve the embedded SPA.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(uiHTML) //nolint:errcheck
	})

	api := newAPI(s.reg, s.collector, s.serverKey, s.version)
	api.register(mux)

	s.httpSrv = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.log.Info("dashboard listening", zap.String("addr", s.addr))

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpSrv.Shutdown(shutCtx) //nolint:errcheck
		return nil
	case err := <-errCh:
		return err
	}
}
