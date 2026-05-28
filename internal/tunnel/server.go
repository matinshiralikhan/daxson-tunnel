package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/auth"
	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/internal/mux"
	"github.com/daxson/tunnel/internal/obfs"
	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/internal/telemetry"
	tlstransport "github.com/daxson/tunnel/internal/transport/tls"
)

// Server listens for tunnel connections and handles each as a mux session.
// For each accepted stream it dials the requested target and relays traffic.
//
// Authentication is dispatched by version byte:
//   - 0x01  HMAC-PSK (relay-to-relay)
//   - 0x02  Ed25519 device auth (registered client)
//   - 0x03  Bootstrap registration (first-time client, invite token)
//   - other → forward to probe upstream (active-probe resistance)
type Server struct {
	cfg           *config.Config
	log           *zap.Logger
	hmacAuth      *auth.Handshaker
	reg           *registry.Registry     // nil = device/bootstrap auth disabled
	collector     *telemetry.Collector   // nil = no telemetry
	met           *metrics.Metrics
	probeUpstream string
	transport     string // TLS persona label for telemetry, e.g. "chrome"
}

// ServerOption configures optional Server behaviour.
type ServerOption func(*Server)

// WithDeviceRegistry enables Ed25519 device auth backed by the given registry.
func WithDeviceRegistry(reg *registry.Registry) ServerOption {
	return func(s *Server) { s.reg = reg }
}

// WithTelemetry attaches a telemetry collector for session tracking.
func WithTelemetry(c *telemetry.Collector) ServerOption {
	return func(s *Server) { s.collector = c }
}

// WithTransportLabel sets the transport persona label recorded in telemetry.
func WithTransportLabel(label string) ServerOption {
	return func(s *Server) { s.transport = label }
}

// NewServer creates a Server from configuration.
func NewServer(cfg *config.Config, log *zap.Logger, met *metrics.Metrics, opts ...ServerOption) *Server {
	s := &Server{
		cfg:           cfg,
		log:           log,
		hmacAuth:      auth.New(cfg.Server.Auth.PSK),
		met:           met,
		probeUpstream: cfg.Server.ProbeUpstream,
		transport:     cfg.Tunnel.TLS.Fingerprint,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ListenAndServe starts the TLS listener and accepts connections until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	sc := s.cfg.Server
	tr, err := tlstransport.NewServer(sc.TLS.CertFile, sc.TLS.KeyFile, sc.TLS.NextProtos)
	if err != nil {
		return fmt.Errorf("server: TLS init: %w", err)
	}

	ln, err := tr.Listen(sc.Listen)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", sc.Listen, err)
	}
	defer ln.Close()

	s.log.Info("tunnel server listening", zap.String("addr", sc.Listen))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("server: accept error", zap.Error(err))
			continue
		}
		s.met.RecordAccept()
		go s.handleConn(ctx, conn)
	}
}

// handleConn runs auth dispatch → mux session → stream loop for one connection.
func (s *Server) handleConn(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()

	remote := rawConn.RemoteAddr().String()
	log := s.log.With(zap.String("remote", remote))

	rawConn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	result, err := auth.ServerDispatch(rawConn, s.hmacAuth, s.reg)
	rawConn.SetDeadline(time.Time{}) //nolint:errcheck

	if err != nil {
		if auth.IsAuthFailed(err) {
			log.Debug("server: auth failed, forwarding to probe upstream")
			s.met.RecordAuthFailure()
			if s.collector != nil {
				s.collector.RecordProbe(remote, "auth_failed")
			}
			s.forwardToProbeUpstream(rawConn)
		} else {
			log.Debug("server: auth error", zap.Error(err))
		}
		return
	}

	log.Debug("server: client authenticated", zap.String("mode", result.Mode))

	tc := s.cfg.Tunnel
	personality := tc.Transport.Obfs.Personality
	if personality == "" {
		personality = "relay"
	}
	obfsCfg := obfs.Config{
		Enabled:     tc.Transport.Obfs.Enabled,
		Personality: personality,
	}
	shapedConn := obfs.Wrap(rawConn, obfsCfg, s.log)

	smuxCfg := mux.SmuxConfig(
		tc.Transport.Mux.MaxStreams,
		tc.Transport.Mux.MaxFrameSize,
		tc.Transport.Mux.ReceiveBuffer,
	)
	sess, err := mux.NewServerSession(shapedConn, smuxCfg)
	if err != nil {
		log.Warn("server: mux session failed", zap.Error(err))
		return
	}
	defer sess.Close()

	s.met.RecordSessionOpen()
	defer s.met.RecordSessionClose()

	// Open a telemetry session record.
	var telSession *telemetry.SessionRecord
	if s.collector != nil {
		deviceID := ""
		deviceLabel := ""
		if result.DevicePub != nil {
			deviceID = string(result.DevicePub[:3]) // short ID placeholder; proper shortID in telemetry
		}
		telSession = s.collector.OpenSession(result.SessionID, deviceID, deviceLabel, remote, s.transport, result.Mode)
		defer s.collector.CloseSession(telSession.SessionID)
	}
	_ = telSession

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() == nil && !sess.IsClosed() {
				log.Debug("server: accept stream error", zap.Error(err))
			}
			return
		}
		go s.handleStream(ctx, stream, log)
	}
}

// handleStream reads the CONNECT request and relays to the target.
func (s *Server) handleStream(ctx context.Context, stream net.Conn, log *zap.Logger) {
	defer stream.Close()
	s.met.RecordStreamOpen()
	defer s.met.RecordStreamClose()

	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	addrType, addr, port, err := readConnectRequest(stream)
	stream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		log.Debug("server: read connect request", zap.Error(err))
		return
	}

	target := targetAddr(addr, port)
	log.Debug("server: connecting to target",
		zap.String("target", target),
		zap.String("addr_type", fmt.Sprintf("0x%02x", byte(addrType))),
	)

	var d net.Dialer
	tconn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Debug("server: dial target failed", zap.String("target", target), zap.Error(err))
		writeConnectResponse(stream, false) //nolint:errcheck
		return
	}
	defer tconn.Close()

	if err := writeConnectResponse(stream, true); err != nil {
		log.Debug("server: write connect response", zap.Error(err))
		return
	}

	s.met.RecordDial(addr, port)
	mux.Relay(stream, tconn)
}

// forwardToProbeUpstream transparently proxies unauthenticated connections to
// a real HTTP server, making active probers see a genuine HTTPS response.
func (s *Server) forwardToProbeUpstream(clientConn net.Conn) {
	if s.probeUpstream == "" {
		return
	}
	upstream, err := net.DialTimeout("tcp", s.probeUpstream, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	mux.Relay(clientConn, upstream)
}
