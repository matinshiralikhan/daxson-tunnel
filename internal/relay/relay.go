// Package relay implements relay mode: the Daxson relay accepts tunneled
// connections from clients and forwards each stream to the upstream server.
//
// Topology:
//
//	[Client] --Daxson--> [Relay] --Daxson--> [Server] --> Internet
//
// The relay maintains one long-lived upstream session and maps each
// downstream stream to one upstream stream. It does NOT inspect stream content.
package relay

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
	tlstransport "github.com/daxson/tunnel/internal/transport/tls"
	"github.com/daxson/tunnel/pkg/protocol"
)

// Relay orchestrates both a downstream server and an upstream client.
type Relay struct {
	cfg           *config.Config
	log           *zap.Logger
	downstreamAuth *auth.Handshaker
	upstreamAuth   *auth.Handshaker
	met           *metrics.Metrics

	upstreamSession *mux.Session
}

// New creates a Relay.
func New(cfg *config.Config, log *zap.Logger, met *metrics.Metrics) *Relay {
	return &Relay{
		cfg:            cfg,
		log:            log,
		downstreamAuth: auth.New(cfg.Server.Auth.PSK),
		upstreamAuth:   auth.New(cfg.Upstream.Auth.PSK),
		met:            met,
	}
}

// Run starts the relay. It connects to upstream first, then starts the listener.
func (r *Relay) Run(ctx context.Context) error {
	if err := r.connectUpstream(ctx); err != nil {
		return fmt.Errorf("relay: initial upstream connect: %w", err)
	}

	// Reconnect loop for upstream.
	go r.upstreamMaintain(ctx)

	// Start downstream listener.
	return r.listenDownstream(ctx)
}

// OpenStream implements the Dialer interface for use as an upstream to downstream streams.
// It opens a stream to upstream, sends the CONNECT request, and returns the stream.
func (r *Relay) OpenStream(ctx context.Context, addrType protocol.AddrType, addr string, port uint16) (net.Conn, error) {
	if r.upstreamSession == nil || r.upstreamSession.IsClosed() {
		return nil, fmt.Errorf("relay: upstream not connected")
	}

	stream, err := r.upstreamSession.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("relay: upstream open stream: %w", err)
	}

	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if err := writeConnectRequest(stream, addrType, addr, port); err != nil {
		stream.Close()
		return nil, fmt.Errorf("relay: write connect: %w", err)
	}
	if err := readConnectResponse(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("relay: read connect response: %w", err)
	}
	stream.SetDeadline(time.Time{}) //nolint:errcheck

	return stream, nil
}

// listenDownstream accepts connections from domestic clients.
func (r *Relay) listenDownstream(ctx context.Context) error {
	sc := r.cfg.Server
	tr, err := tlstransport.NewServer(sc.TLS.CertFile, sc.TLS.KeyFile, sc.TLS.NextProtos)
	if err != nil {
		return fmt.Errorf("relay: downstream TLS init: %w", err)
	}

	ln, err := tr.Listen(sc.Listen)
	if err != nil {
		return fmt.Errorf("relay: downstream listen %s: %w", sc.Listen, err)
	}
	defer ln.Close()

	r.log.Info("relay downstream listening", zap.String("addr", sc.Listen))

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.Warn("relay: accept error", zap.Error(err))
			continue
		}
		r.met.RecordConnect()
		go r.handleDownstreamConn(ctx, conn)
	}
}

func (r *Relay) handleDownstreamConn(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()

	log := r.log.With(zap.String("remote", rawConn.RemoteAddr().String()))

	rawConn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := r.downstreamAuth.ServerHandshake(rawConn); err != nil {
		log.Debug("relay: downstream auth failed", zap.Error(err))
		return
	}
	rawConn.SetDeadline(time.Time{}) //nolint:errcheck

	tc := r.cfg.Tunnel
	obfsCfg := obfs.Config{
		Enabled:     tc.Transport.Obfs.Enabled,
		Personality: tc.Transport.Obfs.Personality,
	}
	shapedConn := obfs.Wrap(rawConn, obfsCfg, r.log)

	smuxCfg := mux.SmuxConfig(
		tc.Transport.Mux.MaxStreams,
		tc.Transport.Mux.MaxFrameSize,
		tc.Transport.Mux.ReceiveBuffer,
	)
	sess, err := mux.NewServerSession(shapedConn, smuxCfg)
	if err != nil {
		log.Warn("relay: downstream mux session failed", zap.Error(err))
		return
	}
	defer sess.Close()

	r.met.RecordSessionOpen()
	defer r.met.RecordSessionClose()

	for {
		downStream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() == nil && !sess.IsClosed() {
				log.Debug("relay: accept downstream stream", zap.Error(err))
			}
			return
		}
		go r.bridgeStream(ctx, downStream, log)
	}
}

// bridgeStream connects one downstream stream to one upstream stream.
func (r *Relay) bridgeStream(ctx context.Context, downstream net.Conn, log *zap.Logger) {
	defer downstream.Close()

	// Read the CONNECT request from the downstream client.
	downstream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	addrType, addr, port, err := readConnectRequest(downstream)
	downstream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		log.Debug("relay: read downstream connect", zap.Error(err))
		return
	}

	// Open a stream toward the upstream server for this target.
	upstream, err := r.OpenStream(ctx, addrType, addr, port)
	if err != nil {
		log.Debug("relay: open upstream stream", zap.Error(err))
		writeConnectResponse(downstream, false) //nolint:errcheck
		return
	}
	defer upstream.Close()

	if err := writeConnectResponse(downstream, true); err != nil {
		log.Debug("relay: write downstream response", zap.Error(err))
		return
	}

	log.Debug("relay: bridging stream",
		zap.String("addr", addr),
		zap.Uint16("port", port),
	)
	mux.Relay(downstream, upstream)
}

// connectUpstream establishes the authenticated mux session to the foreign server.
func (r *Relay) connectUpstream(ctx context.Context) error {
	uc := r.cfg.Upstream
	tr := tlstransport.NewClient(
		uc.TLS.ServerName,
		uc.TLS.Fingerprint,
		uc.TLS.NextProtos,
		uc.TLS.InsecureSkipVerify,
	)

	rawConn, err := tr.Dial(ctx, uc.Addr)
	if err != nil {
		return fmt.Errorf("upstream dial: %w", err)
	}

	if _, err := r.upstreamAuth.ClientHandshake(rawConn); err != nil {
		rawConn.Close()
		return fmt.Errorf("upstream auth: %w", err)
	}

	tc := r.cfg.Tunnel
	// Upstream (relay → foreign server) uses "browser" personality by default
	// so it resembles a browser connecting to the foreign VPS.
	upstreamPersonality := tc.Transport.Obfs.Personality
	if upstreamPersonality == "" {
		upstreamPersonality = "browser"
	}
	obfsCfg := obfs.Config{
		Enabled:     tc.Transport.Obfs.Enabled,
		Personality: upstreamPersonality,
	}
	shapedConn := obfs.Wrap(rawConn, obfsCfg, r.log)

	smuxCfg := mux.SmuxConfig(
		tc.Transport.Mux.MaxStreams,
		tc.Transport.Mux.MaxFrameSize,
		tc.Transport.Mux.ReceiveBuffer,
	)
	sess, err := mux.NewClientSession(shapedConn, smuxCfg)
	if err != nil {
		shapedConn.Close()
		return fmt.Errorf("upstream mux: %w", err)
	}

	if r.upstreamSession != nil {
		r.upstreamSession.Close()
	}
	r.upstreamSession = sess

	r.log.Info("relay: upstream connected", zap.String("addr", uc.Addr))
	return nil
}

// upstreamMaintain reconnects to upstream if the session breaks.
func (r *Relay) upstreamMaintain(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		if r.upstreamSession != nil && !r.upstreamSession.IsClosed() {
			continue
		}

		r.log.Warn("relay: upstream session broken, reconnecting")
		if err := r.connectUpstream(ctx); err != nil {
			r.log.Warn("relay: upstream reconnect failed", zap.Error(err))
		}
	}
}

// writeConnectRequest and readConnectResponse are duplicated from tunnel/protocol.go
// for package isolation. In a larger codebase, extract to a shared internal package.

func writeConnectRequest(w interface{ Write([]byte) (int, error) }, addrType protocol.AddrType, addr string, port uint16) error {
	addrBytes := []byte(addr)
	buf := make([]byte, 2+len(addrBytes)+2)
	buf[0] = byte(addrType)
	buf[1] = byte(len(addrBytes))
	copy(buf[2:], addrBytes)
	buf[2+len(addrBytes)] = byte(port >> 8)
	buf[3+len(addrBytes)] = byte(port)
	_, err := w.Write(buf)
	return err
}

func readConnectResponse(r interface{ Read([]byte) (int, error) }) error {
	var status [1]byte
	for n := 0; n < 1; {
		nn, err := r.Read(status[n:])
		n += nn
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
	}
	if status[0] != 0x00 {
		return fmt.Errorf("relay: upstream refused (status 0x%02x)", status[0])
	}
	return nil
}

func readConnectRequest(r interface{ Read([]byte) (int, error) }) (protocol.AddrType, string, uint16, error) {
	hdr := make([]byte, 2)
	for n := 0; n < 2; {
		nn, err := r.Read(hdr[n:])
		n += nn
		if err != nil {
			return 0, "", 0, err
		}
	}
	addrType := protocol.AddrType(hdr[0])
	addrLen := int(hdr[1])
	rest := make([]byte, addrLen+2)
	for n := 0; n < len(rest); {
		nn, err := r.Read(rest[n:])
		n += nn
		if err != nil {
			return 0, "", 0, err
		}
	}
	addr := string(rest[:addrLen])
	port := uint16(rest[addrLen])<<8 | uint16(rest[addrLen+1])
	return addrType, addr, port, nil
}

func writeConnectResponse(w interface{ Write([]byte) (int, error) }, ok bool) error {
	b := byte(0x01)
	if ok {
		b = 0x00
	}
	_, err := w.Write([]byte{b})
	return err
}
