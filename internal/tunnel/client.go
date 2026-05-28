package tunnel

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/auth"
	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/internal/mux"
	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/internal/obfs"
	tlstransport "github.com/daxson/tunnel/internal/transport/tls"
	"github.com/daxson/tunnel/pkg/protocol"
)

// Client manages a long-lived tunnel session to the server/relay.
// It automatically reconnects on failure using exponential backoff.
//
// Usage:
//
//	c := NewClient(cfg, log, met)
//	go c.Run(ctx)
//	conn, err := c.OpenStream(ctx, protocol.AddrDomain, "example.com", 443)
type Client struct {
	cfg      *config.Config
	log      *zap.Logger
	clientAuth auth.ClientAuth
	met      *metrics.Metrics

	mu      sync.RWMutex
	session *mux.Session

	sessionReady chan struct{}
	reconnects   atomic.Int64
}

// NewClient creates a Client from configuration using HMAC-PSK auth.
func NewClient(cfg *config.Config, log *zap.Logger, met *metrics.Metrics) *Client {
	return &Client{
		cfg:          cfg,
		log:          log,
		clientAuth:   auth.NewHMACClientAuth(cfg.Tunnel.Auth.PSK),
		met:          met,
		sessionReady: make(chan struct{}),
	}
}

// NewClientWithAuth creates a Client with a custom ClientAuth implementation.
// Use this with auth.NewDeviceAuth to authenticate via Ed25519 device identity.
func NewClientWithAuth(cfg *config.Config, log *zap.Logger, met *metrics.Metrics, a auth.ClientAuth) *Client {
	return &Client{
		cfg:          cfg,
		log:          log,
		clientAuth:   a,
		met:          met,
		sessionReady: make(chan struct{}),
	}
}

// Run maintains the tunnel session. It blocks until ctx is cancelled.
// Reconnects are performed with exponential backoff + jitter.
func (c *Client) Run(ctx context.Context) {
	rc := c.cfg.Tunnel.Reconnect
	backoff := rc.BaseDelay.Duration
	attempt := 0

	for {
		c.log.Info("tunnel: dialing server", zap.String("addr", c.cfg.Tunnel.Addr))
		if err := c.connect(ctx); err != nil {
			if ctx.Err() != nil {
				c.log.Info("tunnel: context cancelled, stopping")
				return
			}
			c.log.Warn("tunnel: connection failed",
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)
			c.met.RecordReconnect()

			if rc.MaxRetries >= 0 && attempt >= rc.MaxRetries {
				c.log.Error("tunnel: max retries exceeded, giving up")
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff + jitter(backoff)):
			}

			backoff = time.Duration(math.Min(
				float64(rc.MaxDelay.Duration),
				float64(backoff)*rc.Multiplier,
			))
			attempt++
			continue
		}

		// Connection succeeded; reset backoff.
		backoff = rc.BaseDelay.Duration
		attempt = 0
		c.reconnects.Add(1)
		c.log.Info("tunnel: connected", zap.String("addr", c.cfg.Tunnel.Addr))

		// Block until the session breaks.
		if err := c.runSession(ctx); err != nil && ctx.Err() == nil {
			c.log.Warn("tunnel: session broken", zap.Error(err))
		}
	}
}

// OpenStream opens a new proxied stream to the given target.
// It blocks until a session is available, then opens a smux stream and sends
// the CONNECT request.
func (c *Client) OpenStream(ctx context.Context, addrType protocol.AddrType, addr string, port uint16) (net.Conn, error) {
	sess, err := c.waitSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}

	if err := writeConnectRequest(stream, addrType, addr, port); err != nil {
		stream.Close()
		return nil, fmt.Errorf("tunnel: write connect request: %w", err)
	}

	if err := readConnectResponse(stream); err != nil {
		stream.Close()
		return nil, err
	}

	c.met.RecordStreamOpen()
	return stream, nil
}

// connect dials the server, performs TLS + auth handshake, and stores the session.
func (c *Client) connect(ctx context.Context) error {
	tc := c.cfg.Tunnel
	tr := tlstransport.NewClient(
		tc.TLS.ServerName,
		tc.TLS.Fingerprint,
		tc.TLS.NextProtos,
		tc.TLS.InsecureSkipVerify,
	)

	rawConn, err := tr.Dial(ctx, tc.Addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	if _, err := c.clientAuth.Handshake(rawConn); err != nil {
		rawConn.Close()
		return fmt.Errorf("auth: %w", err)
	}

	// Wrap with Behavioral Camouflage Layer (BCL).
	// BCL intercepts every byte smux writes and shapes timing + frame sizes
	// to match the configured traffic personality profile.
	obfsCfg := obfs.Config{
		Enabled:     tc.Transport.Obfs.Enabled,
		Personality: tc.Transport.Obfs.Personality,
	}
	shapedConn := obfs.Wrap(rawConn, obfsCfg, c.log)

	smuxCfg := mux.SmuxConfig(
		tc.Transport.Mux.MaxStreams,
		tc.Transport.Mux.MaxFrameSize,
		tc.Transport.Mux.ReceiveBuffer,
	)
	sess, err := mux.NewClientSession(shapedConn, smuxCfg)
	if err != nil {
		shapedConn.Close()
		return fmt.Errorf("mux: %w", err)
	}

	c.mu.Lock()
	old := c.session
	c.session = sess
	// Notify waiters that a session is ready.
	select {
	case c.sessionReady <- struct{}{}:
	default:
	}
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}

	c.met.RecordConnect()
	return nil
}

// runSession blocks until the session is broken or ctx is cancelled.
func (c *Client) runSession(ctx context.Context) error {
	c.mu.RLock()
	sess := c.session
	c.mu.RUnlock()

	if sess == nil {
		return fmt.Errorf("tunnel: no session")
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sess.Close()
			return nil
		case <-ticker.C:
			if sess.IsClosed() {
				return fmt.Errorf("session closed")
			}
		}
	}
}

// waitSession waits for a session to be available, respecting ctx cancellation.
func (c *Client) waitSession(ctx context.Context) (*mux.Session, error) {
	for {
		c.mu.RLock()
		sess := c.session
		c.mu.RUnlock()

		if sess != nil && !sess.IsClosed() {
			return sess, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.sessionReady:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// jitter returns a random duration in [0, d/4).
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d / 4)))
}
