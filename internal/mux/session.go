// Package mux wraps smux to provide stream-multiplexed sessions over ObfsConns.
//
// Architecture:
//
//	One long-lived TLS+ObfsConn per client ↔ server pair.
//	Multiple logical streams (one per proxied connection) flow over that conn.
//	smux handles per-stream flow control and frame demultiplexing.
//	We add our STREAM_OPEN/STREAM_CLOSE framing for address negotiation.
package mux

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"
)

// smux configuration tuned for hostile network conditions:
//   - Longer keepalive timeout (mobile handoffs can pause traffic for 10+ seconds)
//   - Large receive buffer to absorb bursts without blocking
//   - Version 2 enables stream-level credit flow control
var defaultSmuxConfig = &smux.Config{
	Version:           2,
	KeepAliveInterval: 15 * time.Second,
	KeepAliveTimeout:  45 * time.Second,
	MaxFrameSize:      32768,
	MaxReceiveBuffer:  4 * 1024 * 1024,
	MaxStreamBuffer:   256 * 1024,
}

// Session is a multiplexed session over a single connection.
// A client session dials streams; a server session accepts them.
type Session struct {
	s    *smux.Session
	conn net.Conn
}

// NewClientSession creates a new client-side mux session over conn.
// conn should already be an authenticated, optionally ObfsConn-wrapped TLS conn.
func NewClientSession(conn net.Conn, cfg *smux.Config) (*Session, error) {
	if cfg == nil {
		cfg = defaultSmuxConfig
	}
	s, err := smux.Client(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("mux: client session: %w", err)
	}
	return &Session{s: s, conn: conn}, nil
}

// NewServerSession creates a new server-side mux session over conn.
func NewServerSession(conn net.Conn, cfg *smux.Config) (*Session, error) {
	if cfg == nil {
		cfg = defaultSmuxConfig
	}
	s, err := smux.Server(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("mux: server session: %w", err)
	}
	return &Session{s: s, conn: conn}, nil
}

// OpenStream opens a new bidirectional stream.
// Returns a net.Conn-compatible stream ready for reading and writing.
func (sess *Session) OpenStream() (net.Conn, error) {
	stream, err := sess.s.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("mux: open stream: %w", err)
	}
	return stream, nil
}

// AcceptStream blocks until a new stream is available.
func (sess *Session) AcceptStream() (net.Conn, error) {
	stream, err := sess.s.AcceptStream()
	if err != nil {
		return nil, fmt.Errorf("mux: accept stream: %w", err)
	}
	return stream, nil
}

// IsClosed reports whether the session is closed or broken.
func (sess *Session) IsClosed() bool {
	return sess.s.IsClosed()
}

// NumStreams returns the number of active streams.
func (sess *Session) NumStreams() int {
	return sess.s.NumStreams()
}

// Close shuts down the session and the underlying connection.
func (sess *Session) Close() error {
	serr := sess.s.Close()
	cerr := sess.conn.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// Relay copies bidirectionally between a and b, returning when either side
// closes. Both connections are closed on return.
func Relay(a, b net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(a, b) //nolint:errcheck
		a.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a) //nolint:errcheck
		b.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
}

// SmuxConfig builds a smux.Config from our config values.
func SmuxConfig(maxStreams, maxFrameSize, receiveBuffer int) *smux.Config {
	cfg := *defaultSmuxConfig
	if maxFrameSize > 0 {
		cfg.MaxFrameSize = maxFrameSize
	}
	if receiveBuffer > 0 {
		cfg.MaxReceiveBuffer = receiveBuffer
	}
	return &cfg
}

// ShortKeepaliveConfig returns a smux config with aggressive keepalive intervals
// for use in tests where fast broken-session detection is required.
func ShortKeepaliveConfig() *smux.Config {
	cfg := *defaultSmuxConfig
	cfg.KeepAliveInterval = 1 * time.Second
	cfg.KeepAliveTimeout = 3 * time.Second
	return &cfg
}
