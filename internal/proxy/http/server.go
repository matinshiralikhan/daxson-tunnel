// Package http implements an HTTP/HTTPS CONNECT proxy inbound.
// HTTP CONNECT is used by browsers and tools to tunnel HTTPS through HTTP proxies.
package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/pkg/protocol"
)

// Dialer is implemented by tunnel.Client.
type Dialer interface {
	OpenStream(ctx context.Context, addrType protocol.AddrType, addr string, port uint16) (net.Conn, error)
}

// Server is an HTTP CONNECT proxy server.
type Server struct {
	addr   string
	dialer Dialer
	log    *zap.Logger
	met    *metrics.Metrics
}

// NewServer creates an HTTP CONNECT proxy server.
func NewServer(addr string, dialer Dialer, log *zap.Logger, met *metrics.Metrics) *Server {
	return &Server{addr: addr, dialer: dialer, log: log, met: met}
}

// ListenAndServe starts the HTTP proxy listener.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("http proxy: listen %s: %w", s.addr, err)
	}
	defer ln.Close()

	s.log.Info("http proxy listening", zap.String("addr", s.addr))

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
			continue
		}
		s.met.RecordProxyAccept("http")
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Time{}) //nolint:errcheck

	if req.Method != http.MethodConnect {
		// For non-CONNECT requests, return a minimal 400.
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) //nolint:errcheck
		return
	}

	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		// Assume port 443 if not specified.
		host = req.Host
		portStr = "443"
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) //nolint:errcheck
		return
	}

	addrType := protocol.AddrDomain
	if net.ParseIP(host) != nil {
		if strings.Contains(host, ":") {
			addrType = protocol.AddrIPv6
		} else {
			addrType = protocol.AddrIPv4
		}
	}

	stream, err := s.dialer.OpenStream(ctx, addrType, host, uint16(port))
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) //nolint:errcheck
		return
	}
	defer stream.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) //nolint:errcheck

	// If the bufio reader has buffered data from after the CONNECT request, drain it first.
	buffered := br.Buffered()
	if buffered > 0 {
		buf := make([]byte, buffered)
		br.Read(buf) //nolint:errcheck
		stream.Write(buf) //nolint:errcheck
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, conn); stream.Close(); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(conn, stream); conn.Close(); done <- struct{}{} }()   //nolint:errcheck
	<-done
	<-done
}
