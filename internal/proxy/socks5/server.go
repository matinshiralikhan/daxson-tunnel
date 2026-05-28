// Package socks5 implements a SOCKS5 inbound proxy server (RFC 1928).
// Each incoming SOCKS5 connection results in a call to Dialer.OpenStream
// which opens a stream through the tunnel to the remote target.
package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/pkg/protocol"
)

// Dialer is implemented by tunnel.Client and relay.Client.
type Dialer interface {
	OpenStream(ctx context.Context, addrType protocol.AddrType, addr string, port uint16) (net.Conn, error)
}

// Server is a SOCKS5 proxy server that tunnels connections via Dialer.
type Server struct {
	addr   string
	dialer Dialer
	log    *zap.Logger
	met    *metrics.Metrics
}

// NewServer creates a SOCKS5 server.
func NewServer(addr string, dialer Dialer, log *zap.Logger, met *metrics.Metrics) *Server {
	return &Server{addr: addr, dialer: dialer, log: log, met: met}
}

// ListenAndServe starts the SOCKS5 listener and blocks until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", s.addr, err)
	}
	defer ln.Close()

	s.log.Info("socks5 proxy listening", zap.String("addr", s.addr))

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
			s.log.Warn("socks5: accept error", zap.Error(err))
			continue
		}
		s.met.RecordProxyAccept("socks5")
		go s.handleConn(ctx, conn)
	}
}

const (
	socks5Version = 0x05

	// Auth methods
	methodNoAuth   = 0x00
	methodNoAccept = 0xFF

	// Commands
	cmdConnect = 0x01

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repConnRefused     = 0x05
	repCommandNotSupp  = 0x07
	repAddrTypeNotSupp = 0x08
)

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck

	// 1. Auth negotiation
	if err := s.negotiate(conn); err != nil {
		s.log.Debug("socks5: negotiate", zap.Error(err))
		return
	}

	// 2. Read CONNECT request
	addrType, addr, port, err := s.readRequest(conn)
	if err != nil {
		s.log.Debug("socks5: read request", zap.Error(err))
		return
	}

	conn.SetDeadline(time.Time{}) //nolint:errcheck

	// 3. Open tunnel stream
	s.log.Debug("socks5: connecting", zap.String("addr", addr), zap.Uint16("port", port))

	stream, err := s.dialer.OpenStream(ctx, addrType, addr, port)
	if err != nil {
		s.log.Debug("socks5: tunnel open stream", zap.Error(err))
		sendReply(conn, repGeneralFailure)
		return
	}
	defer stream.Close()

	if err := sendReply(conn, repSuccess); err != nil {
		s.log.Debug("socks5: send reply", zap.Error(err))
		return
	}

	// 4. Relay
	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, conn); stream.Close(); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(conn, stream); conn.Close(); done <- struct{}{} }()   //nolint:errcheck
	<-done
	<-done
}

// negotiate performs the SOCKS5 method selection handshake.
// We only support NO AUTH (0x00).
func (s *Server) negotiate(rw io.ReadWriter) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", hdr[0])
	}

	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Accept NO AUTH if offered, reject otherwise.
	for _, m := range methods {
		if m == methodNoAuth {
			_, err := rw.Write([]byte{socks5Version, methodNoAuth})
			return err
		}
	}

	rw.Write([]byte{socks5Version, methodNoAccept}) //nolint:errcheck
	return fmt.Errorf("no acceptable auth method")
}

// readRequest reads a SOCKS5 CMD request and returns the target address.
func (s *Server) readRequest(r io.Reader) (protocol.AddrType, string, uint16, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, "", 0, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != socks5Version {
		return 0, "", 0, fmt.Errorf("unexpected version byte: %d", hdr[0])
	}
	if hdr[1] != cmdConnect {
		return 0, "", 0, fmt.Errorf("unsupported command: %d", hdr[1])
	}
	// hdr[2] is reserved (must be 0x00)

	var (
		addr     string
		addrType protocol.AddrType
	)

	switch hdr[3] {
	case atypIPv4:
		addrType = protocol.AddrIPv4
		ipbuf := make([]byte, 4)
		if _, err := io.ReadFull(r, ipbuf); err != nil {
			return 0, "", 0, fmt.Errorf("read IPv4: %w", err)
		}
		addr = net.IP(ipbuf).String()

	case atypDomain:
		addrType = protocol.AddrDomain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return 0, "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, domBuf); err != nil {
			return 0, "", 0, fmt.Errorf("read domain: %w", err)
		}
		addr = string(domBuf)

	case atypIPv6:
		addrType = protocol.AddrIPv6
		ipbuf := make([]byte, 16)
		if _, err := io.ReadFull(r, ipbuf); err != nil {
			return 0, "", 0, fmt.Errorf("read IPv6: %w", err)
		}
		addr = net.IP(ipbuf).String()

	default:
		return 0, "", 0, fmt.Errorf("unsupported address type: %d", hdr[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return 0, "", 0, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return addrType, addr, port, nil
}

// sendReply writes a SOCKS5 reply with the given status code.
// The BND.ADDR and BND.PORT fields are zeroed (0.0.0.0:0).
func sendReply(w io.Writer, code byte) error {
	reply := []byte{
		socks5Version, code, 0x00,
		atypIPv4, 0, 0, 0, 0, // BND.ADDR = 0.0.0.0
		0, 0, // BND.PORT = 0
	}
	_, err := w.Write(reply)
	return err
}
