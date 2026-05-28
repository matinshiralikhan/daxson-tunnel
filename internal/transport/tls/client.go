// Package tls implements TLS transports using uTLS for client-side
// fingerprint impersonation.
//
// uTLS reproduces the exact ClientHello byte layout — including cipher suite
// ordering, extension ordering, and GREASE values — of real browsers.
// This defeats JA3/JA3S fingerprinting at the DPI level.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"

	utls "github.com/refraction-networking/utls"
)

// ClientTransport dials TLS connections using uTLS browser impersonation.
type ClientTransport struct {
	serverName  string
	fingerprint string // "chrome", "firefox", "edge", "safari", "random"
	nextProtos  []string
	insecure    bool
}

// NewClient creates a new client-side TLS transport.
func NewClient(serverName, fingerprint string, nextProtos []string, insecure bool) *ClientTransport {
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	return &ClientTransport{
		serverName:  serverName,
		fingerprint: fingerprint,
		nextProtos:  nextProtos,
		insecure:    insecure,
	}
}

func (t *ClientTransport) Name() string { return "tls-client" }

// Dial opens a TCP connection, then wraps it with uTLS using the configured
// browser fingerprint. The resulting conn passes TLS fingerprint analysis.
func (t *ClientTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	tcpConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls-client: tcp dial %s: %w", addr, err)
	}

	hello := t.selectHello()
	cfg := &utls.Config{
		ServerName:         t.serverName,
		NextProtos:         t.nextProtos,
		InsecureSkipVerify: t.insecure,
	}

	uconn := utls.UClient(tcpConn, cfg, hello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls-client: handshake %s: %w", addr, err)
	}
	return uconn, nil
}

// Listen is a no-op on the client transport; clients don't listen.
func (t *ClientTransport) Listen(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("tls-client: Listen not supported")
}

// selectHello picks a uTLS ClientHelloID based on the configured fingerprint.
// "random" rotates through Chrome, Firefox, and Edge to prevent static fingerprinting.
func (t *ClientTransport) selectHello() utls.ClientHelloID {
	switch t.fingerprint {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "random":
		profiles := []utls.ClientHelloID{
			utls.HelloChrome_Auto,
			utls.HelloFirefox_Auto,
			utls.HelloEdge_Auto,
		}
		return profiles[rand.Intn(len(profiles))]
	default: // "chrome" and anything else
		return utls.HelloChrome_Auto
	}
}

// ServerTransport listens for TLS connections using a real certificate.
// This is used on server and relay nodes.
type ServerTransport struct {
	certFile string
	keyFile  string
	cfg      *tls.Config
}

// NewServer creates a server-side TLS transport.
func NewServer(certFile, keyFile string, nextProtos []string) (*ServerTransport, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls-server: load cert %s: %w", certFile, err)
	}

	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1"}
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS12,
		// Prefer TLS 1.3 (crypto/tls does this automatically when both sides support it).
		// Cipher suites are left to Go defaults (automatically selects strong ones).
	}

	return &ServerTransport{certFile: certFile, keyFile: keyFile, cfg: cfg}, nil
}

func (t *ServerTransport) Name() string { return "tls-server" }

func (t *ServerTransport) Listen(addr string) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, t.cfg)
	if err != nil {
		return nil, fmt.Errorf("tls-server: listen %s: %w", addr, err)
	}
	return ln, nil
}

func (t *ServerTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("tls-server: Dial not supported")
}
