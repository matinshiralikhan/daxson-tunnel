// Package tunnel provides the client and server tunnel orchestration.
//
// This file defines the application-level framing used over smux streams.
// Each smux stream is used for one proxied connection.
//
// Stream opening protocol:
//  1. Stream opener (client) writes a CONNECT request: [AddrType:1][AddrLen:1][Addr:N][Port:2]
//  2. Stream acceptor (server) reads the request, dials the target, writes a CONNECT response.
//  3. CONNECT response: [Status:1] where 0x00=OK, non-zero=error.
//  4. After OK response, both sides relay raw bytes bidirectionally.
package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/daxson/tunnel/pkg/protocol"
)

const (
	connectOK   = 0x00
	connectFail = 0x01
)

// writeConnectRequest writes the target address on a newly opened stream.
func writeConnectRequest(w io.Writer, addrType protocol.AddrType, addr string, port uint16) error {
	addrBytes := []byte(addr)
	if len(addrBytes) > 255 {
		return fmt.Errorf("tunnel: address too long: %d bytes", len(addrBytes))
	}
	buf := make([]byte, 2+len(addrBytes)+2)
	buf[0] = byte(addrType)
	buf[1] = byte(len(addrBytes))
	copy(buf[2:], addrBytes)
	binary.BigEndian.PutUint16(buf[2+len(addrBytes):], port)
	_, err := w.Write(buf)
	return err
}

// readConnectRequest reads the target address from a newly accepted stream.
func readConnectRequest(r io.Reader) (addrType protocol.AddrType, addr string, port uint16, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, "", 0, fmt.Errorf("tunnel: read connect hdr: %w", err)
	}
	addrType = protocol.AddrType(hdr[0])
	addrLen := int(hdr[1])
	if addrLen == 0 {
		return 0, "", 0, fmt.Errorf("tunnel: zero-length address")
	}

	addrBuf := make([]byte, addrLen+2)
	if _, err = io.ReadFull(r, addrBuf); err != nil {
		return 0, "", 0, fmt.Errorf("tunnel: read connect addr: %w", err)
	}
	addr = string(addrBuf[:addrLen])
	port = binary.BigEndian.Uint16(addrBuf[addrLen:])
	return addrType, addr, port, nil
}

// writeConnectResponse writes the status byte after attempting to dial the target.
func writeConnectResponse(w io.Writer, ok bool) error {
	status := byte(connectFail)
	if ok {
		status = connectOK
	}
	_, err := w.Write([]byte{status})
	return err
}

// readConnectResponse reads the server's status byte.
func readConnectResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return fmt.Errorf("tunnel: read connect response: %w", err)
	}
	if status[0] != connectOK {
		return fmt.Errorf("tunnel: server refused connection (status 0x%02x)", status[0])
	}
	return nil
}

// targetAddr formats addr and port into a dial string.
func targetAddr(addr string, port uint16) string {
	return net.JoinHostPort(addr, fmt.Sprintf("%d", port))
}
