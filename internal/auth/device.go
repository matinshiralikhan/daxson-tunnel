// Device authentication and bootstrap protocol implementation.
//
// This file adds two new auth modes alongside the existing HMAC-PSK path:
//
//	0x02  Ed25519 device auth — authenticated device connecting normally.
//	0x03  Bootstrap           — first-time registration using an invite token.
//
// ServerDispatch reads the version byte and routes to the correct handler.
// For clients, DeviceAuth and BootstrapClient implement the ClientAuth interface.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/pkg/identity"
	"github.com/daxson/tunnel/pkg/invite"
	"github.com/daxson/tunnel/pkg/protocol"
)

// ClientAuth is implemented by anything that can authenticate as a client over
// an established TLS connection.
type ClientAuth interface {
	Handshake(conn net.Conn) ([16]byte, error)
}

// ── HMAC auth wrapper (implements ClientAuth) ─────────────────────────────────

type hmacClientAuth struct{ h *Handshaker }

// NewHMACClientAuth wraps a PSK Handshaker to satisfy ClientAuth.
func NewHMACClientAuth(psk string) ClientAuth {
	return &hmacClientAuth{h: New(psk)}
}

func (a *hmacClientAuth) Handshake(conn net.Conn) ([16]byte, error) {
	return a.h.ClientHandshake(conn)
}

// ── Ed25519 device auth (implements ClientAuth) ───────────────────────────────

// DeviceAuth performs Ed25519 device authentication using the device key pair.
type DeviceAuth struct {
	kp *identity.KeyPair
}

// NewDeviceAuth creates a ClientAuth backed by an Ed25519 key pair.
func NewDeviceAuth(kp *identity.KeyPair) ClientAuth {
	return &DeviceAuth{kp: kp}
}

func (a *DeviceAuth) Handshake(conn net.Conn) ([16]byte, error) {
	var zero [16]byte

	req := &invite.DeviceAuthRequest{
		Version:    invite.MsgTypeDeviceAuth,
		TimeBucket: uint64(time.Now().Unix() / 30),
	}
	rand.Read(req.Nonce[:]) //nolint:errcheck
	copy(req.PubKey[:], a.kp.PublicKey)

	// Signed message: PubKey(32) || Nonce(16) || TimeBucket(8).
	var msg [56]byte
	copy(msg[:32], req.PubKey[:])
	copy(msg[32:48], req.Nonce[:])
	binary.BigEndian.PutUint64(msg[48:], req.TimeBucket)
	copy(req.Sig[:], a.kp.Sign(msg[:]))

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(req.Marshal()); err != nil {
		return zero, fmt.Errorf("device auth: send: %w", err)
	}

	buf := make([]byte, invite.DeviceAuthResponseSize)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, buf); err != nil {
		return zero, fmt.Errorf("device auth: recv: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	resp, err := invite.UnmarshalDeviceAuthResponse(buf)
	if err != nil {
		return zero, err
	}

	switch resp.Status {
	case invite.AuthStatusOK:
		return resp.SessionID, nil
	case invite.AuthStatusRevoked:
		return zero, errors.New("device auth: device has been revoked")
	case invite.AuthStatusUnknown:
		return zero, errors.New("device auth: device not registered — run 'daxson import <link>'")
	default:
		return zero, fmt.Errorf("device auth: rejected (0x%02x)", resp.Status)
	}
}

// ── Server-side auth dispatch ─────────────────────────────────────────────────

// ServerAuthResult holds the outcome of a successful server-side handshake.
type ServerAuthResult struct {
	SessionID [16]byte
	DevicePub ed25519.PublicKey // nil for HMAC auth
	Mode      string            // "hmac", "device", or "bootstrap"
}

// ServerDispatch reads the version byte from conn and routes to the appropriate
// auth handler. Returns errAuthFailed (detected by IsAuthFailed) when the version
// byte is unrecognised, signalling the caller to forward to probe upstream.
//
// reg may be nil; if nil, device and bootstrap auth are rejected (relay mode).
func ServerDispatch(conn net.Conn, hmacHS *Handshaker, reg *registry.Registry) (*ServerAuthResult, error) {
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck

	var vb [1]byte
	if _, err := io.ReadFull(conn, vb[:]); err != nil {
		return nil, fmt.Errorf("auth dispatch: read version: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	switch vb[0] {
	case protocol.ProtocolVersion: // 0x01 — HMAC-PSK
		// Re-assemble the full frame for the HMAC handshaker by prepending vb.
		rw := struct {
			io.Reader
			io.Writer
		}{
			Reader: io.MultiReader(bytes.NewReader(vb[:]), conn),
			Writer: conn,
		}
		sid, err := hmacHS.ServerHandshake(rw)
		if err != nil {
			return nil, err
		}
		return &ServerAuthResult{SessionID: sid, Mode: "hmac"}, nil

	case invite.MsgTypeDeviceAuth: // 0x02
		if reg == nil {
			writeDeviceAuthFail(conn, invite.AuthStatusRejected)
			return nil, errAuthFailed
		}
		return deviceServerHandshake(conn, vb[:], reg)

	case invite.MsgTypeBootstrap: // 0x03
		if reg == nil {
			writeBootstrapFail(conn, invite.BootstrapStatusInvalidToken)
			return nil, errAuthFailed
		}
		return bootstrapServerHandshake(conn, vb[:], reg)

	default:
		return nil, errAuthFailed
	}
}

// deviceServerHandshake handles an Ed25519 device auth request.
func deviceServerHandshake(conn net.Conn, firstByte []byte, reg *registry.Registry) (*ServerAuthResult, error) {
	remaining := make([]byte, invite.DeviceAuthRequestSize-1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return nil, fmt.Errorf("device auth server: read: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	full := append(append([]byte{}, firstByte...), remaining...)
	req, err := invite.UnmarshalDeviceAuthRequest(full)
	if err != nil {
		return nil, err
	}

	// Time bucket anti-replay: accept current and adjacent buckets (±30s).
	now := uint64(time.Now().Unix() / 30)
	if req.TimeBucket < now-1 || req.TimeBucket > now+1 {
		writeDeviceAuthFail(conn, invite.AuthStatusRejected)
		return nil, errors.New("device auth server: stale time bucket")
	}

	// Verify signature over PubKey || Nonce || TimeBucket.
	var msg [56]byte
	copy(msg[:32], req.PubKey[:])
	copy(msg[32:48], req.Nonce[:])
	binary.BigEndian.PutUint64(msg[48:], req.TimeBucket)

	pub := ed25519.PublicKey(req.PubKey[:])
	if !identity.Verify(pub, msg[:], req.Sig[:]) {
		writeDeviceAuthFail(conn, invite.AuthStatusRejected)
		return nil, errors.New("device auth server: invalid signature")
	}

	status := reg.AuthorizeDevice(pub)
	var sid [16]byte
	rand.Read(sid[:]) //nolint:errcheck

	resp := &invite.DeviceAuthResponse{Status: status, SessionID: sid}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	conn.Write(resp.Marshal())                             //nolint:errcheck
	conn.SetWriteDeadline(time.Time{})                    //nolint:errcheck

	if status != invite.AuthStatusOK {
		return nil, errAuthFailed
	}
	return &ServerAuthResult{SessionID: sid, DevicePub: pub, Mode: "device"}, nil
}

// bootstrapServerHandshake handles a first-time device registration.
func bootstrapServerHandshake(conn net.Conn, firstByte []byte, reg *registry.Registry) (*ServerAuthResult, error) {
	remaining := make([]byte, invite.BootstrapRequestSize-1)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return nil, fmt.Errorf("bootstrap server: read: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	full := append(append([]byte{}, firstByte...), remaining...)
	req, err := invite.UnmarshalBootstrapRequest(full)
	if err != nil {
		return nil, err
	}

	label := nullTrimBytes(req.Label[:])
	pub := ed25519.PublicKey(req.DevicePub[:])

	status, regErr := reg.Bootstrap(req.Token[:], pub, label)

	var sid [16]byte
	rand.Read(sid[:]) //nolint:errcheck

	resp := &invite.BootstrapResponse{Status: status, SessionID: sid}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	conn.Write(resp.Marshal())                             //nolint:errcheck
	conn.SetWriteDeadline(time.Time{})                    //nolint:errcheck

	if regErr != nil {
		return nil, fmt.Errorf("bootstrap server: %w", regErr)
	}
	if status != invite.BootstrapStatusOK {
		return nil, errAuthFailed
	}
	return &ServerAuthResult{SessionID: sid, DevicePub: pub, Mode: "bootstrap"}, nil
}

// BootstrapClient sends a bootstrap request to register a new device.
// Called by `daxson import` after parsing the invite link.
func BootstrapClient(conn net.Conn, token []byte, kp *identity.KeyPair, label string) ([16]byte, error) {
	var zero [16]byte

	req := &invite.BootstrapRequest{Version: invite.MsgTypeBootstrap}
	copy(req.Token[:], token)
	copy(req.DevicePub[:], kp.PublicKey)
	lb := []byte(label)
	if len(lb) > 64 {
		lb = lb[:64]
	}
	copy(req.Label[:], lb)
	rand.Read(req.Nonce[:]) //nolint:errcheck

	conn.SetWriteDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(req.Marshal()); err != nil {
		return zero, fmt.Errorf("bootstrap: send: %w", err)
	}

	buf := make([]byte, invite.BootstrapResponseSize)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, buf); err != nil {
		return zero, fmt.Errorf("bootstrap: recv: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	resp, err := invite.UnmarshalBootstrapResponse(buf)
	if err != nil {
		return zero, err
	}

	switch resp.Status {
	case invite.BootstrapStatusOK:
		return resp.SessionID, nil
	case invite.BootstrapStatusInvalidToken:
		return zero, errors.New("bootstrap: invalid token — invite link may be wrong or for a different server")
	case invite.BootstrapStatusExpired:
		return zero, errors.New("bootstrap: invite has expired")
	case invite.BootstrapStatusUsed:
		return zero, errors.New("bootstrap: invite has already been used")
	default:
		return zero, fmt.Errorf("bootstrap: rejected (0x%02x)", resp.Status)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeDeviceAuthFail(conn net.Conn, status uint8) {
	var sid [16]byte
	rand.Read(sid[:]) //nolint:errcheck
	resp := &invite.DeviceAuthResponse{Status: status, SessionID: sid}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	conn.Write(resp.Marshal())                             //nolint:errcheck
}

func writeBootstrapFail(conn net.Conn, status uint8) {
	var sid [16]byte
	rand.Read(sid[:]) //nolint:errcheck
	resp := &invite.BootstrapResponse{Status: status, SessionID: sid}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	conn.Write(resp.Marshal())                             //nolint:errcheck
}

func nullTrimBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
