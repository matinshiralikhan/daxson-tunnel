// Package invite implements the daxson:// invite link format and the device
// authentication wire protocol.
//
// # Invite link format
//
//	daxson://v1/<base64url(json_payload)>
//
// The JSON payload carries the server address, a bootstrap token, the server's
// Ed25519 public key for signature verification, and an optional expiry. The
// payload is signed by the server's identity key so clients can verify
// authenticity before connecting.
//
// # Wire message types (sent inside TLS after the encrypted channel is established)
//
//	0x01  HMAC-SHA256 PSK auth   — legacy relay-to-relay auth
//	0x02  Ed25519 device auth    — registered device connecting
//	0x03  Bootstrap registration — first-time device registration with invite token
//
// All messages have fixed wire sizes to prevent traffic analysis via message
// length; the server reads exactly N bytes then dispatches.
package invite

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ── Invite link ───────────────────────────────────────────────────────────────

// Scheme is the URI scheme prefix for Daxson invite links.
const Scheme = "daxson://v1/"

// Payload is the decoded body of a daxson:// invite URL.
type Payload struct {
	Version   int    `json:"v"`
	Server    string `json:"server"`             // host:port to connect to
	ServerKey []byte `json:"server_key"`         // Ed25519 server identity pubkey (32 bytes)
	Token     []byte `json:"token"`              // 32-byte bootstrap credential
	Label     string `json:"label,omitempty"`    // human-readable invite name
	MaxUses   int    `json:"max_uses,omitempty"` // 0 = single-use
	ExpiresAt int64  `json:"expires,omitempty"`  // Unix seconds; 0 = no expiry
	Sig       []byte `json:"sig,omitempty"`      // Ed25519 signature by server identity key
}

// Encode serialises a signed payload to a daxson:// URL.
func Encode(p *Payload) string {
	data, _ := json.Marshal(p)
	return Scheme + base64.RawURLEncoding.EncodeToString(data)
}

// Decode parses a daxson:// URL and returns the payload without verifying the
// signature. Call VerifySignature on the returned payload for full validation.
func Decode(link string) (*Payload, error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, Scheme) {
		peek := link
		if len(peek) > 40 {
			peek = peek[:40] + "..."
		}
		return nil, fmt.Errorf("invite: not a daxson:// link (got %q)", peek)
	}
	encoded := link[len(Scheme):]
	// Accept both padded and unpadded base64url (some terminals add padding).
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("invite: invalid base64: %w", err)
		}
	}
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invite: parse payload: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("invite: unsupported version %d (need v1)", p.Version)
	}
	if p.Server == "" {
		return nil, errors.New("invite: missing server address")
	}
	if len(p.Token) != 32 {
		return nil, fmt.Errorf("invite: token must be 32 bytes (got %d)", len(p.Token))
	}
	return &p, nil
}

// Sign sets p.Sig using the server's Ed25519 private key.
// Call this before Encode.
func (p *Payload) Sign(serverPrivKey ed25519.PrivateKey) error {
	p.Sig = nil
	msg, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("invite: marshal for sign: %w", err)
	}
	p.Sig = ed25519.Sign(serverPrivKey, msg)
	return nil
}

// VerifySignature checks the server's Ed25519 signature on this payload.
func (p *Payload) VerifySignature() error {
	if len(p.ServerKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invite: server key length %d != 32", len(p.ServerKey))
	}
	if len(p.Sig) == 0 {
		return errors.New("invite: missing signature")
	}
	// Save and clear Sig so the signed message can be reproduced.
	sig := p.Sig
	p.Sig = nil
	defer func() { p.Sig = sig }()

	msg, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("invite: marshal for verify: %w", err)
	}
	if !ed25519.Verify(p.ServerKey, msg, sig) {
		return errors.New("invite: signature verification failed — link may be tampered")
	}
	return nil
}

// IsExpired reports whether the invite has passed its expiry time.
func (p *Payload) IsExpired() bool {
	return p.ExpiresAt != 0 && time.Now().Unix() > p.ExpiresAt
}

// TokenFingerprint returns an 8-char hex ID derived from the token for display.
func (p *Payload) TokenFingerprint() string {
	h := sha256.Sum256(p.Token)
	return fmt.Sprintf("%x", h[:4])
}

// GenerateToken creates a cryptographically random 32-byte bootstrap token.
func GenerateToken() ([]byte, error) {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("invite: generate token: %w", err)
	}
	return tok, nil
}

// ── Wire protocol constants ───────────────────────────────────────────────────

// Message type bytes — the first byte of every auth frame.
const (
	MsgTypeHMACAuth   = 0x01 // HMAC-SHA256 PSK auth (relay-to-relay)
	MsgTypeDeviceAuth = 0x02 // Ed25519 device auth
	MsgTypeBootstrap  = 0x03 // first-time device registration
)

// Device auth response status codes.
const (
	AuthStatusOK       = 0x00
	AuthStatusRejected = 0x01
	AuthStatusRevoked  = 0x02
	AuthStatusUnknown  = 0x03 // device not registered
)

// Bootstrap response status codes.
const (
	BootstrapStatusOK           = 0x00
	BootstrapStatusInvalidToken = 0x01
	BootstrapStatusExpired      = 0x02
	BootstrapStatusUsed         = 0x03
)

// ── DeviceAuthRequest ─────────────────────────────────────────────────────────

// DeviceAuthRequest is the fixed-size message sent by a registered device.
// Wire size: 1 + 32 + 16 + 8 + 64 = 121 bytes.
//
//	[Version:1][PubKey:32][Nonce:16][TimeBucket:8][Sig:64]
//
// Sig covers PubKey || Nonce || TimeBucket (56 bytes total).
type DeviceAuthRequest struct {
	Version    uint8
	PubKey     [ed25519.PublicKeySize]byte  // 32 bytes
	Nonce      [16]byte
	TimeBucket uint64 // Unix/30; anti-replay window ±1 bucket (30s each)
	Sig        [ed25519.SignatureSize]byte  // 64 bytes
}

const DeviceAuthRequestSize = 1 + 32 + 16 + 8 + 64 // 121

func (r *DeviceAuthRequest) Marshal() []byte {
	buf := make([]byte, DeviceAuthRequestSize)
	buf[0] = r.Version
	copy(buf[1:33], r.PubKey[:])
	copy(buf[33:49], r.Nonce[:])
	binary.BigEndian.PutUint64(buf[49:57], r.TimeBucket)
	copy(buf[57:], r.Sig[:])
	return buf
}

func UnmarshalDeviceAuthRequest(b []byte) (*DeviceAuthRequest, error) {
	if len(b) < DeviceAuthRequestSize {
		return nil, fmt.Errorf("device auth request: need %d bytes, got %d", DeviceAuthRequestSize, len(b))
	}
	r := &DeviceAuthRequest{Version: b[0]}
	copy(r.PubKey[:], b[1:33])
	copy(r.Nonce[:], b[33:49])
	r.TimeBucket = binary.BigEndian.Uint64(b[49:57])
	copy(r.Sig[:], b[57:121])
	return r, nil
}

// ── DeviceAuthResponse ────────────────────────────────────────────────────────

// DeviceAuthResponse is the server's reply. Wire size: 17 bytes.
//
//	[Status:1][SessionID:16]
type DeviceAuthResponse struct {
	Status    uint8
	SessionID [16]byte
}

const DeviceAuthResponseSize = 17

func (r *DeviceAuthResponse) Marshal() []byte {
	buf := make([]byte, DeviceAuthResponseSize)
	buf[0] = r.Status
	copy(buf[1:], r.SessionID[:])
	return buf
}

func UnmarshalDeviceAuthResponse(b []byte) (*DeviceAuthResponse, error) {
	if len(b) < DeviceAuthResponseSize {
		return nil, fmt.Errorf("device auth response: need %d bytes, got %d", DeviceAuthResponseSize, len(b))
	}
	r := &DeviceAuthResponse{Status: b[0]}
	copy(r.SessionID[:], b[1:17])
	return r, nil
}

// ── BootstrapRequest ──────────────────────────────────────────────────────────

// BootstrapRequest is the first-contact registration message.
// Wire size: 1 + 32 + 32 + 64 + 16 = 145 bytes.
//
//	[Version:1][Token:32][DevicePub:32][Label:64][Nonce:16]
type BootstrapRequest struct {
	Version   uint8
	Token     [32]byte
	DevicePub [ed25519.PublicKeySize]byte // 32 bytes
	Label     [64]byte                    // UTF-8, null-padded
	Nonce     [16]byte
}

const BootstrapRequestSize = 1 + 32 + 32 + 64 + 16 // 145

func (r *BootstrapRequest) Marshal() []byte {
	buf := make([]byte, BootstrapRequestSize)
	buf[0] = r.Version
	copy(buf[1:33], r.Token[:])
	copy(buf[33:65], r.DevicePub[:])
	copy(buf[65:129], r.Label[:])
	copy(buf[129:], r.Nonce[:])
	return buf
}

func UnmarshalBootstrapRequest(b []byte) (*BootstrapRequest, error) {
	if len(b) < BootstrapRequestSize {
		return nil, fmt.Errorf("bootstrap request: need %d bytes, got %d", BootstrapRequestSize, len(b))
	}
	r := &BootstrapRequest{Version: b[0]}
	copy(r.Token[:], b[1:33])
	copy(r.DevicePub[:], b[33:65])
	copy(r.Label[:], b[65:129])
	copy(r.Nonce[:], b[129:145])
	return r, nil
}

// ── BootstrapResponse ─────────────────────────────────────────────────────────

// BootstrapResponse is the server's reply. Wire size: 17 bytes.
//
//	[Status:1][SessionID:16]
type BootstrapResponse struct {
	Status    uint8
	SessionID [16]byte
}

const BootstrapResponseSize = 17

func (r *BootstrapResponse) Marshal() []byte {
	buf := make([]byte, BootstrapResponseSize)
	buf[0] = r.Status
	copy(buf[1:], r.SessionID[:])
	return buf
}

func UnmarshalBootstrapResponse(b []byte) (*BootstrapResponse, error) {
	if len(b) < BootstrapResponseSize {
		return nil, fmt.Errorf("bootstrap response: need %d bytes, got %d", BootstrapResponseSize, len(b))
	}
	r := &BootstrapResponse{Status: b[0]}
	copy(r.SessionID[:], b[1:17])
	return r, nil
}
