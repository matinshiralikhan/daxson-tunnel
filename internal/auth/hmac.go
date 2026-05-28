// Package auth implements the Daxson authentication handshake.
//
// Protocol:
//
//	Client → Server [49 bytes]:
//	  [Version:1][Nonce:16][Token:32]
//	  Token = HMAC-SHA256(PSK, "daxson-v1:" + hex(Nonce) + ":" + TimeBucket)
//	  TimeBucket = strconv.FormatInt(unixTime / 30, 10)
//
//	Server → Client [17 bytes]:
//	  [Status:1][SessionID:16]
//	  Status: 0x00 = OK, 0xFF = fail (random bytes still written)
//
// Time tolerance: ±1 bucket (±30 seconds) to handle clock skew.
// The server tries current and previous bucket before rejecting.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/daxson/tunnel/pkg/protocol"
)

var errAuthFailed = errors.New("auth: authentication failed")

// Handshaker performs the 2-message auth handshake.
type Handshaker struct {
	psk []byte
}

// New creates a Handshaker from a pre-shared key string.
func New(psk string) *Handshaker {
	h := sha256.Sum256([]byte(psk))
	return &Handshaker{psk: h[:]}
}

// ClientHandshake sends the auth request and reads the server response.
// Returns the session ID on success.
func (h *Handshaker) ClientHandshake(rw io.ReadWriter) ([16]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [16]byte{}, fmt.Errorf("auth: generate nonce: %w", err)
	}

	req := make([]byte, protocol.AuthRequestSize)
	req[0] = protocol.ProtocolVersion
	copy(req[1:17], nonce[:])
	tok := computeToken(h.psk, nonce[:], timeBucket(time.Now()))
	copy(req[17:49], tok)

	if _, err := rw.Write(req); err != nil {
		return [16]byte{}, fmt.Errorf("auth: write request: %w", err)
	}

	resp := make([]byte, protocol.AuthResponseSize)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return [16]byte{}, fmt.Errorf("auth: read response: %w", err)
	}

	if resp[0] != protocol.AuthStatusOK {
		return [16]byte{}, errAuthFailed
	}

	var sid [16]byte
	copy(sid[:], resp[1:17])
	return sid, nil
}

// ServerHandshake reads the auth request and writes the server response.
// Returns the session ID assigned if auth succeeds, or errAuthFailed.
func (h *Handshaker) ServerHandshake(rw io.ReadWriter) ([16]byte, error) {
	req := make([]byte, protocol.AuthRequestSize)
	if _, err := io.ReadFull(rw, req); err != nil {
		return [16]byte{}, fmt.Errorf("auth: read request: %w", err)
	}

	if req[0] != protocol.ProtocolVersion {
		h.writeFailResponse(rw)
		return [16]byte{}, errAuthFailed
	}

	nonce := req[1:17]
	token := req[17:49]

	now := time.Now()
	valid := hmac.Equal(token, computeToken(h.psk, nonce, timeBucket(now))) ||
		hmac.Equal(token, computeToken(h.psk, nonce, timeBucket(now.Add(-30*time.Second))))

	if !valid {
		h.writeFailResponse(rw)
		return [16]byte{}, errAuthFailed
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		h.writeFailResponse(rw)
		return [16]byte{}, fmt.Errorf("auth: generate session id: %w", err)
	}

	resp := make([]byte, protocol.AuthResponseSize)
	resp[0] = protocol.AuthStatusOK
	copy(resp[1:], sid[:])
	if _, err := rw.Write(resp); err != nil {
		return [16]byte{}, fmt.Errorf("auth: write response: %w", err)
	}
	return sid, nil
}

// IsAuthFailed reports whether err is an authentication failure.
func IsAuthFailed(err error) bool {
	return errors.Is(err, errAuthFailed)
}

func (h *Handshaker) writeFailResponse(w io.Writer) {
	resp := make([]byte, protocol.AuthResponseSize)
	resp[0] = protocol.AuthStatusFail
	rand.Read(resp[1:]) //nolint:errcheck // best effort; can't do much if this fails
	w.Write(resp)       //nolint:errcheck
}

func computeToken(psk, nonce []byte, bucket string) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("daxson-v1:"))
	mac.Write([]byte(hex.EncodeToString(nonce)))
	mac.Write([]byte(":"))
	mac.Write([]byte(bucket))
	return mac.Sum(nil)
}

func timeBucket(t time.Time) string {
	return strconv.FormatInt(t.Unix()/30, 10)
}
