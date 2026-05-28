// Package identity manages Ed25519 device key pairs for the Daxson platform.
//
// Each device has a unique key pair generated once on first run. The public key
// serves as the device's persistent identity. Device private keys never leave
// the device — only the public key is transmitted to servers during registration.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// KeyPair holds an Ed25519 device identity.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	DeviceID   string    // hex(SHA256(pubkey)[:3]) — 6-char display ID
	CreatedAt  time.Time
}

// Generate creates a new random Ed25519 key pair.
func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		DeviceID:   shortID(pub),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Sign produces an Ed25519 signature over message.
func (kp *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// Verify checks a signature against this device's public key.
func (kp *KeyPair) Verify(message, sig []byte) bool {
	return ed25519.Verify(kp.PublicKey, message, sig)
}

// PublicKeyBase64 returns the unpadded base64url-encoded public key.
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(kp.PublicKey)
}

// Fingerprint returns the 6-hex-char device ID derived from the public key.
func (kp *KeyPair) Fingerprint() string { return kp.DeviceID }

// Verify checks a signature against an arbitrary Ed25519 public key.
func Verify(pubKey ed25519.PublicKey, message, sig []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, message, sig)
}

// ShortID returns the 6-hex-char identifier for a public key.
// Exported so registry and dashboard can display consistent IDs.
func ShortID(pub ed25519.PublicKey) string { return shortID(pub) }

func shortID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:3])
}
