package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type storedKey struct {
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	DeviceID   string    `json:"device_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// Load reads a key pair from path, auto-generating one if the file doesn't exist.
func Load(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return generateAndSave(path)
		}
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	var sk storedKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if len(sk.PublicKey) != ed25519.PublicKeySize || len(sk.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity: corrupt key file %s", path)
	}
	return &KeyPair{
		PublicKey:  ed25519.PublicKey(sk.PublicKey),
		PrivateKey: ed25519.PrivateKey(sk.PrivateKey),
		DeviceID:   sk.DeviceID,
		CreatedAt:  sk.CreatedAt,
	}, nil
}

// Save writes the key pair to path with mode 0600.
func Save(kp *KeyPair, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("identity: mkdir: %w", err)
	}
	sk := storedKey{
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
		DeviceID:   kp.DeviceID,
		CreatedAt:  kp.CreatedAt,
	}
	data, err := json.MarshalIndent(sk, "", "  ")
	if err != nil {
		return fmt.Errorf("identity: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

func generateAndSave(path string) (*KeyPair, error) {
	kp, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := Save(kp, path); err != nil {
		return nil, err
	}
	return kp, nil
}
