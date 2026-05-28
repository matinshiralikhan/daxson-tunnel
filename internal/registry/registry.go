// Package registry manages the server-side device and invite state.
//
// The registry stores:
//   - Registered devices: Ed25519 public keys, labels, and access timestamps.
//   - Invite tokens: one-time or multi-use bootstrap credentials.
//   - Revocation: individual devices can be revoked without affecting others.
//
// State is persisted as JSON; writes are atomic (temp file + rename).
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daxson/tunnel/pkg/invite"
)

// Device is a registered client device.
type Device struct {
	PubKey       []byte    `json:"pub_key"`
	DeviceID     string    `json:"device_id"`
	Label        string    `json:"label"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
}

// InviteRecord is the stored state of a bootstrap invite token.
type InviteRecord struct {
	Token     []byte    `json:"token"`
	TokenID   string    `json:"token_id"`
	Label     string    `json:"label"`
	MaxUses   int       `json:"max_uses"`  // 0 = single-use
	Uses      int       `json:"uses"`
	ExpiresAt int64     `json:"expires_at"` // Unix seconds; 0 = no expiry
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// IsExpired reports whether the invite has passed its expiry.
func (r *InviteRecord) IsExpired() bool {
	return r.ExpiresAt != 0 && time.Now().Unix() > r.ExpiresAt
}

type storeData struct {
	Devices []*Device       `json:"devices"`
	Invites []*InviteRecord `json:"invites"`
}

// Registry is the authoritative server-side device and invite store.
type Registry struct {
	mu   sync.RWMutex
	path string
	data storeData
}

// Load reads the registry from a JSON file, starting empty if the file does not exist.
func Load(path string) (*Registry, error) {
	r := &Registry{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &r.data); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return r, nil
}

// save persists the registry atomically. Caller must hold mu.
func (r *Registry) save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return fmt.Errorf("registry: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("registry: write tmp: %w", err)
	}
	return os.Rename(tmp, r.path)
}

// AuthorizeDevice checks if a device is registered and not revoked.
// Returns an invite.AuthStatus* constant.
func (r *Registry) AuthorizeDevice(pub ed25519.PublicKey) uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()

	pub64 := []byte(pub)
	for _, d := range r.data.Devices {
		if bytesEqual(d.PubKey, pub64) {
			if d.Revoked {
				return invite.AuthStatusRevoked
			}
			d.LastSeenAt = time.Now().UTC()
			r.save() //nolint:errcheck
			return invite.AuthStatusOK
		}
	}
	return invite.AuthStatusUnknown
}

// Bootstrap validates an invite token and registers a new device.
// Returns an invite.BootstrapStatus* constant.
func (r *Registry) Bootstrap(token []byte, pub ed25519.PublicKey, label string) (uint8, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var found *InviteRecord
	for _, inv := range r.data.Invites {
		if !inv.Revoked && bytesEqual(inv.Token, token) {
			found = inv
			break
		}
	}
	if found == nil {
		return invite.BootstrapStatusInvalidToken, nil
	}
	if found.IsExpired() {
		return invite.BootstrapStatusExpired, nil
	}
	maxUses := found.MaxUses
	if maxUses <= 0 {
		maxUses = 1 // default single-use
	}
	if found.Uses >= maxUses {
		return invite.BootstrapStatusUsed, nil
	}

	d := &Device{
		PubKey:       []byte(pub),
		DeviceID:     shortDeviceID(pub),
		Label:        label,
		RegisteredAt: time.Now().UTC(),
	}
	if d.Label == "" {
		d.Label = "device-" + d.DeviceID
	}
	r.data.Devices = append(r.data.Devices, d)
	found.Uses++

	if err := r.save(); err != nil {
		return 0, fmt.Errorf("registry: save after bootstrap: %w", err)
	}
	return invite.BootstrapStatusOK, nil
}

// CreateInvite generates a new invite token, stores it, and returns the record.
func (r *Registry) CreateInvite(label string, maxUses int, ttl time.Duration) (*InviteRecord, error) {
	tok, err := invite.GenerateToken()
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var expiresAt int64
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).Unix()
	}

	rec := &InviteRecord{
		Token:     tok,
		TokenID:   shortHex(tok),
		Label:     label,
		MaxUses:   maxUses,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}
	r.data.Invites = append(r.data.Invites, rec)
	if err := r.save(); err != nil {
		return nil, err
	}
	return rec, nil
}

// RevokeInvite marks an invite as revoked by token ID (exact or prefix match).
func (r *Registry) RevokeInvite(tokenID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, inv := range r.data.Invites {
		if inv.TokenID == tokenID || strings.HasPrefix(inv.TokenID, tokenID) {
			inv.Revoked = true
			return r.save()
		}
	}
	return fmt.Errorf("registry: invite %q not found", tokenID)
}

// RevokeDevice marks a device as revoked by its device ID.
func (r *Registry) RevokeDevice(deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, d := range r.data.Devices {
		if d.DeviceID == deviceID {
			d.Revoked = true
			return r.save()
		}
	}
	return fmt.Errorf("registry: device %q not found", deviceID)
}

// ListDevices returns a snapshot of all registered devices.
func (r *Registry) ListDevices() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Device, len(r.data.Devices))
	copy(out, r.data.Devices)
	return out
}

// ListInvites returns a snapshot of all invite records.
func (r *Registry) ListInvites() []*InviteRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*InviteRecord, len(r.data.Invites))
	copy(out, r.data.Invites)
	return out
}

// DeviceCount returns the number of non-revoked registered devices.
func (r *Registry) DeviceCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, d := range r.data.Devices {
		if !d.Revoked {
			n++
		}
	}
	return n
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func shortDeviceID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:3])
}

func shortHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:4])
}
