// Package obfs is a thin facade over the Behavioral Camouflage Layer (BCL).
//
// Previous design flaw (now fixed):
//   The old ObfsConn embedded net.Conn and only exposed WriteFrame() for keepalives.
//   smux called conn.Write() directly — which went through the embedded net.Conn,
//   bypassing ALL shaping. Padding and timing were only applied to keepalive PINGs,
//   not to any actual tunnel data.
//
// New design:
//   Wrap() now returns a *bcl.Conn which implements net.Conn. Every byte that smux
//   writes goes through the BCL's burst collector, fragmentation engine, size
//   normaliser, and congestion-aware pacer. The BCL also handles keepalive injection.
//   The caller gets a transparent net.Conn — no API change needed in mux or tunnel.
package obfs

import (
	"net"

	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/bcl"
)

// Config mirrors the BCL personality selection plus a few legacy fields
// retained for config compatibility.
type Config struct {
	Enabled     bool
	Personality string // "browser" | "grpc" | "video" | "mobile" | "relay"

	// Deprecated fields retained for config back-compat.
	// These are ignored if Personality is non-empty; kept so existing YAML
	// configs that specify them don't cause parse errors.
	MaxPadding        int `yaml:"max_padding"`
	WriteJitterMax    int `yaml:"write_jitter_max_ms"`
	KeepaliveInterval interface{} `yaml:"keepalive_interval"`
	KeepaliveJitter   interface{} `yaml:"keepalive_jitter"`
}

// DefaultConfig returns a sane default (browser personality, enabled).
func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		Personality: "browser",
	}
}

// Wrap wraps conn with the Behavioral Camouflage Layer.
// Returns a net.Conn whose Write path goes through BCL shaping.
// If cfg.Enabled is false, returns conn unwrapped.
func Wrap(conn net.Conn, cfg Config, log *zap.Logger) net.Conn {
	if !cfg.Enabled {
		return conn
	}

	name := cfg.Personality
	if name == "" {
		name = "browser"
	}

	p, err := bcl.ParsePersonality(name)
	if err != nil {
		log.Warn("obfs: unknown personality, falling back to browser",
			zap.String("personality", name),
			zap.Error(err),
		)
		p = bcl.Browser
	}

	return bcl.Wrap(conn, p, log)
}
