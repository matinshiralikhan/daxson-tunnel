// Package config defines the Daxson configuration schema and loader.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode controls which role this instance plays.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
	ModeRelay  Mode = "relay"
)

// Config is the top-level configuration structure.
type Config struct {
	Mode Mode `yaml:"mode"`

	// Inbound proxy (client and relay).
	Proxy ProxyConfig `yaml:"proxy"`

	// Tunnel connection settings (client and relay).
	Tunnel TunnelConfig `yaml:"tunnel"`

	// Server settings (server and relay).
	Server ServerConfig `yaml:"server"`

	// Upstream for relay mode.
	Upstream UpstreamConfig `yaml:"upstream"`

	// Observability.
	Metrics MetricsConfig `yaml:"metrics"`
	Logging LoggingConfig `yaml:"logging"`
	PProf   PProfConfig   `yaml:"pprof"`
}

// ProxyConfig configures the local proxy inbound.
type ProxyConfig struct {
	SOCKS5 string `yaml:"socks5"` // e.g. "127.0.0.1:1080"
	HTTP   string `yaml:"http"`   // e.g. "127.0.0.1:8080"
}

// TunnelConfig controls how the client connects to the server/relay.
type TunnelConfig struct {
	Addr      string       `yaml:"addr"`       // host:port
	TLS       TLSConfig    `yaml:"tls"`
	Auth      AuthConfig   `yaml:"auth"`
	Transport TransportCfg `yaml:"transport"`
	Reconnect ReconnectCfg `yaml:"reconnect"`
}

// ServerConfig controls the server listener.
type ServerConfig struct {
	Listen string     `yaml:"listen"` // e.g. ":443"
	TLS    TLSConfig  `yaml:"tls"`
	Auth   AuthConfig `yaml:"auth"` // PSK auth for relay-to-relay connections

	// Real upstream for active-probe resistance: unauthenticated connections
	// are forwarded here instead of being dropped.
	ProbeUpstream string `yaml:"probe_upstream"` // e.g. "127.0.0.1:80"

	// Ed25519 identity-based auth (for client device connections).
	// IdentityKey is the path to the server's identity.json key file.
	// Registry is the path to the device registry JSON file.
	// Both are optional; if absent, only HMAC-PSK auth is accepted.
	IdentityKey string `yaml:"identity_key"` // e.g. "/etc/daxson/identity.json"
	Registry    string `yaml:"registry"`     // e.g. "/etc/daxson/registry.json"

	Dashboard DashboardConfig `yaml:"dashboard"`
}

// UpstreamConfig is for relay mode: where to forward to.
type UpstreamConfig struct {
	Addr      string     `yaml:"addr"`
	TLS       TLSConfig  `yaml:"tls"`
	Auth      AuthConfig `yaml:"auth"`
}

// TLSConfig holds TLS parameters.
type TLSConfig struct {
	CertFile   string   `yaml:"cert"`
	KeyFile    string   `yaml:"key"`
	ServerName string   `yaml:"server_name"`
	// Fingerprint to impersonate when dialing (client only).
	// One of: chrome, firefox, edge, safari, random
	Fingerprint string   `yaml:"fingerprint"`
	// InsecureSkipVerify is for testing only; never use in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// NextProtos for ALPN.
	NextProtos []string `yaml:"next_protos"`
}

// AuthConfig holds authentication parameters.
type AuthConfig struct {
	// PSK is the pre-shared key. Must be at least 32 bytes of high-entropy.
	PSK string `yaml:"psk"`
}

// TransportCfg controls obfuscation and connection behavior.
type TransportCfg struct {
	Obfs ObfsConfig `yaml:"obfs"`
	Mux  MuxConfig  `yaml:"mux"`
}

// ObfsConfig controls Behavioral Camouflage Layer (BCL) shaping.
type ObfsConfig struct {
	Enabled bool `yaml:"enabled"`

	// Personality selects the traffic profile to emulate.
	// Options: browser (default), grpc, video, mobile, relay
	// Each personality encodes empirically-derived distributions for burst
	// timing, frame sizing, keepalive cadence, and congestion response.
	Personality string `yaml:"personality"`

	// Deprecated: retained for YAML config back-compat only.
	// Use Personality instead. These are ignored when Personality is set.
	MaxPadding        int      `yaml:"max_padding"`
	WriteJitterMax    int      `yaml:"write_jitter_max_ms"`
	KeepaliveInterval Duration `yaml:"keepalive_interval"`
	KeepaliveJitter   Duration `yaml:"keepalive_jitter"`
}

// MuxConfig controls smux session parameters.
type MuxConfig struct {
	// MaxStreams is the maximum concurrent streams per session.
	MaxStreams int `yaml:"max_streams"`
	// MaxFrameSize is the smux maximum frame size in bytes.
	MaxFrameSize int `yaml:"max_frame_size"`
	// ReceiveBuffer is the smux receive buffer size in bytes.
	ReceiveBuffer int `yaml:"receive_buffer"`
}

// ReconnectCfg controls reconnection behavior.
type ReconnectCfg struct {
	Enabled     bool     `yaml:"enabled"`
	MaxRetries  int      `yaml:"max_retries"` // -1 = infinite
	BaseDelay   Duration `yaml:"base_delay"`
	MaxDelay    Duration `yaml:"max_delay"`
	Multiplier  float64  `yaml:"multiplier"`
}

// MetricsConfig controls Prometheus exposition.
type MetricsConfig struct {
	Listen string `yaml:"listen"` // e.g. ":9090"
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, console
}

// PProfConfig controls pprof HTTP server.
type PProfConfig struct {
	Listen string `yaml:"listen"` // e.g. ":6060"; empty = disabled
}

// Duration is a yaml-unmarshalable time.Duration.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Defaults returns a Config populated with sane defaults.
func Defaults() Config {
	return Config{
		Proxy: ProxyConfig{
			SOCKS5: "127.0.0.1:1080",
			HTTP:   "127.0.0.1:8080",
		},
		Tunnel: TunnelConfig{
			TLS: TLSConfig{
				Fingerprint: "chrome",
				NextProtos:  []string{"h2", "http/1.1"},
			},
			Transport: TransportCfg{
				Obfs: ObfsConfig{
					Enabled:           true,
					MaxPadding:        256,
					WriteJitterMax:    8,
					KeepaliveInterval: Duration{60 * time.Second},
					KeepaliveJitter:   Duration{15 * time.Second},
				},
				Mux: MuxConfig{
					MaxStreams:    512,
					MaxFrameSize:  32768,
					ReceiveBuffer: 4 * 1024 * 1024,
				},
			},
			Reconnect: ReconnectCfg{
				Enabled:    true,
				MaxRetries: -1,
				BaseDelay:  Duration{time.Second},
				MaxDelay:   Duration{60 * time.Second},
				Multiplier: 2.0,
			},
		},
		Server: ServerConfig{
			Listen: ":443",
			TLS: TLSConfig{
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		Metrics: MetricsConfig{Listen: ":9090"},
		Logging: LoggingConfig{Level: "info", Format: "json"},
	}
}

// Load reads and parses a YAML config file, applying defaults first.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}
	return &cfg, nil
}

// Validate checks for required fields and sane values.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeClient:
		if c.Tunnel.Addr == "" {
			return errors.New("client mode requires tunnel.addr")
		}
		if c.Tunnel.Auth.PSK == "" {
			return errors.New("client mode requires tunnel.auth.psk")
		}
		if len(c.Tunnel.Auth.PSK) < 16 {
			return errors.New("tunnel.auth.psk must be at least 16 characters")
		}
	case ModeServer:
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return errors.New("server mode requires server.tls.cert and server.tls.key")
		}
		// Server accepts either PSK auth (for relay-to-relay) or Ed25519 registry auth.
		// At least one must be configured.
		if c.Server.Auth.PSK == "" && c.Server.IdentityKey == "" {
			return errors.New("server mode requires server.auth.psk or server.identity_key")
		}
	case ModeRelay:
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return errors.New("relay mode requires server.tls.cert and server.tls.key")
		}
		if c.Upstream.Addr == "" {
			return errors.New("relay mode requires upstream.addr")
		}
		if c.Server.Auth.PSK == "" || c.Upstream.Auth.PSK == "" {
			return errors.New("relay mode requires server.auth.psk and upstream.auth.psk")
		}
	default:
		return fmt.Errorf("unknown mode: %q (must be client, server, or relay)", c.Mode)
	}
	return nil
}

// ── ClientProfile ────────────────────────────────────────────────────────────

// ClientProfile is the lightweight per-connection profile written by `daxson import`
// and read by `daxson connect`. It lives at ~/.daxson/profiles/<name>.yaml.
//
// Unlike the legacy Config type (which requires a PSK and manual cert config),
// ClientProfile uses Ed25519 device identity: the device key pair is generated
// once and stored separately; the invite link bootstraps trust.
type ClientProfile struct {
	Version   int    `yaml:"version"`
	Name      string `yaml:"name,omitempty"`
	Server    string `yaml:"server"`               // host:port
	ServerKey []byte `yaml:"server_key,omitempty"` // Ed25519 server pubkey for link verification
	DeviceKey string `yaml:"device_key,omitempty"` // path to identity.json; defaults to ~/.daxson/identity.json

	TLS       TLSConfig    `yaml:"tls"`
	Transport TransportCfg `yaml:"transport"`
	Proxy     ProxyConfig  `yaml:"proxy"`
	Reconnect ReconnectCfg `yaml:"reconnect"`
}

// ClientProfileDefaults returns a ClientProfile with sane defaults.
func ClientProfileDefaults() ClientProfile {
	return ClientProfile{
		Version: 1,
		TLS: TLSConfig{
			Fingerprint: "chrome",
			NextProtos:  []string{"h2", "http/1.1"},
		},
		Transport: TransportCfg{
			Obfs: ObfsConfig{
				Enabled:     true,
				Personality: "browser",
			},
			Mux: MuxConfig{
				MaxFrameSize:  32768,
				ReceiveBuffer: 4 * 1024 * 1024,
			},
		},
		Proxy: ProxyConfig{
			SOCKS5: "127.0.0.1:1080",
			HTTP:   "127.0.0.1:8080",
		},
		Reconnect: ReconnectCfg{
			Enabled:    true,
			MaxRetries: -1,
			BaseDelay:  Duration{time.Second},
			MaxDelay:   Duration{60 * time.Second},
			Multiplier: 2.0,
		},
	}
}

// ValidateClientProfile checks a ClientProfile for required fields.
func ValidateClientProfile(p *ClientProfile) error {
	if p.Server == "" {
		return errors.New("profile: server address is required")
	}
	return nil
}

// LoadClientProfile reads a ClientProfile from a YAML file.
func LoadClientProfile(path string) (*ClientProfile, error) {
	p := ClientProfileDefaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	if err := ValidateClientProfile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SaveClientProfile writes a ClientProfile to a YAML file.
func SaveClientProfile(p *ClientProfile, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("profile: mkdir: %w", err)
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("profile: marshal: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// ── Server identity and dashboard ────────────────────────────────────────────

// DashboardConfig controls the management panel HTTP server.
type DashboardConfig struct {
	Listen  string `yaml:"listen"`  // e.g. "127.0.0.1:9443"
	Enabled bool   `yaml:"enabled"`
}
