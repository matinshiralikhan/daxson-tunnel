package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/daxson/tunnel/internal/auth"
	"github.com/daxson/tunnel/internal/config"
	httpproxy "github.com/daxson/tunnel/internal/proxy/http"
	"github.com/daxson/tunnel/internal/proxy/socks5"
	"github.com/daxson/tunnel/internal/tunnel"
	"github.com/daxson/tunnel/pkg/identity"
)

func newConnectCmd() *cobra.Command {
	var profileName string
	var socks5Addr string
	var httpAddr string
	var logLevel string

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to the tunnel",
		Long:  `Connect to the server using the saved profile and expose local proxy endpoints.`,
		Example: "  daxson connect\n  daxson connect --profile work\n  daxson connect --socks5 127.0.0.1:1080\n  daxson connect --log-level debug",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(profileName, socks5Addr, httpAddr, logLevel)
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "default", "Profile name to use")
	cmd.Flags().StringVar(&socks5Addr, "socks5", "", "Override SOCKS5 listen address")
	cmd.Flags().StringVar(&httpAddr, "http", "", "Override HTTP proxy listen address")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug|info|warn|error)")
	return cmd
}

func runConnect(profileName, socks5Override, httpOverride, logLevel string) error {
	profilePath := filepath.Join(defaultProfileDir(), profileName+".yaml")
	profile, err := config.LoadClientProfile(profilePath)
	if err != nil {
		printFail(fmt.Sprintf("Profile %q not found. Run 'daxson import <link>' first.", profileName))
		return err
	}

	if socks5Override != "" {
		profile.Proxy.SOCKS5 = socks5Override
	}
	if httpOverride != "" {
		profile.Proxy.HTTP = httpOverride
	}

	keyPath := profile.DeviceKey
	if keyPath == "" {
		keyPath = defaultIdentityPath()
	}
	kp, err := identity.Load(keyPath)
	if err != nil {
		printFail("Device key error: " + err.Error())
		return err
	}

	fmt.Printf("Connecting to %s%s%s...\n", ansiBold, profile.Server, ansiReset)

	log := buildLogger(logLevel)
	defer log.Sync() //nolint:errcheck

	// Build a legacy config.Config from the ClientProfile so we can reuse
	// the existing tunnel.Client / proxy infrastructure.
	cfg := buildLegacyConfig(profile)

	// Use Ed25519 device auth.
	clientAuth := auth.NewDeviceAuth(kp)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tc := tunnel.NewClientWithAuth(cfg, log, nil, clientAuth)
	go tc.Run(ctx)

	// Wait briefly for the first connection attempt.
	time.Sleep(500 * time.Millisecond)

	errCh := make(chan error, 2)

	if profile.Proxy.SOCKS5 != "" {
		s5 := socks5.NewServer(profile.Proxy.SOCKS5, tc, log, nil)
		go func() {
			if err := s5.ListenAndServe(ctx); err != nil {
				errCh <- fmt.Errorf("socks5: %w", err)
			}
		}()
	}
	if profile.Proxy.HTTP != "" {
		hp := httpproxy.NewServer(profile.Proxy.HTTP, tc, log, nil)
		go func() {
			if err := hp.ListenAndServe(ctx); err != nil {
				errCh <- fmt.Errorf("http proxy: %w", err)
			}
		}()
	}

	// Print the ready banner.
	printOK(fmt.Sprintf("Authenticated  (device: %s%s%s)", ansiBold, kp.DeviceID, ansiReset))
	fmt.Printf("\n%sTunnel ready%s\n", ansiGreen, ansiReset)
	if profile.Proxy.SOCKS5 != "" {
		printInfo(fmt.Sprintf("SOCKS5  %s%s%s", ansiBold, profile.Proxy.SOCKS5, ansiReset))
	}
	if profile.Proxy.HTTP != "" {
		printInfo(fmt.Sprintf("HTTP    %s%s%s", ansiBold, profile.Proxy.HTTP, ansiReset))
	}
	fmt.Printf("\nPress %sCtrl+C%s to disconnect.\n\n", ansiBold, ansiReset)

	// Write status file; remove on exit.
	statusPath := defaultStatusPath()
	writeStatus(statusPath, kp.DeviceID, profile)
	statusTicker := time.NewTicker(10 * time.Second)
	defer statusTicker.Stop()
	defer os.Remove(statusPath)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nDisconnected.")
			return nil
		case err := <-errCh:
			return err
		case <-statusTicker.C:
			writeStatus(statusPath, kp.DeviceID, profile)
		}
	}
}

// buildLegacyConfig maps a ClientProfile onto the existing config.Config so
// tunnel.Client and the proxy servers can be reused without changes.
func buildLegacyConfig(p *config.ClientProfile) *config.Config {
	cfg := config.Defaults()
	cfg.Mode = config.ModeClient
	cfg.Tunnel.Addr = p.Server
	cfg.Tunnel.Auth.PSK = "unused-device-auth" // not used when ClientAuth is overridden
	cfg.Tunnel.TLS = p.TLS
	cfg.Tunnel.Transport = p.Transport
	cfg.Tunnel.Reconnect = p.Reconnect
	cfg.Proxy = p.Proxy
	return &cfg
}

// statusRecord is written to ~/.daxson/status.json while connected.
type statusRecord struct {
	Version     int       `json:"version"`
	Connected   bool      `json:"connected"`
	Server      string    `json:"server"`
	DeviceID    string    `json:"device_id"`
	Profile     string    `json:"profile"`
	SOCKS5Addr  string    `json:"socks5_addr,omitempty"`
	HTTPAddr    string    `json:"http_addr,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var connectStartTime = time.Now()

func writeStatus(path, deviceID string, p *config.ClientProfile) {
	rec := statusRecord{
		Version:     1,
		Connected:   true,
		Server:      p.Server,
		DeviceID:    deviceID,
		Profile:     p.Name,
		SOCKS5Addr:  p.Proxy.SOCKS5,
		HTTPAddr:    p.Proxy.HTTP,
		ConnectedAt: connectStartTime,
		UpdatedAt:   time.Now(),
	}
	data, _ := json.MarshalIndent(rec, "", "  ")
	os.WriteFile(path, data, 0600) //nolint:errcheck
}
