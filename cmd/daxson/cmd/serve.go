package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/internal/dashboard"
	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/internal/telemetry"
	"github.com/daxson/tunnel/internal/tunnel"
	"github.com/daxson/tunnel/pkg/identity"
)

func newServeCmd() *cobra.Command {
	var cfgFile string
	var dashboardAddr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Daxson server",
		Long: `Start the Daxson server: load identity, device registry, optional dashboard,
and begin accepting tunnel connections.`,
		Example: "  daxson serve\n  daxson serve --config /etc/daxson/server.yaml\n  daxson serve --dashboard 127.0.0.1:9443",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cfgFile, dashboardAddr)
		},
	}
	cmd.Flags().StringVar(&cfgFile, "config", "", "Server config file (default: ~/.daxson/server.yaml)")
	cmd.Flags().StringVar(&dashboardAddr, "dashboard", "", "Override dashboard listen address")
	return cmd
}

func runServe(cfgFile, dashboardAddrOverride string) error {
	if cfgFile == "" {
		cfgFile = defaultServerConfigPath()
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		printFail("Config error: " + err.Error())
		return err
	}
	if cfg.Mode != config.ModeServer {
		printFail(fmt.Sprintf("Config mode is %q but serve requires mode: server", cfg.Mode))
		return fmt.Errorf("serve: wrong mode %q", cfg.Mode)
	}

	log, _ := zap.NewProduction()
	defer log.Sync() //nolint:errcheck

	// Load or auto-generate server identity (for device auth and invite signing).
	identityPath := cfg.Server.IdentityKey
	if identityPath == "" {
		identityPath = defaultServerIdentityPath()
	}
	_, identityExisted := os.Stat(identityPath)
	serverKey, err := identity.Load(identityPath) // auto-generates if missing
	if err != nil {
		printFail("Server identity error: " + err.Error())
		return err
	}
	if os.IsNotExist(identityExisted) {
		printOK(fmt.Sprintf("Server identity generated  (id: %s%s%s)  %s", ansiBold, serverKey.DeviceID, ansiReset, identityPath))
	} else {
		printOK(fmt.Sprintf("Server identity loaded  (id: %s%s%s)", ansiBold, serverKey.DeviceID, ansiReset))
	}

	// Load device registry.
	registryPath := cfg.Server.Registry
	if registryPath == "" {
		registryPath = defaultRegistryPath()
	}
	reg, err := registry.Load(registryPath)
	if err != nil {
		printFail("Registry error: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Registry loaded  (%d device(s))", reg.DeviceCount()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	met := metrics.New(nil)
	metrics.Serve(ctx, cfg.Metrics.Listen, log)

	collector := telemetry.New()

	errCh := make(chan error, 2)

	// Start dashboard if configured.
	dashAddr := cfg.Server.Dashboard.Listen
	if dashboardAddrOverride != "" {
		dashAddr = dashboardAddrOverride
	}
	if dashAddr != "" {
		dash := dashboard.New(dashAddr, reg, collector, serverKey, Version, log)
		go func() {
			if err := dash.Start(ctx); err != nil {
				errCh <- fmt.Errorf("dashboard: %w", err)
			}
		}()
		printOK(fmt.Sprintf("Dashboard listening on %s%s%s", ansiBold, dashAddr, ansiReset))
	}

	// Build and start tunnel server.
	var serverOpts []tunnel.ServerOption
	if serverKey != nil {
		serverOpts = append(serverOpts,
			tunnel.WithDeviceRegistry(reg),
			tunnel.WithTelemetry(collector),
			tunnel.WithTransportLabel(cfg.Tunnel.TLS.Fingerprint),
		)
	}

	ts := tunnel.NewServer(cfg, log, met, serverOpts...)
	go func() {
		if err := ts.ListenAndServe(ctx); err != nil {
			errCh <- fmt.Errorf("tunnel server: %w", err)
		}
	}()

	fmt.Printf("\n%sTunnel server ready%s  listening on %s%s%s\n",
		ansiGreen, ansiReset, ansiBold, cfg.Server.Listen, ansiReset)
	fmt.Printf("Press %sCtrl+C%s to stop.\n\n", ansiBold, ansiReset)

	select {
	case <-ctx.Done():
		fmt.Println("\nServer stopped.")
		return nil
	case err := <-errCh:
		return err
	}
}
