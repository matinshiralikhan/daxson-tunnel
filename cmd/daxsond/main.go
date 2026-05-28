// Command daxsond is the Daxson server daemon.
// It listens for authenticated tunnel clients and relays their streams
// to the requested targets on the open internet.
//
// Usage:
//
//	daxsond --config /etc/daxson/server.yaml
//	daxsond --config server.yaml --log-level debug
package main

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Register pprof handlers
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/internal/metrics"
	"github.com/daxson/tunnel/internal/tunnel"
)

var (
	cfgFile  string
	logLevel string
)

func main() {
	root := &cobra.Command{
		Use:   "daxsond",
		Short: "Daxson tunnel server daemon",
		RunE:  run,
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "server.yaml", "Config file path")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "", "Override log level (debug|info|warn|error)")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.Mode != config.ModeServer {
		return fmt.Errorf("daxsond requires mode: server, got %q", cfg.Mode)
	}

	log := buildLogger(cfg, logLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("daxsond starting",
		zap.String("version", version()),
		zap.String("config", cfgFile),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	met := metrics.New(nil)

	// Metrics + health endpoint.
	metrics.Serve(ctx, cfg.Metrics.Listen, log)

	// pprof (if configured).
	if cfg.PProf.Listen != "" {
		go func() {
			log.Info("pprof listening", zap.String("addr", cfg.PProf.Listen))
			http.ListenAndServe(cfg.PProf.Listen, nil) //nolint:errcheck
		}()
	}

	srv := tunnel.NewServer(cfg, log, met)
	if err := srv.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("server: %w", err)
	}

	log.Info("daxsond stopped cleanly")
	return nil
}

func buildLogger(cfg *config.Config, override string) *zap.Logger {
	level := cfg.Logging.Level
	if override != "" {
		level = override
	}

	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	var zapCfg zap.Config
	if cfg.Logging.Format == "console" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	zapCfg.Level = zap.NewAtomicLevelAt(lvl)

	log, err := zapCfg.Build()
	if err != nil {
		log = zap.NewNop()
	}
	return log
}

func version() string {
	return "0.1.0"
}
