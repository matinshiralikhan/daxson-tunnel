// Package cmd implements the Daxson task-oriented CLI.
//
// Command tree:
//
//	daxson import <link>         — import invite link and register device
//	daxson connect [--profile]   — connect to the tunnel
//	daxson disconnect            — disconnect (reserved for daemon mode)
//	daxson status                — show live connection status
//	daxson doctor                — run diagnostics
//	daxson init                  — guided first-time setup wizard
//	daxson serve                 — run as server
//	daxson keys                  — manage device key pair
//	daxson invite                — manage invite links (server)
//	daxson devices               — manage registered devices (server)
//	daxson version               — print version
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version is set at build time via -ldflags.
var Version = "0.2.0"

// configDir returns the Daxson home directory (~/.daxson or %APPDATA%\daxson on Windows).
func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".daxson"
	}
	if runtime.GOOS == "windows" {
		if app := os.Getenv("APPDATA"); app != "" {
			return filepath.Join(app, "daxson")
		}
	}
	return filepath.Join(home, ".daxson")
}

// defaultIdentityPath returns the default path to the device key file.
func defaultIdentityPath() string {
	return filepath.Join(configDir(), "identity.json")
}

// defaultProfileDir returns the directory where client profiles are stored.
func defaultProfileDir() string {
	return filepath.Join(configDir(), "profiles")
}

// defaultStatusPath returns the path to the live connection status file.
func defaultStatusPath() string {
	return filepath.Join(configDir(), "status.json")
}

// defaultServerConfigPath returns the default server config path.
func defaultServerConfigPath() string {
	return filepath.Join(configDir(), "server.yaml")
}

// defaultRegistryPath returns the default device registry path (server-side).
func defaultRegistryPath() string {
	return filepath.Join(configDir(), "registry.json")
}

// defaultServerIdentityPath returns the default server identity key path.
func defaultServerIdentityPath() string {
	return filepath.Join(configDir(), "server-identity.json")
}

// ── Terminal output helpers ───────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

func printOK(msg string) {
	fmt.Printf("  %s✓%s %s\n", ansiGreen, ansiReset, msg)
}

func printFail(msg string) {
	fmt.Printf("  %s✗%s %s\n", ansiRed, ansiReset, msg)
}

func printWarn(msg string) {
	fmt.Printf("  %s!%s %s\n", ansiYellow, ansiReset, msg)
}

func printInfo(msg string) {
	fmt.Printf("  %s→%s %s\n", ansiCyan, ansiReset, msg)
}

func printHeader(msg string) {
	fmt.Printf("\n%s%s%s\n", ansiBold, msg, ansiReset)
}

func printKey(k, v string) {
	fmt.Printf("  %s%-16s%s %s\n", ansiDim, k, ansiReset, v)
}

// buildLogger creates a zap logger at the given level.
// level is one of: debug, info, warn, error.
func buildLogger(level string) *zap.Logger {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	var cfg zap.Config
	if lvl == zapcore.DebugLevel {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	log, err := cfg.Build()
	if err != nil {
		return zap.NewNop()
	}
	return log
}

// NewRootCmd builds the root cobra command with all sub-commands attached.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "daxson",
		Short:         "Censorship-resistant tunnel",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newImportCmd(),
		newConnectCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newInitCmd(),
		newServeCmd(),
		newKeysCmd(),
		newInviteCmd(),
		newDevicesCmd(),
		&cobra.Command{
			Use:   "version",
			Short: "Print version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("daxson %s\n", Version)
			},
		},
	)
	return root
}
