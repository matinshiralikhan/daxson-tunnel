// Command daxson is the Daxson tunnel client, server, and management CLI.
//
// Usage:
//
//	daxson import <daxson://...>     — import invite link and register device
//	daxson connect [--profile]       — connect to the tunnel
//	daxson status                    — show live connection status
//	daxson doctor                    — run diagnostics
//	daxson init                      — guided first-time setup wizard
//	daxson serve [--config]          — run as server
//	daxson keys show|rotate|export   — manage device key pair
//	daxson invite create|list|revoke — manage invite links (server)
//	daxson devices list|revoke       — manage registered devices (server)
//	daxson version                   — print version
package main

import (
	"fmt"
	"os"

	"github.com/daxson/tunnel/cmd/daxson/cmd"
)

func main() {
	root := cmd.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
