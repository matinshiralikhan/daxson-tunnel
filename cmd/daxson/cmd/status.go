package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show live connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}
}

func runStatus() error {
	path := defaultStatusPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not connected.")
			fmt.Printf("Run %s'daxson connect'%s to start the tunnel.\n", ansiBold, ansiReset)
			return nil
		}
		return err
	}

	var rec statusRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		fmt.Println("Status file corrupted.")
		return nil
	}

	// If the status file is more than 30s stale, the process is probably dead.
	stale := time.Since(rec.UpdatedAt) > 30*time.Second

	if stale || !rec.Connected {
		fmt.Printf("%sNot connected%s  (last seen %s ago)\n", ansiRed, ansiReset, fmtDuration(time.Since(rec.UpdatedAt)))
		return nil
	}

	uptime := time.Since(rec.ConnectedAt)

	printHeader("Connection")
	printKey("Server", fmt.Sprintf("%s%s%s", ansiBold, rec.Server, ansiReset))
	printKey("Device", rec.DeviceID)
	printKey("Profile", rec.Profile)
	printKey("Uptime", fmtDuration(uptime))

	if rec.SOCKS5Addr != "" || rec.HTTPAddr != "" {
		printHeader("Proxy")
		if rec.SOCKS5Addr != "" {
			printKey("SOCKS5", fmt.Sprintf("%s%s%s", ansiBold, rec.SOCKS5Addr, ansiReset))
		}
		if rec.HTTPAddr != "" {
			printKey("HTTP", fmt.Sprintf("%s%s%s", ansiBold, rec.HTTPAddr, ansiReset))
		}
	}
	fmt.Println()
	return nil
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
