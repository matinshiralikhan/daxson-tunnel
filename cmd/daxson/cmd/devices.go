package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newDevicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage registered devices (server-side)",
	}
	cmd.AddCommand(
		newDevicesListCmd(),
		newDevicesRevokeCmd(),
	)
	return cmd
}

func newDevicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDevicesList()
		},
	}
}

func newDevicesRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Revoke a device by its ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDevicesRevoke(args[0])
		},
	}
}

func runDevicesList() error {
	reg, err := loadServerRegistry()
	if err != nil {
		return err
	}

	devices := reg.ListDevices()
	if len(devices) == 0 {
		fmt.Println("No registered devices.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sDEVICE-ID\tLABEL\tREGISTERED\tLAST SEEN\tSTATUS%s\n", ansiBold, ansiReset)
	for _, d := range devices {
		status := ansiGreen + "active" + ansiReset
		if d.Revoked {
			status = ansiRed + "revoked" + ansiReset
		}

		lastSeen := "never"
		if !d.LastSeenAt.IsZero() {
			lastSeen = fmtDuration(time.Since(d.LastSeenAt)) + " ago"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			d.DeviceID,
			d.Label,
			d.RegisteredAt.UTC().Format("2006-01-02"),
			lastSeen,
			status,
		)
	}
	w.Flush()
	return nil
}

func runDevicesRevoke(deviceID string) error {
	reg, err := loadServerRegistry()
	if err != nil {
		return err
	}
	if err := reg.RevokeDevice(deviceID); err != nil {
		printFail(err.Error())
		return err
	}
	printOK(fmt.Sprintf("Device %s%s%s revoked — active sessions will be rejected at next re-auth", ansiBold, deviceID, ansiReset))
	return nil
}
