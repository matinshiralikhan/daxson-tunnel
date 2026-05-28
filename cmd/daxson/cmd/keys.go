package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/daxson/tunnel/pkg/identity"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage the device key pair",
	}
	cmd.AddCommand(
		newKeysShowCmd(),
		newKeysRotateCmd(),
		newKeysExportCmd(),
	)
	return cmd
}

func newKeysShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the current device identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeysShow()
		},
	}
}

func newKeysRotateCmd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new device key pair (old key is moved to .bak)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeysRotate(force)
		},
	}
	c.Flags().BoolVar(&force, "force", false, "Overwrite backup if it already exists")
	return c
}

func newKeysExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Print the public key in base64url format",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeysExport()
		},
	}
}

func runKeysShow() error {
	keyPath := defaultIdentityPath()
	kp, err := identity.Load(keyPath)
	if err != nil {
		printFail("Device key error: " + err.Error())
		return err
	}

	printHeader("Device Identity")
	printKey("Device ID", fmt.Sprintf("%s%s%s", ansiBold, kp.DeviceID, ansiReset))
	printKey("Public Key", base64.RawURLEncoding.EncodeToString(kp.PublicKey))
	printKey("Created", kp.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	printKey("Path", keyPath)
	fmt.Println()
	return nil
}

func runKeysRotate(force bool) error {
	keyPath := defaultIdentityPath()

	// Load existing key first for display.
	existing, err := identity.Load(keyPath)
	if err != nil {
		printFail("Cannot read existing key: " + err.Error())
		return err
	}

	// Back up existing key.
	bakPath := keyPath + ".bak"
	if _, statErr := os.Stat(bakPath); statErr == nil && !force {
		printFail(fmt.Sprintf("Backup already exists at %s — use --force to overwrite", bakPath))
		return fmt.Errorf("keys rotate: backup exists")
	}
	if err := os.Rename(keyPath, bakPath); err != nil {
		printFail("Cannot back up existing key: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Backed up old key (device: %s%s%s) → %s", ansiBold, existing.DeviceID, ansiReset, bakPath))

	// Generate new key.
	newKP, err := identity.Load(keyPath) // auto-generates because we just moved the old one
	if err != nil {
		printFail("Key generation failed: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Generated new key  device: %s%s%s", ansiBold, newKP.DeviceID, ansiReset))

	fmt.Println()
	printWarn("You must re-register this device with 'daxson import' before connecting again.")
	fmt.Println()
	return nil
}

func runKeysExport() error {
	keyPath := defaultIdentityPath()
	kp, err := identity.Load(keyPath)
	if err != nil {
		printFail("Device key error: " + err.Error())
		return err
	}
	fmt.Printf("%s\n", base64.RawURLEncoding.EncodeToString(kp.PublicKey))
	return nil
}
