package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/daxson/tunnel/pkg/identity"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Guided first-time setup wizard",
		Long:  `Walk through first-time setup: generate a device identity and show next steps.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit()
		},
	}
}

func runInit() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sDaxson Setup Wizard%s\n", ansiBold, ansiReset)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Println()

	// Step 1: Check/create device identity.
	printHeader("Step 1 — Device Identity")
	keyPath := defaultIdentityPath()
	if _, err := os.Stat(keyPath); err == nil {
		kp, err := identity.Load(keyPath)
		if err == nil {
			printOK(fmt.Sprintf("Identity already exists  (device: %s%s%s)", ansiBold, kp.DeviceID, ansiReset))
			fmt.Printf("  Path: %s\n", keyPath)
		} else {
			printFail("Existing identity file could not be read: " + err.Error())
			return err
		}
	} else {
		printInfo("No identity found — generating a new Ed25519 key pair...")
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			printFail("Cannot create config directory: " + err.Error())
			return err
		}
		kp, err := identity.Load(keyPath) // auto-generates if missing
		if err != nil {
			printFail("Key generation failed: " + err.Error())
			return err
		}
		printOK(fmt.Sprintf("Generated identity  (device: %s%s%s)", ansiBold, kp.DeviceID, ansiReset))
		fmt.Printf("  Path: %s\n", keyPath)
	}

	// Step 2: Check for profiles.
	printHeader("Step 2 — Connection Profiles")
	profileDir := defaultProfileDir()
	entries, _ := os.ReadDir(profileDir)
	var profiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			profiles = append(profiles, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}

	if len(profiles) == 0 {
		printInfo("No profiles found yet.")
		fmt.Println()
		fmt.Println("  To get started, ask your server admin for an invite link, then run:")
		fmt.Printf("    %sdaxson import daxson://v1/<token>%s\n", ansiBold, ansiReset)
	} else {
		for _, p := range profiles {
			printOK(fmt.Sprintf("Profile %q", p))
		}
		fmt.Println()
		fmt.Println("  To connect, run:")
		fmt.Printf("    %sdaxson connect%s\n", ansiBold, ansiReset)
	}

	// Step 3: Quick check of config directory.
	printHeader("Step 3 — Configuration Directory")
	cfgDir := configDir()
	printOK(fmt.Sprintf("Config directory: %s%s%s", ansiBold, cfgDir, ansiReset))

	// Step 4: Optional — ask if they want to run doctor.
	fmt.Println()
	fmt.Printf("Run diagnostics now? [y/N] ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "y" || line == "yes" {
		fmt.Println()
		_ = runDoctor("default")
	}

	fmt.Println()
	fmt.Printf("%sSetup complete.%s\n", ansiGreen, ansiReset)
	return nil
}
