package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/daxson/tunnel/internal/auth"
	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/internal/obfs"
	tlstransport "github.com/daxson/tunnel/internal/transport/tls"
	"github.com/daxson/tunnel/pkg/identity"
	"github.com/daxson/tunnel/pkg/invite"
)

func newImportCmd() *cobra.Command {
	var profileName string
	var deviceLabel string
	var noVerify bool

	cmd := &cobra.Command{
		Use:   "import <daxson://...>",
		Short: "Import an invite link and register this device",
		Long: `Import a daxson:// invite link, register this device with the server,
and save the connection profile. After importing, run 'daxson connect'.`,
		Example: "  daxson import daxson://v1/eyJ...\n  daxson import daxson://v1/eyJ... --name work --label my-laptop",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(args[0], profileName, deviceLabel, noVerify)
		},
	}
	cmd.Flags().StringVar(&profileName, "name", "default", "Profile name to save as")
	cmd.Flags().StringVar(&deviceLabel, "label", "", "Label for this device (shown in server dashboard)")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "Skip server signature verification")
	return cmd
}

func runImport(link, profileName, deviceLabel string, noVerify bool) error {
	fmt.Printf("Importing invite...\n\n")

	// 1. Parse the invite link.
	payload, err := invite.Decode(link)
	if err != nil {
		printFail("Invalid invite link: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Server: %s%s%s", ansiBold, payload.Server, ansiReset))

	if payload.IsExpired() {
		printFail("Invite has expired")
		return fmt.Errorf("invite expired")
	}

	// 2. Verify server signature (if server key present).
	if len(payload.ServerKey) > 0 && !noVerify {
		if err := payload.VerifySignature(); err != nil {
			printFail("Signature verification failed: " + err.Error())
			return err
		}
		printOK("Server signature verified")
	} else if noVerify {
		printWarn("Skipping signature verification")
	}

	// 3. Load or generate device key pair.
	keyPath := defaultIdentityPath()
	kp, err := identity.Load(keyPath)
	if err != nil {
		printFail("Failed to load/generate device key: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Device identity: %s%s%s (key: %s)", ansiBold, kp.DeviceID, ansiReset, keyPath))

	if deviceLabel == "" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			deviceLabel = hostname
		} else {
			deviceLabel = "device-" + kp.DeviceID
		}
	}

	// 4. Dial the server and send bootstrap request.
	fmt.Printf("\nRegistering with server...\n")

	tr := tlstransport.NewClient(
		extractHostname(payload.Server),
		"chrome",
		[]string{"h2", "http/1.1"},
		false,
	)

	log := zap.NewNop()
	rawConn, err := tr.Dial(context.Background(), payload.Server)
	if err != nil {
		printFail("Cannot reach server: " + err.Error())
		return fmt.Errorf("dial %s: %w", payload.Server, err)
	}
	defer rawConn.Close()

	// Wrap with minimal BCL (relay personality: low overhead).
	obfsCfg := obfs.Config{Enabled: false}
	conn := obfs.Wrap(rawConn, obfsCfg, log)

	_, err = auth.BootstrapClient(conn, payload.Token, kp, deviceLabel)
	if err != nil {
		printFail("Registration failed: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Registered as %s%s%s", ansiBold, deviceLabel, ansiReset))

	// 5. Save the connection profile.
	profile := config.ClientProfileDefaults()
	profile.Version = 1
	profile.Name = profileName
	profile.Server = payload.Server
	profile.ServerKey = payload.ServerKey
	profile.DeviceKey = keyPath

	profilePath := filepath.Join(defaultProfileDir(), profileName+".yaml")
	if err := config.SaveClientProfile(&profile, profilePath); err != nil {
		printFail("Could not save profile: " + err.Error())
		return err
	}
	printOK(fmt.Sprintf("Profile saved to %s", profilePath))

	fmt.Printf("\n%sReady!%s Run %s'daxson connect'%s to start the tunnel.\n",
		ansiGreen, ansiReset, ansiBold, ansiReset)
	return nil
}

func extractHostname(addr string) string {
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}
