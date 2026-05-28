package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/daxson/tunnel/internal/config"
	"github.com/daxson/tunnel/pkg/identity"
)

func newDoctorCmd() *cobra.Command {
	var profileName string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostics and check configuration",
		Long:  `Check device identity, profile configuration, server reachability, and proxy listeners.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(profileName)
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "default", "Profile to diagnose")
	return cmd
}

func runDoctor(profileName string) error {
	allOK := true
	fail := func(msg string) {
		printFail(msg)
		allOK = false
	}

	printHeader("Identity")
	keyPath := defaultIdentityPath()
	kp, err := identity.Load(keyPath)
	if err != nil {
		fail("Device key: " + err.Error())
	} else {
		printOK(fmt.Sprintf("Device ID  %s%s%s  (%s)", ansiBold, kp.DeviceID, ansiReset, keyPath))
	}

	printHeader("Profile")
	profilePath := filepath.Join(defaultProfileDir(), profileName+".yaml")
	profile, err := config.LoadClientProfile(profilePath)
	if err != nil {
		fail(fmt.Sprintf("Profile %q not found (%s)", profileName, profilePath))
		printInfo("Run 'daxson import <link>' to create a profile.")
		fmt.Println()
		if allOK {
			return nil
		}
		return fmt.Errorf("doctor: %d check(s) failed", countFails(allOK))
	}
	printOK(fmt.Sprintf("Profile %q  server: %s%s%s", profile.Name, ansiBold, profile.Server, ansiReset))

	printHeader("Connectivity")
	checkTCPAndTLS(profile.Server, &allOK)

	printHeader("Proxy")
	if profile.Proxy.SOCKS5 != "" {
		checkPortFree("SOCKS5", profile.Proxy.SOCKS5, &allOK)
	} else {
		printWarn("SOCKS5 not configured in profile")
	}
	if profile.Proxy.HTTP != "" {
		checkPortFree("HTTP", profile.Proxy.HTTP, &allOK)
	} else {
		printWarn("HTTP proxy not configured in profile")
	}

	printHeader("Status")
	statusPath := defaultStatusPath()
	if _, err := os.Stat(statusPath); err == nil {
		data, _ := os.ReadFile(statusPath)
		if len(data) > 0 {
			printOK("Status file present (tunnel may be running — check 'daxson status')")
		}
	} else {
		printInfo("Not connected (no status file)")
	}

	fmt.Println()
	if allOK {
		fmt.Printf("%sAll checks passed.%s\n", ansiGreen, ansiReset)
	} else {
		fmt.Printf("%sSome checks failed.%s\n", ansiRed, ansiReset)
		return fmt.Errorf("doctor: one or more checks failed")
	}
	return nil
}

func checkTCPAndTLS(addr string, allOK *bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		printFail(fmt.Sprintf("TCP connect %s: %s", addr, err))
		*allOK = false
		return
	}
	printOK(fmt.Sprintf("TCP connect  %s%s%s", ansiBold, addr, ansiReset))

	host, _, _ := net.SplitHostPort(addr)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
	})
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	err = tlsConn.Handshake()
	tlsConn.Close()

	if err != nil {
		printWarn(fmt.Sprintf("TLS handshake: %s (server uses custom fingerprint — may be normal)", err))
	} else {
		state := tlsConn.ConnectionState()
		printOK(fmt.Sprintf("TLS handshake  proto=%s", state.NegotiatedProtocol))
	}
}

func checkPortFree(label, addr string, allOK *bool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		printFail(fmt.Sprintf("%s %s: port in use — %s", label, addr, err))
		*allOK = false
		return
	}
	ln.Close()
	printOK(fmt.Sprintf("%s %s%s%s  port is free", label, ansiBold, addr, ansiReset))
}

func countFails(allOK bool) int {
	if allOK {
		return 0
	}
	return 1
}
