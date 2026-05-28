package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/daxson/tunnel/internal/registry"
	"github.com/daxson/tunnel/pkg/identity"
	"github.com/daxson/tunnel/pkg/invite"
)

func newInviteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Manage invite links (server-side)",
	}
	cmd.AddCommand(
		newInviteCreateCmd(),
		newInviteListCmd(),
		newInviteRevokeCmd(),
	)
	return cmd
}

func newInviteCreateCmd() *cobra.Command {
	var label string
	var maxUses int
	var ttl time.Duration
	var server string

	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new invite link",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInviteCreate(server, label, maxUses, ttl)
		},
	}
	c.Flags().StringVar(&server, "server", "", "Server address (host:port) to embed in the link")
	c.Flags().StringVar(&label, "label", "", "Human-readable label for this invite")
	c.Flags().IntVar(&maxUses, "max-uses", 1, "Maximum number of devices that can use this link (0 = unlimited)")
	c.Flags().DurationVar(&ttl, "ttl", 24*time.Hour, "How long the invite is valid (e.g. 24h, 7d)")
	_ = c.MarkFlagRequired("server")
	return c
}

func newInviteListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all invite records",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInviteList()
		},
	}
}

func newInviteRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke an invite by token ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInviteRevoke(args[0])
		},
	}
}

func runInviteCreate(server, label string, maxUses int, ttl time.Duration) error {
	reg, err := loadServerRegistry()
	if err != nil {
		return err
	}

	rec, err := reg.CreateInvite(label, maxUses, ttl)
	if err != nil {
		printFail("Create invite: " + err.Error())
		return err
	}

	// Build the signed invite link if server identity is available.
	payload := &invite.Payload{
		Version:   1,
		Server:    server,
		Token:     rec.Token,
		Label:     rec.Label,
		MaxUses:   rec.MaxUses,
		ExpiresAt: rec.ExpiresAt,
	}

	serverKey, err := tryLoadServerKey()
	if err == nil && serverKey != nil {
		payload.ServerKey = serverKey.PublicKey
		if signErr := payload.Sign(serverKey.PrivateKey); signErr != nil {
			printWarn("Could not sign invite link: " + signErr.Error())
		}
	} else {
		printWarn("Server identity not found — invite link will not be signed")
	}

	link := invite.Encode(payload)

	printOK(fmt.Sprintf("Invite created  (token-id: %s%s%s)", ansiBold, rec.TokenID, ansiReset))
	if rec.ExpiresAt != 0 {
		printKey("Expires", time.Unix(rec.ExpiresAt, 0).UTC().Format("2006-01-02 15:04 UTC"))
	}
	printKey("Max uses", fmt.Sprintf("%d", rec.MaxUses))
	fmt.Println()
	fmt.Printf("%s%s%s\n\n", ansiBold, link, ansiReset)
	fmt.Println("Share this link with the device owner. They run:")
	fmt.Printf("  daxson import %s<link>%s\n\n", ansiBold, ansiReset)
	return nil
}

func runInviteList() error {
	reg, err := loadServerRegistry()
	if err != nil {
		return err
	}

	invites := reg.ListInvites()
	if len(invites) == 0 {
		fmt.Println("No invites.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%sTOKEN-ID\tLABEL\tUSES\tEXPIRES\tSTATUS%s\n", ansiBold, ansiReset)
	for _, inv := range invites {
		status := "active"
		if inv.Revoked {
			status = ansiRed + "revoked" + ansiReset
		} else if inv.IsExpired() {
			status = ansiYellow + "expired" + ansiReset
		}

		maxStr := fmt.Sprintf("%d", inv.MaxUses)
		if inv.MaxUses <= 0 {
			maxStr = "∞"
		}
		usesStr := fmt.Sprintf("%d/%s", inv.Uses, maxStr)

		expires := "never"
		if inv.ExpiresAt != 0 {
			expires = time.Unix(inv.ExpiresAt, 0).UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", inv.TokenID, inv.Label, usesStr, expires, status)
	}
	w.Flush()
	return nil
}

func runInviteRevoke(tokenID string) error {
	reg, err := loadServerRegistry()
	if err != nil {
		return err
	}
	if err := reg.RevokeInvite(tokenID); err != nil {
		printFail(err.Error())
		return err
	}
	printOK(fmt.Sprintf("Invite %s%s%s revoked", ansiBold, tokenID, ansiReset))
	return nil
}

// loadServerRegistry opens the registry from the default path, printing a useful error if missing.
func loadServerRegistry() (*registry.Registry, error) {
	path := defaultRegistryPath()
	reg, err := registry.Load(path)
	if err != nil {
		printFail("Registry error: " + err.Error())
		return nil, err
	}
	return reg, nil
}

// tryLoadServerKey loads the server identity key if present, returning nil without error if absent.
func tryLoadServerKey() (*identity.KeyPair, error) {
	path := defaultServerIdentityPath()
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	return identity.Load(path)
}
