package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
)

// newInviteCommand manages the invitations of the invite-only registration mode. It is run on the
// server by the operator and talks to the database directly: there is no invitation API.
func newInviteCommand() *cobra.Command {
	invite := &cobra.Command{
		Use:   "invite",
		Short: "Manage invitations for AIRLANCE_AUTH_REGISTRATION=invite (needs AIRLANCE_AUTH_DATABASE_URL)",
	}
	run := func(cmd *cobra.Command, req bootstrap.InviteRequest) error {
		cfg, err := config.Load(os.LookupEnv)
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return bootstrap.Invite(ctx, cfg, req, cmd.OutOrStdout())
	}

	create := &cobra.Command{
		Use:   "create EMAIL",
		Short: "Allow an address to register and email it the invitation (renews an existing invitation)",
		Args:  cobra.ExactArgs(1),
	}
	ttl := create.Flags().Duration("ttl", 7*24*time.Hour, "how long the invitation allows a registration (1h to 2160h)")
	noMail := create.Flags().Bool("no-mail", false, "do not queue the invitation email; tell them yourself")
	create.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, bootstrap.InviteRequest{Action: bootstrap.InviteCreate, Email: args[0], TTL: *ttl, NoMail: *noMail})
	}

	invite.AddCommand(create,
		&cobra.Command{
			Use:   "list",
			Short: "List invitations, active and expired",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return run(cmd, bootstrap.InviteRequest{Action: bootstrap.InviteList})
			},
		},
		&cobra.Command{
			Use:   "revoke EMAIL",
			Short: "Withdraw an invitation",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return run(cmd, bootstrap.InviteRequest{Action: bootstrap.InviteRevoke, Email: args[0]})
			},
		},
	)

	return invite
}
