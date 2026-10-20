package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
)

// newOperatorCommand manages the operators of the admin API. It is run on the server by whoever holds it and
// talks to the database directly: the admin API cannot create or enable an operator.
func newOperatorCommand() *cobra.Command {
	operator := &cobra.Command{
		Use:   "operator",
		Short: "Manage the operators of the admin API (needs AIRLANCE_AUTH_DATABASE_URL)",
	}
	run := func(cmd *cobra.Command, req bootstrap.OperatorRequest) error {
		cfg, err := config.Load(os.LookupEnv)
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return bootstrap.Operator(ctx, cfg, req, cmd.OutOrStdout())
	}
	withEmail := func(use, short string, action bootstrap.OperatorAction) *cobra.Command {
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return run(cmd, bootstrap.OperatorRequest{Action: action, Email: args[0]})
			},
		}
	}
	operator.AddCommand(
		withEmail("create EMAIL", "Register an operator and print the one-time code that enrolls their first key", bootstrap.OperatorCreate),
		withEmail("enroll EMAIL", "Print a new one-time code that adds a key to an operator, or brings back one who lost every key", bootstrap.OperatorEnroll),
		withEmail("disable EMAIL", "Bar an operator and end all their sessions", bootstrap.OperatorDisable),
		withEmail("enable EMAIL", "Lift the bar on an operator", bootstrap.OperatorEnable),
		&cobra.Command{
			Use:   "list",
			Short: "List operators with their key counts",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return run(cmd, bootstrap.OperatorRequest{Action: bootstrap.OperatorList})
			},
		},
	)

	return operator
}
