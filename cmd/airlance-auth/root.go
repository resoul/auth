package main

import (
	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "airlance-auth",
		Short:         "Passwordless authentication service",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServeCommand(), newMigrateCommand(), newVersionCommand(), newHealthcheckCommand(), newInviteCommand(), newOperatorCommand(), newOIDCCommand())
	return root
}
