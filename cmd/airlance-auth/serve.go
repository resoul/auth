package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"airlance.org/auth/internal/bootstrap"
	"airlance.org/auth/internal/config"
)

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the service until SIGINT or SIGTERM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(os.LookupEnv)
			if err != nil {
				return err
			}
			logger := bootstrap.NewLogger(cmd.ErrOrStderr(), cfg.Log).With("version", version())

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				stop()
			}()

			return bootstrap.Run(ctx, cfg, logger)
		},
	}
}
