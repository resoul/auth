package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/resoul/api/internal/di"
	"github.com/resoul/api/internal/transport/http/router"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var serveCmd = cobra.Command{
	Use:  "serve",
	Long: "Start API server",
	Run: func(cmd *cobra.Command, args []string) {
		serve(cmd)
	},
}

func serve(cmd *cobra.Command) {
	ctx := cmd.Context()

	container, err := di.NewContainer(ctx)
	if err != nil {
		logrus.WithError(err).Fatal("failed to initialize container")
	}
	defer container.Close()

	// Config is owned by the container — no second config.Init call here.
	cfg := container.Config

	r := router.New(cfg, container.DB, container.ProfileService)

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logrus.Infof("starting server on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	logrus.Info("shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Error("forced shutdown")
	}

	logrus.Info("server exited")
}
