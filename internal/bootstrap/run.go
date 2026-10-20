package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"go.airlance.org/auth/internal/config"
)

// Run starts the service and blocks until ctx is cancelled or a component fails.
// The mail worker runs when SMTP is configured and the API when an HTTP address is;
// both share one database pool and one metrics registry.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	logKeyring(ctx, logger, cfg.Keyring)

	if public := config.PublicProxyNetworks(cfg.HTTP.TrustedProxies); len(public) > 0 {
		logger.WarnContext(ctx, "trusted proxy networks include public addresses; only a CDN in front of the service belongs there",
			"networks", public)
	}

	otp, err := newOTP(cfg.Keyring)
	if err != nil {
		return err
	}

	tokens, err := newJWT(cfg)
	if err != nil {
		return err
	}

	lc := newLifecycle(cfg.ShutdownTimeout)

	attrs := []any{"shutdown_timeout", cfg.ShutdownTimeout.String(), "registration", cfg.Registration}
	if cfg.SMTP.Enabled() || cfg.HTTP.Enabled() || cfg.Admin.Enabled() {
		store, err := openStore(ctx, cfg, cfg.Database.MaxConns)
		if err != nil {
			return err
		}
		// Closed after the lifecycle returns: the worker has finished its last job and
		// the server its last request.
		defer store.Close()

		registry, err := newMetrics(store)
		if err != nil {
			return err
		}

		oidc, err := newOIDCParts(cfg, store)
		if err != nil {
			return err
		}

		if oidc != nil {
			worker, err := newOIDCLogoutWorker(cfg, logger, oidc)
			if err != nil {
				return fmt.Errorf("start logout notice worker: %w", err)
			}

			lc.add(component{
				name: "oidc logout notices",
				// The worker watches ctx itself and finishes the notice it holds before returning.
				run:  worker.Run,
				stop: func(context.Context) error { return nil },
			})

			attrs = append(attrs, "oidc_issuer", cfg.OIDC.Issuer)
		}

		if cfg.Metrics.Enabled() {
			if config.ListensBeyondLoopback(cfg.Metrics.Addr) {
				logger.Warn("metrics listener is not on the loopback and has no authentication: keep its port inside the cluster or the compose network", "metrics_addr", cfg.Metrics.Addr)
			}

			srv, addr, err := newMetricsServer(cfg.Metrics.Addr, logger, registry)
			if err != nil {
				return fmt.Errorf("start metrics listener: %w", err)
			}

			lc.add(srv)

			attrs = append(attrs, "metrics_addr", addr.String())
		}

		if cfg.SMTP.Enabled() {
			worker, err := newMailWorker(cfg, logger, otp, store, registry)
			if err != nil {
				return fmt.Errorf("start mail worker: %w", err)
			}

			lc.add(component{
				name: "mail worker",
				// The worker watches ctx itself and finishes the job it holds before returning.
				run:  worker.Run,
				stop: func(context.Context) error { return nil },
			})
		}

		if cfg.HTTP.Enabled() {
			api, addr, err := newHTTP(cfg, logger, otp, tokens, store, registry, oidc)
			if err != nil {
				return fmt.Errorf("start http api: %w", err)
			}

			lc.add(api)

			attrs = append(attrs, "http_addr", addr.String())
		}

		if cfg.Admin.Enabled() {
			admin, addr, err := newAdmin(cfg, logger, store, registry)
			if err != nil {
				return fmt.Errorf("start admin api: %w", err)
			}

			lc.add(admin)

			attrs = append(attrs, "admin_addr", addr.String(), "admin_rp_id", cfg.Admin.RPID)
		}

		if cfg.HTTP.Enabled() || cfg.Admin.Enabled() {
			lc.add(newCleanup(logger, store))
		}
	}

	logger.InfoContext(ctx, "service started", attrs...)

	if err := lc.run(ctx); err != nil {
		return fmt.Errorf("service stopped: %w", err)
	}

	logger.InfoContext(context.WithoutCancel(ctx), "service stopped")

	return nil
}

// logKeyring reports which purposes and key IDs are configured. Paths and
// key material are never logged.
func logKeyring(ctx context.Context, logger *slog.Logger, ring *config.Keyring) {
	if ring == nil {
		logger.InfoContext(ctx, "keyring not configured")
		return
	}

	purposes := []struct {
		name string
		set  *config.KeySet
	}{
		{"otp_hmac", ring.OTPHMAC},
		{"jwt_signing", ring.JWTSigning},
	}
	for _, p := range purposes {
		if p.set == nil {
			continue
		}

		logger.InfoContext(ctx, "keyring purpose configured",
			"purpose", p.name,
			"active_kid", p.set.ActiveKID,
			"kids", slices.Sorted(maps.Keys(p.set.Keys)),
		)
	}
}
