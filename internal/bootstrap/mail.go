package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"airlance.org/auth/internal/adapter/clock"
	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/mail"
	"airlance.org/auth/internal/adapter/metrics"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/config"
)

// smtpTimeout bounds connecting to the SMTP server and each command.
const smtpTimeout = 10 * time.Second

// newMetrics builds the registry with the queue collectors, which read the store on each scrape.
func newMetrics(store *postgres.Store) (*metrics.Registry, error) {
	registry := metrics.New()
	err := registry.RegisterQueue(func(ctx context.Context, now time.Time) (port.QueueStats, error) {
		var stats port.QueueStats
		err := store.Do(ctx, func(ctx context.Context, st port.Stores) error {
			var err error
			stats, err = st.Outbox.Stats(ctx, now)
			return err
		})
		return stats, err
	}, clock.System{})
	if err != nil {
		return nil, fmt.Errorf("register queue metrics: %w", err)
	}
	return registry, nil
}

// newMailWorker builds the outbox worker on the shared store.
func newMailWorker(cfg config.Config, logger *slog.Logger, otp *crypto.OTP, store *postgres.Store, registry *metrics.Registry) (*mail.Worker, error) {
	if otp == nil {
		return nil, errors.New("mail worker needs the otp_hmac keys")
	}
	sender, err := mail.NewSMTPSender(mail.SMTPConfig{
		Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, TLS: mail.TLSMode(cfg.SMTP.TLS),
		Username: cfg.SMTP.Username, Password: cfg.SMTP.Password.Reveal(),
		FromAddress: cfg.SMTP.From, FromName: cfg.SMTP.FromName, Timeout: smtpTimeout,
	}, clock.System{})
	if err != nil {
		return nil, fmt.Errorf("create smtp sender: %w", err)
	}
	worker, err := mail.NewWorker(mail.WorkerDeps{
		UnitOfWork: store, Clock: clock.System{}, OTP: otp, Sender: sender, Metrics: registry,
		Logger: logger, Policy: mail.DefaultDeliveryPolicy(), InvitationURL: cfg.InvitationURL,
	})
	if err != nil {
		return nil, fmt.Errorf("create mail worker: %w", err)
	}
	return worker, nil
}
