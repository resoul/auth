package bootstrap

import (
	"context"
	"log/slog"
	"time"

	"airlance.org/auth/internal/adapter/clock"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/port"
)

// cleanupEvery is how often the retention sweep runs. Each sweep is bounded, so a backlog
// drains over several runs without a long lock.
const cleanupEvery = 10 * time.Minute

// sweeper deletes the records the retention policy no longer keeps.
type sweeper interface {
	Cleanup(ctx context.Context, now time.Time, p postgres.CleanupPolicy) (postgres.CleanupResult, error)
}

// newCleanup is the component that applies the retention policies.
// It stops with the service; a sweep in flight ends at the next batch boundary.
func newCleanup(logger *slog.Logger, s sweeper) component {
	return component{
		name: "cleanup",
		run: func(ctx context.Context) error {
			sweepEvery(ctx, logger, s, clock.System{}, postgres.DefaultCleanupPolicy(), cleanupEvery)
			return nil
		},
		stop: func(context.Context) error { return nil },
	}
}

// sweepEvery sweeps once at start and then every interval until ctx ends. A failed sweep is
// logged and retried at the next tick: stale rows cost space, not correctness, because
// expiry is checked when a record is used.
func sweepEvery(ctx context.Context, logger *slog.Logger, s sweeper, clk port.Clock, p postgres.CleanupPolicy, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		res, err := s.Cleanup(ctx, clk.Now(), p)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			logger.WarnContext(ctx, "cleanup failed", "error", err)
		case res.Total() > 0:
			logger.InfoContext(ctx, "cleanup finished",
				"flows", res.Flows, "recognized_clients", res.RecognizedClients, "sessions", res.Sessions,
				"audit_events", res.AuditEvents, "quota_events", res.QuotaEvents,
				"challenges", res.Challenges, "tickets", res.Tickets, "more", res.More)
		}
		wait := every
		if res.More {
			wait = time.Second // a backlog is left: continue soon instead of waiting a whole interval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
