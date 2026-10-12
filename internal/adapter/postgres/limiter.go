package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/quota"
)

// limiter keeps one row per admitted spend and counts the rows inside each window,
// so the windows slide and a burst on a bucket boundary is counted. The budgets of a
// spend are locked with advisory locks, in a fixed order, before they are counted:
// concurrent spends of one budget run one after another and never admit more than
// the limit. The locks end with the transaction, together with the charge.
type limiter struct {
	q       *sqlc.Queries
	profile quota.Profile
}

type budget struct {
	limit  quota.Limit
	hash   []byte
	lockID int64
}

func (l *limiter) Allow(ctx context.Context, spend port.Spend) (bool, error) {
	limits, err := l.profile.Limits(spend)
	if err != nil {
		return false, err
	}
	if len(limits) == 0 {
		return true, nil
	}

	budgets := make([]budget, len(limits))
	for i, lim := range limits {
		sum := sha256.Sum256([]byte(string(lim.Scope) + "\x00" + lim.Key))
		budgets[i] = budget{limit: lim, hash: sum[:], lockID: int64(binary.BigEndian.Uint64(sum[:8]))}
	}
	slices.SortFunc(budgets, func(a, b budget) int {
		switch {
		case a.lockID < b.lockID:
			return -1
		case a.lockID > b.lockID:
			return 1
		}
		return 0
	})
	for _, b := range budgets {
		if err := l.q.LockQuotaBudget(ctx, b.lockID); err != nil {
			return false, fmt.Errorf("lock quota budget: %w", err)
		}
	}

	for _, b := range budgets {
		for _, w := range b.limit.Windows {
			used, err := l.q.CountQuotaEvents(ctx, sqlc.CountQuotaEventsParams{KeyHash: b.hash, After: spend.Now.Add(-w.Per)})
			if err != nil {
				return false, fmt.Errorf("count quota events: %w", err)
			}
			if used >= int64(w.Limit) {
				return false, nil
			}
		}
	}
	for _, b := range budgets {
		if err := l.q.PruneQuotaBudget(ctx, sqlc.PruneQuotaBudgetParams{KeyHash: b.hash, Horizon: spend.Now.Add(-quota.MaxWindow)}); err != nil {
			return false, fmt.Errorf("prune quota events: %w", err)
		}
		if err := l.q.AddQuotaEvent(ctx, sqlc.AddQuotaEventParams{KeyHash: b.hash, At: spend.Now}); err != nil {
			return false, fmt.Errorf("add quota event: %w", err)
		}
	}
	return true, nil
}
