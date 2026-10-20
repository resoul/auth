package memory

import (
	"context"
	"slices"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/quota"
)

type limiter struct {
	tx      *state
	profile quota.Profile
}

func eventKey(l quota.Limit) string { return string(l.Scope) + "\x00" + l.Key }

// Allow keeps the times of the admitted spends per budget and counts those inside the
// sliding window, like the PostgreSQL limiter. Slices are replaced, never appended in
// place, so a rolled back transaction cannot leak into the committed copy.
func (l *limiter) Allow(_ context.Context, spend port.Spend) (bool, error) {
	limits, err := l.profile.Limits(spend)
	if err != nil {
		return false, err
	}

	for _, lim := range limits {
		events := l.tx.events[eventKey(lim)]
		for _, w := range lim.Windows {
			if countAfter(events, spend.Now.Add(-w.Per)) >= w.Limit {
				return false, nil
			}
		}
	}

	horizon := spend.Now.Add(-quota.MaxWindow)

	for _, lim := range limits {
		key := eventKey(lim)
		kept := slices.DeleteFunc(slices.Clone(l.tx.events[key]), func(at time.Time) bool { return !at.After(horizon) })
		l.tx.events[key] = append(kept, spend.Now)
	}

	l.tx.spent[spendKey{spend.Kind, spend.Email.String()}]++

	return true, nil
}

func countAfter(events []time.Time, from time.Time) int {
	n := 0

	for _, at := range events {
		if at.After(from) {
			n++
		}
	}

	return n
}
