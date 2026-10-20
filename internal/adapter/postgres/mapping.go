package postgres

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"go.airlance.org/auth/internal/domain/identity"
)

// dbTime normalizes a time for storage: PostgreSQL keeps microseconds, so the
// value is truncated here, in UTC, and a read returns exactly what was written.
func dbTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

func dbTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	v := dbTime(t)

	return &v
}

func goTime(t time.Time) time.Time {
	return t.UTC()
}

func goTimePtr(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}

	return t.UTC()
}

func toUUID(s string) (uuid.UUID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("parse uuid: %w", err)
	}

	return u, nil
}

func userUUID(id identity.UserID) (uuid.UUID, error) {
	return toUUID(id.String())
}

func toInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("value %d does not fit a bigint", v)
	}

	return int64(v), nil
}

func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}
