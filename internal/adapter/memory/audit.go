package memory

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.airlance.org/auth/internal/application/port"
)

type audit struct{ tx *state }

func (a *audit) Record(_ context.Context, e port.AuditEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}

	e.Fields = maps.Clone(e.Fields) // the caller keeps its own map
	a.tx.audit = append(a.tx.audit, e)

	return nil
}

// entryID orders entries recorded at the same instant by their position in the log.
func entryID(position int) string {
	return fmt.Sprintf("%012d", position)
}

func (a *audit) List(_ context.Context, q port.AuditQuery) ([]port.AuditEntry, error) {
	var out []port.AuditEntry

	for i := len(a.tx.audit) - 1; i >= 0; i-- {
		e := a.tx.audit[i]
		switch {
		case !q.UserID.IsZero() && e.UserID != q.UserID,
			!q.OperatorID.IsZero() && e.OperatorID != q.OperatorID,
			q.Type != "" && e.Type != q.Type:
			continue
		}

		entry := port.AuditEntry{ID: entryID(i), AuditEvent: e}
		if !q.Before.IsZero() && !entryBefore(entry, q.Before) {
			continue
		}

		entry.Fields = maps.Clone(e.Fields)
		out = append(out, entry)
	}
	// The log is in recording order, which is not always time order: sort as the database does.
	sortEntries(out)

	if len(out) > q.Limit {
		out = out[:q.Limit]
	}

	return out, nil
}

// entryBefore reports whether the entry sorts after the cursor, that is, is older than it.
func entryBefore(e port.AuditEntry, c port.AuditCursor) bool {
	if !e.At.Equal(c.At) {
		return e.At.Before(c.At)
	}

	return e.ID < c.ID
}

func sortEntries(entries []port.AuditEntry) {
	slices.SortFunc(entries, func(a, b port.AuditEntry) int {
		if c := b.At.Compare(a.At); c != 0 {
			return c
		}

		return strings.Compare(b.ID, a.ID)
	})
}
