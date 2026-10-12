package admin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/operator"
)

// AuditDeps are the dependencies of Audit.
type AuditDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

// Audit lets an operator read the audit log.
type Audit struct{ AuditDeps }

// NewAudit checks the dependencies once, at assembly time.
func NewAudit(d AuditDeps) (*Audit, error) {
	if d.UnitOfWork == nil || d.Clock == nil {
		return nil, errors.New("new admin audit: all dependencies are required")
	}
	return &Audit{d}, nil
}

// ListAuditCommand is the input of List. An empty filter does not filter.
type ListAuditCommand struct {
	Actor      Actor
	UserID     string
	OperatorID string
	Type       string
	// Before is the Next of the previous page.
	Before string
	// Limit is the page size; 0 means DefaultPageSize.
	Limit int
}

// ListAuditResult is the output of List.
type ListAuditResult struct {
	Outcome Outcome
	Entries []port.AuditEntry
	// Next is the Before of the following page, or "" on the last one.
	Next string
}

// List returns a page of audit entries, newest first.
func (a *Audit) List(ctx context.Context, cmd ListAuditCommand) (ListAuditResult, error) {
	q := port.AuditQuery{}
	var err error
	if cmd.UserID != "" {
		if q.UserID, err = identity.ParseUserID(cmd.UserID); err != nil {
			return ListAuditResult{}, invalid("the user id is not valid")
		}
	}
	if cmd.OperatorID != "" {
		if q.OperatorID, err = operator.ParseID(cmd.OperatorID); err != nil {
			return ListAuditResult{}, invalid("the operator id is not valid")
		}
	}
	if cmd.Type != "" {
		q.Type = port.AuditType(cmd.Type)
		if !q.Type.Valid() {
			return ListAuditResult{}, invalid("unknown event type")
		}
	}
	if cmd.Before != "" {
		if q.Before, err = decodeCursor(cmd.Before); err != nil {
			return ListAuditResult{}, invalid("the cursor is not valid")
		}
	}
	limit := cmd.Limit
	switch {
	case limit == 0:
		limit = DefaultPageSize
	case limit < 0 || limit > MaxPageSize:
		return ListAuditResult{}, invalid("the page size must be between 1 and %d", MaxPageSize)
	}
	q.Limit = limit + 1 // one more tells whether another page follows

	now := a.Clock.Now()
	var result ListAuditResult
	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}
		entries, err := st.AuditReads.List(ctx, q)
		if err != nil {
			return fmt.Errorf("list audit: %w", err)
		}
		result = ListAuditResult{Outcome: OutcomeOK, Entries: entries}
		if len(entries) > limit {
			result.Entries = entries[:limit]
			last := entries[limit-1]
			result.Next = encodeCursor(port.AuditCursor{At: last.At, ID: last.ID})
		}
		return nil
	})
	if err != nil {
		return ListAuditResult{}, fmt.Errorf("list audit: %w", err)
	}
	return result, nil
}

func encodeCursor(c port.AuditCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.At.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeCursor(s string) (port.AuditCursor, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return port.AuditCursor{}, err
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return port.AuditCursor{}, errors.New("cursor: want time|id")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return port.AuditCursor{}, fmt.Errorf("cursor: %w", err)
	}
	return port.AuditCursor{At: t, ID: id}, nil
}
