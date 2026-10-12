package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/session"
)

type audit struct {
	q   *sqlc.Queries
	ids RecordIDs
}

func (a *audit) Record(ctx context.Context, e port.AuditEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	id, err := a.ids.NewRecordID()
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	var userID, sessionID, operatorID *uuid.UUID
	if !e.UserID.IsZero() {
		u, err := userUUID(e.UserID)
		if err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		userID = &u
	}
	if !e.SessionID.IsZero() {
		s, err := toUUID(e.SessionID.String())
		if err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		sessionID = &s
	}
	if !e.OperatorID.IsZero() {
		o, err := toUUID(e.OperatorID.String())
		if err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		operatorID = &o
	}
	fields := e.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("record audit event: encode fields: %w", err)
	}
	if err := a.q.RecordAuditEvent(ctx, sqlc.RecordAuditEventParams{
		ID: id, UserID: userID, SessionID: sessionID, OperatorID: operatorID, Event: string(e.Type), Result: string(e.Result),
		OccurredAt: dbTime(e.At), Fields: encoded,
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func (a *audit) List(ctx context.Context, q port.AuditQuery) ([]port.AuditEntry, error) {
	params := sqlc.ListAuditEventsParams{MaxRows: int32(q.Limit)}
	var err error
	if params.UserID, err = optionalUserUUID(q.UserID); err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	if !q.OperatorID.IsZero() {
		o, err := toUUID(q.OperatorID.String())
		if err != nil {
			return nil, fmt.Errorf("list audit events: %w", err)
		}
		params.OperatorID = &o
	}
	if q.Type != "" {
		params.Event = pgText(string(q.Type))
	}
	if !q.Before.IsZero() {
		at := dbTime(q.Before.At)
		id, err := toUUID(q.Before.ID)
		if err != nil {
			return nil, fmt.Errorf("list audit events: cursor: %w", err)
		}
		params.BeforeAt, params.BeforeID = &at, &id
	}
	rows, err := a.q.ListAuditEvents(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	out := make([]port.AuditEntry, 0, len(rows))
	for _, row := range rows {
		entry, err := auditFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func auditFromRow(row sqlc.ListAuditEventsRow) (port.AuditEntry, error) {
	e := port.AuditEvent{Type: port.AuditType(row.Event), Result: port.AuditResult(row.Result), At: goTime(row.OccurredAt)}
	var err error
	if e.UserID, err = userFromOptional(row.UserID); err != nil {
		return port.AuditEntry{}, fmt.Errorf("stored audit user: %w", err)
	}
	if row.SessionID != nil {
		if e.SessionID, err = session.ParseID(row.SessionID.String()); err != nil {
			return port.AuditEntry{}, fmt.Errorf("stored audit session: %w", err)
		}
	}
	if row.OperatorID != nil {
		if e.OperatorID, err = operator.ParseID(row.OperatorID.String()); err != nil {
			return port.AuditEntry{}, fmt.Errorf("stored audit operator: %w", err)
		}
	}
	var fields map[string]string
	if err := json.Unmarshal(row.Fields, &fields); err != nil {
		return port.AuditEntry{}, fmt.Errorf("stored audit fields: %w", err)
	}
	if len(fields) > 0 {
		e.Fields = fields
	}
	return port.AuditEntry{ID: row.ID.String(), AuditEvent: e}, nil
}
