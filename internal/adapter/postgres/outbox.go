package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

type outbox struct {
	q   *sqlc.Queries
	ids RecordIDs
}

func (o *outbox) Enqueue(ctx context.Context, job port.MailJob) error {
	if err := job.Validate(); err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	id, err := o.ids.NewRecordID()
	if err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	generation, err := toInt64(job.Generation)
	if err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	var recipient pgtype.Text
	if !job.Recipient.IsZero() {
		recipient = pgText(job.Recipient.String())
	}

	var flowID pgtype.Text
	if !job.FlowID.IsZero() {
		flowID = pgText(job.FlowID.String())
	}

	if kind := job.EffectiveKind(); kind == port.JobInvitation || kind == port.JobNewDevice {
		generation = 1 // the column is NOT NULL and counts from 1; nothing reads it for these kinds
	}

	var (
		deviceName pgtype.Text
		clientIP   pgtype.Text
		eventAt    *time.Time
	)

	userID, err := optionalUserUUID(job.UserID)
	if err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	if job.EffectiveKind() == port.JobNewDevice {
		deviceName = pgText(job.DeviceName)
		if job.ClientIP.IsValid() {
			clientIP = pgText(job.ClientIP.String())
		}

		at := dbTime(job.EventAt)
		eventAt = &at
	}

	if err := o.q.EnqueueMail(ctx, sqlc.EnqueueMailParams{
		ID: id, FlowID: flowID, Generation: generation,
		QuotaClass: string(job.QuotaClass), AvailableAt: dbTime(job.AvailableAt),
		Kind: string(job.EffectiveKind()), Recipient: recipient,
		UserID: userID, DeviceName: deviceName, ClientIp: clientIP, EventAt: eventAt,
	}); err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	return nil
}

func (o *outbox) Claim(ctx context.Context, now time.Time, lease time.Duration) (port.ClaimedMail, error) {
	// Recognized clients are served first, then the rest.
	for _, class := range []authflow.QuotaClass{authflow.QuotaRecognized, authflow.QuotaUnknown} {
		row, err := o.q.ClaimMail(ctx, sqlc.ClaimMailParams{
			LeaseUntil: dbTime(now.Add(lease)), QuotaClass: string(class), Now: dbTime(now),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}

		if err != nil {
			return port.ClaimedMail{}, fmt.Errorf("claim mail: %w", err)
		}

		id, err := port.ParseMailJobID(row.ID.String())
		if err != nil {
			return port.ClaimedMail{}, fmt.Errorf("stored mail job id: %w", err)
		}

		var flowID authflow.FlowID
		if row.FlowID.Valid {
			if flowID, err = authflow.ParseFlowID(row.FlowID.String); err != nil {
				return port.ClaimedMail{}, fmt.Errorf("stored mail job flow: %w", err)
			}
		}

		var recipient identity.Email
		if row.Recipient.Valid {
			if recipient, err = identity.ParseEmail(row.Recipient.String); err != nil {
				return port.ClaimedMail{}, fmt.Errorf("stored mail job recipient: %w", err)
			}
		}

		userID, err := userFromOptional(row.UserID)
		if err != nil {
			return port.ClaimedMail{}, fmt.Errorf("stored mail job user: %w", err)
		}

		var clientIP netip.Addr
		if row.ClientIp.Valid {
			if clientIP, err = netip.ParseAddr(row.ClientIp.String); err != nil {
				return port.ClaimedMail{}, fmt.Errorf("stored mail job address: %w", err)
			}
		}

		var eventAt time.Time
		if row.EventAt != nil {
			eventAt = goTime(*row.EventAt)
		}

		return port.ClaimedMail{
			Kind: port.MailJobKind(row.Kind), Recipient: recipient,
			UserID: userID, DeviceName: row.DeviceName.String, ClientIP: clientIP, EventAt: eventAt,
			ID: id, FlowID: flowID, Generation: uint64(row.Generation), QuotaClass: authflow.QuotaClass(row.QuotaClass),
			Attempts: int(row.Attempts), AvailableAt: goTime(row.AvailableAt),
		}, nil
	}

	return port.ClaimedMail{}, port.ErrNotFound
}

func (o *outbox) Complete(ctx context.Context, id port.MailJobID) error {
	u, err := toUUID(id.String())
	if err != nil {
		return fmt.Errorf("complete mail: %w", err)
	}

	return queuedOnly(o.q.CompleteMail(ctx, u))
}

func (o *outbox) Retry(ctx context.Context, id port.MailJobID, availableAt time.Time, reason port.MailReason) error {
	if !reason.Valid() {
		return errors.New("retry mail: invalid reason code")
	}

	u, err := toUUID(id.String())
	if err != nil {
		return fmt.Errorf("retry mail: %w", err)
	}

	r := string(reason)

	return queuedOnly(o.q.RetryMail(ctx, sqlc.RetryMailParams{ID: u, AvailableAt: dbTime(availableAt), LastError: pgText(r)}))
}

func (o *outbox) Abandon(ctx context.Context, id port.MailJobID, reason port.MailReason) error {
	if !reason.Valid() {
		return errors.New("abandon mail: invalid reason code")
	}

	u, err := toUUID(id.String())
	if err != nil {
		return fmt.Errorf("abandon mail: %w", err)
	}

	return queuedOnly(o.q.AbandonMail(ctx, sqlc.AbandonMailParams{ID: u, LastError: pgText(string(reason))}))
}

// queuedOnly turns "no row updated" into ErrNotFound: the job was already finished.
func queuedOnly(n int64, err error) error {
	if err != nil {
		return fmt.Errorf("update mail job: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (o *outbox) Stats(ctx context.Context, now time.Time) (port.QueueStats, error) {
	rows, err := o.q.MailQueueStats(ctx)
	if err != nil {
		return port.QueueStats{}, fmt.Errorf("mail queue stats: %w", err)
	}

	stats := port.QueueStats{
		Queued:     map[authflow.QuotaClass]int{authflow.QuotaRecognized: 0, authflow.QuotaUnknown: 0},
		OldestWait: map[authflow.QuotaClass]time.Duration{authflow.QuotaRecognized: 0, authflow.QuotaUnknown: 0},
	}

	for _, row := range rows {
		class := authflow.QuotaClass(row.QuotaClass)

		stats.Queued[class] = int(row.Queued)
		if wait := now.Sub(row.OldestDue); wait > 0 {
			stats.OldestWait[class] = wait
		}
	}

	return stats, nil
}
