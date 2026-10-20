package memory

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

const (
	statusQueued = "queued"
	statusSent   = "sent"
	statusDead   = "dead"
)

type mailRecord struct {
	id         string
	job        port.MailJob
	status     string
	attempts   int
	leaseUntil time.Time
	lastError  port.MailReason
}

type outbox struct{ tx *state }

func (o *outbox) Enqueue(_ context.Context, job port.MailJob) error {
	if err := job.Validate(); err != nil {
		return fmt.Errorf("enqueue mail: %w", err)
	}

	job.Kind = job.EffectiveKind()
	for _, r := range o.tx.outbox {
		// An invitation job has no flow, so nothing identifies it: the same address may be invited again.
		if job.Kind != port.JobInvitation && job.Kind != port.JobNewDevice && r.job.FlowID == job.FlowID && r.job.Generation == job.Generation && r.job.Kind == job.Kind {
			return fmt.Errorf("enqueue mail: generation %d of this flow is already queued", job.Generation)
		}
	}

	id := fmt.Sprintf("00000000-0000-7000-8000-%012x", len(o.tx.outbox)+1)
	o.tx.outbox = append(o.tx.outbox, mailRecord{id: id, job: job, status: statusQueued})

	return nil
}

func (o *outbox) ready(r mailRecord, class authflow.QuotaClass, now time.Time) bool {
	return r.status == statusQueued && r.job.QuotaClass == class && !r.job.AvailableAt.After(now) &&
		(r.leaseUntil.IsZero() || !r.leaseUntil.After(now))
}

func (o *outbox) Claim(_ context.Context, now time.Time, lease time.Duration) (port.ClaimedMail, error) {
	// Recognized clients first; within a class the oldest due job.
	for _, class := range []authflow.QuotaClass{authflow.QuotaRecognized, authflow.QuotaUnknown} {
		best := -1

		for i, r := range o.tx.outbox {
			if !o.ready(r, class, now) {
				continue
			}

			if best < 0 || r.job.AvailableAt.Before(o.tx.outbox[best].job.AvailableAt) {
				best = i
			}
		}

		if best < 0 {
			continue
		}

		r := &o.tx.outbox[best]
		r.attempts++
		r.leaseUntil = now.Add(lease)

		id, err := port.ParseMailJobID(r.id)
		if err != nil {
			return port.ClaimedMail{}, err
		}

		return port.ClaimedMail{
			Kind: r.job.Kind, Recipient: r.job.Recipient,
			UserID: r.job.UserID, DeviceName: r.job.DeviceName, ClientIP: r.job.ClientIP, EventAt: r.job.EventAt,
			ID: id, FlowID: r.job.FlowID, Generation: r.job.Generation, QuotaClass: r.job.QuotaClass,
			Attempts: r.attempts, AvailableAt: r.job.AvailableAt,
		}, nil
	}

	return port.ClaimedMail{}, port.ErrNotFound
}

func (o *outbox) queued(id port.MailJobID) (*mailRecord, error) {
	for i := range o.tx.outbox {
		if o.tx.outbox[i].id == id.String() && o.tx.outbox[i].status == statusQueued {
			return &o.tx.outbox[i], nil
		}
	}

	return nil, port.ErrNotFound
}

func (o *outbox) Complete(_ context.Context, id port.MailJobID) error {
	r, err := o.queued(id)
	if err != nil {
		return err
	}

	r.status, r.leaseUntil, r.lastError = statusSent, time.Time{}, ""
	r.job.ClientIP = netip.Addr{} // kept only to be put into the mail

	return nil
}

func (o *outbox) Retry(_ context.Context, id port.MailJobID, availableAt time.Time, reason port.MailReason) error {
	if !reason.Valid() {
		return fmt.Errorf("retry mail: invalid reason code")
	}

	r, err := o.queued(id)
	if err != nil {
		return err
	}

	r.job.AvailableAt, r.leaseUntil, r.lastError = availableAt, time.Time{}, reason

	return nil
}

func (o *outbox) Abandon(_ context.Context, id port.MailJobID, reason port.MailReason) error {
	if !reason.Valid() {
		return fmt.Errorf("abandon mail: invalid reason code")
	}

	r, err := o.queued(id)
	if err != nil {
		return err
	}

	r.status, r.leaseUntil, r.lastError = statusDead, time.Time{}, reason
	r.job.ClientIP = netip.Addr{}

	return nil
}

func (o *outbox) Stats(_ context.Context, now time.Time) (port.QueueStats, error) {
	stats := port.QueueStats{
		Queued:     map[authflow.QuotaClass]int{authflow.QuotaRecognized: 0, authflow.QuotaUnknown: 0},
		OldestWait: map[authflow.QuotaClass]time.Duration{authflow.QuotaRecognized: 0, authflow.QuotaUnknown: 0},
	}

	for _, r := range o.tx.outbox {
		if r.status != statusQueued {
			continue
		}

		class := r.job.QuotaClass

		stats.Queued[class]++
		if wait := now.Sub(r.job.AvailableAt); wait > stats.OldestWait[class] {
			stats.OldestWait[class] = wait
		}
	}

	return stats, nil
}
