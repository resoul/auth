package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/quota"
)

// CleanupPolicy holds retention bounds. A grace period counts from the moment a record stopped
// being useful.
type CleanupPolicy struct {
	// FlowGrace keeps a flow after its expires_at; the outbox rows go with it.
	FlowGrace time.Duration
	// RecognizedGrace keeps a recognition record after expires_at or revoked_at.
	RecognizedGrace time.Duration
	// SessionGrace keeps a session and its refresh tokens after the session ended.
	SessionGrace time.Duration
	// ChallengeGrace keeps a WebAuthn challenge after it expired.
	ChallengeGrace time.Duration
	// TicketGrace keeps a sign-in or step-up ticket after it expired.
	TicketGrace time.Duration
	// InvitationGrace keeps an unused invitation after it expired, so the operator can still see it, and the
	// mail that announced an invitation for as long after it was made.
	InvitationGrace time.Duration
	// AuditRetention keeps audit events; LastingAuditRetention keeps the longer-lived ones
	// (port.AuditEvent.Lasting) and is never shorter.
	AuditRetention        time.Duration
	LastingAuditRetention time.Duration
	// BatchSize rows per statement, MaxBatches statements per table per sweep: a sweep
	// holds no long lock and ends in bounded time. What is left waits for the next sweep.
	BatchSize  int
	MaxBatches int
}

// DefaultCleanupPolicy is the retention table of the security document.
func DefaultCleanupPolicy() CleanupPolicy {
	return CleanupPolicy{
		FlowGrace:       24 * time.Hour,
		RecognizedGrace: 24 * time.Hour,
		SessionGrace:    7 * 24 * time.Hour,
		ChallengeGrace:  time.Hour,
		TicketGrace:     24 * time.Hour,
		InvitationGrace: 7 * 24 * time.Hour,
		AuditRetention:  90 * 24 * time.Hour,

		LastingAuditRetention: 365 * 24 * time.Hour,
		BatchSize:             500,
		MaxBatches:            20,
	}
}

func (p CleanupPolicy) validate() error {
	if p.FlowGrace < 0 || p.RecognizedGrace < 0 || p.SessionGrace < 0 || p.ChallengeGrace < 0 || p.TicketGrace < 0 || p.InvitationGrace < 0 || p.AuditRetention <= 0 || p.LastingAuditRetention < p.AuditRetention || p.BatchSize < 1 || p.MaxBatches < 1 {
		return errors.New("cleanup policy: grace periods must not be negative, retention and batch bounds must be positive, and the lasting audit retention not shorter than the ordinary one")
	}

	return nil
}

// CleanupResult counts the rows a sweep deleted. More reports that a table still had rows
// to delete when its batch budget ran out.
type CleanupResult struct {
	Flows, RecognizedClients, Sessions, AuditEvents, QuotaEvents, Challenges, Tickets, Invitations, InvitationMails int64
	// OperatorRows are the sessions, ceremonies and enrollment codes of the admin API.
	OperatorRows int64
	// DeviceRequests are the expired requests of device sign-ins.
	DeviceRequests int64
	// OIDCRows are the expired requests and codes of the OpenID Provider, and its ended sign-ins with their grants.
	OIDCRows int64
	More     bool
}

// Total is the number of rows deleted.
func (r CleanupResult) Total() int64 {
	return r.Flows + r.RecognizedClients + r.Sessions + r.AuditEvents + r.QuotaEvents + r.Challenges + r.Tickets + r.Invitations + r.InvitationMails + r.OperatorRows + r.DeviceRequests + r.OIDCRows
}

// Cleanup deletes what the retention policy no longer keeps. It never touches an active
// flow, a mail under a live lease, a live session with its token history, or a quota
// counter inside its window: each statement selects only rows past their grace period, and
// the expiry of live records is checked at request time regardless of this sweep. Every
// batch is its own short transaction, so a stop between batches leaves consistent data.
func (s *Store) Cleanup(ctx context.Context, now time.Time, p CleanupPolicy) (CleanupResult, error) {
	if err := p.validate(); err != nil {
		return CleanupResult{}, err
	}

	q := sqlc.New(s.pool)

	var lastingEvents []string
	for _, t := range port.LastingAuditTypes() {
		lastingEvents = append(lastingEvents, string(t))
	}

	var res CleanupResult

	steps := []struct {
		name  string
		total *int64
		run   func() (int64, error)
	}{
		{"flows", &res.Flows, func() (int64, error) {
			return q.DeleteExpiredFlows(ctx, sqlc.DeleteExpiredFlowsParams{
				Horizon: now.Add(-p.FlowGrace), Now: &now, MaxRows: int32(p.BatchSize),
			})
		}},
		{"recognized clients", &res.RecognizedClients, func() (int64, error) {
			return q.DeleteEndedRecognizedClients(ctx, sqlc.DeleteEndedRecognizedClientsParams{
				Horizon: now.Add(-p.RecognizedGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"sessions", &res.Sessions, func() (int64, error) {
			horizon := now.Add(-p.SessionGrace)
			return q.DeleteEndedSessions(ctx, sqlc.DeleteEndedSessionsParams{Horizon: &horizon, MaxRows: int32(p.BatchSize)})
		}},
		{"challenges", &res.Challenges, func() (int64, error) {
			return q.DeleteExpiredChallenges(ctx, sqlc.DeleteExpiredChallengesParams{
				Horizon: now.Add(-p.ChallengeGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"tickets", &res.Tickets, func() (int64, error) {
			return q.DeleteExpiredTickets(ctx, sqlc.DeleteExpiredTicketsParams{
				Horizon: now.Add(-p.TicketGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"invitations", &res.Invitations, func() (int64, error) {
			return q.DeleteExpiredInvitations(ctx, sqlc.DeleteExpiredInvitationsParams{
				Horizon: now.Add(-p.InvitationGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"invitation mail", &res.InvitationMails, func() (int64, error) {
			return q.DeleteOldInvitationMail(ctx, sqlc.DeleteOldInvitationMailParams{
				Horizon: now.Add(-p.InvitationGrace), Now: &now, MaxRows: int32(p.BatchSize),
			})
		}},
		{"operator sessions", &res.OperatorRows, func() (int64, error) {
			return q.DeleteOldOperatorSessions(ctx, sqlc.DeleteOldOperatorSessionsParams{
				Horizon: now.Add(-p.SessionGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"operator challenges", &res.OperatorRows, func() (int64, error) {
			return q.DeleteExpiredOperatorChallenges(ctx, sqlc.DeleteExpiredOperatorChallengesParams{
				Horizon: now.Add(-p.ChallengeGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"operator enrollments", &res.OperatorRows, func() (int64, error) {
			return q.DeleteExpiredOperatorEnrollments(ctx, sqlc.DeleteExpiredOperatorEnrollmentsParams{
				Horizon: now.Add(-p.TicketGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"device requests", &res.DeviceRequests, func() (int64, error) {
			return q.DeleteExpiredDeviceRequests(ctx, sqlc.DeleteExpiredDeviceRequestsParams{
				Horizon: now.Add(-p.ChallengeGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"oidc requests", &res.OIDCRows, func() (int64, error) {
			return q.DeleteExpiredOIDCRequests(ctx, sqlc.DeleteExpiredOIDCRequestsParams{
				Horizon: now.Add(-p.ChallengeGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"oidc codes", &res.OIDCRows, func() (int64, error) {
			return q.DeleteExpiredOIDCCodes(ctx, sqlc.DeleteExpiredOIDCCodesParams{
				Horizon: now.Add(-p.TicketGrace), Now: now, MaxRows: int32(p.BatchSize),
			})
		}},
		{"oidc sessions", &res.OIDCRows, func() (int64, error) {
			return q.DeleteEndedOIDCSessions(ctx, sqlc.DeleteEndedOIDCSessionsParams{
				Horizon: now.Add(-p.SessionGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"oidc logout notices", &res.OIDCRows, func() (int64, error) {
			return q.DeleteOldOIDCLogout(ctx, sqlc.DeleteOldOIDCLogoutParams{
				Horizon: now.Add(-p.InvitationGrace), MaxRows: int32(p.BatchSize),
			})
		}},
		{"audit events", &res.AuditEvents, func() (int64, error) {
			return q.DeleteOldAuditEvents(ctx, sqlc.DeleteOldAuditEventsParams{
				Horizon: now.Add(-p.AuditRetention), LastingHorizon: now.Add(-p.LastingAuditRetention),
				LastingEvents: lastingEvents, CloneReason: port.CloneSuspectedReason, MaxRows: int32(p.BatchSize),
			})
		}},
		{"quota events", &res.QuotaEvents, func() (int64, error) {
			return q.PurgeQuotaEvents(ctx, sqlc.PurgeQuotaEventsParams{
				Horizon: now.Add(-quota.MaxWindow), MaxRows: int32(p.BatchSize),
			})
		}},
	}
	for _, step := range steps {
		for batch := 0; ; batch++ {
			if err := ctx.Err(); err != nil {
				return res, fmt.Errorf("cleanup %s: %w", step.name, err)
			}

			if batch == p.MaxBatches {
				res.More = true
				break
			}

			n, err := step.run()
			if err != nil {
				return res, fmt.Errorf("cleanup %s: %w", step.name, err)
			}

			*step.total += n
			if n < int64(p.BatchSize) {
				break
			}
		}
	}

	return res, nil
}
