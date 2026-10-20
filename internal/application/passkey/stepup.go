package passkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// Step-up: sensitive operations need a strong proof made now, not one made when the session was
// opened. The proof is a passkey assertion with user verification; it buys one ticket for one
// operation of one session, valid for five minutes.

// BeginStepUpDeps are the dependencies of BeginStepUp.
type BeginStepUpDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	PasskeyIDs port.PasskeyIDGenerator
}

// BeginStepUp starts the assertion that proves a fresh factor for one operation.
type BeginStepUp struct {
	BeginStepUpDeps
}

// NewBeginStepUp checks the dependencies once, at assembly time.
func NewBeginStepUp(d BeginStepUpDeps) (*BeginStepUp, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new begin step up: all dependencies are required")
	}

	return &BeginStepUp{d}, nil
}

// BeginStepUpCommand is the input of BeginStepUp. Actor comes from Authenticator.
type BeginStepUpCommand struct {
	Actor     appsession.Actor
	Operation dpasskey.Operation
	ClientIP  netip.Addr
}

// Execute prepares the assertion for the operation.
func (u *BeginStepUp) Execute(ctx context.Context, cmd BeginStepUpCommand) (CeremonyResult, error) {
	if !cmd.Operation.Valid() {
		return CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonBadTicket}, nil
	}

	now := u.Clock.Now()

	var result CeremonyResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}

		creds, err := st.Credentials.ListByUser(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}

		if len(creds) == 0 {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonNoKey}
			return nil
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendPasskey, IP: cmd.ClientIP, Ref: cmd.Actor.SessionID.String(), Now: now})
		if err != nil {
			return fmt.Errorf("spend passkey quota: %w", err)
		}

		if !allowed {
			result = CeremonyResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		ceremony, err := u.WebAuthn.BeginLogin()
		if err != nil {
			return fmt.Errorf("begin assertion: %w", err)
		}

		id, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new challenge id: %w", err)
		}

		challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
			ID: id, Purpose: dpasskey.ChallengeStepUp, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID,
			Operation: cmd.Operation, Data: ceremony.State, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new challenge: %w", err)
		}

		if err := st.Challenges.Create(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		result = CeremonyResult{Outcome: OutcomeOK, ChallengeID: id.String(), Options: ceremony.Options}

		return nil
	})
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin step up: %w", err)
	}

	return result, nil
}

// FinishStepUpDeps are the dependencies of FinishStepUp.
type FinishStepUpDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Tickets    port.TicketSecrets
	PasskeyIDs port.PasskeyIDGenerator
}

// FinishStepUp verifies the assertion and hands out the step-up ticket.
type FinishStepUp struct {
	FinishStepUpDeps
}

// NewFinishStepUp checks the dependencies once, at assembly time.
func NewFinishStepUp(d FinishStepUpDeps) (*FinishStepUp, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Tickets == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new finish step up: all dependencies are required")
	}

	return &FinishStepUp{d}, nil
}

// FinishStepUpCommand is the input of FinishStepUp. Actor comes from Authenticator.
type FinishStepUpCommand struct {
	Actor       appsession.Actor
	ChallengeID string
	// Response is the JSON the client got from navigator.credentials.get.
	Response []byte
}

// FinishStepUpResult is the output of FinishStepUp. The ticket fields are set only for OutcomeOK.
type FinishStepUpResult struct {
	Outcome         Outcome
	Reason          Reason
	Operation       dpasskey.Operation
	TicketSecret    string
	TicketExpiresAt time.Time
}

// Execute proves the factor. A refused ceremony spends its challenge, so each try needs a new one.
func (u *FinishStepUp) Execute(ctx context.Context, cmd FinishStepUpCommand) (FinishStepUpResult, error) {
	denied := func(reason Reason) (FinishStepUpResult, error) {
		return FinishStepUpResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}

	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return denied(ReasonBadChallenge)
	}

	now := u.Clock.Now()

	var result FinishStepUpResult

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result, _ = denied(ReasonNoSession)
			return nil
		}

		challenge, err := st.Challenges.GetForUpdate(ctx, challengeID)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}

		if err != nil {
			return fmt.Errorf("load challenge: %w", err)
		}
		// The challenge belongs to one session of one user: another session's cannot be finished here.
		if challenge.UserID() != cmd.Actor.UserID || challenge.SessionID() != cmd.Actor.SessionID {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}

		if challengeDenied(challenge.Consume(now, dpasskey.ChallengeStepUp)) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}

		if err := st.Challenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		var credential *dpasskey.Credential

		lookup := func(credentialID []byte, userHandle port.UserHandle) (*dpasskey.Credential, error) {
			c, err := st.Credentials.GetForUpdate(ctx, credentialID)
			if err != nil {
				return nil, err
			}

			if !bytes.Equal(dpasskey.UserHandle(c.UserID()), userHandle) {
				return nil, port.ErrNotFound
			}

			credential = c

			return c, nil
		}

		assertion, err := u.WebAuthn.FinishLogin(challenge.Data(), cmd.Response, lookup)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result, _ = denied(ReasonCeremonyFailed)
			return refuse(ctx, st, now, cmd.Actor.UserID, ReasonCeremonyFailed)
		}

		if err != nil {
			return fmt.Errorf("finish assertion: %w", err)
		}

		if credential.UserID() != cmd.Actor.UserID {
			// A valid key of someone else proves nothing about the signed-in user.
			result, _ = denied(ReasonUnknownKey)
			return refuse(ctx, st, now, cmd.Actor.UserID, ReasonUnknownKey)
		}

		if err := credential.RecordUse(now, assertion.SignCount, assertion.BackupState); errors.Is(err, dpasskey.ErrCloneSuspected) {
			result, _ = denied(ReasonCloneSuspected)
			return refuse(ctx, st, now, cmd.Actor.UserID, ReasonCloneSuspected)
		} else if err != nil {
			return fmt.Errorf("record use: %w", err)
		}

		if err := st.Credentials.Save(ctx, credential); err != nil {
			return fmt.Errorf("store credential: %w", err)
		}

		secret, hash, err := u.Tickets.NewTicketSecret()
		if err != nil {
			return fmt.Errorf("new ticket secret: %w", err)
		}

		id, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new ticket id: %w", err)
		}

		ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
			ID: id, Kind: dpasskey.TicketStepUp, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID,
			Operation: challenge.Operation(), SecretHash: hash, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new ticket: %w", err)
		}

		if err := st.Tickets.Create(ctx, ticket); err != nil {
			return fmt.Errorf("store ticket: %w", err)
		}

		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditStepUpGranted, Result: port.AuditSuccess, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now,
			Fields: map[string]string{"operation": string(challenge.Operation())},
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}

		result = FinishStepUpResult{Outcome: OutcomeOK, Operation: challenge.Operation(), TicketSecret: secret, TicketExpiresAt: ticket.ExpiresAt()}

		return nil
	})
	if err != nil {
		return FinishStepUpResult{}, fmt.Errorf("finish step up: %w", err)
	}

	return result, nil
}

// StepUpTicket loads the ticket a protected request presents and checks it is the actor's, for
// this session and this operation. It does not use it up: the caller does that once the
// operation is going to happen. ok is false when the request must run a step-up first.
func StepUpTicket(ctx context.Context, st port.Stores, tickets port.TicketSecrets, secret string, actor appsession.Actor,
	op dpasskey.Operation, now time.Time) (ticket *dpasskey.Ticket, ok bool, err error) {
	hash, err := tickets.HashTicketSecret(secret)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("step-up ticket: %w", err)
	}

	ticket, err = st.Tickets.GetByHashForUpdate(ctx, hash)
	if errors.Is(err, port.ErrNotFound) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("load step-up ticket: %w", err)
	}

	presented := dpasskey.Presented{Kind: dpasskey.TicketStepUp, SessionID: actor.SessionID, Operation: op}
	if ticket.UserID() != actor.UserID || ticketDenied(ticket.Check(now, presented)) {
		return nil, false, nil
	}

	return ticket, true, nil
}

// SpendStepUp uses the ticket up and stores that.
func SpendStepUp(ctx context.Context, st port.Stores, ticket *dpasskey.Ticket, actor appsession.Actor, op dpasskey.Operation, now time.Time) error {
	if err := ticket.Use(now, dpasskey.Presented{Kind: dpasskey.TicketStepUp, SessionID: actor.SessionID, Operation: op}); err != nil {
		return fmt.Errorf("use step-up ticket: %w", err)
	}

	if err := st.Tickets.Save(ctx, ticket); err != nil {
		return fmt.Errorf("store step-up ticket: %w", err)
	}

	return nil
}
