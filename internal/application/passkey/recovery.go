package passkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// RedeemRecoveryDeps are the dependencies of RedeemRecovery.
type RedeemRecoveryDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Bindings   port.BindingSecrets
	Tickets    port.TicketSecrets
	Recovery   port.RecoveryCodes
	PasskeyIDs port.PasskeyIDGenerator
}

// RedeemRecovery spends a recovery code in place of a passkey. It opens no session: the code
// buys a ticket to register a new passkey, so recovery always ends with a working key.
type RedeemRecovery struct {
	RedeemRecoveryDeps
}

// NewRedeemRecovery checks the dependencies once, at assembly time.
func NewRedeemRecovery(d RedeemRecoveryDeps) (*RedeemRecovery, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Bindings == nil || d.Tickets == nil || d.Recovery == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new redeem recovery: all dependencies are required")
	}

	return &RedeemRecovery{d}, nil
}

// RedeemRecoveryCommand is the input of RedeemRecovery.
type RedeemRecoveryCommand struct {
	// TicketSecret is the second-factor ticket of an email sign-in.
	TicketSecret  string
	BindingSecret string
	// Code is the recovery code as the person typed it.
	Code string
}

// RedeemRecoveryResult is the output of RedeemRecovery. The ticket fields are set only for
// OutcomeOK.
type RedeemRecoveryResult struct {
	Outcome         Outcome
	Reason          Reason
	TicketSecret    string
	TicketExpiresAt time.Time
}

// Execute spends the code. The second-factor ticket is consumed by every attempt that reaches
// the code, right or wrong, so guessing needs a new email proof each time.
func (u *RedeemRecovery) Execute(ctx context.Context, cmd RedeemRecoveryCommand) (RedeemRecoveryResult, error) {
	denied := func(reason Reason) (RedeemRecoveryResult, error) {
		return RedeemRecoveryResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}

	binding, err := u.Bindings.HashBinding(cmd.BindingSecret)
	if errors.Is(err, port.ErrInvalidBindingSecret) {
		return denied(ReasonBadBinding)
	}

	if err != nil {
		return RedeemRecoveryResult{}, fmt.Errorf("redeem recovery: binding: %w", err)
	}

	ticketHash, err := u.Tickets.HashTicketSecret(cmd.TicketSecret)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return denied(ReasonBadTicket)
	}

	if err != nil {
		return RedeemRecoveryResult{}, fmt.Errorf("redeem recovery: ticket: %w", err)
	}

	now := u.Clock.Now()

	var result RedeemRecoveryResult

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		ticket, err := st.Tickets.GetByHashForUpdate(ctx, ticketHash)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadTicket)
			return nil
		}

		if err != nil {
			return fmt.Errorf("load ticket: %w", err)
		}

		presented := dpasskey.Presented{Kind: dpasskey.TicketSecondFactor, Binding: binding}
		if ticketDenied(ticket.Use(now, presented)) {
			result, _ = denied(ReasonBadTicket)
			return nil
		}
		// The ticket is spent from here, right code or wrong: a refusal commits that.
		if err := st.Tickets.Save(ctx, ticket); err != nil {
			return fmt.Errorf("store ticket: %w", err)
		}

		codeHash, err := u.Recovery.HashRecoveryCode(cmd.Code)
		if errors.Is(err, port.ErrInvalidRecoveryCode) {
			result, _ = denied(ReasonBadRecoveryCode)
			return refuse(ctx, st, now, ticket.UserID(), ReasonBadRecoveryCode)
		}

		if err != nil {
			return fmt.Errorf("hash recovery code: %w", err)
		}

		code, err := st.Recovery.GetByHashForUpdate(ctx, codeHash)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadRecoveryCode)
			return refuse(ctx, st, now, ticket.UserID(), ReasonBadRecoveryCode)
		}

		if err != nil {
			return fmt.Errorf("load recovery code: %w", err)
		}
		// A code of another User proves nothing about this one.
		if code.UserID() != ticket.UserID() || code.Use(now) != nil {
			result, _ = denied(ReasonBadRecoveryCode)
			return refuse(ctx, st, now, ticket.UserID(), ReasonBadRecoveryCode)
		}

		if err := st.Recovery.Save(ctx, code); err != nil {
			return fmt.Errorf("store recovery code: %w", err)
		}

		secret, hash, err := u.Tickets.NewTicketSecret()
		if err != nil {
			return fmt.Errorf("new ticket secret: %w", err)
		}

		id, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new ticket id: %w", err)
		}

		next, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
			ID: id, Kind: dpasskey.TicketRecoveryEnroll, UserID: ticket.UserID(), Binding: ticket.Binding(), SecretHash: hash, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new ticket: %w", err)
		}

		if err := st.Tickets.Create(ctx, next); err != nil {
			return fmt.Errorf("store ticket: %w", err)
		}

		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditRecoveryCodeUsed, Result: port.AuditSuccess, UserID: ticket.UserID(), At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}

		result = RedeemRecoveryResult{Outcome: OutcomeOK, TicketSecret: secret, TicketExpiresAt: next.ExpiresAt()}

		return nil
	})
	if err != nil {
		return RedeemRecoveryResult{}, fmt.Errorf("redeem recovery: %w", err)
	}

	return result, nil
}
