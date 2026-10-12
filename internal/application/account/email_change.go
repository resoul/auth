package account

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// Changing the address requires a step-up proof for change_email, a code sent to the new
// address, and a notice to the old address. The flow belongs to the account and to the
// binding of the session that asked, so nobody else can finish it and a login flow cannot
// stand in for it.

// StartEmailChangeDeps are the dependencies of StartEmailChange.
type StartEmailChangeDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	FlowIDs    port.FlowIDGenerator
	OTP        port.OTPGenerations
	Tickets    port.TicketSecrets
	Policy     authflow.Policy
}

// StartEmailChange asks for a code at the new address.
type StartEmailChange struct{ StartEmailChangeDeps }

// NewStartEmailChange checks the dependencies once, at assembly time.
func NewStartEmailChange(d StartEmailChangeDeps) (*StartEmailChange, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.FlowIDs == nil || d.OTP == nil || d.Tickets == nil {
		return nil, errors.New("new start email change: all dependencies are required")
	}
	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new start email change: %w", err)
	}
	return &StartEmailChange{d}, nil
}

// StartEmailChangeCommand is the input of StartEmailChange. Actor comes from Authenticator.
type StartEmailChangeCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
	Email        string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// StartEmailChangeResult is the output of StartEmailChange. FlowID and ExpiresAt are set only
// for OutcomeOK.
type StartEmailChangeResult struct {
	Outcome   Outcome
	Reason    Reason
	FlowID    authflow.FlowID
	ExpiresAt time.Time
}

// Execute starts the change. The answer does not depend on whether the address has an account:
// the code goes out either way, so the request cannot be used to find out who is registered.
// The step-up ticket is used up here, once the code is queued; a refusal before that keeps it.
func (u *StartEmailChange) Execute(ctx context.Context, cmd StartEmailChangeCommand) (StartEmailChangeResult, error) {
	email, err := identity.ParseEmail(cmd.Email)
	if err != nil {
		return StartEmailChangeResult{}, fmt.Errorf("start email change: %w", err)
	}
	flowID, err := u.FlowIDs.NewFlowID()
	if err != nil {
		return StartEmailChangeResult{}, fmt.Errorf("start email change: %w", err)
	}
	gen, err := u.OTP.NewGeneration()
	if err != nil {
		return StartEmailChangeResult{}, fmt.Errorf("start email change: %w", err)
	}
	now := u.Clock.Now()

	var result StartEmailChangeResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now)
		if err != nil {
			return err
		}
		if !ok {
			result = StartEmailChangeResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		ticket, ok, err := passkey.StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationChangeEmail, now)
		if err != nil {
			return err
		}
		if !ok {
			result = StartEmailChangeResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}
		user, err := st.Users.Get(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		if user.Email() == email {
			result = StartEmailChangeResult{Outcome: OutcomeInvalid, Reason: ReasonSameEmail}
			return nil
		}

		// The new address is a stranger to the service until it proves itself, so it draws from
		// the budgets of an unknown client: they are what keeps a mailbox from being flooded.
		allowed, err := st.Limiter.Allow(ctx, port.Spend{
			Kind: port.SpendSend, Email: email, Class: authflow.QuotaUnknown, Binding: sess.Binding(),
			IP: cmd.ClientIP, Now: now,
		})
		if err != nil {
			return fmt.Errorf("spend send quota: %w", err)
		}
		if !allowed {
			result = StartEmailChangeResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		flow, err := authflow.Start(authflow.StartParams{
			ID: flowID, Email: email, Purpose: authflow.PurposeChangeEmail, Binding: sess.Binding(),
			Salt: gen.Salt, KeyID: gen.KeyID, QuotaClass: authflow.QuotaUnknown, UserID: user.ID(),
		}, now, u.Policy)
		if err != nil {
			return fmt.Errorf("create flow state: %w", err)
		}
		if err := st.Flows.Create(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		if err := st.Outbox.Enqueue(ctx, port.MailJob{
			FlowID: flow.ID(), Generation: flow.Generation(), QuotaClass: flow.QuotaClass(), AvailableAt: now,
		}); err != nil {
			return fmt.Errorf("enqueue mail: %w", err)
		}
		if err := passkey.SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationChangeEmail, now); err != nil {
			return err
		}
		result = StartEmailChangeResult{Outcome: OutcomeOK, FlowID: flow.ID(), ExpiresAt: flow.ExpiresAt()}
		return nil
	})
	if err != nil {
		return StartEmailChangeResult{}, fmt.Errorf("start email change: %w", err)
	}
	return result, nil
}

// ConfirmEmailChangeDeps are the dependencies of ConfirmEmailChange.
type ConfirmEmailChangeDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	OTP        port.OTPCodes
	Policy     authflow.Policy
}

// ConfirmEmailChange checks the code from the new address and moves the account. Like verify,
// it works in two phases: a committed reservation of one attempt, then a result transaction.
type ConfirmEmailChange struct{ ConfirmEmailChangeDeps }

// NewConfirmEmailChange checks the dependencies once, at assembly time.
func NewConfirmEmailChange(d ConfirmEmailChangeDeps) (*ConfirmEmailChange, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.OTP == nil {
		return nil, errors.New("new confirm email change: all dependencies are required")
	}
	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new confirm email change: %w", err)
	}
	return &ConfirmEmailChange{d}, nil
}

// ConfirmEmailChangeCommand is the input of ConfirmEmailChange. Actor comes from Authenticator.
type ConfirmEmailChangeCommand struct {
	Actor    appsession.Actor
	FlowID   string
	Code     string
	ClientIP netip.Addr
}

// ConfirmEmailChangeResult is the output of ConfirmEmailChange. Email is set only for OutcomeOK.
type ConfirmEmailChangeResult struct {
	Outcome Outcome
	Reason  Reason
	Email   identity.Email
}

// Execute proves the code. Every refusal of the proof is OutcomeDenied (the client sees one
// reason); an exhausted quota is OutcomeRateLimited. An address that another account took in the
// meantime is OutcomeConflict, and the flow stays as it was.
func (u *ConfirmEmailChange) Execute(ctx context.Context, cmd ConfirmEmailChangeCommand) (ConfirmEmailChangeResult, error) {
	id, err := authflow.ParseFlowID(cmd.FlowID)
	if err != nil {
		return ConfirmEmailChangeResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}, nil
	}

	res, err := u.reserve(ctx, id, cmd)
	if err != nil {
		return ConfirmEmailChangeResult{}, fmt.Errorf("confirm email change: reserve attempt: %w", err)
	}
	if res.refusal != nil {
		return *res.refusal, nil
	}

	// The comparison uses the generation that was reserved, even if the flow changes before
	// the result transaction.
	matched, err := u.OTP.Matches(res.flow, cmd.Code)
	if err != nil {
		return ConfirmEmailChangeResult{}, fmt.Errorf("confirm email change: derive code: %w", err)
	}
	result, err := u.settle(ctx, id, cmd, res.attempt, matched)
	if err != nil {
		return ConfirmEmailChangeResult{}, fmt.Errorf("confirm email change: record result: %w", err)
	}
	return result, nil
}

type reservation struct {
	flow    *authflow.Flow
	attempt authflow.Attempt
	refusal *ConfirmEmailChangeResult
}

func denied(reason Reason) *ConfirmEmailChangeResult {
	return &ConfirmEmailChangeResult{Outcome: OutcomeDenied, Reason: reason}
}

// reserve is the first, short transaction: it checks the flow belongs to the session, spends the
// verify quota and one attempt, and commits before the code is compared.
func (u *ConfirmEmailChange) reserve(ctx context.Context, id authflow.FlowID, cmd ConfirmEmailChangeCommand) (reservation, error) {
	var out reservation
	now := u.Clock.Now()
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now)
		if err != nil {
			return err
		}
		if !ok {
			out.refusal = denied(ReasonNoSession)
			return nil
		}
		flow, err := st.Flows.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			out.refusal = denied(ReasonUnknownFlow)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load flow: %w", err)
		}
		// Another account's flow, and a flow of another purpose, are unknown here.
		if flow.UserID() != cmd.Actor.UserID {
			out.refusal = denied(ReasonUnknownFlow)
			return nil
		}

		attempt, err := flow.Reserve(now, authflow.PurposeChangeEmail, sess.Binding(), u.Policy)
		if reason, ok := denial(err); ok {
			if changedFlow(err) {
				if err := st.Flows.Save(ctx, flow); err != nil {
					return fmt.Errorf("store expired flow: %w", err)
				}
			}
			out.refusal = denied(reason)
			return nil
		}
		if err != nil {
			return fmt.Errorf("reserve attempt: %w", err)
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{
			Kind: port.SpendVerify, Email: flow.Email(), Class: flow.QuotaClass(),
			Binding: sess.Binding(), IP: cmd.ClientIP, Now: now,
		})
		if err != nil {
			return fmt.Errorf("spend verify quota: %w", err)
		}
		if !allowed {
			// The attempt exists only in memory; not saving it leaves the flow untouched.
			out.refusal = &ConfirmEmailChangeResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}
		if err := st.Flows.Save(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		out.flow, out.attempt = flow, attempt
		return nil
	})
	return out, err
}

// settle is the result transaction. It re-reads the flow under lock and records the result only if
// the reservation is still valid. The move of the account, the end of the recognized clients, the
// notice to the old address and the audit event commit together with the consumed flow.
func (u *ConfirmEmailChange) settle(ctx context.Context, id authflow.FlowID, cmd ConfirmEmailChangeCommand, attempt authflow.Attempt, matched bool) (ConfirmEmailChangeResult, error) {
	var result ConfirmEmailChangeResult
	now := u.Clock.Now()
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = *denied(ReasonNoSession)
			return nil
		}
		flow, err := st.Flows.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result = *denied(ReasonUnknownFlow)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load flow: %w", err)
		}

		if matched {
			err = flow.Accept(attempt, now)
		} else {
			err = flow.Reject(attempt, now, u.Policy)
		}
		if reason, ok := denial(err); ok {
			if changedFlow(err) {
				if err := st.Flows.Save(ctx, flow); err != nil {
					return fmt.Errorf("store expired flow: %w", err)
				}
			}
			result = *denied(reason)
			return nil
		}
		if err != nil {
			return fmt.Errorf("record result: %w", err)
		}
		if !matched {
			if err := st.Flows.Save(ctx, flow); err != nil {
				return fmt.Errorf("store flow: %w", err)
			}
			result = *denied(ReasonWrongCode)
			return nil
		}

		user, err := st.Users.Get(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		previous := user.Email()
		if err := user.ChangeEmail(flow.Email(), now); errors.Is(err, identity.ErrSameEmail) {
			// The account already has this address, through another flow.
			result = ConfirmEmailChangeResult{Outcome: OutcomeInvalid, Reason: ReasonSameEmail}
			return nil
		} else if err != nil {
			return fmt.Errorf("change email: %w", err)
		}
		if err := st.Users.ChangeEmail(ctx, user); errors.Is(err, port.ErrEmailTaken) {
			result = ConfirmEmailChangeResult{Outcome: OutcomeConflict, Reason: ReasonEmailTaken}
			return errRollback
		} else if err != nil {
			return fmt.Errorf("store user: %w", err)
		}
		// Recognition was earned for the old address. The records of this account all end, so
		// every device proves the new address again before it is a recognized client.
		if err := st.Recognized.RevokeAll(ctx, user.ID(), now); err != nil {
			return fmt.Errorf("revoke recognized clients: %w", err)
		}
		// Other sessions were opened for the old address and its owner: only the one that proved the key now stays.
		if err := appsession.RevokeOthers(ctx, st, user.ID(), cmd.Actor.SessionID, now, "email_changed"); err != nil {
			return err
		}
		if err := st.Outbox.Enqueue(ctx, port.MailJob{
			Kind: port.JobEmailChanged, FlowID: flow.ID(), Generation: flow.Generation(), QuotaClass: flow.QuotaClass(),
			AvailableAt: now, Recipient: previous,
		}); err != nil {
			return fmt.Errorf("enqueue notice: %w", err)
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditEmailChanged, Result: port.AuditSuccess, UserID: user.ID(), SessionID: cmd.Actor.SessionID, At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		if err := st.Flows.Save(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		result = ConfirmEmailChangeResult{Outcome: OutcomeOK, Email: user.Email()}
		return nil
	})
	if errors.Is(err, errRollback) {
		return result, nil
	}
	return result, err
}

// errRollback ends a transaction without writing and without reporting a failure: the result is
// already decided. A taken address is the case, and a rollback also covers the rare one where the
// database refused the move after the check, which leaves the transaction unusable.
var errRollback = errors.New("roll back, the result is set")
