package emailauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/passkey"
)

// VerifyCodeDeps are the dependencies of VerifyCode.
type VerifyCodeDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	OTP        port.OTPCodes
	Bindings   port.BindingSecrets
	UserIDs    port.UserIDGenerator
	// RecognizedIDs names the recognized-client record a successful verify registers.
	RecognizedIDs port.RecognizedClientIDGenerator
	// PasskeyIDs names the ticket a successful verify issues.
	PasskeyIDs port.PasskeyIDGenerator
	// Tickets creates the ticket secret the client carries to the next step.
	Tickets port.TicketSecrets
	Policy  authflow.Policy
	// Registration is who may open an account; the zero value is open.
	Registration identity.RegistrationMode
}

// VerifyCode checks a submitted code in two phases: a committed reservation of
// one attempt, then a result transaction.
type VerifyCode struct {
	VerifyCodeDeps
}

// NewVerifyCode checks the dependencies once, at assembly time.
func NewVerifyCode(d VerifyCodeDeps) (*VerifyCode, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.OTP == nil || d.Bindings == nil || d.UserIDs == nil ||
		d.RecognizedIDs == nil || d.PasskeyIDs == nil || d.Tickets == nil {
		return nil, errors.New("new verify code: all dependencies are required")
	}
	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new verify code: %w", err)
	}
	return &VerifyCode{d}, nil
}

// VerifyCodeCommand is the input of VerifyCode.
type VerifyCodeCommand struct {
	FlowID        string
	Code          string
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// NextStep is what the client must do after the email is proven. A session is never issued
// by VerifyCode: it needs a passkey.
type NextStep string

// Next steps.
const (
	// NextEnrollPasskey: the User has no passkey and registers one with the ticket.
	NextEnrollPasskey NextStep = "enroll_passkey"
	// NextSecondFactor: the User has a passkey and proves it, or a recovery code, with the ticket.
	NextSecondFactor NextStep = "second_factor"
)

// VerifyCodeResult is the output of VerifyCode. Everything but Outcome and Reason is set
// only for OutcomeOK: the user, what to do next and the secret of the ticket for that step.
type VerifyCodeResult struct {
	Outcome         Outcome
	Reason          Reason
	User            *identity.User
	UserCreated     bool
	Next            NextStep
	TicketSecret    string
	TicketExpiresAt time.Time
}

// reservation is the internal admission of one comparison.
type reservation struct {
	flow    *authflow.Flow
	attempt authflow.Attempt
}

// Execute proves the code. Every refusal is OutcomeDenied (the client sees one
// reason); an exhausted quota is OutcomeRateLimited. A technical failure after the
// reservation does not return the spent attempt.
func (s *VerifyCode) Execute(ctx context.Context, cmd VerifyCodeCommand) (VerifyCodeResult, error) {
	id, err := authflow.ParseFlowID(cmd.FlowID)
	if err != nil {
		return VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}, nil
	}
	binding, err := s.Bindings.HashBinding(cmd.BindingSecret)
	if errors.Is(err, port.ErrInvalidBindingSecret) {
		return VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonBadBinding}, nil
	}
	if err != nil {
		return VerifyCodeResult{}, fmt.Errorf("verify code: binding: %w", err)
	}

	res, err := s.reserve(ctx, id, binding, cmd.ClientIP)
	if err != nil {
		return VerifyCodeResult{}, fmt.Errorf("verify code: reserve attempt: %w", err)
	}
	if res.refusal != nil {
		return *res.refusal, nil
	}

	// The comparison uses the generation that was reserved, even if a resend
	// happens before the result transaction.
	matched, err := s.OTP.Matches(res.flow, cmd.Code)
	if err != nil {
		return VerifyCodeResult{}, fmt.Errorf("verify code: derive code: %w", err)
	}

	result, err := s.settle(ctx, id, res.attempt, matched)
	if err != nil {
		return VerifyCodeResult{}, fmt.Errorf("verify code: record result: %w", err)
	}
	return result, nil
}

type reserveOutcome struct {
	*reservation
	refusal *VerifyCodeResult
}

// reserve is the first, short transaction: it checks the flow, spends the verify
// quota and one attempt, and commits before the code is compared.
func (s *VerifyCode) reserve(ctx context.Context, id authflow.FlowID, binding identity.BindingHash, ip netip.Addr) (reserveOutcome, error) {
	var out reserveOutcome
	now := s.Clock.Now()
	err := s.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		flow, err := st.Flows.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			out.refusal = &VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load flow: %w", err)
		}

		attempt, err := flow.Reserve(now, authflow.PurposeLogin, binding, s.Policy)
		if outcome, reason, ok := denial(err); ok {
			if changedFlow(err) {
				if err := st.Flows.Save(ctx, flow); err != nil {
					return fmt.Errorf("store expired flow: %w", err)
				}
			}
			out.refusal = &VerifyCodeResult{Outcome: outcome, Reason: reason}
			return nil
		}
		if err != nil {
			return fmt.Errorf("reserve attempt: %w", err)
		}

		if lost, err := recognitionLost(ctx, st, flow, now); err != nil {
			return err
		} else if lost {
			out.refusal = &VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonRecognitionLost}
			return nil
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{
			Kind: port.SpendVerify, Email: flow.Email(), Class: flow.QuotaClass(),
			RecognizedClientID: flow.RecognizedClientID(), Binding: binding, IP: ip, Now: now,
		})
		if err != nil {
			return fmt.Errorf("spend verify quota: %w", err)
		}
		if !allowed {
			// The attempt exists only in memory; not saving it leaves the flow untouched.
			out.refusal = &VerifyCodeResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		if err := st.Flows.Save(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		out.reservation = &reservation{flow: flow, attempt: attempt}
		return nil
	})
	return out, err
}

// settle is the result transaction. It re-reads the flow under lock and records
// the result only if the reservation is still valid.
func (s *VerifyCode) settle(ctx context.Context, id authflow.FlowID, attempt authflow.Attempt, matched bool) (VerifyCodeResult, error) {
	var result VerifyCodeResult
	now := s.Clock.Now()
	err := s.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		flow, err := st.Flows.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result = VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load flow: %w", err)
		}

		if matched {
			err = flow.Accept(attempt, now)
		} else {
			err = flow.Reject(attempt, now, s.Policy)
		}
		if outcome, reason, ok := denial(err); ok {
			if changedFlow(err) {
				if err := st.Flows.Save(ctx, flow); err != nil {
					return fmt.Errorf("store expired flow: %w", err)
				}
			}
			result = VerifyCodeResult{Outcome: outcome, Reason: reason}
			return nil
		}
		if err != nil {
			return fmt.Errorf("record result: %w", err)
		}

		if !matched {
			if err := st.Flows.Save(ctx, flow); err != nil {
				return fmt.Errorf("store flow: %w", err)
			}
			result = VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonWrongCode}
			return nil
		}

		// In the invite-only mode a new account needs an invitation, taken here in the same
		// transaction that creates the account; a user who exists signs in without one.
		invited := false
		if s.Registration.Invites() {
			if _, err := st.Users.FindByEmail(ctx, flow.Email()); errors.Is(err, port.ErrNotFound) {
				used, err := st.Invitations.Consume(ctx, flow.Email(), now)
				if err != nil {
					return fmt.Errorf("use invitation: %w", err)
				}
				if !used {
					// Not saved: the flow stays as it was, as after any other refusal of the proof.
					result = VerifyCodeResult{Outcome: OutcomeDenied, Reason: ReasonNotInvited}
					return nil
				}
				invited = true
			} else if err != nil {
				return fmt.Errorf("look up user: %w", err)
			}
		}
		userID, err := s.UserIDs.NewUserID()
		if err != nil {
			return fmt.Errorf("new user id: %w", err)
		}
		candidate, err := identity.NewUser(userID, flow.Email(), now)
		if err != nil {
			return fmt.Errorf("new user: %w", err)
		}
		user, created, err := st.Users.Ensure(ctx, candidate)
		if err != nil {
			return fmt.Errorf("ensure user: %w", err)
		}

		// One transaction: the user, the ticket for the next step, the recognized client,
		// the audit event and the consumed flow. The email is proven here; the session
		// comes only after a passkey.
		credentials, err := st.Credentials.ListByUser(ctx, user.ID())
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}
		next, kind := NextEnrollPasskey, passkey.TicketEnroll
		if len(credentials) > 0 {
			next, kind = NextSecondFactor, passkey.TicketSecondFactor
		}
		secret, hash, err := s.Tickets.NewTicketSecret()
		if err != nil {
			return fmt.Errorf("new ticket secret: %w", err)
		}
		ticketID, err := s.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new ticket id: %w", err)
		}
		ticket, err := passkey.NewTicket(passkey.NewTicketParams{
			ID: ticketID, Kind: kind, UserID: user.ID(), Binding: flow.BindingHash(), SecretHash: hash, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new ticket: %w", err)
		}
		if err := st.Tickets.Create(ctx, ticket); err != nil {
			return fmt.Errorf("store ticket: %w", err)
		}
		clientID, err := s.RecognizedIDs.NewRecognizedClientID()
		if err != nil {
			return fmt.Errorf("new recognized client id: %w", err)
		}
		client, err := identity.NewRecognizedClient(clientID, user.ID(), flow.Email(), flow.BindingHash(), now)
		if err != nil {
			return fmt.Errorf("new recognized client: %w", err)
		}
		if _, err := st.Recognized.Register(ctx, client); err != nil {
			return fmt.Errorf("register recognized client: %w", err)
		}
		if invited {
			if err := st.Audit.Record(ctx, port.AuditEvent{
				Type: port.AuditInvitationUsed, Result: port.AuditSuccess, UserID: user.ID(), At: now,
			}); err != nil {
				return fmt.Errorf("record audit event: %w", err)
			}
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditEmailVerified, Result: port.AuditSuccess, UserID: user.ID(), At: now,
			Fields: map[string]string{"method": "otp", "new_user": strconv.FormatBool(created), "quota_class": string(flow.QuotaClass()), "next": string(next)},
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		if err := st.Flows.Save(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		result = VerifyCodeResult{
			Outcome: OutcomeOK, User: user, UserCreated: created, Next: next, TicketSecret: secret, TicketExpiresAt: ticket.ExpiresAt(),
		}
		return nil
	})
	return result, err
}
