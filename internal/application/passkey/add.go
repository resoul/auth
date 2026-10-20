package passkey

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// BeginAddPasskeyDeps are the dependencies of BeginAddPasskey.
type BeginAddPasskeyDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Tickets    port.TicketSecrets
	PasskeyIDs port.PasskeyIDGenerator
}

// BeginAddPasskey starts the registration of another passkey for the signed-in user. It needs
// the step-up ticket for add_passkey; the ticket is spent when the registration is finished.
type BeginAddPasskey struct{ BeginAddPasskeyDeps }

// NewBeginAddPasskey checks the dependencies once, at assembly time.
func NewBeginAddPasskey(d BeginAddPasskeyDeps) (*BeginAddPasskey, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Tickets == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new begin add passkey: all dependencies are required")
	}

	return &BeginAddPasskey{d}, nil
}

// BeginAddCommand is the input of BeginAddPasskey.
type BeginAddCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
	ClientIP     netip.Addr
}

// Execute prepares the registration.
func (u *BeginAddPasskey) Execute(ctx context.Context, cmd BeginAddCommand) (CeremonyResult, error) {
	now := u.Clock.Now()

	var result CeremonyResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}

		ticket, ok, err := StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationAddPasskey, now)
		if err != nil {
			return err
		}

		if !ok {
			result = CeremonyResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}
		// Locked before the keys are counted: two additions at the limit queue, and the second sees the first.
		user, err := st.Users.GetForUpdate(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}

		creds, err := st.Credentials.ListByUser(ctx, user.ID())
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}

		if len(creds) >= dpasskey.MaxPerUser {
			result = CeremonyResult{Outcome: OutcomeConflict, Reason: ReasonTooManyKeys}
			return nil
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendPasskey, IP: cmd.ClientIP, Ref: ticket.ID().String(), Now: now})
		if err != nil {
			return fmt.Errorf("spend passkey quota: %w", err)
		}

		if !allowed {
			result = CeremonyResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		ceremony, err := u.WebAuthn.BeginRegistration(port.Subject{ID: user.ID(), Email: user.Email(), Credentials: creds})
		if err != nil {
			return fmt.Errorf("begin registration: %w", err)
		}

		id, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new challenge id: %w", err)
		}

		challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
			ID: id, Purpose: dpasskey.ChallengeRegistration, UserID: user.ID(), TicketID: ticket.ID(), Data: ceremony.State, Now: now,
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
		return CeremonyResult{}, fmt.Errorf("begin add passkey: %w", err)
	}

	return result, nil
}

// FinishAddPasskeyDeps are the dependencies of FinishAddPasskey.
type FinishAddPasskeyDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Tickets    port.TicketSecrets
	PasskeyIDs port.PasskeyIDGenerator
}

// FinishAddPasskey verifies the new passkey and stores it next to the others.
type FinishAddPasskey struct{ FinishAddPasskeyDeps }

// NewFinishAddPasskey checks the dependencies once, at assembly time.
func NewFinishAddPasskey(d FinishAddPasskeyDeps) (*FinishAddPasskey, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Tickets == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new finish add passkey: all dependencies are required")
	}

	return &FinishAddPasskey{d}, nil
}

// FinishAddCommand is the input of FinishAddPasskey.
type FinishAddCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
	ChallengeID  string
	Response     []byte
	Name         string
}

// FinishAddResult is the output of FinishAddPasskey. Credential is set only for OutcomeOK.
type FinishAddResult struct {
	Outcome    Outcome
	Reason     Reason
	Credential CredentialSummary
}

// Execute finishes the registration. A refused ceremony spends its challenge, not the ticket.
func (u *FinishAddPasskey) Execute(ctx context.Context, cmd FinishAddCommand) (FinishAddResult, error) {
	name := cmd.Name
	if name == "" {
		name = DefaultCredentialName
	}

	if !dpasskey.ValidName(name) {
		return FinishAddResult{}, fmt.Errorf("finish add passkey: %w", ErrInvalidName)
	}

	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonBadChallenge}, nil
	}

	now := u.Clock.Now()

	var result FinishAddResult

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}

		ticket, ok, err := StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationAddPasskey, now)
		if err != nil {
			return err
		}

		if !ok {
			result = FinishAddResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}

		challenge, err := st.Challenges.GetForUpdate(ctx, challengeID)
		if errors.Is(err, port.ErrNotFound) {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonBadChallenge}
			return nil
		}

		if err != nil {
			return fmt.Errorf("load challenge: %w", err)
		}

		if challenge.TicketID() != ticket.ID() || challenge.UserID() != cmd.Actor.UserID {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonBadChallenge}
			return nil
		}

		if challengeDenied(challenge.Consume(now, dpasskey.ChallengeRegistration)) {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonBadChallenge}
			return nil
		}

		if err := st.Challenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		// The user is held exclusively (StepUpTicket took it) while the keys are counted and the new one is stored: two
		// additions of one user run one after the other, and the second counts the first one's key.
		user, err := st.Users.GetForUpdate(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}

		creds, err := st.Credentials.ListByUser(ctx, user.ID())
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}

		if len(creds) >= dpasskey.MaxPerUser {
			result = FinishAddResult{Outcome: OutcomeConflict, Reason: ReasonTooManyKeys}
			return nil
		}

		registered, err := u.WebAuthn.FinishRegistration(port.Subject{ID: user.ID(), Email: user.Email(), Credentials: creds}, challenge.Data(), cmd.Response)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonCeremonyFailed}
			return refuse(ctx, st, now, user.ID(), ReasonCeremonyFailed)
		}

		if err != nil {
			return fmt.Errorf("finish registration: %w", err)
		}

		credentialID, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new credential id: %w", err)
		}

		credential, err := dpasskey.NewCredential(dpasskey.NewCredentialParams{
			ID: credentialID, UserID: user.ID(), CredentialID: registered.CredentialID, PublicKey: registered.PublicKey,
			AAGUID: registered.AAGUID, Transports: registered.Transports, SignCount: registered.SignCount,
			BackupEligible: registered.BackupEligible, BackupState: registered.BackupState, Name: name, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new credential: %w", err)
		}

		if err := st.Credentials.Create(ctx, credential); errors.Is(err, port.ErrCredentialConflict) {
			result = FinishAddResult{Outcome: OutcomeDenied, Reason: ReasonCeremonyFailed}
			return refuse(ctx, st, now, user.ID(), ReasonCeremonyFailed)
		} else if err != nil {
			return fmt.Errorf("store credential: %w", err)
		}

		if err := SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationAddPasskey, now); err != nil {
			return err
		}

		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditPasskeyEnrolled, Result: port.AuditSuccess, UserID: user.ID(), SessionID: cmd.Actor.SessionID, At: now,
			Fields: map[string]string{"method": "added"},
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}

		result = FinishAddResult{Outcome: OutcomeOK, Credential: summarize(credential)}

		return nil
	})
	if err != nil {
		return FinishAddResult{}, fmt.Errorf("finish add passkey: %w", err)
	}

	return result, nil
}
