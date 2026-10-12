package admin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/operator"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// BeginEnrollCommand is the input of BeginEnroll.
type BeginEnrollCommand struct {
	// Code is the one-time code the server printed.
	Code     string
	ClientIP netip.Addr
}

// BeginEnroll starts the registration of a key for the operator the code belongs to.
func (a *Auth) BeginEnroll(ctx context.Context, cmd BeginEnrollCommand) (CeremonyResult, error) {
	denied := func(reason Reason) (CeremonyResult, error) {
		return CeremonyResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	hash, err := a.Secrets.HashTicketSecret(cmd.Code)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return denied(ReasonBadCode)
	}
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin enroll: code: %w", err)
	}
	now := a.Clock.Now()
	var result CeremonyResult
	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if ok, err := a.spend(ctx, st, now, cmd.ClientIP); err != nil {
			return err
		} else if !ok {
			result = CeremonyResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}
		enrollment, err := st.Operators.GetEnrollmentByHashForUpdate(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadCode)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load enrollment: %w", err)
		}
		if enrollment.Usable(now) != nil {
			result, _ = denied(ReasonBadCode)
			return nil
		}
		op, err := st.Operators.Get(ctx, enrollment.OperatorID())
		if err != nil {
			return fmt.Errorf("load operator: %w", err)
		}
		if op.Disabled() {
			result, _ = denied(ReasonOperatorOff)
			return nil
		}
		keys, err := st.Operators.ListCredentials(ctx, op.ID())
		if err != nil {
			return fmt.Errorf("list operator credentials: %w", err)
		}
		if len(keys) >= operator.MaxCredentials {
			result = CeremonyResult{Outcome: OutcomeConflict, Reason: ReasonTooManyKeys}
			return nil
		}
		ceremony, err := a.WebAuthn.BeginRegistration(port.Subject{ID: op.ID().Owner(), Email: op.Email(), Credentials: keys})
		if err != nil {
			return fmt.Errorf("begin registration: %w", err)
		}
		id, err := a.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("challenge id: %w", err)
		}
		challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
			ID: id, Purpose: dpasskey.ChallengeRegistration, UserID: op.ID().Owner(), TicketID: enrollment.ID(), Data: ceremony.State, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new challenge: %w", err)
		}
		if err := st.OperatorChallenges.Create(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}
		result = CeremonyResult{Outcome: OutcomeOK, ChallengeID: id.String(), Options: ceremony.Options}
		return nil
	})
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin enroll: %w", err)
	}
	return result, nil
}

// FinishEnrollCommand is the input of FinishEnroll.
type FinishEnrollCommand struct {
	ChallengeID string
	// Response is the JSON the page got from navigator.credentials.create.
	Response []byte
	// Name labels the key; empty gets a default.
	Name     string
	ClientIP netip.Addr
}

// FinishEnrollResult is the output of FinishEnroll.
type FinishEnrollResult struct {
	Outcome Outcome
	Reason  Reason
}

// FinishEnroll verifies the new key and stores it. The code is spent only by a stored key, so a
// ceremony that failed can be retried while the code lasts; a ceremony itself is single use.
func (a *Auth) FinishEnroll(ctx context.Context, cmd FinishEnrollCommand) (FinishEnrollResult, error) {
	denied := func(reason Reason) (FinishEnrollResult, error) {
		return FinishEnrollResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	if cmd.Name != "" && !dpasskey.ValidName(cmd.Name) {
		return FinishEnrollResult{}, invalid("the key name is empty, too long or has control characters")
	}
	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return denied(ReasonBadChallenge)
	}
	now := a.Clock.Now()
	var result FinishEnrollResult
	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if ok, err := a.spend(ctx, st, now, cmd.ClientIP); err != nil {
			return err
		} else if !ok {
			result = FinishEnrollResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}
		challenge, err := st.OperatorChallenges.GetForUpdate(ctx, challengeID)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load challenge: %w", err)
		}
		if challengeDenied(challenge.Consume(now, dpasskey.ChallengeRegistration)) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}
		// From here the challenge is spent whatever happens: a refusal commits that.
		if err := st.OperatorChallenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}
		enrollment, err := st.Operators.GetEnrollmentForUpdate(ctx, challenge.TicketID())
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadCode)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load enrollment: %w", err)
		}
		if enrollment.Usable(now) != nil || enrollment.OperatorID().Owner() != challenge.UserID() {
			result, _ = denied(ReasonBadCode)
			return nil
		}
		op, err := st.Operators.Get(ctx, enrollment.OperatorID())
		if err != nil {
			return fmt.Errorf("load operator: %w", err)
		}
		if op.Disabled() {
			result, _ = denied(ReasonOperatorOff)
			return nil
		}
		keys, err := st.Operators.ListCredentials(ctx, op.ID())
		if err != nil {
			return fmt.Errorf("list operator credentials: %w", err)
		}
		if len(keys) >= operator.MaxCredentials {
			result = FinishEnrollResult{Outcome: OutcomeConflict, Reason: ReasonTooManyKeys}
			return nil
		}
		registered, err := a.WebAuthn.FinishRegistration(port.Subject{ID: op.ID().Owner(), Email: op.Email(), Credentials: keys}, challenge.Data(), cmd.Response)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result, _ = denied(ReasonCeremonyFailed)
			return nil
		}
		if err != nil {
			return fmt.Errorf("finish registration: %w", err)
		}
		credentialID, err := a.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("credential id: %w", err)
		}
		name := cmd.Name
		if name == "" {
			name = fmt.Sprintf("Key %d", len(keys)+1)
		}
		credential, err := dpasskey.NewCredential(dpasskey.NewCredentialParams{
			ID: credentialID, UserID: op.ID().Owner(), CredentialID: registered.CredentialID, PublicKey: registered.PublicKey,
			AAGUID: registered.AAGUID, Transports: registered.Transports, SignCount: registered.SignCount,
			BackupEligible: registered.BackupEligible, BackupState: registered.BackupState, Name: name, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new credential: %w", err)
		}
		if err := st.Operators.CreateCredential(ctx, credential); errors.Is(err, port.ErrCredentialConflict) {
			result, _ = denied(ReasonCeremonyFailed)
			return nil
		} else if err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
		if err := enrollment.Consume(now); err != nil {
			return fmt.Errorf("consume enrollment: %w", err)
		}
		if err := st.Operators.SaveEnrollment(ctx, enrollment); err != nil {
			return fmt.Errorf("store enrollment: %w", err)
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditOperatorEnrolled, Result: port.AuditSuccess, OperatorID: op.ID(), At: now}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		result = FinishEnrollResult{Outcome: OutcomeOK}
		return nil
	})
	if err != nil {
		return FinishEnrollResult{}, fmt.Errorf("finish enroll: %w", err)
	}
	return result, nil
}
