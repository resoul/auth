package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/operator"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// BeginLoginCommand is the input of BeginLogin.
type BeginLoginCommand struct{ ClientIP netip.Addr }

// BeginLogin starts a discoverable assertion. It names no operator: the key tells whose it is.
func (a *Auth) BeginLogin(ctx context.Context, cmd BeginLoginCommand) (CeremonyResult, error) {
	now := a.Clock.Now()

	ceremony, err := a.WebAuthn.BeginLogin()
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: %w", err)
	}

	id, err := a.PasskeyIDs.NewPasskeyID()
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: challenge id: %w", err)
	}

	challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{ID: id, Purpose: dpasskey.ChallengeLogin, Data: ceremony.State, Now: now})
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: new challenge: %w", err)
	}

	result := CeremonyResult{Outcome: OutcomeOK, ChallengeID: id.String(), Options: ceremony.Options}

	if err := a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if ok, err := a.spend(ctx, st, now, cmd.ClientIP); err != nil {
			return err
		} else if !ok {
			result = CeremonyResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		return st.OperatorChallenges.Create(ctx, challenge)
	}); err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: store challenge: %w", err)
	}

	return result, nil
}

// FinishLoginCommand is the input of FinishLogin.
type FinishLoginCommand struct {
	ChallengeID string
	// Response is the JSON the page got from navigator.credentials.get.
	Response []byte
	ClientIP netip.Addr
}

// FinishLoginResult is the output of FinishLogin. Everything but Outcome and Reason is set only for OutcomeOK.
type FinishLoginResult struct {
	Outcome Outcome
	Reason  Reason
	// SessionSecret goes into the cookie; it exists only here, the store keeps its hash.
	SessionSecret string
	Operator      *operator.Operator
	ExpiresAt     time.Time
}

// refuseLogin records a refused sign-in of a known operator.
func refuseLogin(ctx context.Context, st port.Stores, now time.Time, id operator.ID, reason Reason) error {
	if id.IsZero() {
		return nil
	}

	return st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOperatorLogin, Result: port.AuditDenied, OperatorID: id, At: now,
		Fields: map[string]string{"reason": string(reason)},
	})
}

// FinishLogin verifies the assertion and opens a session. A refused ceremony consumes its challenge, so
// each try needs a new one; every refusal looks the same to the client.
func (a *Auth) FinishLogin(ctx context.Context, cmd FinishLoginCommand) (FinishLoginResult, error) {
	denied := func(reason Reason) (FinishLoginResult, error) {
		return FinishLoginResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}

	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return denied(ReasonBadChallenge)
	}

	now := a.Clock.Now()

	var result FinishLoginResult

	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if ok, err := a.spend(ctx, st, now, cmd.ClientIP); err != nil {
			return err
		} else if !ok {
			result = FinishLoginResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
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

		if challengeDenied(challenge.Consume(now, dpasskey.ChallengeLogin)) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}

		if err := st.OperatorChallenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		var credential *dpasskey.Credential

		lookup := func(credentialID []byte, userHandle port.UserHandle) (*dpasskey.Credential, error) {
			c, err := st.Operators.GetCredentialForUpdate(ctx, credentialID)
			if err != nil {
				return nil, err
			}
			// The handle the authenticator keeps must be the owner's.
			if !bytes.Equal(dpasskey.UserHandle(c.UserID()), userHandle) {
				return nil, port.ErrNotFound
			}

			credential = c

			return c, nil
		}

		assertion, err := a.WebAuthn.FinishLogin(challenge.Data(), cmd.Response, lookup)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result, _ = denied(ReasonCeremonyFailed)

			if credential != nil {
				opID, idErr := operator.IDFromOwner(credential.UserID())
				if idErr != nil {
					return fmt.Errorf("stored credential owner: %w", idErr)
				}

				return refuseLogin(ctx, st, now, opID, ReasonCeremonyFailed)
			}

			return nil
		}

		if err != nil {
			return fmt.Errorf("finish login: %w", err)
		}

		opID, err := operator.IDFromOwner(credential.UserID())
		if err != nil {
			return fmt.Errorf("stored credential owner: %w", err)
		}

		op, err := st.Operators.Get(ctx, opID)
		if err != nil {
			return fmt.Errorf("load operator: %w", err)
		}

		if op.Disabled() {
			result, _ = denied(ReasonOperatorOff)
			return refuseLogin(ctx, st, now, op.ID(), ReasonOperatorOff)
		}

		if err := credential.RecordUse(now, assertion.SignCount, assertion.BackupState); errors.Is(err, dpasskey.ErrCloneSuspected) {
			result, _ = denied(ReasonCloneSuspected)
			return refuseLogin(ctx, st, now, op.ID(), ReasonCloneSuspected)
		} else if err != nil {
			return fmt.Errorf("record use: %w", err)
		}

		if err := st.Operators.SaveCredential(ctx, credential); err != nil {
			return fmt.Errorf("store credential: %w", err)
		}

		secret, hash, err := a.Secrets.NewTicketSecret()
		if err != nil {
			return fmt.Errorf("new session secret: %w", err)
		}

		sessionID, err := a.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("session id: %w", err)
		}

		sess, err := operator.NewSession(sessionID, op.ID(), hash, now)
		if err != nil {
			return fmt.Errorf("new session: %w", err)
		}

		if err := st.OperatorSessions.Create(ctx, sess); err != nil {
			return fmt.Errorf("store session: %w", err)
		}

		if err := st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditOperatorLogin, Result: port.AuditSuccess, OperatorID: op.ID(), At: now}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}

		result = FinishLoginResult{Outcome: OutcomeOK, SessionSecret: secret, Operator: op, ExpiresAt: sessionEnd(sess)}

		return nil
	})
	if err != nil {
		return FinishLoginResult{}, fmt.Errorf("finish login: %w", err)
	}

	return result, nil
}

// sessionEnd is when the session ends if it is not used again, or at its absolute end, whichever is first.
func sessionEnd(s *operator.Session) time.Time {
	idle := s.LastSeenAt().Add(operator.IdleTimeout)
	if idle.Before(s.ExpiresAt()) {
		return idle
	}

	return s.ExpiresAt()
}
