package passkey

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	dsession "airlance.org/auth/internal/domain/session"
)

// DefaultCredentialName labels a passkey whose owner gave no name.
const DefaultCredentialName = "Passkey"

// enrollKinds are the tickets that allow registering a passkey.
var enrollKinds = []dpasskey.TicketKind{dpasskey.TicketEnroll, dpasskey.TicketRecoveryEnroll}

// BeginEnrollDeps are the dependencies of BeginEnroll.
type BeginEnrollDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Bindings   port.BindingSecrets
	Tickets    port.TicketSecrets
	PasskeyIDs port.PasskeyIDGenerator
}

// BeginEnroll starts the registration of a passkey for the holder of an enroll ticket.
type BeginEnroll struct {
	BeginEnrollDeps
}

// NewBeginEnroll checks the dependencies once, at assembly time.
func NewBeginEnroll(d BeginEnrollDeps) (*BeginEnroll, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Bindings == nil || d.Tickets == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new begin enroll: all dependencies are required")
	}
	return &BeginEnroll{d}, nil
}

// BeginEnrollCommand is the input of BeginEnroll.
type BeginEnrollCommand struct {
	TicketSecret  string
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// CeremonyResult is a ceremony the client must complete: the challenge it echoes back and the
// options it passes to the browser or platform API.
type CeremonyResult struct {
	Outcome     Outcome
	Reason      Reason
	ChallengeID string
	Options     []byte
}

// Execute prepares the registration. The ticket is not consumed: that happens when the
// registration is finished.
func (u *BeginEnroll) Execute(ctx context.Context, cmd BeginEnrollCommand) (CeremonyResult, error) {
	binding, err := u.Bindings.HashBinding(cmd.BindingSecret)
	if errors.Is(err, port.ErrInvalidBindingSecret) {
		return CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonBadBinding}, nil
	}
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin enroll: binding: %w", err)
	}
	hash, err := u.Tickets.HashTicketSecret(cmd.TicketSecret)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonBadTicket}, nil
	}
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin enroll: ticket: %w", err)
	}
	now := u.Clock.Now()

	var result CeremonyResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		ticket, err := st.Tickets.GetByHashForUpdate(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonBadTicket}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load ticket: %w", err)
		}
		if !slices.Contains(enrollKinds, ticket.Kind()) || ticketDenied(ticket.Check(now, dpasskey.Presented{Kind: ticket.Kind(), Binding: binding})) {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: ReasonBadTicket}
			return nil
		}
		user, creds, reason, err := enrollSubject(ctx, st, ticket, false)
		if err != nil {
			return err
		}
		if reason != "" {
			result = CeremonyResult{Outcome: OutcomeDenied, Reason: reason}
			return nil
		}

		// A ticket may start a ceremony only so often: each one writes a row.
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
		challengeID, err := u.PasskeyIDs.NewPasskeyID()
		if err != nil {
			return fmt.Errorf("new challenge id: %w", err)
		}
		challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
			ID: challengeID, Purpose: dpasskey.ChallengeRegistration, UserID: user.ID(), TicketID: ticket.ID(),
			Data: ceremony.State, Now: now,
		})
		if err != nil {
			return fmt.Errorf("new challenge: %w", err)
		}
		if err := st.Challenges.Create(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}
		result = CeremonyResult{Outcome: OutcomeOK, ChallengeID: challengeID.String(), Options: ceremony.Options}
		return nil
	})
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin enroll: %w", err)
	}
	return result, nil
}

// enrollSubject loads the User of an enroll ticket and the keys they already have. An enroll
// ticket is for a User without keys: if one appeared since the ticket was issued, a stale
// ticket must not add another. A recovery ticket is for a User whose keys are lost: they
// are all replaced by the new one, so the old ones are neither counted nor excluded.
//
// Finishing locks the user exclusively before reading the keys, so two registrations of one user queue and the
// second sees the first one's key. Beginning only reads, and shares the lock.
func enrollSubject(ctx context.Context, st port.Stores, ticket *dpasskey.Ticket, finishing bool) (*identity.User, []*dpasskey.Credential, Reason, error) {
	load := st.Users.GetForShare
	if finishing {
		load = st.Users.GetForUpdate
	}
	user, err := load(ctx, ticket.UserID())
	if err != nil {
		return nil, nil, "", fmt.Errorf("load user: %w", err)
	}
	creds, err := st.Credentials.ListByUser(ctx, user.ID())
	if err != nil {
		return nil, nil, "", fmt.Errorf("list credentials: %w", err)
	}
	if ticket.Kind() == dpasskey.TicketRecoveryEnroll {
		return user, nil, "", nil
	}
	if len(creds) > 0 {
		return nil, nil, ReasonAlreadyEnrolled, nil
	}
	return user, creds, "", nil
}

func withMethod(fields map[string]string, method string) map[string]string {
	fields["method"] = method
	return fields
}

// FinishEnrollDeps are the dependencies of FinishEnroll.
type FinishEnrollDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Bindings   port.BindingSecrets
	Tickets    port.TicketSecrets
	PasskeyIDs port.PasskeyIDGenerator
	Recovery   port.RecoveryCodes
	SessionDeps
}

// FinishEnroll verifies the new passkey, stores it with a fresh set of recovery codes and
// opens the session the ticket was waiting for.
type FinishEnroll struct {
	FinishEnrollDeps
}

// NewFinishEnroll checks the dependencies once, at assembly time.
func NewFinishEnroll(d FinishEnrollDeps) (*FinishEnroll, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Bindings == nil || d.Tickets == nil || d.PasskeyIDs == nil || d.Recovery == nil {
		return nil, errors.New("new finish enroll: all dependencies are required")
	}
	if err := d.validate("finish enroll"); err != nil {
		return nil, err
	}
	return &FinishEnroll{d}, nil
}

// FinishEnrollCommand is the input of FinishEnroll.
type FinishEnrollCommand struct {
	TicketSecret  string
	BindingSecret string
	ChallengeID   string
	// Response is the JSON the client got from navigator.credentials.create.
	Response []byte
	// CredentialName labels the passkey; empty means DefaultCredentialName.
	CredentialName string
	// DeviceName is an optional client-chosen label of the new session.
	DeviceName string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown. A notice of a new client
	// carries it and nothing else keeps it.
	ClientIP netip.Addr
}

// FinishEnrollResult is the output of FinishEnroll. Everything but Outcome and Reason is set
// only for OutcomeOK.
type FinishEnrollResult struct {
	Outcome Outcome
	Reason  Reason
	SignedIn
	CredentialID  dpasskey.ID
	RecoveryCodes []string
}

// ErrInvalidName reports a credential or device name that cannot be stored; nothing is spent.
var ErrInvalidName = errors.New("invalid name")

// Execute finishes the registration. A refused ceremony consumes its challenge, so each try
// needs a new one, and leaves the ticket usable until it expires.
func (u *FinishEnroll) Execute(ctx context.Context, cmd FinishEnrollCommand) (FinishEnrollResult, error) {
	name := cmd.CredentialName
	if name == "" {
		name = DefaultCredentialName
	}
	if !dpasskey.ValidName(name) || !dsession.ValidDeviceName(cmd.DeviceName) {
		return FinishEnrollResult{}, fmt.Errorf("finish enroll: %w", ErrInvalidName)
	}
	denied := func(reason Reason) (FinishEnrollResult, error) {
		return FinishEnrollResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	binding, err := u.Bindings.HashBinding(cmd.BindingSecret)
	if errors.Is(err, port.ErrInvalidBindingSecret) {
		return denied(ReasonBadBinding)
	}
	if err != nil {
		return FinishEnrollResult{}, fmt.Errorf("finish enroll: binding: %w", err)
	}
	hash, err := u.Tickets.HashTicketSecret(cmd.TicketSecret)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return denied(ReasonBadTicket)
	}
	if err != nil {
		return FinishEnrollResult{}, fmt.Errorf("finish enroll: ticket: %w", err)
	}
	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return denied(ReasonBadChallenge)
	}
	now := u.Clock.Now()

	var result FinishEnrollResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		ticket, err := st.Tickets.GetByHashForUpdate(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonBadTicket)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load ticket: %w", err)
		}
		if !slices.Contains(enrollKinds, ticket.Kind()) {
			result, _ = denied(ReasonBadTicket)
			return nil
		}
		presented := dpasskey.Presented{Kind: ticket.Kind(), Binding: binding}
		if ticketDenied(ticket.Check(now, presented)) {
			result, _ = denied(ReasonBadTicket)
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
		// The challenge must belong to this ticket: another User's ceremony cannot be finished with it.
		if challenge.TicketID() != ticket.ID() || challenge.UserID() != ticket.UserID() {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}
		if challengeDenied(challenge.Consume(now, dpasskey.ChallengeRegistration)) {
			result, _ = denied(ReasonBadChallenge)
			return nil
		}
		// From here the challenge is spent whatever happens: a refusal commits that.
		if err := st.Challenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		user, creds, reason, err := enrollSubject(ctx, st, ticket, true)
		if err != nil {
			return err
		}
		if reason != "" {
			result, _ = denied(reason)
			return refuse(ctx, st, now, ticket.UserID(), reason)
		}
		if user.Blocked() {
			result, _ = denied(ReasonBlocked)
			return refuse(ctx, st, now, user.ID(), ReasonBlocked)
		}

		registered, err := u.WebAuthn.FinishRegistration(
			port.Subject{ID: user.ID(), Email: user.Email(), Credentials: creds}, challenge.Data(), cmd.Response)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result, _ = denied(ReasonCeremonyFailed)
			return refuse(ctx, st, now, user.ID(), ReasonCeremonyFailed)
		}
		if err != nil {
			return fmt.Errorf("finish registration: %w", err)
		}

		// A recovery proves the old keys are lost, or that someone else holds them: none of them may open the account
		// again. They go before the new key is stored, so the same authenticator can be registered anew.
		fields := map[string]string{}
		if ticket.Kind() == dpasskey.TicketRecoveryEnroll {
			revoked, err := st.Credentials.DeleteAllForUser(ctx, user.ID())
			if err != nil {
				return fmt.Errorf("revoke old keys: %w", err)
			}
			fields["old_keys"] = "none"
			if revoked > 0 {
				fields["old_keys"] = "revoked"
			}
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
			result, _ = denied(ReasonCeremonyFailed)
			if ticket.Kind() == dpasskey.TicketRecoveryEnroll {
				// The authenticator is registered to another user. A refusal commits, and the old keys are already
				// gone in this transaction: roll it all back instead, so a failed recovery changes nothing.
				return errRolledBack
			}
			return refuse(ctx, st, now, user.ID(), ReasonCeremonyFailed)
		} else if err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
		if err := ticket.Use(now, presented); err != nil {
			return fmt.Errorf("use ticket: %w", err)
		}
		if err := st.Tickets.Save(ctx, ticket); err != nil {
			return fmt.Errorf("store ticket: %w", err)
		}

		codes, err := issueRecoveryCodes(ctx, st, u.Recovery, u.PasskeyIDs, user.ID(), now)
		if err != nil {
			return err
		}
		amr, method := amrEnroll, "otp_passkey"
		if ticket.Kind() == dpasskey.TicketRecoveryEnroll {
			// The old keys are lost: whatever they opened must close before the new session opens.
			if err := appsession.RevokeEverything(ctx, st, user.ID(), now); err != nil {
				return fmt.Errorf("revoke old sessions: %w", err)
			}
			amr, method = amrRecovery, "recovery_passkey"
		}
		signed, err := u.signIn(ctx, st, now, user, ticket.Binding(), amr, cmd.DeviceName, method, cmd.ClientIP)
		if err != nil {
			return err
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditPasskeyEnrolled, Result: port.AuditSuccess, UserID: user.ID(), SessionID: signed.Session.ID(), At: now,
			Fields: withMethod(fields, method),
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		result = FinishEnrollResult{Outcome: OutcomeOK, SignedIn: signed, CredentialID: credentialID, RecoveryCodes: codes}
		return nil
	})
	if errors.Is(err, errRolledBack) {
		return result, nil
	}
	if err != nil {
		return FinishEnrollResult{}, fmt.Errorf("finish enroll: %w", err)
	}
	return result, nil
}

// errRolledBack ends a transaction without committing, for a refusal that must leave nothing behind. The result
// the caller returns is already set.
var errRolledBack = errors.New("transaction rolled back by design")
