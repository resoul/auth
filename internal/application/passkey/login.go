package passkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	dsession "airlance.org/auth/internal/domain/session"
)

// BeginLoginDeps are the dependencies of BeginLogin.
type BeginLoginDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	PasskeyIDs port.PasskeyIDGenerator
}

// BeginLogin starts an assertion. It names no User: the authenticator offers the passkeys it
// holds for the relying party, and the assertion tells the server whose they are. The same
// ceremony serves a passkey sign-in and the second factor after an email code.
type BeginLogin struct {
	BeginLoginDeps
}

// NewBeginLogin checks the dependencies once, at assembly time.
func NewBeginLogin(d BeginLoginDeps) (*BeginLogin, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new begin login: all dependencies are required")
	}
	return &BeginLogin{d}, nil
}

// BeginLoginCommand is the input of BeginLogin.
type BeginLoginCommand struct {
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// Execute prepares the assertion. The caller has proven nothing yet, so each address may start
// only so many ceremonies: every one writes a row.
func (u *BeginLogin) Execute(ctx context.Context, cmd BeginLoginCommand) (CeremonyResult, error) {
	now := u.Clock.Now()
	ceremony, err := u.WebAuthn.BeginLogin()
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: %w", err)
	}
	id, err := u.PasskeyIDs.NewPasskeyID()
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: challenge id: %w", err)
	}
	challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
		ID: id, Purpose: dpasskey.ChallengeLogin, Data: ceremony.State, Now: now,
	})
	if err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: new challenge: %w", err)
	}
	result := CeremonyResult{Outcome: OutcomeOK, ChallengeID: id.String(), Options: ceremony.Options}
	if err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendPasskey, IP: cmd.ClientIP, Now: now})
		if err != nil {
			return fmt.Errorf("spend passkey quota: %w", err)
		}
		if !allowed {
			result = CeremonyResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}
		return st.Challenges.Create(ctx, challenge)
	}); err != nil {
		return CeremonyResult{}, fmt.Errorf("begin login: store challenge: %w", err)
	}
	return result, nil
}

// FinishLoginDeps are the dependencies of FinishLogin.
type FinishLoginDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	Bindings   port.BindingSecrets
	Tickets    port.TicketSecrets
	SessionDeps
}

// FinishLogin verifies an assertion and opens a session. With a second-factor ticket it
// completes the sign-in an email code started; without one the passkey alone signs in.
type FinishLogin struct {
	FinishLoginDeps
}

// NewFinishLogin checks the dependencies once, at assembly time.
func NewFinishLogin(d FinishLoginDeps) (*FinishLogin, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.Bindings == nil || d.Tickets == nil {
		return nil, errors.New("new finish login: all dependencies are required")
	}
	if err := d.validate("finish login"); err != nil {
		return nil, err
	}
	return &FinishLogin{d}, nil
}

// FinishLoginCommand is the input of FinishLogin.
type FinishLoginCommand struct {
	ChallengeID string
	// Response is the JSON the client got from navigator.credentials.get.
	Response []byte
	// TicketSecret is the second-factor ticket of an email sign-in; empty for a passkey sign-in.
	TicketSecret string
	// BindingSecret is the client binding. A second-factor ticket requires it. A passkey
	// sign-in may omit it, and then a new binding is issued.
	BindingSecret string
	// DeviceName is an optional client-chosen label of the new session.
	DeviceName string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown. A notice of a new client
	// carries it and nothing else keeps it.
	ClientIP netip.Addr
}

// FinishLoginResult is the output of FinishLogin. Everything but Outcome and Reason is set
// only for OutcomeOK.
type FinishLoginResult struct {
	Outcome Outcome
	Reason  Reason
	SignedIn
	// NewBindingSecret is set when the server issued the client binding: the client keeps it.
	NewBindingSecret string
}

// providedBinding is the client binding a request carried, if any.
type providedBinding struct {
	Hash identity.BindingHash
	Set  bool
}

// Execute finishes the sign-in. A refused ceremony consumes its challenge, so each try needs
// a new one, and leaves a second-factor ticket usable until it expires.
func (u *FinishLogin) Execute(ctx context.Context, cmd FinishLoginCommand) (FinishLoginResult, error) {
	if !dsession.ValidDeviceName(cmd.DeviceName) {
		return FinishLoginResult{}, fmt.Errorf("finish login: %w", ErrInvalidName)
	}
	denied := func(reason Reason) (FinishLoginResult, error) {
		return FinishLoginResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	challengeID, err := dpasskey.ParseID(cmd.ChallengeID)
	if err != nil {
		return denied(ReasonBadChallenge)
	}
	secondFactor := cmd.TicketSecret != ""
	var ticketHash dpasskey.SecretHash
	if secondFactor {
		if ticketHash, err = u.Tickets.HashTicketSecret(cmd.TicketSecret); errors.Is(err, port.ErrInvalidTicketSecret) {
			return denied(ReasonBadTicket)
		} else if err != nil {
			return FinishLoginResult{}, fmt.Errorf("finish login: ticket: %w", err)
		}
	}
	var binding providedBinding
	if cmd.BindingSecret != "" || secondFactor {
		hash, err := u.Bindings.HashBinding(cmd.BindingSecret)
		if errors.Is(err, port.ErrInvalidBindingSecret) {
			return denied(ReasonBadBinding)
		}
		if err != nil {
			return FinishLoginResult{}, fmt.Errorf("finish login: binding: %w", err)
		}
		binding = providedBinding{Hash: hash, Set: true}
	}
	now := u.Clock.Now()

	var result FinishLoginResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		challenge, err := st.Challenges.GetForUpdate(ctx, challengeID)
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
		// From here the challenge is spent whatever happens: a refusal commits that.
		if err := st.Challenges.Save(ctx, challenge); err != nil {
			return fmt.Errorf("store challenge: %w", err)
		}

		var ticket *dpasskey.Ticket
		presented := dpasskey.Presented{Kind: dpasskey.TicketSecondFactor, Binding: binding.Hash}
		if secondFactor {
			if ticket, err = st.Tickets.GetByHashForUpdate(ctx, ticketHash); errors.Is(err, port.ErrNotFound) {
				result, _ = denied(ReasonBadTicket)
				return nil
			} else if err != nil {
				return fmt.Errorf("load ticket: %w", err)
			}
			if ticketDenied(ticket.Check(now, presented)) {
				result, _ = denied(ReasonBadTicket)
				return nil
			}
		}

		var credential *dpasskey.Credential
		lookup := func(credentialID []byte, userHandle port.UserHandle) (*dpasskey.Credential, error) {
			c, err := st.Credentials.GetForUpdate(ctx, credentialID)
			if err != nil {
				return nil, err
			}
			// The handle the authenticator keeps must be the owner's: a credential is never
			// accepted under another User's name.
			if !bytes.Equal(dpasskey.UserHandle(c.UserID()), userHandle) {
				return nil, port.ErrNotFound
			}
			credential = c
			return c, nil
		}
		assertion, err := u.WebAuthn.FinishLogin(challenge.Data(), cmd.Response, lookup)
		if errors.Is(err, port.ErrCeremonyFailed) {
			result, _ = denied(ReasonCeremonyFailed)
			if credential != nil {
				return refuse(ctx, st, now, credential.UserID(), ReasonCeremonyFailed)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("finish login: %w", err)
		}
		if secondFactor && credential.UserID() != ticket.UserID() {
			// A valid key of another User: the email code proved someone else.
			result, _ = denied(ReasonUnknownKey)
			return refuse(ctx, st, now, ticket.UserID(), ReasonUnknownKey)
		}

		if err := credential.RecordUse(now, assertion.SignCount, assertion.BackupState); errors.Is(err, dpasskey.ErrCloneSuspected) {
			result, _ = denied(ReasonCloneSuspected)
			return refuse(ctx, st, now, credential.UserID(), ReasonCloneSuspected)
		} else if err != nil {
			return fmt.Errorf("record use: %w", err)
		}
		if err := st.Credentials.Save(ctx, credential); err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
		if secondFactor {
			if err := ticket.Use(now, presented); err != nil {
				return fmt.Errorf("use ticket: %w", err)
			}
			if err := st.Tickets.Save(ctx, ticket); err != nil {
				return fmt.Errorf("store ticket: %w", err)
			}
		}

		user, err := st.Users.GetForShare(ctx, credential.UserID())
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		if user.Blocked() {
			result, _ = denied(ReasonBlocked)
			return refuse(ctx, st, now, user.ID(), ReasonBlocked)
		}
		amr, method, hash := amrLogin, "passkey", binding.Hash
		newSecret := ""
		switch {
		case secondFactor:
			amr, method, hash = amrSecond, "otp_passkey", ticket.Binding()
		case !binding.Set:
			if newSecret, hash, err = u.Bindings.NewBinding(); err != nil {
				return fmt.Errorf("new binding: %w", err)
			}
		}
		signed, err := u.signIn(ctx, st, now, user, hash, amr, cmd.DeviceName, method, cmd.ClientIP)
		if err != nil {
			return err
		}
		result = FinishLoginResult{Outcome: OutcomeOK, SignedIn: signed, NewBindingSecret: newSecret}
		return nil
	})
	if err != nil {
		return FinishLoginResult{}, fmt.Errorf("finish login: %w", err)
	}
	return result, nil
}
