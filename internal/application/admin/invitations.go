package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

// Invite allows an address to register, in the caller's transaction, and queues the email that announces
// it unless noMail. An address that already has an account is not invited: registered is true and nothing
// changes. The running service sends the mail and looks the invitation up again at that moment, so a
// revoked one is not announced. The command line and the admin API both call this.
func Invite(ctx context.Context, st port.Stores, email identity.Email, now time.Time, ttl time.Duration, noMail bool) (inv *identity.Invitation, registered bool, err error) {
	inv, err = identity.NewInvitation(email, now, ttl)
	if err != nil {
		return nil, false, err
	}

	if _, err := st.Users.FindByEmail(ctx, email); err == nil {
		return nil, true, nil
	} else if !errors.Is(err, port.ErrNotFound) {
		return nil, false, fmt.Errorf("look up user: %w", err)
	}

	if err := st.Invitations.Save(ctx, inv); err != nil {
		return nil, false, fmt.Errorf("store invitation: %w", err)
	}

	if noMail {
		return inv, false, nil
	}

	if err := st.Outbox.Enqueue(ctx, port.MailJob{Kind: port.JobInvitation, Recipient: email, QuotaClass: authflow.QuotaUnknown, AvailableAt: now}); err != nil {
		return nil, false, fmt.Errorf("queue invitation mail: %w", err)
	}

	return inv, false, nil
}

// InvitationsDeps are the dependencies of Invitations.
type InvitationsDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

// Invitations is what an operator may do to invitations.
type Invitations struct{ InvitationsDeps }

// NewInvitations checks the dependencies once, at assembly time.
func NewInvitations(d InvitationsDeps) (*Invitations, error) {
	if d.UnitOfWork == nil || d.Clock == nil {
		return nil, errors.New("new admin invitations: all dependencies are required")
	}

	return &Invitations{d}, nil
}

// DefaultInvitationTTL is the lifetime of an invitation that names none.
const DefaultInvitationTTL = 7 * 24 * time.Hour

// CreateInvitationCommand is the input of Create.
type CreateInvitationCommand struct {
	Actor Actor
	Email string
	// TTL is the lifetime; 0 means DefaultInvitationTTL.
	TTL time.Duration
	// NoMail makes the invitation without the email that announces it.
	NoMail bool
}

// CreateInvitationResult is the output of Create.
type CreateInvitationResult struct {
	Outcome Outcome
	Reason  Reason
	// Invitation is set for OutcomeOK.
	Invitation *identity.Invitation
}

// Create invites an address. An address with an account is a conflict: there is nothing to allow.
func (i *Invitations) Create(ctx context.Context, cmd CreateInvitationCommand) (CreateInvitationResult, error) {
	email, err := identity.ParseEmail(cmd.Email)
	if err != nil {
		return CreateInvitationResult{}, invalid("the address is not valid")
	}

	ttl := cmd.TTL
	if ttl == 0 {
		ttl = DefaultInvitationTTL
	}

	if ttl < identity.MinInvitationTTL || ttl > identity.MaxInvitationTTL {
		return CreateInvitationResult{}, invalid("the lifetime must be between %v and %v", identity.MinInvitationTTL, identity.MaxInvitationTTL)
	}

	now := i.Clock.Now()

	var result CreateInvitationResult

	err = i.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}

		inv, registered, err := Invite(ctx, st, email, now, ttl, cmd.NoMail)
		if err != nil {
			return err
		}

		if registered {
			result = CreateInvitationResult{Outcome: OutcomeConflict, Reason: ReasonAlreadyUser}
			return nil
		}

		result = CreateInvitationResult{Outcome: OutcomeOK, Invitation: inv}

		return act(ctx, st, now, cmd.Actor, noUser, "invite")
	})
	if err != nil {
		return CreateInvitationResult{}, fmt.Errorf("invite: %w", err)
	}

	return result, nil
}

// ListInvitationsResult is the output of List.
type ListInvitationsResult struct {
	Outcome     Outcome
	Invitations []*identity.Invitation
	// At is the instant the list was read, which decides what is still Active.
	At time.Time
}

// List returns every invitation, active and expired, oldest first.
func (i *Invitations) List(ctx context.Context, actor Actor) (ListInvitationsResult, error) {
	now := i.Clock.Now()

	var result ListInvitationsResult

	err := i.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}

		list, err := st.Invitations.List(ctx)
		if err != nil {
			return fmt.Errorf("list invitations: %w", err)
		}

		result = ListInvitationsResult{Outcome: OutcomeOK, Invitations: list, At: now}

		return nil
	})
	if err != nil {
		return ListInvitationsResult{}, fmt.Errorf("list invitations: %w", err)
	}

	return result, nil
}

// RevokeInvitationCommand is the input of Revoke.
type RevokeInvitationCommand struct {
	Actor Actor
	Email string
}

// Revoke withdraws the invitation of an address. An address without one is not found.
func (i *Invitations) Revoke(ctx context.Context, cmd RevokeInvitationCommand) (Result, error) {
	email, err := identity.ParseEmail(cmd.Email)
	if err != nil {
		return Result{}, invalid("the address is not valid")
	}

	now := i.Clock.Now()

	var result Result

	err = i.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}

		removed, err := st.Invitations.Delete(ctx, email)
		if err != nil {
			return fmt.Errorf("delete invitation: %w", err)
		}

		if !removed {
			result.Outcome = OutcomeNotFound
			return nil
		}

		result.Outcome = OutcomeOK

		return act(ctx, st, now, cmd.Actor, noUser, "uninvite")
	})
	if err != nil {
		return Result{}, fmt.Errorf("revoke invitation: %w", err)
	}

	return result, nil
}
