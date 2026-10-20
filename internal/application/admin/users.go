package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	dsession "go.airlance.org/auth/internal/domain/session"
)

// Paging of the user list.
const (
	DefaultPageSize = 50
	MaxPageSize     = 100
	// maxAddress bounds a search prefix or a cursor: no address is longer.
	maxAddress = 254
	// maxDetailSessions bounds the sessions shown on a user's page.
	maxDetailSessions = 50
)

// UsersDeps are the dependencies of Users.
type UsersDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

// Users is what an operator may do to users.
type Users struct{ UsersDeps }

// NewUsers checks the dependencies once, at assembly time.
func NewUsers(d UsersDeps) (*Users, error) {
	if d.UnitOfWork == nil || d.Clock == nil {
		return nil, errors.New("new admin users: all dependencies are required")
	}

	return &Users{d}, nil
}

// ListUsersCommand is the input of List.
type ListUsersCommand struct {
	Actor Actor
	// Prefix selects addresses that start with it, case-insensitively.
	Prefix string
	// After is the address Next of the previous page returned.
	After string
	// Limit is the page size; 0 means DefaultPageSize.
	Limit int
}

// ListUsersResult is the output of List.
type ListUsersResult struct {
	Outcome Outcome
	Users   []*identity.User
	// Next is the After of the following page, or "" on the last one.
	Next string
}

// List returns a page of users in address order.
func (u *Users) List(ctx context.Context, cmd ListUsersCommand) (ListUsersResult, error) {
	prefix, after := strings.ToLower(strings.TrimSpace(cmd.Prefix)), strings.ToLower(strings.TrimSpace(cmd.After))
	if len(prefix) > maxAddress || len(after) > maxAddress {
		return ListUsersResult{}, invalid("the search is longer than any address")
	}

	limit := cmd.Limit
	switch {
	case limit == 0:
		limit = DefaultPageSize
	case limit < 0 || limit > MaxPageSize:
		return ListUsersResult{}, invalid("the page size must be between 1 and %d", MaxPageSize)
	}

	now := u.Clock.Now()

	var result ListUsersResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}
		// One more than a page tells whether another page follows.
		users, err := st.Users.List(ctx, port.UserQuery{EmailPrefix: prefix, After: after, Limit: limit + 1})
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}

		result = ListUsersResult{Outcome: OutcomeOK, Users: users}
		if len(users) > limit {
			result.Users = users[:limit]
			result.Next = users[limit-1].Email().String()
		}

		return nil
	})
	if err != nil {
		return ListUsersResult{}, fmt.Errorf("list users: %w", err)
	}

	return result, nil
}

// UserCommand names a user an operator acts on.
type UserCommand struct {
	Actor  Actor
	UserID string
}

// UserDetail is everything the card of a user shows.
type UserDetail struct {
	User     *identity.User
	Sessions []*dsession.Session
	Keys     []*dpasskey.Credential
	// RecoveryCodesLeft is how many recovery codes are still unused.
	RecoveryCodesLeft int
}

// GetResult is the output of Get.
type GetResult struct {
	Outcome Outcome
	Detail  UserDetail
}

// Get returns the card of one user.
func (u *Users) Get(ctx context.Context, cmd UserCommand) (GetResult, error) {
	id, err := identity.ParseUserID(cmd.UserID)
	if err != nil {
		return GetResult{Outcome: OutcomeNotFound}, nil
	}

	now := u.Clock.Now()

	var result GetResult

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, false); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}

		user, err := st.Users.Get(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result.Outcome = OutcomeNotFound
			return nil
		}

		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}

		sessions, err := st.Sessions.ListActive(ctx, id, now, maxDetailSessions)
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}

		keys, err := st.Credentials.ListByUser(ctx, id)
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}

		left, err := st.Recovery.CountUnused(ctx, id)
		if err != nil {
			return fmt.Errorf("count recovery codes: %w", err)
		}

		result = GetResult{Outcome: OutcomeOK, Detail: UserDetail{User: user, Sessions: sessions, Keys: keys, RecoveryCodesLeft: left}}

		return nil
	})
	if err != nil {
		return GetResult{}, fmt.Errorf("get user: %w", err)
	}

	return result, nil
}

// Result is the output of the operations that return nothing but whether they happened.
type Result struct {
	Outcome Outcome
	Reason  Reason
}

// change runs one operation on an existing user: authorize, load, apply, audit, and then after, which
// must come last because it may remove what the audit event names. The operations differ only in apply,
// in after and in the operation they record.
func (u *Users) change(ctx context.Context, cmd UserCommand, fresh bool, operation string,
	apply func(ctx context.Context, st port.Stores, user *identity.User) (Result, error),
	after func(ctx context.Context, st port.Stores, user *identity.User) error) (Result, error) {
	id, err := identity.ParseUserID(cmd.UserID)
	if err != nil {
		return Result{Outcome: OutcomeNotFound}, nil
	}

	now := u.Clock.Now()

	var result Result

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if outcome, err := cmd.Actor.authorize(ctx, st, now, fresh); err != nil || outcome != OutcomeOK {
			result.Outcome = outcome
			return err
		}

		user, err := st.Users.Get(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result.Outcome = OutcomeNotFound
			return nil
		}

		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}

		if result, err = apply(ctx, st, user); err != nil || result.Outcome != OutcomeOK {
			return err
		}

		if err := act(ctx, st, now, cmd.Actor, about(id), operation); err != nil {
			return err
		}

		if after != nil {
			return after(ctx, st, user)
		}

		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", operation, err)
	}

	return result, nil
}

// Block bars the user from signing in and ends everything they have open. The block is written first: the
// write takes the user's row, so a sign-in that is under way either sees it or is revoked right after.
func (u *Users) Block(ctx context.Context, cmd UserCommand) (Result, error) {
	now := u.Clock.Now()

	return u.change(ctx, cmd, false, "block", func(ctx context.Context, st port.Stores, user *identity.User) (Result, error) {
		if err := user.Block(now); err != nil {
			return Result{}, err
		}

		if err := st.Users.SetBlocked(ctx, user); err != nil {
			return Result{}, fmt.Errorf("store block: %w", err)
		}

		if err := appsession.RevokeEverything(ctx, st, user.ID(), now); err != nil {
			return Result{}, fmt.Errorf("revoke sessions: %w", err)
		}

		return Result{Outcome: OutcomeOK}, nil
	}, nil)
}

// Unblock lets the user sign in again. The sessions that were ended stay ended.
func (u *Users) Unblock(ctx context.Context, cmd UserCommand) (Result, error) {
	now := u.Clock.Now()

	return u.change(ctx, cmd, false, "unblock", func(ctx context.Context, st port.Stores, user *identity.User) (Result, error) {
		if err := user.Unblock(now); err != nil {
			return Result{}, err
		}

		if err := st.Users.SetBlocked(ctx, user); err != nil {
			return Result{}, fmt.Errorf("store unblock: %w", err)
		}

		return Result{Outcome: OutcomeOK}, nil
	}, nil)
}

// RevokeSessions ends every session, token and recognition record of the user.
func (u *Users) RevokeSessions(ctx context.Context, cmd UserCommand) (Result, error) {
	now := u.Clock.Now()

	return u.change(ctx, cmd, false, "revoke_sessions", func(ctx context.Context, st port.Stores, user *identity.User) (Result, error) {
		if err := appsession.RevokeEverything(ctx, st, user.ID(), now); err != nil {
			return Result{}, fmt.Errorf("revoke sessions: %w", err)
		}

		return Result{Outcome: OutcomeOK}, nil
	}, nil)
}

// DeleteCommand is the input of Delete.
type DeleteCommand struct {
	UserCommand
	// ConfirmEmail must be the user's address: the operator names who they are deleting.
	ConfirmEmail string
}

// Delete removes the account for good. It needs a recent sign-in of the operator and the user's address.
// The audit event is written first, while it still names the user; deleting clears that reference.
func (u *Users) Delete(ctx context.Context, cmd DeleteCommand) (Result, error) {
	confirm, err := identity.ParseEmail(cmd.ConfirmEmail)
	if err != nil {
		// An address that cannot be one cannot match: the same answer as a wrong address.
		confirm = identity.Email{}
	}

	return u.change(ctx, cmd.UserCommand, true, "delete_user", func(ctx context.Context, st port.Stores, user *identity.User) (Result, error) {
		if confirm.IsZero() || confirm != user.Email() {
			return Result{Outcome: OutcomeConflict, Reason: ReasonConfirmMismatch}, nil
		}

		return Result{Outcome: OutcomeOK}, nil
	}, func(ctx context.Context, st port.Stores, user *identity.User) error {
		return st.Users.Delete(ctx, user.ID())
	})
}
