package port

import (
	"context"
	"errors"

	"go.airlance.org/auth/internal/domain/identity"
)

// ErrEmailTaken reports a change to an address another user already has.
var ErrEmailTaken = errors.New("email already belongs to another user")

// UserRepository stores users.
type UserRepository interface {
	// Ensure returns the user with candidate's email, creating candidate when none
	// exists. It must be safe against concurrent creation of the same email: both
	// callers get the same user and exactly one of them sees created.
	Ensure(ctx context.Context, candidate *identity.User) (u *identity.User, created bool, err error)
	// Get loads a user by ID. It returns ErrNotFound.
	Get(ctx context.Context, id identity.UserID) (*identity.User, error)
	// GetForShare loads a user and keeps the row share-locked until the transaction ends, so a block
	// committed meanwhile is seen and a block that starts waits for this transaction. Issuing a session
	// reads the user this way. It returns ErrNotFound.
	GetForShare(ctx context.Context, id identity.UserID) (*identity.User, error)
	// GetForUpdate loads a user and keeps the row exclusively locked until the transaction ends. A use case that
	// reads what the user can sign in with and then changes it (their keys, their recovery codes) takes it first, so
	// two such transactions run one after the other, and issuing a session (GetForShare) waits for both. It returns
	// ErrNotFound.
	GetForUpdate(ctx context.Context, id identity.UserID) (*identity.User, error)
	// Delete removes the user, dependent access data, flows addressed to the current email
	// or owned by the user, and their mail jobs. Audit references are cleared; quotas remain.
	// It returns ErrNotFound when the user is gone.
	Delete(ctx context.Context, id identity.UserID) error
	// FindByEmail loads the user that has the address. It returns ErrNotFound.
	FindByEmail(ctx context.Context, email identity.Email) (*identity.User, error)
	// ChangeEmail stores the new address, verification time and update time of a user loaded
	// in this transaction. It returns ErrNotFound when the user is gone and ErrEmailTaken,
	// changing nothing, when another user has the address.
	ChangeEmail(ctx context.Context, u *identity.User) error
	// SetBlocked stores the blocked state and update time of a user loaded in this transaction.
	// It returns ErrNotFound when the user is gone.
	SetBlocked(ctx context.Context, u *identity.User) error
	// List returns the users the query selects, in address order. Query.Limit must be positive.
	List(ctx context.Context, q UserQuery) ([]*identity.User, error)
}
