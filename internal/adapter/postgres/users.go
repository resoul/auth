package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
)

type users struct{ q *sqlc.Queries }

func (r *users) Get(ctx context.Context, id identity.UserID) (*identity.User, error) {
	u, err := userUUID(id)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	row, err := r.q.GetUserByID(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return userFromRow(row)
}

func (r *users) GetForShare(ctx context.Context, id identity.UserID) (*identity.User, error) {
	u, err := userUUID(id)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	row, err := r.q.GetUserForShare(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return userFromRow(row)
}

func (r *users) GetForUpdate(ctx context.Context, id identity.UserID) (*identity.User, error) {
	u, err := userUUID(id)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	row, err := r.q.GetUserForUpdate(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return userFromRow(row)
}

// lockUser takes the user row exclusively, so that what a user can sign in with and what they are signed in
// with change one transaction at a time. It reports false when the user is gone. Callers lock the user before
// any session, token or credential row.
func lockUser(ctx context.Context, q *sqlc.Queries, id identity.UserID) (bool, error) {
	u, err := userUUID(id)
	if err != nil {
		return false, err
	}
	if _, err := q.LockUser(ctx, u); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("lock user: %w", err)
	}
	return true, nil
}

func (r *users) FindByEmail(ctx context.Context, email identity.Email) (*identity.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	return userFromRow(row)
}

func (r *users) Ensure(ctx context.Context, candidate *identity.User) (*identity.User, bool, error) {
	rec := candidate.Record()
	id, err := userUUID(rec.ID)
	if err != nil {
		return nil, false, fmt.Errorf("ensure user: %w", err)
	}
	inserted, err := r.q.InsertUserIfAbsent(ctx, sqlc.InsertUserIfAbsentParams{
		ID: id, Email: rec.Email.String(), EmailVerifiedAt: dbTime(rec.EmailVerifiedAt),
		CreatedAt: dbTime(rec.CreatedAt), UpdatedAt: dbTime(rec.UpdatedAt),
	})
	if err != nil {
		return nil, false, fmt.Errorf("ensure user: insert: %w", err)
	}
	row, err := r.q.GetUserByEmail(ctx, rec.Email.String())
	if err != nil {
		return nil, false, fmt.Errorf("ensure user: load: %w", err)
	}
	user, err := userFromRow(row)
	if err != nil {
		return nil, false, fmt.Errorf("ensure user: %w", err)
	}
	return user, inserted == 1, nil
}

func userFromRow(row sqlc.User) (*identity.User, error) {
	userID, err := identity.ParseUserID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored user id: %w", err)
	}
	email, err := identity.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("stored user email: %w", err)
	}
	return identity.RestoreUser(identity.UserRecord{
		ID: userID, Email: email, EmailVerifiedAt: goTime(row.EmailVerifiedAt),
		CreatedAt: goTime(row.CreatedAt), UpdatedAt: goTime(row.UpdatedAt), BlockedAt: goTimePtr(row.BlockedAt),
	})
}

func (r *users) ChangeEmail(ctx context.Context, u *identity.User) error {
	rec := u.Record()
	id, err := userUUID(rec.ID)
	if err != nil {
		return fmt.Errorf("change email: %w", err)
	}
	n, err := r.q.UpdateUserEmail(ctx, sqlc.UpdateUserEmailParams{
		ID: id, Email: rec.Email.String(), EmailVerifiedAt: dbTime(rec.EmailVerifiedAt), UpdatedAt: dbTime(rec.UpdatedAt),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "users_email_unique" {
		// Two accounts moved to one address in the same instant: the later one lost.
		return port.ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("change email: %w", err)
	}
	if n == 1 {
		return nil
	}
	// No row changed: the user is gone or the address belongs to someone else.
	if _, err := r.q.GetUserByID(ctx, id); errors.Is(err, pgx.ErrNoRows) {
		return port.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("change email: %w", err)
	}
	return port.ErrEmailTaken
}

func (r *users) Delete(ctx context.Context, id identity.UserID) error {
	uid, err := userUUID(id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	row, err := r.q.GetUserForDeletion(ctx, uid)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock user for deletion: %w", err)
	}
	if err := r.q.DeleteAccountFlows(ctx, sqlc.DeleteAccountFlowsParams{UserID: &uid, Email: row.Email}); err != nil {
		return fmt.Errorf("delete account flows: %w", err)
	}
	if _, err := r.q.DeleteUser(ctx, uid); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (r *users) SetBlocked(ctx context.Context, u *identity.User) error {
	id, err := userUUID(u.ID())
	if err != nil {
		return fmt.Errorf("set blocked: %w", err)
	}
	n, err := r.q.SetUserBlocked(ctx, sqlc.SetUserBlockedParams{ID: id, BlockedAt: dbTimePtr(u.BlockedAt()), UpdatedAt: dbTime(u.UpdatedAt())})
	if err != nil {
		return fmt.Errorf("set blocked: %w", err)
	}
	if n == 0 {
		return port.ErrNotFound
	}
	return nil
}

// likeEscaper makes a prefix literal in a LIKE pattern.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (r *users) List(ctx context.Context, q port.UserQuery) ([]*identity.User, error) {
	rows, err := r.q.ListUsers(ctx, sqlc.ListUsersParams{
		Pattern: likeEscaper.Replace(q.EmailPrefix) + "%", After: q.After, MaxRows: int32(q.Limit),
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	out := make([]*identity.User, 0, len(rows))
	for _, row := range rows {
		u, err := userFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}
