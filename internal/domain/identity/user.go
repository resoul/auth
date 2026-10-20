package identity

import (
	"errors"
	"time"
)

// User is a confirmed owner of an email address. It exists only after a successful
// proof; before that there is only a flow.
type User struct {
	id              UserID
	email           Email
	emailVerifiedAt time.Time
	createdAt       time.Time
	updatedAt       time.Time
	// blockedAt is the zero time while the User may sign in.
	blockedAt time.Time
}

// NewUser creates a User whose email was just proven.
func NewUser(id UserID, email Email, now time.Time) (*User, error) {
	if id.IsZero() {
		return nil, errors.New("new user: id is required")
	}

	if email.IsZero() {
		return nil, errors.New("new user: email is required")
	}

	if now.IsZero() {
		return nil, errors.New("new user: time is required")
	}

	return &User{id: id, email: email, emailVerifiedAt: now, createdAt: now, updatedAt: now}, nil
}

// ErrSameEmail reports a change to the address the User already has.
var ErrSameEmail = errors.New("the address is already the User's")

// ChangeEmail moves the User to an address that was just proven. The proof of the old
// address does not carry over: the verification time is the time of the new proof.
func (u *User) ChangeEmail(email Email, now time.Time) error {
	switch {
	case email.IsZero():
		return errors.New("change email: email is required")
	case now.IsZero():
		return errors.New("change email: time is required")
	case email == u.email:
		return ErrSameEmail
	}

	u.email, u.emailVerifiedAt, u.updatedAt = email, now, now

	return nil
}

// Block stops the User from signing in. Blocking a blocked User keeps the first time.
func (u *User) Block(now time.Time) error {
	if now.IsZero() {
		return errors.New("block user: time is required")
	}

	if u.blockedAt.IsZero() {
		u.blockedAt, u.updatedAt = now, now
	}

	return nil
}

// Unblock lets the User sign in again.
func (u *User) Unblock(now time.Time) error {
	if now.IsZero() {
		return errors.New("unblock user: time is required")
	}

	if !u.blockedAt.IsZero() {
		u.blockedAt, u.updatedAt = time.Time{}, now
	}

	return nil
}

// Blocked reports whether the User is barred from signing in.
func (u *User) Blocked() bool { return !u.blockedAt.IsZero() }

// BlockedAt returns when the User was blocked, or the zero time.
func (u *User) BlockedAt() time.Time { return u.blockedAt }

// UserRecord is the stored form of a User, used by adapters to rebuild it. BlockedAt is the
// zero time for a User who may sign in.
type UserRecord struct {
	ID              UserID
	Email           Email
	EmailVerifiedAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	BlockedAt       time.Time
}

// RestoreUser rebuilds a User from storage and rejects incomplete records.
func RestoreUser(r UserRecord) (*User, error) {
	if r.ID.IsZero() || r.Email.IsZero() || r.EmailVerifiedAt.IsZero() || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return nil, errors.New("restore user: incomplete record")
	}

	return &User{id: r.ID, email: r.Email, emailVerifiedAt: r.EmailVerifiedAt, createdAt: r.CreatedAt, updatedAt: r.UpdatedAt, blockedAt: r.BlockedAt}, nil
}

// Record returns the stored form of the User.
func (u *User) Record() UserRecord {
	return UserRecord{ID: u.id, Email: u.email, EmailVerifiedAt: u.emailVerifiedAt, CreatedAt: u.createdAt, UpdatedAt: u.updatedAt, BlockedAt: u.blockedAt}
}

// ID returns the User identifier.
func (u *User) ID() UserID { return u.id }

// Email returns the confirmed normalized address.
func (u *User) Email() Email { return u.email }

// EmailVerifiedAt returns when the address was proven.
func (u *User) EmailVerifiedAt() time.Time { return u.emailVerifiedAt }

// CreatedAt returns when the User was created.
func (u *User) CreatedAt() time.Time { return u.createdAt }

// UpdatedAt returns when the User last changed.
func (u *User) UpdatedAt() time.Time { return u.updatedAt }
