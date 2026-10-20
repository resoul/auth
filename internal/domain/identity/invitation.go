package identity

import (
	"errors"
	"fmt"
	"time"
)

// RegistrationMode says who may open a new account. The zero value is RegistrationOpen.
type RegistrationMode string

// Registration modes.
const (
	// RegistrationOpen lets any address that proves its mailbox create an account.
	RegistrationOpen RegistrationMode = "open"
	// RegistrationInviteOnly lets only an invited address create one. An existing user signs in as before.
	RegistrationInviteOnly RegistrationMode = "invite"
)

// ParseRegistrationMode accepts the two mode names.
func ParseRegistrationMode(s string) (RegistrationMode, error) {
	switch RegistrationMode(s) {
	case RegistrationOpen, RegistrationInviteOnly:
		return RegistrationMode(s), nil
	}

	return "", fmt.Errorf("unknown registration mode %q", s)
}

// Invites reports whether the mode needs an invitation to register.
func (m RegistrationMode) Invites() bool { return m == RegistrationInviteOnly }

// Limits of an invitation's life: long enough to be read in a week, short enough not to pile up.
const (
	MinInvitationTTL = time.Hour
	MaxInvitationTTL = 90 * 24 * time.Hour
)

// Invitation is the permission of one address to register. It carries no secret: the address itself,
// proven through the mailbox, is the credential. It is removed when the account is created.
type Invitation struct {
	email     Email
	createdAt time.Time
	expiresAt time.Time
}

// NewInvitation creates an invitation that lasts ttl from now.
func NewInvitation(email Email, now time.Time, ttl time.Duration) (*Invitation, error) {
	switch {
	case email.IsZero():
		return nil, errors.New("new invitation: email is required")
	case now.IsZero():
		return nil, errors.New("new invitation: time is required")
	case ttl < MinInvitationTTL || ttl > MaxInvitationTTL:
		return nil, fmt.Errorf("new invitation: the lifetime must be between %v and %v", MinInvitationTTL, MaxInvitationTTL)
	}

	return &Invitation{email: email, createdAt: now, expiresAt: now.Add(ttl)}, nil
}

// InvitationRecord is the stored form of an Invitation.
type InvitationRecord struct {
	Email     Email
	CreatedAt time.Time
	ExpiresAt time.Time
}

// RestoreInvitation rebuilds an Invitation from storage and rejects incomplete records.
func RestoreInvitation(r InvitationRecord) (*Invitation, error) {
	if r.Email.IsZero() || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, errors.New("restore invitation: incomplete record")
	}

	return &Invitation{email: r.Email, createdAt: r.CreatedAt, expiresAt: r.ExpiresAt}, nil
}

// Record returns the stored form of the Invitation.
func (i *Invitation) Record() InvitationRecord {
	return InvitationRecord{Email: i.email, CreatedAt: i.createdAt, ExpiresAt: i.expiresAt}
}

// Email returns the invited address.
func (i *Invitation) Email() Email { return i.email }

// CreatedAt returns when the invitation was made.
func (i *Invitation) CreatedAt() time.Time { return i.createdAt }

// ExpiresAt returns when the invitation stops allowing a registration.
func (i *Invitation) ExpiresAt() time.Time { return i.expiresAt }

// Active reports whether the invitation allows a registration at now.
func (i *Invitation) Active(now time.Time) bool { return now.Before(i.expiresAt) }
