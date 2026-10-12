package operator

import (
	"errors"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// MaxCredentials bounds the passkeys of one operator.
const MaxCredentials = 5

// Operator is a person allowed to use the admin API. The email is a label for lists and the
// audit log: nothing is ever sent to it and it is not proven.
type Operator struct {
	id         ID
	email      identity.Email
	createdAt  time.Time
	disabledAt time.Time
}

// New creates an operator without credentials.
func New(id ID, email identity.Email, now time.Time) (*Operator, error) {
	switch {
	case id.IsZero():
		return nil, errors.New("new operator: id is required")
	case email.IsZero():
		return nil, errors.New("new operator: email is required")
	case now.IsZero():
		return nil, errors.New("new operator: time is required")
	}
	return &Operator{id: id, email: email, createdAt: now}, nil
}

// Disable bars the operator: sessions are not accepted and a sign-in is refused. It keeps the first time.
func (o *Operator) Disable(now time.Time) error {
	if now.IsZero() {
		return errors.New("disable operator: time is required")
	}
	if o.disabledAt.IsZero() {
		o.disabledAt = now
	}
	return nil
}

// Enable lifts a disable.
func (o *Operator) Enable() { o.disabledAt = time.Time{} }

// Disabled reports whether the operator is barred.
func (o *Operator) Disabled() bool { return !o.disabledAt.IsZero() }

// ID returns the identifier.
func (o *Operator) ID() ID { return o.id }

// Email returns the label address.
func (o *Operator) Email() identity.Email { return o.email }

// CreatedAt returns the creation time.
func (o *Operator) CreatedAt() time.Time { return o.createdAt }

// DisabledAt returns when the operator was disabled, or the zero time.
func (o *Operator) DisabledAt() time.Time { return o.disabledAt }

// Record is the stored form of an operator.
type Record struct {
	ID         ID
	Email      identity.Email
	CreatedAt  time.Time
	DisabledAt time.Time
}

// Restore rebuilds an operator from storage and rejects incomplete records.
func Restore(r Record) (*Operator, error) {
	if r.ID.IsZero() || r.Email.IsZero() || r.CreatedAt.IsZero() {
		return nil, errors.New("restore operator: incomplete record")
	}
	return &Operator{id: r.ID, email: r.Email, createdAt: r.CreatedAt, disabledAt: r.DisabledAt}, nil
}

// Record returns the stored form.
func (o *Operator) Record() Record {
	return Record{ID: o.id, Email: o.email, CreatedAt: o.createdAt, DisabledAt: o.disabledAt}
}
