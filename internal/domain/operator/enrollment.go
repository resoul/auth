package operator

import (
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/passkey"
)

// EnrollmentTTL is how long the operator has to register a key with the code the server printed.
const EnrollmentTTL = time.Hour

// Errors of an enrollment.
var (
	// ErrEnrollmentExpired means the code is past its lifetime.
	ErrEnrollmentExpired = errors.New("enrollment expired")
	// ErrEnrollmentUsed means the code already registered a key.
	ErrEnrollmentUsed = errors.New("enrollment already used")
)

// Enrollment is a one-time code that lets its operator register one passkey. The code itself is
// printed once on the server and never stored; the row keeps its hash.
type Enrollment struct {
	id         passkey.ID
	operatorID ID
	codeHash   passkey.SecretHash
	createdAt  time.Time
	expiresAt  time.Time
	consumedAt time.Time
}

// NewEnrollment validates an enrollment issued now.
func NewEnrollment(id passkey.ID, operatorID ID, codeHash passkey.SecretHash, now time.Time) (*Enrollment, error) {
	switch {
	case id.IsZero():
		return nil, errors.New("new enrollment: id is required")
	case operatorID.IsZero():
		return nil, errors.New("new enrollment: operator id is required")
	case codeHash.IsZero():
		return nil, errors.New("new enrollment: code hash is required")
	case now.IsZero():
		return nil, errors.New("new enrollment: time is required")
	}

	return &Enrollment{id: id, operatorID: operatorID, codeHash: codeHash, createdAt: now, expiresAt: now.Add(EnrollmentTTL)}, nil
}

// Usable reports why the code cannot start or finish a registration now.
func (e *Enrollment) Usable(now time.Time) error {
	switch {
	case !e.consumedAt.IsZero():
		return ErrEnrollmentUsed
	case !now.Before(e.expiresAt):
		return ErrEnrollmentExpired
	}

	return nil
}

// Consume spends the code.
func (e *Enrollment) Consume(now time.Time) error {
	if err := e.Usable(now); err != nil {
		return err
	}

	e.consumedAt = now

	return nil
}

// ID returns the row identifier.
func (e *Enrollment) ID() passkey.ID {
	return e.id
}

// OperatorID returns the operator the code belongs to.
func (e *Enrollment) OperatorID() ID {
	return e.operatorID
}

// CodeHash returns the stored hash of the code.
func (e *Enrollment) CodeHash() passkey.SecretHash {
	return e.codeHash
}

// CreatedAt returns the issue time.
func (e *Enrollment) CreatedAt() time.Time {
	return e.createdAt
}

// ExpiresAt returns when the code stops working.
func (e *Enrollment) ExpiresAt() time.Time {
	return e.expiresAt
}

// ConsumedAt returns when the code was spent, or the zero time.
func (e *Enrollment) ConsumedAt() time.Time {
	return e.consumedAt
}

// EnrollmentRecord is the stored form of an enrollment.
type EnrollmentRecord struct {
	ID         passkey.ID
	OperatorID ID
	CodeHash   passkey.SecretHash
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// RestoreEnrollment rebuilds an enrollment from storage and rejects impossible ones.
func RestoreEnrollment(r EnrollmentRecord) (*Enrollment, error) {
	if r.ID.IsZero() || r.OperatorID.IsZero() || r.CodeHash.IsZero() || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, errors.New("restore enrollment: incomplete or impossible record")
	}

	return &Enrollment{id: r.ID, operatorID: r.OperatorID, codeHash: r.CodeHash, createdAt: r.CreatedAt, expiresAt: r.ExpiresAt, consumedAt: r.ConsumedAt}, nil
}

// Record returns the stored form.
func (e *Enrollment) Record() EnrollmentRecord {
	return EnrollmentRecord{ID: e.id, OperatorID: e.operatorID, CodeHash: e.codeHash, CreatedAt: e.createdAt, ExpiresAt: e.expiresAt, ConsumedAt: e.consumedAt}
}
