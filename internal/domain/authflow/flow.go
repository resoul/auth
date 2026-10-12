package authflow

import (
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// Flow is one email proof procedure. Fields change only through its operations.
type Flow struct {
	id                 FlowID
	email              identity.Email
	purpose            Purpose
	generation         uint64
	salt               []byte
	keyID              string
	bindingHash        identity.BindingHash
	state              State
	createdAt          time.Time
	expiresAt          time.Time
	attempts           int
	resendAfter        time.Time
	quotaClass         QuotaClass
	recognizedClientID identity.RecognizedClientID
	userID             identity.UserID
}

// Record is the stored form of a Flow, used by adapters to rebuild it.
type Record struct {
	ID                 FlowID
	Email              identity.Email
	Purpose            Purpose
	Generation         uint64
	Salt               []byte
	KeyID              string
	BindingHash        identity.BindingHash
	State              State
	CreatedAt          time.Time
	ExpiresAt          time.Time
	Attempts           int
	ResendAfter        time.Time
	QuotaClass         QuotaClass
	RecognizedClientID identity.RecognizedClientID
	// UserID is the account a change_email flow acts for; it is zero for every other purpose.
	UserID identity.UserID
}

// Restore rebuilds a Flow from storage. It rejects records that no sequence of
// operations could have produced.
func Restore(r Record) (*Flow, error) {
	f := &Flow{
		id: r.ID, email: r.Email, purpose: r.Purpose, generation: r.Generation,
		salt: append([]byte(nil), r.Salt...), keyID: r.KeyID, bindingHash: r.BindingHash,
		state: r.State, createdAt: r.CreatedAt, expiresAt: r.ExpiresAt, attempts: r.Attempts,
		resendAfter: r.ResendAfter, quotaClass: r.QuotaClass, recognizedClientID: r.RecognizedClientID,
		userID: r.UserID,
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("restore flow: %w", err)
	}
	return f, nil
}

func (f *Flow) validate() error {
	switch {
	case f.id.IsZero():
		return errors.New("id is required")
	case f.email.IsZero():
		return errors.New("email is required")
	case !f.purpose.valid():
		return errors.New("unknown purpose")
	case f.generation == 0:
		return errors.New("generation starts at 1")
	case f.keyID == "":
		return errors.New("key id is required")
	case f.bindingHash.IsZero():
		return errors.New("binding hash is required")
	case !f.state.valid():
		return errors.New("unknown state")
	case f.createdAt.IsZero() || !f.expiresAt.After(f.createdAt) || f.resendAfter.IsZero():
		return errors.New("invalid times")
	case f.attempts < 0:
		return errors.New("negative attempts")
	case !f.quotaClass.valid():
		return errors.New("unknown quota class")
	case (f.quotaClass == QuotaRecognized) == f.recognizedClientID.IsZero():
		return errors.New("recognized client is required exactly for the recognized quota class")
	case (f.purpose == PurposeChangeEmail) == f.userID.IsZero():
		return errors.New("a user is required exactly for the change_email purpose")
	case f.state == StatePending && len(f.salt) != SaltLength:
		return errors.New("pending flow needs a salt")
	case f.state != StatePending && len(f.salt) != 0:
		return errors.New("closed flow must not keep a salt")
	}
	return nil
}

// Record returns the stored form of the Flow.
func (f *Flow) Record() Record {
	return Record{
		ID: f.id, Email: f.email, Purpose: f.purpose, Generation: f.generation,
		Salt: append([]byte(nil), f.salt...), KeyID: f.keyID, BindingHash: f.bindingHash,
		State: f.state, CreatedAt: f.createdAt, ExpiresAt: f.expiresAt, Attempts: f.attempts,
		ResendAfter: f.resendAfter, QuotaClass: f.quotaClass, RecognizedClientID: f.recognizedClientID,
		UserID: f.userID,
	}
}

// ID returns the flow identifier.
func (f *Flow) ID() FlowID { return f.id }

// Email returns the delivery address fixed at start.
func (f *Flow) Email() identity.Email { return f.email }

// Purpose returns what the flow proves.
func (f *Flow) Purpose() Purpose { return f.purpose }

// Generation returns the current code generation, starting at 1.
func (f *Flow) Generation() uint64 { return f.generation }

// Salt returns a copy of the current OTP salt; it is empty once the flow is closed.
func (f *Flow) Salt() []byte { return append([]byte(nil), f.salt...) }

// KeyID returns the OTP key ID recorded for the current generation.
func (f *Flow) KeyID() string { return f.keyID }

// BindingHash returns the hash of the client binding the flow was started with.
func (f *Flow) BindingHash() identity.BindingHash { return f.bindingHash }

// State returns the lifecycle state.
func (f *Flow) State() State { return f.state }

// CreatedAt returns when the flow started.
func (f *Flow) CreatedAt() time.Time { return f.createdAt }

// ExpiresAt returns when the flow stops accepting proofs. Resend does not move it.
func (f *Flow) ExpiresAt() time.Time { return f.expiresAt }

// Attempts returns the number of reserved verification attempts.
func (f *Flow) Attempts() int { return f.attempts }

// ResendAfter returns the earliest time of the next resend.
func (f *Flow) ResendAfter() time.Time { return f.resendAfter }

// QuotaClass returns the quota class chosen at start.
func (f *Flow) QuotaClass() QuotaClass { return f.quotaClass }

// RecognizedClientID returns the recognized client reference; it is zero for the unknown class.
func (f *Flow) RecognizedClientID() identity.RecognizedClientID { return f.recognizedClientID }

// UserID returns the account of a change_email flow; it is zero for every other purpose.
func (f *Flow) UserID() identity.UserID { return f.userID }

// CanDeliver reports whether a mail job for the given generation still matters:
// the flow is pending, the generation is the current one and the lifetime has not
// ended. A job that fails the check ends without sending anything.
func (f *Flow) CanDeliver(generation uint64, now time.Time) bool {
	return f.state == StatePending && f.generation == generation && now.Before(f.expiresAt)
}

// ExpireIfDue moves a pending flow past its lifetime to expired and clears its salt.
// It reports whether the state changed.
func (f *Flow) ExpireIfDue(now time.Time) bool {
	if f.state != StatePending || now.Before(f.expiresAt) {
		return false
	}
	f.close(StateExpired)
	return true
}

func (f *Flow) close(state State) {
	f.state = state
	f.salt = nil
}

// checkOpen returns the denial that applies before any request-specific check.
func (f *Flow) checkOpen(now time.Time) error {
	if f.state != StatePending {
		return ErrClosed
	}
	if f.ExpireIfDue(now) {
		return ErrExpired
	}
	return nil
}

// checkCaller verifies purpose and binding in constant time.
func (f *Flow) checkCaller(purpose Purpose, binding identity.BindingHash) error {
	if purpose != f.purpose {
		return ErrPurposeMismatch
	}
	if !f.bindingHash.Equal(binding) {
		return ErrBindingMismatch
	}
	return nil
}
