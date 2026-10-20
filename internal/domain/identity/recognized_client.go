package identity

import (
	"errors"
	"fmt"
	"time"
)

// RecognitionTTL is how long a recognized client stays recognized after its last
// proof of ownership.
const RecognitionTTL = 90 * 24 * time.Hour

// ErrNotActive means the record is revoked or expired and cannot be extended.
var ErrNotActive = errors.New("recognized client is not active")

// RecognizedClient is the server-side record that a client holding a binding
// secret proved ownership of an email. It earns a separate quota class; it never
// replaces the OTP.
type RecognizedClient struct {
	id         RecognizedClientID
	userID     UserID
	email      Email
	binding    BindingHash
	verifiedAt time.Time
	expiresAt  time.Time
	revokedAt  time.Time
}

// NewRecognizedClient records a successful verify at now.
func NewRecognizedClient(id RecognizedClientID, userID UserID, email Email, binding BindingHash, now time.Time) (*RecognizedClient, error) {
	c := &RecognizedClient{
		id: id, userID: userID, email: email, binding: binding,
		verifiedAt: now, expiresAt: now.Add(RecognitionTTL),
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("new recognized client: %w", err)
	}

	return c, nil
}

func (c *RecognizedClient) validate() error {
	switch {
	case c.id.IsZero():
		return errors.New("id is required")
	case c.userID.IsZero():
		return errors.New("user id is required")
	case c.email.IsZero():
		return errors.New("email is required")
	case c.binding.IsZero():
		return errors.New("binding hash is required")
	case c.verifiedAt.IsZero():
		return errors.New("verified time is required")
	case !c.expiresAt.After(c.verifiedAt):
		return errors.New("expiry must be after verification")
	}

	return nil
}

// Active reports whether the record may grant the recognized quota class at now.
func (c *RecognizedClient) Active(now time.Time) bool {
	return c.revokedAt.IsZero() && now.Before(c.expiresAt)
}

// Renew applies a successful verify: the email was just proven again, so the
// record starts a new period and a revoked or expired record becomes active.
func (c *RecognizedClient) Renew(now time.Time) {
	c.verifiedAt = now
	c.expiresAt = now.Add(RecognitionTTL)
	c.revokedAt = time.Time{}
}

// Extend applies a successful refresh. It never restores a revoked or expired
// record and never shortens the period.
func (c *RecognizedClient) Extend(now time.Time) error {
	if !c.Active(now) {
		return ErrNotActive
	}

	if next := now.Add(RecognitionTTL); next.After(c.expiresAt) {
		c.expiresAt = next
	}

	return nil
}

// Revoke ends recognition. Revoking twice keeps the first time.
func (c *RecognizedClient) Revoke(now time.Time) {
	if c.revokedAt.IsZero() {
		c.revokedAt = now
	}
}

// RecognizedClientRecord is the stored form, used by adapters to rebuild the
// record. RevokedAt is the zero time when the record was never revoked.
type RecognizedClientRecord struct {
	ID         RecognizedClientID
	UserID     UserID
	Email      Email
	Binding    BindingHash
	VerifiedAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

// RestoreRecognizedClient rebuilds a record from storage and rejects impossible ones.
func RestoreRecognizedClient(r RecognizedClientRecord) (*RecognizedClient, error) {
	c := &RecognizedClient{
		id: r.ID, userID: r.UserID, email: r.Email, binding: r.Binding,
		verifiedAt: r.VerifiedAt, expiresAt: r.ExpiresAt, revokedAt: r.RevokedAt,
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("restore recognized client: %w", err)
	}

	return c, nil
}

// Record returns the stored form.
func (c *RecognizedClient) Record() RecognizedClientRecord {
	return RecognizedClientRecord{
		ID: c.id, UserID: c.userID, Email: c.email, Binding: c.binding,
		VerifiedAt: c.verifiedAt, ExpiresAt: c.expiresAt, RevokedAt: c.revokedAt,
	}
}

// ID returns the record identifier. It survives binding secret updates.
func (c *RecognizedClient) ID() RecognizedClientID { return c.id }

// UserID returns the User that proved the email.
func (c *RecognizedClient) UserID() UserID { return c.userID }

// Email returns the confirmed address the record is valid for.
func (c *RecognizedClient) Email() Email { return c.email }

// Binding returns the hash of the client's binding secret.
func (c *RecognizedClient) Binding() BindingHash { return c.binding }

// VerifiedAt returns the time of the last successful verify.
func (c *RecognizedClient) VerifiedAt() time.Time { return c.verifiedAt }

// ExpiresAt returns when recognition ends unless extended.
func (c *RecognizedClient) ExpiresAt() time.Time { return c.expiresAt }

// RevokedAt returns the revocation time, or the zero time.
func (c *RecognizedClient) RevokedAt() time.Time { return c.revokedAt }
