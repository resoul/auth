package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/passkey"
)

// Lifetimes of an operator session.
const (
	// IdleTimeout ends a session that was not used for this long.
	IdleTimeout = 30 * time.Minute
	// MaxAge is the absolute lifetime of a session, however busy.
	MaxAge = 8 * time.Hour
	// FreshFor is how long after sign-in the session may still do what needs a recent proof.
	FreshFor = 10 * time.Minute
	// TouchEvery limits how often a busy session writes its last-use time.
	TouchEvery = time.Minute
)

// Session is the sign-in of an operator in one browser. The cookie holds a secret whose hash is
// stored here, as for tickets.
type Session struct {
	id         passkey.ID
	operatorID ID
	secretHash passkey.SecretHash
	createdAt  time.Time
	lastSeenAt time.Time
	expiresAt  time.Time
	revokedAt  time.Time
}

// NewSession validates a session that starts now.
func NewSession(id passkey.ID, operatorID ID, secretHash passkey.SecretHash, now time.Time) (*Session, error) {
	switch {
	case id.IsZero():
		return nil, errors.New("new operator session: id is required")
	case operatorID.IsZero():
		return nil, errors.New("new operator session: operator id is required")
	case secretHash.IsZero():
		return nil, errors.New("new operator session: secret hash is required")
	case now.IsZero():
		return nil, errors.New("new operator session: time is required")
	}

	return &Session{id: id, operatorID: operatorID, secretHash: secretHash, createdAt: now, lastSeenAt: now, expiresAt: now.Add(MaxAge)}, nil
}

// Active reports whether the session may be used at now: not revoked, not past its absolute
// lifetime and not idle for too long.
func (s *Session) Active(now time.Time) bool {
	return s.revokedAt.IsZero() && now.Before(s.expiresAt) && now.Before(s.lastSeenAt.Add(IdleTimeout))
}

// Fresh reports whether the sign-in is recent enough for an operation that needs one.
func (s *Session) Fresh(now time.Time) bool { return now.Before(s.createdAt.Add(FreshFor)) }

// Touch records a use and reports whether the session changed and must be saved.
func (s *Session) Touch(now time.Time) bool {
	if now.Sub(s.lastSeenAt) < TouchEvery {
		return false
	}

	s.lastSeenAt = now

	return true
}

// Revoke ends the session. It keeps the first time.
func (s *Session) Revoke(now time.Time) {
	if s.revokedAt.IsZero() {
		s.revokedAt = now
	}
}

// ID returns the row identifier.
func (s *Session) ID() passkey.ID { return s.id }

// OperatorID returns the owner.
func (s *Session) OperatorID() ID { return s.operatorID }

// SecretHash returns the stored hash of the cookie secret.
func (s *Session) SecretHash() passkey.SecretHash { return s.secretHash }

// CreatedAt returns the sign-in time.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// LastSeenAt returns the last recorded use.
func (s *Session) LastSeenAt() time.Time { return s.lastSeenAt }

// ExpiresAt returns the absolute end of the session.
func (s *Session) ExpiresAt() time.Time { return s.expiresAt }

// RevokedAt returns when the session was revoked, or the zero time.
func (s *Session) RevokedAt() time.Time { return s.revokedAt }

// SessionRecord is the stored form of a session.
type SessionRecord struct {
	ID         passkey.ID
	OperatorID ID
	SecretHash passkey.SecretHash
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

// RestoreSession rebuilds a session from storage and rejects impossible ones.
func RestoreSession(r SessionRecord) (*Session, error) {
	if r.ID.IsZero() || r.OperatorID.IsZero() || r.SecretHash.IsZero() || r.CreatedAt.IsZero() ||
		r.LastSeenAt.Before(r.CreatedAt) || !r.ExpiresAt.After(r.CreatedAt) {
		return nil, errors.New("restore operator session: incomplete or impossible record")
	}

	return &Session{id: r.ID, operatorID: r.OperatorID, secretHash: r.SecretHash, createdAt: r.CreatedAt, lastSeenAt: r.LastSeenAt, expiresAt: r.ExpiresAt, revokedAt: r.RevokedAt}, nil
}

// Record returns the stored form.
func (s *Session) Record() SessionRecord {
	return SessionRecord{ID: s.id, OperatorID: s.operatorID, SecretHash: s.secretHash, CreatedAt: s.createdAt, LastSeenAt: s.lastSeenAt, ExpiresAt: s.expiresAt, RevokedAt: s.revokedAt}
}

// CSRFToken derives the token a page must send in X-CSRF-Token from the session secret. It is
// shown only to a caller that holds the cookie, so another origin can neither read nor guess it.
func CSRFToken(secret string) string {
	sum := sha256.Sum256([]byte("airlance-auth-admin-csrf\x00" + secret))
	return hex.EncodeToString(sum[:])
}
