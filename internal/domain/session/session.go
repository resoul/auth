package session

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"go.airlance.org/auth/internal/domain/identity"
)

// MaxDeviceNameLength is the longest device name in characters.
const MaxDeviceNameLength = 64

// ErrNotActive means the session is revoked or past one of its lifetimes.
var ErrNotActive = errors.New("session is not active")

// Policy holds the session lifetimes. DefaultPolicy has the initial values.
type Policy struct {
	// IdleTTL is how long a session lives without a refresh.
	IdleTTL time.Duration
	// AbsoluteTTL is the longest life of a session whatever its activity.
	AbsoluteTTL time.Duration
}

// DefaultPolicy returns 30 days of idle time and 90 days of total life.
func DefaultPolicy() Policy {
	return Policy{IdleTTL: 30 * 24 * time.Hour, AbsoluteTTL: 90 * 24 * time.Hour}
}

// Validate rejects lifetimes that make a session unusable.
func (p Policy) Validate() error {
	if p.IdleTTL <= 0 || p.AbsoluteTTL < p.IdleTTL {
		return errors.New("invalid session policy")
	}

	return nil
}

// Session is one signed-in device. Fields change only through its operations.
type Session struct {
	id            ID
	userID        identity.UserID
	binding       identity.BindingHash
	amr           []string
	authTime      time.Time
	deviceName    string
	createdAt     time.Time
	lastActiveAt  time.Time
	idleExpiresAt time.Time
	expiresAt     time.Time
	revokedAt     time.Time
}

// NewParams are the inputs of a new session.
type NewParams struct {
	ID      ID
	UserID  identity.UserID
	Binding identity.BindingHash
	// AMR lists the authentication methods used, for the access token claim.
	AMR []string
	// AuthTime is when the user proved ownership, normally now.
	AuthTime   time.Time
	DeviceName string
}

// New creates a session at now.
func New(p NewParams, now time.Time, policy Policy) (*Session, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	s := &Session{
		id: p.ID, userID: p.UserID, binding: p.Binding, amr: append([]string(nil), p.AMR...),
		authTime: p.AuthTime, deviceName: p.DeviceName, createdAt: now, lastActiveAt: now,
		expiresAt: now.Add(policy.AbsoluteTTL), idleExpiresAt: now.Add(policy.IdleTTL),
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	return s, nil
}

func (s *Session) validate() error {
	switch {
	case s.id.IsZero():
		return errors.New("id is required")
	case s.userID.IsZero():
		return errors.New("user id is required")
	case s.binding.IsZero():
		return errors.New("binding hash is required")
	case len(s.amr) == 0:
		return errors.New("at least one authentication method is required")
	case s.authTime.IsZero() || s.authTime.After(s.createdAt):
		return errors.New("auth time must be set and not in the future")
	case s.createdAt.IsZero() || s.lastActiveAt.Before(s.createdAt):
		return errors.New("invalid activity times")
	case !s.expiresAt.After(s.createdAt) || s.idleExpiresAt.After(s.expiresAt) || !s.idleExpiresAt.After(s.createdAt):
		return errors.New("invalid lifetimes")
	case !ValidDeviceName(s.deviceName):
		return errors.New("invalid device name")
	}

	for _, method := range s.amr {
		if method == "" {
			return errors.New("empty authentication method")
		}
	}

	return nil
}

// ValidDeviceName accepts a client-chosen label of up to MaxDeviceNameLength
// characters without control characters. The empty name is allowed.
func ValidDeviceName(name string) bool {
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxDeviceNameLength {
		return false
	}

	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}

	return true
}

// Active reports whether the session can issue tokens at now.
func (s *Session) Active(now time.Time) bool {
	return s.revokedAt.IsZero() && now.Before(s.idleExpiresAt) && now.Before(s.expiresAt)
}

// Touch records a refresh: activity moves the idle limit forward, never past the
// absolute limit.
func (s *Session) Touch(now time.Time, policy Policy) error {
	if !s.Active(now) {
		return ErrNotActive
	}

	s.lastActiveAt = now
	s.idleExpiresAt = s.RefreshExpiry(now, policy)

	return nil
}

// RefreshExpiry is the expiry of a refresh token issued at now: the idle period,
// capped by the end of the session's life.
func (s *Session) RefreshExpiry(now time.Time, policy Policy) time.Time {
	expiry := now.Add(policy.IdleTTL)
	if expiry.After(s.expiresAt) {
		return s.expiresAt
	}

	return expiry
}

// Revoke ends the session. Revoking twice keeps the first time.
func (s *Session) Revoke(now time.Time) {
	if s.revokedAt.IsZero() {
		s.revokedAt = now
	}
}

// Record is the stored form of a Session, used by adapters to rebuild it.
// RevokedAt is the zero time while the session is not revoked.
type Record struct {
	ID            ID
	UserID        identity.UserID
	Binding       identity.BindingHash
	AMR           []string
	AuthTime      time.Time
	DeviceName    string
	CreatedAt     time.Time
	LastActiveAt  time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time
}

// Restore rebuilds a Session from storage and rejects impossible records.
func Restore(r Record) (*Session, error) {
	s := &Session{
		id: r.ID, userID: r.UserID, binding: r.Binding, amr: append([]string(nil), r.AMR...),
		authTime: r.AuthTime, deviceName: r.DeviceName, createdAt: r.CreatedAt, lastActiveAt: r.LastActiveAt,
		idleExpiresAt: r.IdleExpiresAt, expiresAt: r.ExpiresAt, revokedAt: r.RevokedAt,
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("restore session: %w", err)
	}

	return s, nil
}

// Record returns the stored form.
func (s *Session) Record() Record {
	return Record{
		ID: s.id, UserID: s.userID, Binding: s.binding, AMR: append([]string(nil), s.amr...),
		AuthTime: s.authTime, DeviceName: s.deviceName, CreatedAt: s.createdAt, LastActiveAt: s.lastActiveAt,
		IdleExpiresAt: s.idleExpiresAt, ExpiresAt: s.expiresAt, RevokedAt: s.revokedAt,
	}
}

// ID returns the session identifier.
func (s *Session) ID() ID { return s.id }

// UserID returns the owner.
func (s *Session) UserID() identity.UserID { return s.userID }

// Binding returns the hash of the client binding secret the session was created with.
func (s *Session) Binding() identity.BindingHash { return s.binding }

// AMR returns a copy of the authentication methods.
func (s *Session) AMR() []string { return append([]string(nil), s.amr...) }

// AuthTime returns when the user proved ownership.
func (s *Session) AuthTime() time.Time { return s.authTime }

// DeviceName returns the client-chosen label.
func (s *Session) DeviceName() string { return s.deviceName }

// CreatedAt returns when the session started.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// LastActiveAt returns the time of the last refresh.
func (s *Session) LastActiveAt() time.Time { return s.lastActiveAt }

// IdleExpiresAt returns when the session ends without activity.
func (s *Session) IdleExpiresAt() time.Time { return s.idleExpiresAt }

// ExpiresAt returns the absolute end of the session.
func (s *Session) ExpiresAt() time.Time { return s.expiresAt }

// RevokedAt returns the revocation time, or the zero time.
func (s *Session) RevokedAt() time.Time { return s.revokedAt }
