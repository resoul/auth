package passkey

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
)

// ChallengeTTL is how long a WebAuthn ceremony may take.
const ChallengeTTL = 5 * time.Minute

// Errors of a challenge.
var (
	// ErrChallengeExpired means the ceremony took too long.
	ErrChallengeExpired = errors.New("challenge expired")
	// ErrChallengeUsed means the challenge was already consumed.
	ErrChallengeUsed = errors.New("challenge already used")
	// ErrChallengePurpose means the challenge was made for another ceremony.
	ErrChallengePurpose = errors.New("challenge purpose mismatch")
)

// ChallengePurpose is the ceremony a challenge belongs to; purposes are not interchangeable.
type ChallengePurpose string

// Challenge purposes.
const (
	// ChallengeRegistration creates a credential.
	ChallengeRegistration ChallengePurpose = "registration"
	// ChallengeLogin signs in; the User may be unknown until the assertion names the credential.
	ChallengeLogin ChallengePurpose = "login"
	// ChallengeStepUp proves a fresh strong factor for one operation of a signed-in session.
	ChallengeStepUp ChallengePurpose = "step_up"
)

func (p ChallengePurpose) valid() bool {
	switch p {
	case ChallengeRegistration, ChallengeLogin, ChallengeStepUp:
		return true
	}

	return false
}

// MaxChallengeDataLength bounds the stored ceremony state.
const MaxChallengeDataLength = 8 << 10

// Challenge is the server-side state of one WebAuthn ceremony. It is single use.
type Challenge struct {
	id         ID
	purpose    ChallengePurpose
	userID     identity.UserID
	ticketID   ID
	sessionID  session.ID
	operation  Operation
	data       []byte
	createdAt  time.Time
	expiresAt  time.Time
	consumedAt time.Time
}

// NewChallengeParams are the fields of a challenge just issued. UserID is zero for a login
// that names no User; TicketID is zero unless a ticket authorizes the ceremony. A step-up
// challenge names the session and the operation it proves a fresh factor for.
type NewChallengeParams struct {
	ID        ID
	Purpose   ChallengePurpose
	UserID    identity.UserID
	TicketID  ID
	SessionID session.ID
	Operation Operation
	// Data is the opaque ceremony state of the WebAuthn library, including the challenge.
	Data []byte
	Now  time.Time
}

// NewChallenge validates and stores the state of a ceremony that starts now.
func NewChallenge(p NewChallengeParams) (*Challenge, error) {
	c := &Challenge{
		id: p.ID, purpose: p.Purpose, userID: p.UserID, ticketID: p.TicketID, sessionID: p.SessionID, operation: p.Operation,
		data: slices.Clone(p.Data), createdAt: p.Now, expiresAt: p.Now.Add(ChallengeTTL),
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("new challenge: %w", err)
	}

	return c, nil
}

func (c *Challenge) validate() error {
	switch {
	case c.id.IsZero():
		return errors.New("id is required")
	case !c.purpose.valid():
		return errors.New("unknown purpose")
	case c.purpose != ChallengeLogin && c.userID.IsZero():
		return errors.New("user id is required")
	case c.purpose == ChallengeStepUp && (c.sessionID.IsZero() || !c.operation.Valid()):
		return errors.New("a step-up challenge needs a session and a known operation")
	case c.purpose != ChallengeStepUp && (!c.sessionID.IsZero() || c.operation != ""):
		return errors.New("only a step-up challenge has a session and an operation")
	case len(c.data) == 0 || len(c.data) > MaxChallengeDataLength:
		return errors.New("ceremony data length is out of range")
	case c.createdAt.IsZero():
		return errors.New("creation time is required")
	case !c.expiresAt.After(c.createdAt):
		return errors.New("expiry must be after creation")
	}

	return nil
}

// Consume uses the challenge once for a ceremony of the given purpose.
func (c *Challenge) Consume(now time.Time, purpose ChallengePurpose) error {
	switch {
	case c.purpose != purpose:
		return ErrChallengePurpose
	case !c.consumedAt.IsZero():
		return ErrChallengeUsed
	case !now.Before(c.expiresAt):
		return ErrChallengeExpired
	}

	c.consumedAt = now

	return nil
}

// ChallengeRecord is the stored form of a challenge. UserID and TicketID may be zero;
// ConsumedAt is the zero time until the challenge is used.
type ChallengeRecord struct {
	ID         ID
	Purpose    ChallengePurpose
	UserID     identity.UserID
	TicketID   ID
	SessionID  session.ID
	Operation  Operation
	Data       []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// RestoreChallenge rebuilds a challenge from storage and rejects impossible ones.
func RestoreChallenge(r ChallengeRecord) (*Challenge, error) {
	c := &Challenge{
		id: r.ID, purpose: r.Purpose, userID: r.UserID, ticketID: r.TicketID, sessionID: r.SessionID, operation: r.Operation,
		data: slices.Clone(r.Data), createdAt: r.CreatedAt, expiresAt: r.ExpiresAt, consumedAt: r.ConsumedAt,
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("restore challenge: %w", err)
	}

	return c, nil
}

// Record returns the stored form.
func (c *Challenge) Record() ChallengeRecord {
	return ChallengeRecord{
		ID: c.id, Purpose: c.purpose, UserID: c.userID, TicketID: c.ticketID, SessionID: c.sessionID, Operation: c.operation,
		Data:      slices.Clone(c.data),
		CreatedAt: c.createdAt, ExpiresAt: c.expiresAt, ConsumedAt: c.consumedAt,
	}
}

// ID returns the row identifier, which the client sends back with the ceremony result.
func (c *Challenge) ID() ID { return c.id }

// Purpose returns the ceremony.
func (c *Challenge) Purpose() ChallengePurpose { return c.purpose }

// UserID returns the User the ceremony is for, or the zero value.
func (c *Challenge) UserID() identity.UserID { return c.userID }

// TicketID returns the ticket that authorized the ceremony, or the zero value.
func (c *Challenge) TicketID() ID { return c.ticketID }

// SessionID returns the session of a step-up challenge, or the zero value.
func (c *Challenge) SessionID() session.ID { return c.sessionID }

// Operation returns the operation of a step-up challenge, or "".
func (c *Challenge) Operation() Operation { return c.operation }

// Data returns the ceremony state.
func (c *Challenge) Data() []byte { return slices.Clone(c.data) }

// ExpiresAt returns when the challenge stops being accepted.
func (c *Challenge) ExpiresAt() time.Time { return c.expiresAt }

// ConsumedAt returns when the challenge was used, or the zero time.
func (c *Challenge) ConsumedAt() time.Time { return c.consumedAt }
