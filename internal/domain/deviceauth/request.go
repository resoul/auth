package deviceauth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

// Limits of a request.
const (
	// TTL is how long a request may be approved and redeemed, from the moment it is made.
	TTL = 5 * time.Minute
	// MaxAttempts is how many wrong pairing codes kill a request.
	MaxAttempts = 3
	// PairingCodeLength is the number of digits the new device shows and the approving device types.
	PairingCodeLength = 6
	requestIDBytes    = 16
)

// Errors of a request. Transports map every one of them to the same refusal.
var (
	// ErrExpired means the request is past its lifetime.
	ErrExpired = errors.New("device request expired")
	// ErrNotPending means the request was already approved, denied, redeemed or killed.
	ErrNotPending = errors.New("device request is not pending")
	// ErrWrongCode means the typed pairing code is not the one the new device shows.
	ErrWrongCode = errors.New("wrong pairing code")
	// ErrAttemptsExhausted means the wrong code was the last one allowed: the request is dead.
	ErrAttemptsExhausted = errors.New("pairing attempts exhausted")
	// ErrNotApproved means the request has not been approved, or was approved and already redeemed.
	ErrNotApproved = errors.New("device request is not approved")
	// ErrMismatch means the poll secret or the client binding is not the one the request was made with.
	ErrMismatch = errors.New("device request does not match")
)

// RequestID identifies a request: 16 random bytes in unpadded base64url. It is what a QR code carries and it
// proves nothing by itself: redeeming needs the poll secret the new device keeps.
type RequestID struct{ value string }

// ParseRequestID validates the textual form.
func ParseRequestID(s string) (RequestID, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != requestIDBytes || base64.RawURLEncoding.EncodeToString(raw) != s {
		return RequestID{}, errors.New("invalid device request id")
	}

	return RequestID{value: s}, nil
}

// NewRequestID encodes 16 random bytes. The caller provides cryptographic randomness.
func NewRequestID(random [requestIDBytes]byte) RequestID {
	return RequestID{value: base64.RawURLEncoding.EncodeToString(random[:])}
}

// String returns the textual form.
func (id RequestID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id RequestID) IsZero() bool { return id.value == "" }

// State is the lifecycle state of a request. Expiry is not a state: it is a time, checked at use.
type State string

// States.
const (
	StatePending  State = "pending"
	StateApproved State = "approved"
	StateDenied   State = "denied"
	StateRedeemed State = "redeemed"
)

func (s State) valid() bool {
	switch s {
	case StatePending, StateApproved, StateDenied, StateRedeemed:
		return true
	}

	return false
}

var pairingCode = regexp.MustCompile(`^[0-9]{6}$`)

// ValidPairingCode reports whether s has the shape of a pairing code.
func ValidPairingCode(s string) bool { return pairingCode.MatchString(s) }

// Request is a new device asking for a session. It starts pending; a signed-in device approves it by proving a
// passkey and typing the pairing code the new device shows; the new device then redeems it once.
type Request struct {
	id         RequestID
	pollHash   passkey.SecretHash
	binding    identity.BindingHash
	deviceName string
	code       string
	state      State
	attempts   int
	userID     identity.UserID
	sessionID  session.ID
	createdAt  time.Time
	expiresAt  time.Time
	decidedAt  time.Time
	redeemedAt time.Time
}

// NewParams are the fields of a request just made.
type NewParams struct {
	ID          RequestID
	PollHash    passkey.SecretHash
	Binding     identity.BindingHash
	DeviceName  string
	PairingCode string
}

// New validates a request that starts now.
func New(p NewParams, now time.Time) (*Request, error) {
	r := &Request{
		id: p.ID, pollHash: p.PollHash, binding: p.Binding, deviceName: p.DeviceName, code: p.PairingCode,
		state: StatePending, createdAt: now, expiresAt: now.Add(TTL),
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("new device request: %w", err)
	}

	return r, nil
}

func (r *Request) validate() error {
	switch {
	case r.id.IsZero():
		return errors.New("id is required")
	case r.pollHash.IsZero():
		return errors.New("poll secret hash is required")
	case r.binding.IsZero():
		return errors.New("client binding is required")
	case !session.ValidDeviceName(r.deviceName):
		return errors.New("invalid device name")
	case !pairingCode.MatchString(r.code):
		return errors.New("invalid pairing code")
	case !r.state.valid():
		return errors.New("unknown state")
	case r.attempts < 0 || r.attempts > MaxAttempts:
		return errors.New("attempts out of range")
	case r.createdAt.IsZero() || !r.expiresAt.After(r.createdAt):
		return errors.New("invalid lifetime")
	}

	approved := r.state == StateApproved || r.state == StateRedeemed
	if approved && (r.userID.IsZero() || r.decidedAt.IsZero()) {
		return errors.New("an approved request needs its approver and time")
	}

	if !approved && !r.userID.IsZero() {
		return errors.New("only an approved request has an approver")
	}

	if (r.state == StateRedeemed) != !r.redeemedAt.IsZero() {
		return errors.New("a request is redeemed exactly when it has a redemption time")
	}

	return nil
}

// Live reports whether the request may still be approved or redeemed at now.
func (r *Request) Live(now time.Time) bool { return now.Before(r.expiresAt) }

// Approve records that the user of a signed-in session approved the request after proving a passkey. The typed
// code must be the one the new device shows. A wrong code spends one of MaxAttempts and, on the last, kills the
// request; the request is changed then and must be saved.
func (r *Request) Approve(now time.Time, userID identity.UserID, sessionID session.ID, typedCode string) error {
	switch {
	case userID.IsZero() || sessionID.IsZero():
		return errors.New("approve device request: the approver is required")
	case !r.Live(now):
		return ErrExpired
	case r.state != StatePending:
		return ErrNotPending
	}

	if subtle.ConstantTimeCompare([]byte(typedCode), []byte(r.code)) != 1 {
		r.attempts++
		if r.attempts >= MaxAttempts {
			r.state, r.decidedAt = StateDenied, now
			return ErrAttemptsExhausted
		}

		return ErrWrongCode
	}

	r.state, r.userID, r.sessionID, r.decidedAt = StateApproved, userID, sessionID, now

	return nil
}

// Deny ends a pending request the person on the approving device refused.
func (r *Request) Deny(now time.Time) error {
	switch {
	case !r.Live(now):
		return ErrExpired
	case r.state != StatePending:
		return ErrNotPending
	}

	r.state, r.decidedAt = StateDenied, now

	return nil
}

// Redeem lets the device that made the request take its session, once. The poll secret hash and the client
// binding must be the ones the request was made with.
func (r *Request) Redeem(now time.Time, pollHash passkey.SecretHash, binding identity.BindingHash) error {
	if pollHash.IsZero() || r.pollHash != pollHash || !r.binding.Equal(binding) {
		return ErrMismatch
	}

	switch {
	case !r.Live(now):
		return ErrExpired
	case r.state != StateApproved:
		return ErrNotApproved
	}

	r.state, r.redeemedAt = StateRedeemed, now

	return nil
}

// Matches reports whether the poll secret hash and the binding are the ones the request was made with.
func (r *Request) Matches(pollHash passkey.SecretHash, binding identity.BindingHash) bool {
	return !pollHash.IsZero() && r.pollHash == pollHash && r.binding.Equal(binding)
}

// ID returns the identifier.
func (r *Request) ID() RequestID { return r.id }

// State returns the lifecycle state.
func (r *Request) State() State { return r.state }

// Binding returns the client binding the request was made with, which the session inherits.
func (r *Request) Binding() identity.BindingHash { return r.binding }

// DeviceName returns the label the new device gave itself.
func (r *Request) DeviceName() string { return r.deviceName }

// PairingCode returns the code the new device shows; it is never sent to the approving device.
func (r *Request) PairingCode() string { return r.code }

// Attempts returns the wrong codes typed so far.
func (r *Request) Attempts() int { return r.attempts }

// UserID returns the approver, or the zero value before approval.
func (r *Request) UserID() identity.UserID { return r.userID }

// ApproverSessionID returns the session that approved, or the zero value.
func (r *Request) ApproverSessionID() session.ID { return r.sessionID }

// CreatedAt returns the time of the request.
func (r *Request) CreatedAt() time.Time { return r.createdAt }

// ExpiresAt returns when the request stops being approvable and redeemable.
func (r *Request) ExpiresAt() time.Time { return r.expiresAt }

// Record is the stored form of a request. UserID and SessionID are zero until approval; DecidedAt and
// RedeemedAt are the zero time until then.
type Record struct {
	ID         RequestID
	PollHash   passkey.SecretHash
	Binding    identity.BindingHash
	DeviceName string
	Code       string
	State      State
	Attempts   int
	UserID     identity.UserID
	SessionID  session.ID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DecidedAt  time.Time
	RedeemedAt time.Time
}

// Restore rebuilds a request from storage and rejects impossible ones.
func Restore(rec Record) (*Request, error) {
	r := &Request{
		id: rec.ID, pollHash: rec.PollHash, binding: rec.Binding, deviceName: rec.DeviceName, code: rec.Code,
		state: rec.State, attempts: rec.Attempts, userID: rec.UserID, sessionID: rec.SessionID,
		createdAt: rec.CreatedAt, expiresAt: rec.ExpiresAt, decidedAt: rec.DecidedAt, redeemedAt: rec.RedeemedAt,
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("restore device request: %w", err)
	}

	return r, nil
}

// Record returns the stored form.
func (r *Request) Record() Record {
	return Record{
		ID: r.id, PollHash: r.pollHash, Binding: r.binding, DeviceName: r.deviceName, Code: r.code, State: r.state,
		Attempts: r.attempts, UserID: r.userID, SessionID: r.sessionID, CreatedAt: r.createdAt, ExpiresAt: r.expiresAt,
		DecidedAt: r.decidedAt, RedeemedAt: r.redeemedAt,
	}
}
