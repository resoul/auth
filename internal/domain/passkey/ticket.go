package passkey

import (
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
)

// SecretHashLength is the size of the stored hash of a ticket secret (SHA-256).
const SecretHashLength = 32

// SecretHash is the stored SHA-256 hash of a high-entropy secret. The secret itself
// is never stored.
type SecretHash struct {
	value [SecretHashLength]byte
	set   bool
}

// NewSecretHash wraps a hash of exactly SecretHashLength bytes.
func NewSecretHash(hash []byte) (SecretHash, error) {
	if len(hash) != SecretHashLength {
		return SecretHash{}, errors.New("secret hash must be 32 bytes")
	}

	var h SecretHash
	copy(h.value[:], hash)
	h.set = true

	return h, nil
}

// Bytes returns a copy of the hash.
func (h SecretHash) Bytes() []byte { return append([]byte(nil), h.value[:]...) }

// IsZero reports whether h is the invalid zero value.
func (h SecretHash) IsZero() bool { return !h.set }

// Lifetimes of a ticket.
const (
	// EnrollTicketTTL is how long a User has to register a passkey after proving the email.
	EnrollTicketTTL = 10 * time.Minute
	// SecondFactorTicketTTL is how long a User has to prove a key after proving the email.
	SecondFactorTicketTTL = 10 * time.Minute
	// StepUpTicketTTL is how long a fresh strong proof allows one operation.
	StepUpTicketTTL = 5 * time.Minute
)

// Errors of a ticket.
var (
	// ErrTicketExpired means the ticket is past its lifetime.
	ErrTicketExpired = errors.New("ticket expired")
	// ErrTicketUsed means the ticket was already redeemed.
	ErrTicketUsed = errors.New("ticket already used")
	// ErrTicketMismatch means the ticket belongs to another kind, client, session or operation.
	ErrTicketMismatch = errors.New("ticket mismatch")
)

// TicketKind says what a ticket allows. Kinds are not interchangeable.
type TicketKind string

// Ticket kinds.
const (
	// TicketEnroll lets a User who proved the email register a passkey and receive a session.
	TicketEnroll TicketKind = "enroll"
	// TicketSecondFactor lets a User who proved the email and owns a passkey prove it and sign in.
	TicketSecondFactor TicketKind = "second_factor"
	// TicketRecoveryEnroll lets a User who proved the email and spent a recovery code register
	// a new passkey although older ones exist. It is the only way past a lost key.
	TicketRecoveryEnroll TicketKind = "recovery_enroll"
	// TicketStepUp allows one sensitive operation of one session.
	TicketStepUp TicketKind = "step_up"
)

func (k TicketKind) valid() bool {
	switch k {
	case TicketEnroll, TicketSecondFactor, TicketRecoveryEnroll, TicketStepUp:
		return true
	}

	return false
}

func (k TicketKind) ttl() time.Duration {
	switch k {
	case TicketEnroll, TicketRecoveryEnroll:
		return EnrollTicketTTL
	case TicketSecondFactor:
		return SecondFactorTicketTTL
	}

	return StepUpTicketTTL
}

// Operation is a sensitive operation a step-up ticket allows.
type Operation string

// Operations that need a step-up.
const (
	OperationAddPasskey      Operation = "add_passkey"
	OperationDeletePasskey   Operation = "delete_passkey"
	OperationChangeEmail     Operation = "change_email"
	OperationRegenerateCodes Operation = "regenerate_recovery_codes"
	OperationDeleteAccount   Operation = "delete_account"
	// OperationApproveDevice lets another device sign in as the user.
	OperationApproveDevice Operation = "approve_device"
)

// Valid reports whether o is an operation that needs a step-up.
func (o Operation) Valid() bool {
	switch o {
	case OperationAddPasskey, OperationDeletePasskey, OperationChangeEmail, OperationRegenerateCodes, OperationDeleteAccount, OperationApproveDevice:
		return true
	}

	return false
}

// Ticket carries one sign-in or one operation between two requests. The client holds the
// secret; the server keeps its hash. It is single use.
type Ticket struct {
	id         ID
	kind       TicketKind
	userID     identity.UserID
	sessionID  session.ID
	operation  Operation
	binding    identity.BindingHash
	secretHash SecretHash
	createdAt  time.Time
	expiresAt  time.Time
	consumedAt time.Time
}

// NewTicketParams are the fields of a ticket just issued. Enroll and second-factor tickets
// are bound to the client binding of the verified flow; a step-up ticket is bound to a
// session and an operation.
type NewTicketParams struct {
	ID         ID
	Kind       TicketKind
	UserID     identity.UserID
	SessionID  session.ID
	Operation  Operation
	Binding    identity.BindingHash
	SecretHash SecretHash
	Now        time.Time
}

// NewTicket validates a ticket that starts now.
func NewTicket(p NewTicketParams) (*Ticket, error) {
	t := &Ticket{
		id: p.ID, kind: p.Kind, userID: p.UserID, sessionID: p.SessionID, operation: p.Operation,
		binding: p.Binding, secretHash: p.SecretHash, createdAt: p.Now,
	}
	if t.kind.valid() {
		t.expiresAt = p.Now.Add(t.kind.ttl())
	}

	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("new ticket: %w", err)
	}

	return t, nil
}

func (t *Ticket) validate() error {
	switch {
	case t.id.IsZero():
		return errors.New("id is required")
	case !t.kind.valid():
		return errors.New("unknown kind")
	case t.userID.IsZero():
		return errors.New("user id is required")
	case t.secretHash.IsZero():
		return errors.New("secret hash is required")
	case t.createdAt.IsZero():
		return errors.New("creation time is required")
	case !t.expiresAt.After(t.createdAt):
		return errors.New("expiry must be after creation")
	}

	if t.kind == TicketStepUp {
		if t.sessionID.IsZero() || !t.operation.Valid() {
			return errors.New("a step-up ticket needs a session and a known operation")
		}

		return nil
	}

	if t.binding.IsZero() {
		return errors.New("binding hash is required")
	}

	if !t.sessionID.IsZero() || t.operation != "" {
		return errors.New("only a step-up ticket has a session and an operation")
	}

	return nil
}

// Presented is what the caller proves about itself when it offers a ticket.
type Presented struct {
	Kind      TicketKind
	Binding   identity.BindingHash
	SessionID session.ID
	Operation Operation
}

// Check reports whether the ticket may be used now by the caller, without using it.
func (t *Ticket) Check(now time.Time, p Presented) error {
	switch {
	case t.kind != p.Kind:
		return ErrTicketMismatch
	case t.kind == TicketStepUp && (t.sessionID != p.SessionID || t.operation != p.Operation):
		return ErrTicketMismatch
	case t.kind != TicketStepUp && !t.binding.Equal(p.Binding):
		return ErrTicketMismatch
	case !t.consumedAt.IsZero():
		return ErrTicketUsed
	case !now.Before(t.expiresAt):
		return ErrTicketExpired
	}

	return nil
}

// Use checks the ticket and consumes it.
func (t *Ticket) Use(now time.Time, p Presented) error {
	if err := t.Check(now, p); err != nil {
		return err
	}

	t.consumedAt = now

	return nil
}

// TicketRecord is the stored form of a ticket. SessionID and Operation are zero unless
// the ticket is a step-up; Binding is zero for a step-up; ConsumedAt is the zero time
// until the ticket is used.
type TicketRecord struct {
	ID         ID
	Kind       TicketKind
	UserID     identity.UserID
	SessionID  session.ID
	Operation  Operation
	Binding    identity.BindingHash
	SecretHash SecretHash
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// RestoreTicket rebuilds a ticket from storage and rejects impossible ones.
func RestoreTicket(r TicketRecord) (*Ticket, error) {
	t := &Ticket{
		id: r.ID, kind: r.Kind, userID: r.UserID, sessionID: r.SessionID, operation: r.Operation,
		binding: r.Binding, secretHash: r.SecretHash, createdAt: r.CreatedAt, expiresAt: r.ExpiresAt,
		consumedAt: r.ConsumedAt,
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("restore ticket: %w", err)
	}

	return t, nil
}

// Record returns the stored form.
func (t *Ticket) Record() TicketRecord {
	return TicketRecord{
		ID: t.id, Kind: t.kind, UserID: t.userID, SessionID: t.sessionID, Operation: t.operation,
		Binding: t.binding, SecretHash: t.secretHash, CreatedAt: t.createdAt, ExpiresAt: t.expiresAt,
		ConsumedAt: t.consumedAt,
	}
}

// ID returns the row identifier.
func (t *Ticket) ID() ID { return t.id }

// Kind returns what the ticket allows.
func (t *Ticket) Kind() TicketKind { return t.kind }

// UserID returns the User the ticket is for.
func (t *Ticket) UserID() identity.UserID { return t.userID }

// SessionID returns the session of a step-up ticket, or the zero value.
func (t *Ticket) SessionID() session.ID { return t.sessionID }

// Operation returns the operation of a step-up ticket, or "".
func (t *Ticket) Operation() Operation { return t.operation }

// Binding returns the client binding of an enroll or second-factor ticket.
func (t *Ticket) Binding() identity.BindingHash { return t.binding }

// ExpiresAt returns when the ticket stops being accepted.
func (t *Ticket) ExpiresAt() time.Time { return t.expiresAt }

// ConsumedAt returns when the ticket was used, or the zero time.
func (t *Ticket) ConsumedAt() time.Time { return t.consumedAt }
