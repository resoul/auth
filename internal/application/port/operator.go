package port

import (
	"context"
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
)

// ErrOperatorExists reports an operator with the address that is already registered.
var ErrOperatorExists = errors.New("operator already exists")

// OperatorIDGenerator creates operator identifiers (UUIDv4).
type OperatorIDGenerator interface {
	NewOperatorID() (operator.ID, error)
}

// OperatorRepository stores operators, the codes that enroll their keys and the keys themselves.
// Credentials are the same records users have; their owner is the operator's Owner and they live in
// separate tables, so a User's key never signs an operator in.
type OperatorRepository interface {
	// Create stores an operator. It returns ErrOperatorExists when the address is taken.
	Create(ctx context.Context, o *operator.Operator) error
	// Get loads an operator without locking it. It returns ErrNotFound.
	Get(ctx context.Context, id operator.ID) (*operator.Operator, error)
	// GetForUpdate loads an operator and keeps it locked until the transaction ends, so that changes of its keys run
	// one after the other. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id operator.ID) (*operator.Operator, error)
	// FindByEmail loads the operator with the address. It returns ErrNotFound.
	FindByEmail(ctx context.Context, email identity.Email) (*operator.Operator, error)
	// List returns every operator, oldest first.
	List(ctx context.Context) ([]*operator.Operator, error)
	// Save writes the disabled state of an operator.
	Save(ctx context.Context, o *operator.Operator) error

	// CreateEnrollment stores a code. It returns ErrTicketConflict when the hash exists.
	CreateEnrollment(ctx context.Context, e *operator.Enrollment) error
	// GetEnrollmentByHashForUpdate loads the enrollment of a presented code and keeps it locked
	// until the transaction ends. It returns ErrNotFound.
	GetEnrollmentByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*operator.Enrollment, error)
	// GetEnrollmentForUpdate loads an enrollment by ID and keeps it locked. It returns ErrNotFound.
	GetEnrollmentForUpdate(ctx context.Context, id passkey.ID) (*operator.Enrollment, error)
	// SaveEnrollment writes the changed state of an enrollment loaded for update.
	SaveEnrollment(ctx context.Context, e *operator.Enrollment) error

	// CreateCredential stores a key. It returns ErrCredentialConflict when the credential ID exists, and the transaction
	// stays usable, so that the refusal can still be committed.
	CreateCredential(ctx context.Context, c *passkey.Credential) error
	// ListCredentials returns the keys of an operator, oldest first.
	ListCredentials(ctx context.Context, id operator.ID) ([]*passkey.Credential, error)
	// GetCredentialForUpdate loads a key by its WebAuthn credential ID and keeps it locked until
	// the transaction ends. It returns ErrNotFound.
	GetCredentialForUpdate(ctx context.Context, credentialID []byte) (*passkey.Credential, error)
	// SaveCredential writes the changed state of a key loaded by GetCredentialForUpdate.
	SaveCredential(ctx context.Context, c *passkey.Credential) error
}

// OperatorSessionRepository stores operator sessions.
type OperatorSessionRepository interface {
	// Create stores a session. It returns ErrTicketConflict when the secret hash exists.
	Create(ctx context.Context, s *operator.Session) error
	// GetByHashForUpdate loads the session of a presented secret and keeps it locked until the
	// transaction ends. It returns ErrNotFound.
	GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*operator.Session, error)
	// GetForUpdate loads a session by ID and keeps it locked. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id passkey.ID) (*operator.Session, error)
	// Save writes the changed state of a session loaded for update.
	Save(ctx context.Context, s *operator.Session) error
	// RevokeAllForOperator revokes every session of the operator that is not revoked yet.
	RevokeAllForOperator(ctx context.Context, id operator.ID, now time.Time) error
}

// UserQuery selects the users an operator lists: those whose address starts with EmailPrefix, in
// address order, after the address After, at most Limit of them. A zero After starts from the beginning.
type UserQuery struct {
	EmailPrefix string
	After       string
	Limit       int
}

// AuditQuery selects audit entries, newest first. A zero field does not filter. Before is a cursor
// taken from the last entry of the previous page.
type AuditQuery struct {
	UserID     identity.UserID
	OperatorID operator.ID
	Type       AuditType
	Before     AuditCursor
	Limit      int
}

// AuditCursor positions a page after an entry: entries are ordered by time and then by ID, newest first.
type AuditCursor struct {
	At time.Time
	ID string
}

// IsZero reports whether the cursor starts from the newest entry.
func (c AuditCursor) IsZero() bool {
	return c.At.IsZero()
}

// AuditEntry is a stored event with the identifier that orders it.
type AuditEntry struct {
	ID string
	AuditEvent
}

// AuditReader reads the audit log for the admin API.
type AuditReader interface {
	// List returns the entries that match the query, newest first.
	List(ctx context.Context, q AuditQuery) ([]AuditEntry, error)
}
