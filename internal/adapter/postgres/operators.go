package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
)

func operatorUUID(id operator.ID) (uuid.UUID, error) { return toUUID(id.String()) }

type operators struct{ q *sqlc.Queries }

func (r *operators) Create(ctx context.Context, o *operator.Operator) error {
	rec := o.Record()

	id, err := operatorUUID(rec.ID)
	if err != nil {
		return fmt.Errorf("create operator: %w", err)
	}

	err = r.q.CreateOperator(ctx, sqlc.CreateOperatorParams{ID: id, Email: rec.Email.String(), CreatedAt: dbTime(rec.CreatedAt), DisabledAt: dbTimePtr(rec.DisabledAt)})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "operators_email_unique" {
		return port.ErrOperatorExists
	}

	if err != nil {
		return fmt.Errorf("create operator: %w", err)
	}

	return nil
}

func (r *operators) Get(ctx context.Context, id operator.ID) (*operator.Operator, error) {
	u, err := operatorUUID(id)
	if err != nil {
		return nil, fmt.Errorf("get operator: %w", err)
	}

	row, err := r.q.GetOperatorByID(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get operator: %w", err)
	}

	return operatorFromRow(row)
}

func (r *operators) FindByEmail(ctx context.Context, email identity.Email) (*operator.Operator, error) {
	row, err := r.q.GetOperatorByEmail(ctx, email.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find operator: %w", err)
	}

	return operatorFromRow(row)
}

func (r *operators) List(ctx context.Context) ([]*operator.Operator, error) {
	rows, err := r.q.ListOperators(ctx)
	if err != nil {
		return nil, fmt.Errorf("list operators: %w", err)
	}

	out := make([]*operator.Operator, 0, len(rows))
	for _, row := range rows {
		o, err := operatorFromRow(row)
		if err != nil {
			return nil, err
		}

		out = append(out, o)
	}

	return out, nil
}

func (r *operators) Save(ctx context.Context, o *operator.Operator) error {
	id, err := operatorUUID(o.ID())
	if err != nil {
		return fmt.Errorf("save operator: %w", err)
	}

	n, err := r.q.UpdateOperator(ctx, sqlc.UpdateOperatorParams{ID: id, DisabledAt: dbTimePtr(o.DisabledAt())})
	if err != nil {
		return fmt.Errorf("save operator: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func operatorFromRow(row sqlc.Operator) (*operator.Operator, error) {
	id, err := operator.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator id: %w", err)
	}

	email, err := identity.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("stored operator email: %w", err)
	}

	return operator.Restore(operator.Record{ID: id, Email: email, CreatedAt: goTime(row.CreatedAt), DisabledAt: goTimePtr(row.DisabledAt)})
}

func (r *operators) CreateEnrollment(ctx context.Context, e *operator.Enrollment) error {
	rec := e.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create enrollment: %w", err)
	}

	op, err := operatorUUID(rec.OperatorID)
	if err != nil {
		return fmt.Errorf("create enrollment: %w", err)
	}

	err = r.q.CreateOperatorEnrollment(ctx, sqlc.CreateOperatorEnrollmentParams{
		ID: id, OperatorID: op, CodeHash: rec.CodeHash.Bytes(), CreatedAt: dbTime(rec.CreatedAt),
		ExpiresAt: dbTime(rec.ExpiresAt), ConsumedAt: dbTimePtr(rec.ConsumedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "operator_enrollments_code_hash_unique" {
		return port.ErrTicketConflict
	}

	if err != nil {
		return fmt.Errorf("create enrollment: %w", err)
	}

	return nil
}

func (r *operators) GetEnrollmentByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*operator.Enrollment, error) {
	row, err := r.q.GetOperatorEnrollmentByHashForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get enrollment: %w", err)
	}

	return enrollmentFromRow(row)
}

func (r *operators) GetEnrollmentForUpdate(ctx context.Context, id passkey.ID) (*operator.Enrollment, error) {
	u, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("get enrollment: %w", err)
	}

	row, err := r.q.GetOperatorEnrollmentForUpdate(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get enrollment: %w", err)
	}

	return enrollmentFromRow(row)
}

func (r *operators) SaveEnrollment(ctx context.Context, e *operator.Enrollment) error {
	id, err := toUUID(e.ID().String())
	if err != nil {
		return fmt.Errorf("save enrollment: %w", err)
	}

	n, err := r.q.UpdateOperatorEnrollment(ctx, sqlc.UpdateOperatorEnrollmentParams{ID: id, ConsumedAt: dbTimePtr(e.ConsumedAt())})
	if err != nil {
		return fmt.Errorf("save enrollment: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func enrollmentFromRow(row sqlc.OperatorEnrollment) (*operator.Enrollment, error) {
	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored enrollment id: %w", err)
	}

	op, err := operator.ParseID(row.OperatorID.String())
	if err != nil {
		return nil, fmt.Errorf("stored enrollment operator: %w", err)
	}

	hash, err := passkey.NewSecretHash(row.CodeHash)
	if err != nil {
		return nil, fmt.Errorf("stored enrollment code hash: %w", err)
	}

	return operator.RestoreEnrollment(operator.EnrollmentRecord{
		ID: id, OperatorID: op, CodeHash: hash, CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt), ConsumedAt: goTimePtr(row.ConsumedAt),
	})
}

func (r *operators) CreateCredential(ctx context.Context, c *passkey.Credential) error {
	rec := c.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create operator credential: %w", err)
	}

	owner, err := userUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create operator credential: %w", err)
	}

	transports := rec.Transports
	if transports == nil {
		transports = []string{}
	}

	err = r.q.CreateOperatorCredential(ctx, sqlc.CreateOperatorCredentialParams{
		ID: id, OperatorID: owner, CredentialID: rec.CredentialID, PublicKey: rec.PublicKey, Aaguid: rec.AAGUID,
		Transports: transports, SignCount: int64(rec.SignCount), BackupEligible: rec.BackupEligible,
		BackupState: rec.BackupState, Name: rec.Name, CreatedAt: dbTime(rec.CreatedAt), LastUsedAt: dbTimePtr(rec.LastUsedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "operator_credentials_credential_id_unique" {
		return port.ErrCredentialConflict
	}

	if err != nil {
		return fmt.Errorf("create operator credential: %w", err)
	}

	return nil
}

func (r *operators) ListCredentials(ctx context.Context, id operator.ID) ([]*passkey.Credential, error) {
	u, err := operatorUUID(id)
	if err != nil {
		return nil, fmt.Errorf("list operator credentials: %w", err)
	}

	rows, err := r.q.ListOperatorCredentials(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("list operator credentials: %w", err)
	}

	out := make([]*passkey.Credential, 0, len(rows))
	for _, row := range rows {
		c, err := operatorCredentialFromRow(row)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, nil
}

func (r *operators) GetCredentialForUpdate(ctx context.Context, credentialID []byte) (*passkey.Credential, error) {
	row, err := r.q.GetOperatorCredentialForUpdate(ctx, credentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get operator credential: %w", err)
	}

	return operatorCredentialFromRow(row)
}

func (r *operators) SaveCredential(ctx context.Context, c *passkey.Credential) error {
	rec := c.Record()

	n, err := r.q.UpdateOperatorCredential(ctx, sqlc.UpdateOperatorCredentialParams{
		CredentialID: rec.CredentialID, SignCount: int64(rec.SignCount), BackupState: rec.BackupState,
		Name: rec.Name, LastUsedAt: dbTimePtr(rec.LastUsedAt),
	})
	if err != nil {
		return fmt.Errorf("save operator credential: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func operatorCredentialFromRow(row sqlc.OperatorCredential) (*passkey.Credential, error) {
	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator credential id: %w", err)
	}

	owner, err := identity.ParseUserID(row.OperatorID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator credential owner: %w", err)
	}

	if row.SignCount < 0 || row.SignCount > 1<<32-1 {
		return nil, fmt.Errorf("stored operator credential sign count %d is out of range", row.SignCount)
	}

	return passkey.RestoreCredential(passkey.CredentialRecord{
		ID: id, UserID: owner, CredentialID: row.CredentialID, PublicKey: row.PublicKey, AAGUID: row.Aaguid,
		Transports: row.Transports, SignCount: uint32(row.SignCount), BackupEligible: row.BackupEligible,
		BackupState: row.BackupState, Name: row.Name, CreatedAt: goTime(row.CreatedAt), LastUsedAt: goTimePtr(row.LastUsedAt),
	})
}

// operatorChallenges stores the ceremonies of operators: a registration names its operator (as the
// owner) and its enrollment (as the ticket), a login names neither.
type operatorChallenges struct{ q *sqlc.Queries }

func (r *operatorChallenges) Create(ctx context.Context, c *passkey.Challenge) error {
	rec := c.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create operator challenge: %w", err)
	}

	owner, err := optionalUserUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create operator challenge: %w", err)
	}

	enrollment, err := optionalPasskeyUUID(rec.TicketID)
	if err != nil {
		return fmt.Errorf("create operator challenge: %w", err)
	}

	if err := r.q.CreateOperatorChallenge(ctx, sqlc.CreateOperatorChallengeParams{
		ID: id, Purpose: string(rec.Purpose), OperatorID: owner, EnrollmentID: enrollment, Data: rec.Data,
		CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt), ConsumedAt: dbTimePtr(rec.ConsumedAt),
	}); err != nil {
		return fmt.Errorf("create operator challenge: %w", err)
	}

	return nil
}

func (r *operatorChallenges) GetForUpdate(ctx context.Context, id passkey.ID) (*passkey.Challenge, error) {
	row, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("get operator challenge: %w", err)
	}

	got, err := r.q.GetOperatorChallengeForUpdate(ctx, row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get operator challenge: %w", err)
	}

	cid, err := passkey.ParseID(got.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator challenge id: %w", err)
	}

	owner, err := userFromOptional(got.OperatorID)
	if err != nil {
		return nil, fmt.Errorf("stored operator challenge owner: %w", err)
	}

	enrollment, err := passkeyFromOptional(got.EnrollmentID)
	if err != nil {
		return nil, fmt.Errorf("stored operator challenge enrollment: %w", err)
	}

	return passkey.RestoreChallenge(passkey.ChallengeRecord{
		ID: cid, Purpose: passkey.ChallengePurpose(got.Purpose), UserID: owner, TicketID: enrollment, Data: got.Data,
		CreatedAt: goTime(got.CreatedAt), ExpiresAt: goTime(got.ExpiresAt), ConsumedAt: goTimePtr(got.ConsumedAt),
	})
}

func (r *operatorChallenges) Save(ctx context.Context, c *passkey.Challenge) error {
	id, err := toUUID(c.ID().String())
	if err != nil {
		return fmt.Errorf("save operator challenge: %w", err)
	}

	n, err := r.q.UpdateOperatorChallenge(ctx, sqlc.UpdateOperatorChallengeParams{ID: id, ConsumedAt: dbTimePtr(c.ConsumedAt())})
	if err != nil {
		return fmt.Errorf("save operator challenge: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

type operatorSessions struct{ q *sqlc.Queries }

func (r *operatorSessions) Create(ctx context.Context, s *operator.Session) error {
	rec := s.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create operator session: %w", err)
	}

	op, err := operatorUUID(rec.OperatorID)
	if err != nil {
		return fmt.Errorf("create operator session: %w", err)
	}

	err = r.q.CreateOperatorSession(ctx, sqlc.CreateOperatorSessionParams{
		ID: id, OperatorID: op, SecretHash: rec.SecretHash.Bytes(), CreatedAt: dbTime(rec.CreatedAt),
		LastSeenAt: dbTime(rec.LastSeenAt), ExpiresAt: dbTime(rec.ExpiresAt), RevokedAt: dbTimePtr(rec.RevokedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "operator_sessions_secret_hash_unique" {
		return port.ErrTicketConflict
	}

	if err != nil {
		return fmt.Errorf("create operator session: %w", err)
	}

	return nil
}

func (r *operatorSessions) GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*operator.Session, error) {
	row, err := r.q.GetOperatorSessionByHashForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get operator session: %w", err)
	}

	return operatorSessionFromRow(row)
}

func (r *operatorSessions) GetForUpdate(ctx context.Context, id passkey.ID) (*operator.Session, error) {
	u, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("get operator session: %w", err)
	}

	row, err := r.q.GetOperatorSessionForUpdate(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get operator session: %w", err)
	}

	return operatorSessionFromRow(row)
}

func (r *operatorSessions) Save(ctx context.Context, s *operator.Session) error {
	id, err := toUUID(s.ID().String())
	if err != nil {
		return fmt.Errorf("save operator session: %w", err)
	}

	n, err := r.q.UpdateOperatorSession(ctx, sqlc.UpdateOperatorSessionParams{ID: id, LastSeenAt: dbTime(s.LastSeenAt()), RevokedAt: dbTimePtr(s.RevokedAt())})
	if err != nil {
		return fmt.Errorf("save operator session: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *operatorSessions) RevokeAllForOperator(ctx context.Context, id operator.ID, now time.Time) error {
	op, err := operatorUUID(id)
	if err != nil {
		return fmt.Errorf("revoke operator sessions: %w", err)
	}

	revokedAt := dbTime(now)
	if err := r.q.RevokeOperatorSessions(ctx, sqlc.RevokeOperatorSessionsParams{OperatorID: op, RevokedAt: &revokedAt}); err != nil {
		return fmt.Errorf("revoke operator sessions: %w", err)
	}

	return nil
}

func operatorSessionFromRow(row sqlc.OperatorSession) (*operator.Session, error) {
	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator session id: %w", err)
	}

	op, err := operator.ParseID(row.OperatorID.String())
	if err != nil {
		return nil, fmt.Errorf("stored operator session owner: %w", err)
	}

	hash, err := passkey.NewSecretHash(row.SecretHash)
	if err != nil {
		return nil, fmt.Errorf("stored operator session secret: %w", err)
	}

	return operator.RestoreSession(operator.SessionRecord{
		ID: id, OperatorID: op, SecretHash: hash, CreatedAt: goTime(row.CreatedAt), LastSeenAt: goTime(row.LastSeenAt),
		ExpiresAt: goTime(row.ExpiresAt), RevokedAt: goTimePtr(row.RevokedAt),
	})
}
