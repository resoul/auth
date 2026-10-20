package memory

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
)

type operators struct{ tx *state }

func (r *operators) Create(_ context.Context, o *operator.Operator) error {
	for _, rec := range r.tx.operators {
		if rec.Email == o.Email() {
			return port.ErrOperatorExists
		}
	}

	r.tx.operators[o.ID().String()] = o.Record()

	return nil
}

func (r *operators) Get(_ context.Context, id operator.ID) (*operator.Operator, error) {
	rec, ok := r.tx.operators[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	return restoreOperator(rec)
}

func (r *operators) FindByEmail(_ context.Context, email identity.Email) (*operator.Operator, error) {
	for _, rec := range r.tx.operators {
		if rec.Email == email {
			return restoreOperator(rec)
		}
	}

	return nil, port.ErrNotFound
}

func (r *operators) List(_ context.Context) ([]*operator.Operator, error) {
	recs := make([]operator.Record, 0, len(r.tx.operators))
	for _, rec := range r.tx.operators {
		recs = append(recs, rec)
	}

	slices.SortFunc(recs, func(a, b operator.Record) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}

		return bytes.Compare([]byte(a.ID.String()), []byte(b.ID.String()))
	})

	out := make([]*operator.Operator, 0, len(recs))
	for _, rec := range recs {
		o, err := restoreOperator(rec)
		if err != nil {
			return nil, err
		}

		out = append(out, o)
	}

	return out, nil
}

func (r *operators) Save(_ context.Context, o *operator.Operator) error {
	if _, ok := r.tx.operators[o.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.operators[o.ID().String()] = o.Record()

	return nil
}

func restoreOperator(rec operator.Record) (*operator.Operator, error) {
	o, err := operator.Restore(rec)
	if err != nil {
		return nil, fmt.Errorf("restore operator: %w", err)
	}

	return o, nil
}

func (r *operators) CreateEnrollment(_ context.Context, e *operator.Enrollment) error {
	rec := e.Record()
	for _, other := range r.tx.operatorEnrollments {
		if other.CodeHash == rec.CodeHash {
			return port.ErrTicketConflict
		}
	}

	if _, ok := r.tx.operatorEnrollments[e.ID().String()]; ok {
		return fmt.Errorf("enrollment %s already exists", e.ID())
	}

	r.tx.operatorEnrollments[e.ID().String()] = rec

	return nil
}

func (r *operators) GetEnrollmentByHashForUpdate(_ context.Context, hash passkey.SecretHash) (*operator.Enrollment, error) {
	for _, rec := range r.tx.operatorEnrollments {
		if rec.CodeHash == hash {
			return restoreEnrollment(rec)
		}
	}

	return nil, port.ErrNotFound
}

func (r *operators) GetEnrollmentForUpdate(_ context.Context, id passkey.ID) (*operator.Enrollment, error) {
	rec, ok := r.tx.operatorEnrollments[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	return restoreEnrollment(rec)
}

func (r *operators) SaveEnrollment(_ context.Context, e *operator.Enrollment) error {
	if _, ok := r.tx.operatorEnrollments[e.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.operatorEnrollments[e.ID().String()] = e.Record()

	return nil
}

func restoreEnrollment(rec operator.EnrollmentRecord) (*operator.Enrollment, error) {
	e, err := operator.RestoreEnrollment(rec)
	if err != nil {
		return nil, fmt.Errorf("restore enrollment: %w", err)
	}

	return e, nil
}

func (r *operators) CreateCredential(_ context.Context, c *passkey.Credential) error {
	key := credentialKey(c.CredentialID())
	if _, ok := r.tx.operatorCredentials[key]; ok {
		return port.ErrCredentialConflict
	}

	r.tx.operatorCredentials[key] = c.Record()

	return nil
}

func (r *operators) ListCredentials(_ context.Context, id operator.ID) ([]*passkey.Credential, error) {
	var recs []passkey.CredentialRecord

	for _, rec := range r.tx.operatorCredentials {
		if rec.UserID == id.Owner() {
			recs = append(recs, rec)
		}
	}

	slices.SortFunc(recs, func(a, b passkey.CredentialRecord) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}

		return bytes.Compare([]byte(a.ID.String()), []byte(b.ID.String()))
	})

	out := make([]*passkey.Credential, 0, len(recs))
	for _, rec := range recs {
		c, err := passkey.RestoreCredential(rec)
		if err != nil {
			return nil, fmt.Errorf("restore credential: %w", err)
		}

		out = append(out, c)
	}

	return out, nil
}

func (r *operators) GetCredentialForUpdate(_ context.Context, credentialID []byte) (*passkey.Credential, error) {
	rec, ok := r.tx.operatorCredentials[credentialKey(credentialID)]
	if !ok {
		return nil, port.ErrNotFound
	}

	c, err := passkey.RestoreCredential(rec)
	if err != nil {
		return nil, fmt.Errorf("restore credential: %w", err)
	}

	return c, nil
}

func (r *operators) SaveCredential(_ context.Context, c *passkey.Credential) error {
	key := credentialKey(c.CredentialID())
	if _, ok := r.tx.operatorCredentials[key]; !ok {
		return port.ErrNotFound
	}

	r.tx.operatorCredentials[key] = c.Record()

	return nil
}

type operatorSessions struct{ tx *state }

func (r *operatorSessions) Create(_ context.Context, s *operator.Session) error {
	rec := s.Record()
	for _, other := range r.tx.operatorSessions {
		if other.SecretHash == rec.SecretHash {
			return port.ErrTicketConflict
		}
	}

	if _, ok := r.tx.operatorSessions[s.ID().String()]; ok {
		return fmt.Errorf("operator session %s already exists", s.ID())
	}

	r.tx.operatorSessions[s.ID().String()] = rec

	return nil
}

func (r *operatorSessions) GetByHashForUpdate(_ context.Context, hash passkey.SecretHash) (*operator.Session, error) {
	for _, rec := range r.tx.operatorSessions {
		if rec.SecretHash == hash {
			return restoreOperatorSession(rec)
		}
	}

	return nil, port.ErrNotFound
}

func (r *operatorSessions) GetForUpdate(_ context.Context, id passkey.ID) (*operator.Session, error) {
	rec, ok := r.tx.operatorSessions[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	return restoreOperatorSession(rec)
}

func (r *operatorSessions) Save(_ context.Context, s *operator.Session) error {
	if _, ok := r.tx.operatorSessions[s.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.operatorSessions[s.ID().String()] = s.Record()

	return nil
}

func (r *operatorSessions) RevokeAllForOperator(_ context.Context, id operator.ID, now time.Time) error {
	for key, rec := range r.tx.operatorSessions {
		if rec.OperatorID == id && rec.RevokedAt.IsZero() {
			rec.RevokedAt = now
			r.tx.operatorSessions[key] = rec
		}
	}

	return nil
}

func restoreOperatorSession(rec operator.SessionRecord) (*operator.Session, error) {
	s, err := operator.RestoreSession(rec)
	if err != nil {
		return nil, fmt.Errorf("restore operator session: %w", err)
	}

	return s, nil
}
