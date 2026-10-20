package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

type credentials struct{ q *sqlc.Queries }

func (r *credentials) Create(ctx context.Context, c *passkey.Credential) error {
	rec := c.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	userID, err := userUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	transports := rec.Transports
	if transports == nil {
		transports = []string{}
	}

	err = r.q.CreatePasskeyCredential(ctx, sqlc.CreatePasskeyCredentialParams{
		ID: id, UserID: userID, CredentialID: rec.CredentialID, PublicKey: rec.PublicKey, Aaguid: rec.AAGUID,
		Transports: transports, SignCount: int64(rec.SignCount), BackupEligible: rec.BackupEligible,
		BackupState: rec.BackupState, Name: rec.Name, CreatedAt: dbTime(rec.CreatedAt), LastUsedAt: dbTimePtr(rec.LastUsedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "passkey_credentials_credential_id_unique" {
		return port.ErrCredentialConflict
	}

	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	return nil
}

func (r *credentials) ListByUser(ctx context.Context, userID identity.UserID) ([]*passkey.Credential, error) {
	user, err := userUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}

	rows, err := r.q.ListPasskeyCredentials(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}

	out := make([]*passkey.Credential, 0, len(rows))
	for _, row := range rows {
		c, err := credentialFromRow(row)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, nil
}

func (r *credentials) GetForUpdate(ctx context.Context, credentialID []byte) (*passkey.Credential, error) {
	// The owner is locked (shared) before the credential row, the order every statement that changes a user's
	// keys uses. Without it a login that holds the credential and waits for the user could deadlock with a
	// recovery that holds the user and waits for the credential.
	owner, err := r.q.GetPasskeyCredentialOwner(ctx, credentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}

	if _, err := r.q.LockUserShare(ctx, owner); errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("get credential: lock user: %w", err)
	}

	row, err := r.q.GetPasskeyCredentialForUpdate(ctx, credentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}

	return credentialFromRow(row)
}

func (r *credentials) Save(ctx context.Context, c *passkey.Credential) error {
	rec := c.Record()

	n, err := r.q.UpdatePasskeyCredential(ctx, sqlc.UpdatePasskeyCredentialParams{
		CredentialID: rec.CredentialID, SignCount: int64(rec.SignCount), BackupState: rec.BackupState,
		Name: rec.Name, LastUsedAt: dbTimePtr(rec.LastUsedAt),
	})
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *credentials) Delete(ctx context.Context, userID identity.UserID, id passkey.ID) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	row, err := toUUID(id.String())
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	// The user row serializes the deletes of one user: without it two transactions could
	// both count two keys and each delete one.
	if ok, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	} else if !ok {
		return port.ErrNotFound
	}

	owned, err := r.q.PasskeyCredentialOwned(ctx, sqlc.PasskeyCredentialOwnedParams{ID: row, UserID: user})
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if !owned {
		return port.ErrNotFound
	}

	count, err := r.q.CountPasskeyCredentials(ctx, user)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if count <= 1 {
		return port.ErrLastCredential
	}

	if _, err := r.q.DeletePasskeyCredential(ctx, sqlc.DeletePasskeyCredentialParams{ID: row, UserID: user}); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	return nil
}

func (r *credentials) DeleteAllForUser(ctx context.Context, userID identity.UserID) (int, error) {
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return 0, fmt.Errorf("delete credentials: %w", err)
	}

	user, err := userUUID(userID)
	if err != nil {
		return 0, fmt.Errorf("delete credentials: %w", err)
	}

	n, err := r.q.DeletePasskeyCredentialsOfUser(ctx, user)
	if err != nil {
		return 0, fmt.Errorf("delete credentials: %w", err)
	}

	return int(n), nil
}

func credentialFromRow(row sqlc.PasskeyCredential) (*passkey.Credential, error) {
	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored credential id: %w", err)
	}

	userID, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored credential user: %w", err)
	}

	if row.SignCount < 0 || row.SignCount > 1<<32-1 {
		return nil, fmt.Errorf("stored credential sign count %d is out of range", row.SignCount)
	}

	return passkey.RestoreCredential(passkey.CredentialRecord{
		ID: id, UserID: userID, CredentialID: row.CredentialID, PublicKey: row.PublicKey, AAGUID: row.Aaguid,
		Transports: row.Transports, SignCount: uint32(row.SignCount), BackupEligible: row.BackupEligible,
		BackupState: row.BackupState, Name: row.Name, CreatedAt: goTime(row.CreatedAt), LastUsedAt: goTimePtr(row.LastUsedAt),
	})
}

type challenges struct{ q *sqlc.Queries }

func (r *challenges) Create(ctx context.Context, c *passkey.Challenge) error {
	rec := c.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create challenge: %w", err)
	}

	userID, err := optionalUserUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create challenge: %w", err)
	}

	ticketID, err := optionalPasskeyUUID(rec.TicketID)
	if err != nil {
		return fmt.Errorf("create challenge: %w", err)
	}

	var sessionID *uuid.UUID

	if !rec.SessionID.IsZero() {
		s, err := toUUID(rec.SessionID.String())
		if err != nil {
			return fmt.Errorf("create challenge: %w", err)
		}

		sessionID = &s
	}

	var operation pgtype.Text
	if rec.Operation != "" {
		operation = pgText(string(rec.Operation))
	}

	if err := r.q.CreatePasskeyChallenge(ctx, sqlc.CreatePasskeyChallengeParams{
		ID: id, Purpose: string(rec.Purpose), UserID: userID, TicketID: ticketID, SessionID: sessionID, Operation: operation, Data: rec.Data,
		CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt), ConsumedAt: dbTimePtr(rec.ConsumedAt),
	}); err != nil {
		return fmt.Errorf("create challenge: %w", err)
	}

	return nil
}

func (r *challenges) GetForUpdate(ctx context.Context, id passkey.ID) (*passkey.Challenge, error) {
	row, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("get challenge: %w", err)
	}

	got, err := r.q.GetPasskeyChallengeForUpdate(ctx, row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get challenge: %w", err)
	}

	cid, err := passkey.ParseID(got.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored challenge id: %w", err)
	}

	userID, err := userFromOptional(got.UserID)
	if err != nil {
		return nil, fmt.Errorf("stored challenge user: %w", err)
	}

	ticketID, err := passkeyFromOptional(got.TicketID)
	if err != nil {
		return nil, fmt.Errorf("stored challenge ticket: %w", err)
	}

	var sessionID session.ID
	if got.SessionID != nil {
		if sessionID, err = session.ParseID(got.SessionID.String()); err != nil {
			return nil, fmt.Errorf("stored challenge session: %w", err)
		}
	}

	return passkey.RestoreChallenge(passkey.ChallengeRecord{
		ID: cid, Purpose: passkey.ChallengePurpose(got.Purpose), UserID: userID, TicketID: ticketID,
		SessionID: sessionID, Operation: passkey.Operation(got.Operation.String), Data: got.Data,
		CreatedAt: goTime(got.CreatedAt), ExpiresAt: goTime(got.ExpiresAt), ConsumedAt: goTimePtr(got.ConsumedAt),
	})
}

func (r *challenges) Save(ctx context.Context, c *passkey.Challenge) error {
	id, err := toUUID(c.ID().String())
	if err != nil {
		return fmt.Errorf("save challenge: %w", err)
	}

	n, err := r.q.UpdatePasskeyChallenge(ctx, sqlc.UpdatePasskeyChallengeParams{ID: id, ConsumedAt: dbTimePtr(c.ConsumedAt())})
	if err != nil {
		return fmt.Errorf("save challenge: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

type tickets struct{ q *sqlc.Queries }

func (r *tickets) Create(ctx context.Context, t *passkey.Ticket) error {
	rec := t.Record()

	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create ticket: %w", err)
	}

	userID, err := userUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create ticket: %w", err)
	}

	var sessionID *uuid.UUID

	if !rec.SessionID.IsZero() {
		s, err := toUUID(rec.SessionID.String())
		if err != nil {
			return fmt.Errorf("create ticket: %w", err)
		}

		sessionID = &s
	}

	var operation pgtype.Text
	if rec.Operation != "" {
		operation = pgText(string(rec.Operation))
	}

	var binding []byte
	if !rec.Binding.IsZero() {
		binding = rec.Binding.Bytes()
	}

	err = r.q.CreateAuthTicket(ctx, sqlc.CreateAuthTicketParams{
		ID: id, Kind: string(rec.Kind), UserID: userID, SessionID: sessionID, Operation: operation,
		BindingHash: binding, SecretHash: rec.SecretHash.Bytes(), CreatedAt: dbTime(rec.CreatedAt),
		ExpiresAt: dbTime(rec.ExpiresAt), ConsumedAt: dbTimePtr(rec.ConsumedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "auth_tickets_secret_hash_unique" {
		return port.ErrTicketConflict
	}

	if err != nil {
		return fmt.Errorf("create ticket: %w", err)
	}

	return nil
}

func (r *tickets) GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*passkey.Ticket, error) {
	row, err := r.q.GetAuthTicketByHashForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get ticket: %w", err)
	}

	return ticketFromRow(row)
}

func (r *tickets) GetForUpdate(ctx context.Context, id passkey.ID) (*passkey.Ticket, error) {
	u, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("get ticket: %w", err)
	}

	row, err := r.q.GetAuthTicketForUpdate(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get ticket: %w", err)
	}

	return ticketFromRow(row)
}

func (r *tickets) Save(ctx context.Context, t *passkey.Ticket) error {
	id, err := toUUID(t.ID().String())
	if err != nil {
		return fmt.Errorf("save ticket: %w", err)
	}

	n, err := r.q.UpdateAuthTicket(ctx, sqlc.UpdateAuthTicketParams{ID: id, ConsumedAt: dbTimePtr(t.ConsumedAt())})
	if err != nil {
		return fmt.Errorf("save ticket: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func ticketFromRow(row sqlc.AuthTicket) (*passkey.Ticket, error) {
	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored ticket id: %w", err)
	}

	userID, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored ticket user: %w", err)
	}

	var sessionID session.ID
	if row.SessionID != nil {
		if sessionID, err = session.ParseID(row.SessionID.String()); err != nil {
			return nil, fmt.Errorf("stored ticket session: %w", err)
		}
	}

	var binding identity.BindingHash
	if row.BindingHash != nil {
		if binding, err = identity.NewBindingHash(row.BindingHash); err != nil {
			return nil, fmt.Errorf("stored ticket binding: %w", err)
		}
	}

	secret, err := passkey.NewSecretHash(row.SecretHash)
	if err != nil {
		return nil, fmt.Errorf("stored ticket secret: %w", err)
	}

	return passkey.RestoreTicket(passkey.TicketRecord{
		ID: id, Kind: passkey.TicketKind(row.Kind), UserID: userID, SessionID: sessionID,
		Operation: passkey.Operation(row.Operation.String), Binding: binding, SecretHash: secret,
		CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt), ConsumedAt: goTimePtr(row.ConsumedAt),
	})
}

type recovery struct{ q *sqlc.Queries }

func (r *recovery) Replace(ctx context.Context, userID identity.UserID, codes []*passkey.RecoveryCode) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	// Two replacements of one user's set queue on the user row: the later one supersedes the earlier whole.
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}

	if err := r.q.DeleteRecoveryCodes(ctx, user); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}

	for _, c := range codes {
		rec := c.Record()
		if rec.UserID != userID {
			return fmt.Errorf("replace recovery codes: code %s belongs to another user", rec.ID)
		}

		id, err := toUUID(rec.ID.String())
		if err != nil {
			return fmt.Errorf("replace recovery codes: %w", err)
		}

		err = r.q.CreateRecoveryCode(ctx, sqlc.CreateRecoveryCodeParams{
			ID: id, UserID: user, CodeHash: rec.Hash.Bytes(), CreatedAt: dbTime(rec.CreatedAt), UsedAt: dbTimePtr(rec.UsedAt),
		})

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "recovery_codes_hash_unique" {
			return port.ErrTicketConflict
		}

		if err != nil {
			return fmt.Errorf("replace recovery codes: %w", err)
		}
	}

	return nil
}

func (r *recovery) GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*passkey.RecoveryCode, error) {
	row, err := r.q.GetRecoveryCodeByHashForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get recovery code: %w", err)
	}

	id, err := passkey.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored recovery code id: %w", err)
	}

	userID, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored recovery code user: %w", err)
	}

	stored, err := passkey.NewSecretHash(row.CodeHash)
	if err != nil {
		return nil, fmt.Errorf("stored recovery code hash: %w", err)
	}

	return passkey.RestoreRecoveryCode(passkey.RecoveryCodeRecord{
		ID: id, UserID: userID, Hash: stored, CreatedAt: goTime(row.CreatedAt), UsedAt: goTimePtr(row.UsedAt),
	})
}

func (r *recovery) Save(ctx context.Context, c *passkey.RecoveryCode) error {
	id, err := toUUID(c.ID().String())
	if err != nil {
		return fmt.Errorf("save recovery code: %w", err)
	}

	n, err := r.q.UpdateRecoveryCode(ctx, sqlc.UpdateRecoveryCodeParams{ID: id, UsedAt: dbTimePtr(c.UsedAt())})
	if err != nil {
		return fmt.Errorf("save recovery code: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *recovery) CountUnused(ctx context.Context, userID identity.UserID) (int, error) {
	user, err := userUUID(userID)
	if err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}

	n, err := r.q.CountUnusedRecoveryCodes(ctx, user)
	if err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}

	return int(n), nil
}

func optionalUserUUID(id identity.UserID) (*uuid.UUID, error) {
	if id.IsZero() {
		return nil, nil
	}

	u, err := userUUID(id)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func optionalPasskeyUUID(id passkey.ID) (*uuid.UUID, error) {
	if id.IsZero() {
		return nil, nil
	}

	u, err := toUUID(id.String())
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func userFromOptional(u *uuid.UUID) (identity.UserID, error) {
	if u == nil {
		return identity.UserID{}, nil
	}

	return identity.ParseUserID(u.String())
}

func passkeyFromOptional(u *uuid.UUID) (passkey.ID, error) {
	if u == nil {
		return passkey.ID{}, nil
	}

	return passkey.ParseID(u.String())
}
