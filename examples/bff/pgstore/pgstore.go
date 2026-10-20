// Package pgstore is a bff.Store on PostgreSQL: sessions that survive a restart, and several instances of the application
// that share them. It is an example to copy next to the application, like the package it serves.
//
// What the interface asks for, and how it is given here:
//
//   - WithSessionLock holds an advisory lock on the session while the function runs, so two tabs, or two instances, never
//     refresh at once: the second one waits, then finds the first one's token. The function calls the provider, so one connection
//     of the pool is held for as long as that call takes, and a second request for the same session holds one while it waits. Size the pool for the number of refreshes in flight, and keep the
//     client's timeout short. What the function leaves is stored with a context the request cannot cancel, and a refresh is
//     recorded as begun (Session.BeginRefresh) before the provider is asked: a token that may have been rotated is never presented again.
//   - EndProviderSession is one transaction: the notice's jti, the ended sign-in and the deletion of its sessions all happen or
//     none does. A transaction-level advisory lock on (issuer, sid) orders it against CreateSession, which takes the same lock,
//     so a session cannot slip in between "no notice yet" and its insert.
//   - Dates are the application's clock (Now), not the database's, as in the memory store. Instances whose clocks differ by more
//     than the time a code exchange takes can decide the race of a callback and a notice differently; keep them in sync.
package pgstore

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"go.airlance.org/auth/examples/bff"
)

//go:embed schema.sql
var schema string

// Schema is the SQL that creates the tables; it is idempotent.
func Schema() string { return schema }

// Migrate creates the tables if they are not there.
//
// Several instances may start at once: the statements run in one transaction under an advisory lock, because `IF NOT EXISTS`
// alone does not stop two sessions from creating the same table at the same moment.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
			return err
		}

		_, err := tx.Exec(ctx, schema)

		return err
	})
	if err != nil {
		return fmt.Errorf("pgstore: migrate: %w", err)
	}

	return nil
}

// migrationLock is the key of the advisory lock that orders migrations; it is this package's alone.
const migrationLock int64 = 0x62666673746f7265

// endedMemory is how long a sign-in stays remembered as ended: longer than a session can live. deliveryWindow is how long a
// provider may keep re-delivering a notice, with a margin; a jti is remembered at least that long, whatever the JWT's lifetime.
const (
	endedMemory    = 24 * time.Hour
	deliveryWindow = 26 * time.Hour
)

// Store is a bff.Store on a pgx pool.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ bff.Store = (*Store)(nil)

// New returns a store on the pool. now is the clock, time.Now if nil. The tables must exist (Migrate).
func New(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}

	return &Store{pool: pool, now: now}
}

// utc keeps what is stored in one zone; the database keeps microseconds.
func utc(t time.Time) time.Time { return t.UTC() }

// PutLogin implements bff.Store. It also removes what has expired, so no job is needed for the small tables.
func (s *Store) PutLogin(ctx context.Context, tx bff.LoginTx) error {
	now := utc(s.now())
	batch := &pgx.Batch{}
	batch.Queue(`DELETE FROM bff_logins WHERE expires_at <= $1`, now)
	batch.Queue(`DELETE FROM bff_sessions WHERE expires_at <= $1`, now)
	batch.Queue(`INSERT INTO bff_logins (key, state, nonce, verifier, return_to, started_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (key) DO UPDATE SET state = excluded.state, nonce = excluded.nonce, verifier = excluded.verifier,
		return_to = excluded.return_to, started_at = excluded.started_at, expires_at = excluded.expires_at`,
		tx.Key, tx.State, tx.Nonce, tx.Verifier, tx.ReturnTo, utc(tx.StartedAt), utc(tx.ExpiresAt))

	res := s.pool.SendBatch(ctx, batch)
	defer func() { _ = res.Close() }()

	for range 3 {
		if _, err := res.Exec(); err != nil {
			return fmt.Errorf("pgstore: put login: %w", err)
		}
	}

	return nil
}

// TakeLogin implements bff.Store: one DELETE ... RETURNING, so two requests never both get the transaction.
func (s *Store) TakeLogin(ctx context.Context, key string, now time.Time) (bff.LoginTx, bool, error) {
	var tx bff.LoginTx

	err := s.pool.QueryRow(ctx, `DELETE FROM bff_logins WHERE key = $1 RETURNING key, state, nonce, verifier, return_to, started_at, expires_at`, key).
		Scan(&tx.Key, &tx.State, &tx.Nonce, &tx.Verifier, &tx.ReturnTo, &tx.StartedAt, &tx.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return bff.LoginTx{}, false, nil
	}

	if err != nil {
		return bff.LoginTx{}, false, fmt.Errorf("pgstore: take login: %w", err)
	}

	if !now.Before(tx.ExpiresAt) {
		return bff.LoginTx{}, false, nil
	}

	return tx, true, nil
}

// UpsertUser implements bff.Store.
func (s *Store) UpsertUser(ctx context.Context, issuer, subject string) (string, error) {
	var id string
	// The no-op update is what makes RETURNING give the existing row's id when two instances insert at once.
	err := s.pool.QueryRow(ctx, `INSERT INTO bff_users (issuer, subject) VALUES ($1, $2)
		ON CONFLICT (issuer, subject) DO UPDATE SET issuer = excluded.issuer RETURNING id`, issuer, subject).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("pgstore: upsert user: %w", err)
	}

	return id, nil
}

// lockSignIn serializes everything about one sign-in (issuer, sid) for the rest of the transaction.
func lockSignIn(ctx context.Context, tx pgx.Tx, issuer, sid string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, strconv.Itoa(len(issuer))+":"+issuer+sid)
	return err
}

// CreateSession implements bff.Store.
func (s *Store) CreateSession(ctx context.Context, sess bff.Session) error {
	access, err := json.Marshal(sess.Access)
	if err != nil {
		return fmt.Errorf("pgstore: create session: %w", err)
	}

	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockSignIn(ctx, tx, sess.Issuer, sess.ProviderSession); err != nil {
			return fmt.Errorf("pgstore: create session: %w", err)
		}

		var at time.Time

		err := tx.QueryRow(ctx, `SELECT at FROM bff_ended WHERE issuer = $1 AND sid = $2`, sess.Issuer, sess.ProviderSession).Scan(&at)
		switch {
		case err == nil:
			// Only a sign-in that began before the notice is ended by it: the provider's session may be signed in to again.
			if !utc(sess.SignInStarted).After(at) {
				return bff.ErrSessionEnded
			}
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("pgstore: create session: %w", err)
		}

		_, err = tx.Exec(ctx, `INSERT INTO bff_sessions (key, user_id, issuer, subject, provider_session, id_token_sealed, refresh_sealed, access,
			created_at, sign_in_started, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (key) DO UPDATE SET user_id = excluded.user_id, issuer = excluded.issuer, subject = excluded.subject,
			provider_session = excluded.provider_session, id_token_sealed = excluded.id_token_sealed, refresh_sealed = excluded.refresh_sealed,
			access = excluded.access, created_at = excluded.created_at, sign_in_started = excluded.sign_in_started, expires_at = excluded.expires_at`,
			sess.Key, sess.UserID, sess.Issuer, sess.Subject, sess.ProviderSession, sess.IDTokenSealed, sess.RefreshSealed, access,
			utc(sess.CreatedAt), utc(sess.SignInStarted), utc(sess.ExpiresAt))
		if err != nil {
			return fmt.Errorf("pgstore: create session: %w", err)
		}

		return nil
	})
}

const sessionColumns = `key, user_id, issuer, subject, provider_session, id_token_sealed, refresh_sealed, access, created_at, sign_in_started, expires_at, refresh_started_at`

func scanSession(row pgx.Row) (bff.Session, error) {
	var (
		sess    bff.Session
		access  []byte
		started *time.Time
	)

	err := row.Scan(&sess.Key, &sess.UserID, &sess.Issuer, &sess.Subject, &sess.ProviderSession, &sess.IDTokenSealed, &sess.RefreshSealed,
		&access, &sess.CreatedAt, &sess.SignInStarted, &sess.ExpiresAt, &started)
	if errors.Is(err, pgx.ErrNoRows) {
		return bff.Session{}, bff.ErrNoSession
	}

	if err != nil {
		return bff.Session{}, fmt.Errorf("pgstore: read session: %w", err)
	}

	sess.RefreshInterrupted = started != nil

	sess.Access = map[string]bff.SealedAccess{}
	if err := json.Unmarshal(access, &sess.Access); err != nil {
		return bff.Session{}, fmt.Errorf("pgstore: read session: %w", err)
	}

	return sess, nil
}

// GetSession implements bff.Store.
func (s *Store) GetSession(ctx context.Context, key string) (bff.Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM bff_sessions WHERE key = $1`, key))
}

// DeleteSession implements bff.Store.
func (s *Store) DeleteSession(ctx context.Context, key string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM bff_sessions WHERE key = $1`, key); err != nil {
		return fmt.Errorf("pgstore: delete session: %w", err)
	}

	return nil
}

// EndProviderSession implements bff.Store.
func (s *Store) EndProviderSession(ctx context.Context, issuer, sid, jti string, exp time.Time) (bool, int, error) {
	first, ended := false, 0

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockSignIn(ctx, tx, issuer, sid); err != nil {
			return err
		}

		now := utc(s.now())
		if _, err := tx.Exec(ctx, `DELETE FROM bff_logout_seen WHERE until <= $1`, now); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `DELETE FROM bff_ended WHERE at <= $1`, now.Add(-endedMemory)); err != nil {
			return err
		}
		// A jti is remembered for the whole time the provider may deliver it again, whatever the JWT's own lifetime says.
		until := now.Add(deliveryWindow)
		if l := utc(exp).Add(time.Hour); l.After(until) {
			until = l
		}

		tag, err := tx.Exec(ctx, `INSERT INTO bff_logout_seen (issuer, jti, until) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, issuer, jti, until)
		if err != nil {
			return err
		}

		if tag.RowsAffected() == 0 {
			return nil
		}

		first = true

		if _, err := tx.Exec(ctx, `INSERT INTO bff_ended (issuer, sid, at) VALUES ($1, $2, $3)
			ON CONFLICT (issuer, sid) DO UPDATE SET at = GREATEST(bff_ended.at, excluded.at)`, issuer, sid, now); err != nil {
			return err
		}

		tag, err = tx.Exec(ctx, `DELETE FROM bff_sessions WHERE issuer = $1 AND provider_session = $2`, issuer, sid)
		if err != nil {
			return err
		}

		ended = int(tag.RowsAffected())

		return nil
	})
	if err != nil {
		return false, 0, fmt.Errorf("pgstore: end provider session: %w", err)
	}

	return first, ended, nil
}

// lockKey names the session lock; the session's key is a hash, so it is as good as any.
func lockKey(key string) string { return "bff-session:" + key }

// writeTimeout bounds what is done after the function has run, with a context nobody can cancel.
const writeTimeout = 15 * time.Second

// WithSessionLock implements bff.Store. The lock is a session-level advisory lock on a connection held for the whole call, not a
// row lock held by an open transaction, for two reasons. The function marks the refresh as begun (Session.BeginRefresh) on that
// same connection, committed at once, which a transaction would not do. And what the function leaves must be stored whatever happened to the
// request since: a refresh that rotated the token at the provider and then lost its result to a cancelled request would leave the
// old token in the database, and the next request would replay it and end the grant. So the lock and the read use the request's
// context, the function gets it, and the write after it does not.
func (s *Store) WithSessionLock(ctx context.Context, key string, fn func(sess *bff.Session) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("pgstore: session lock: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 1))`, lockKey(key)); err != nil {
		return fmt.Errorf("pgstore: session lock: %w", err)
	}
	// Whatever happens next, the lock goes. If it cannot be released the connection is closed, which releases it.
	defer func() {
		done, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()

		if _, err := conn.Exec(done, `SELECT pg_advisory_unlock(hashtextextended($1, 1))`, lockKey(key)); err != nil {
			_ = conn.Hijack().Close(done)
		}
	}()

	sess, err := scanSession(conn.QueryRow(ctx, `SELECT `+sessionColumns+` FROM bff_sessions WHERE key = $1`, key))
	if err != nil {
		return err
	}
	// The mark is written on the connection that holds the session, not on another from the pool: a pool whose connections
	// are all held by refreshes waiting for a second one would never move.
	sess.BeginRefresh = func(ctx context.Context) error {
		tag, err := conn.Exec(ctx, `UPDATE bff_sessions SET refresh_started_at = $2 WHERE key = $1`, key, utc(s.now()))
		if err != nil {
			return fmt.Errorf("pgstore: mark refresh: %w", err)
		}

		if tag.RowsAffected() == 0 {
			return bff.ErrNoSession
		}

		return nil
	}
	fnErr := fn(&sess)
	sess.BeginRefresh = nil

	done, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()

	if fnErr != nil {
		// An error means nothing was rotated (the function reports a refresh whose outcome is unknown as a result, not as an
		// error), so only the mark goes.
		if _, err := conn.Exec(done, `UPDATE bff_sessions SET refresh_started_at = NULL WHERE key = $1`, key); err != nil {
			return fmt.Errorf("pgstore: clear refresh mark: %w", err)
		}

		return fnErr
	}

	access, err := json.Marshal(sess.Access)
	if err != nil {
		return fmt.Errorf("pgstore: store session: %w", err)
	}
	// A session that was deleted meanwhile, by a logout notice, stays deleted: the update finds no row.
	_, err = conn.Exec(done, `UPDATE bff_sessions SET id_token_sealed = $2, refresh_sealed = $3, access = $4, expires_at = $5, refresh_started_at = NULL WHERE key = $1`,
		key, sess.IDTokenSealed, sess.RefreshSealed, access, utc(sess.ExpiresAt))
	if err != nil {
		return fmt.Errorf("pgstore: store session: %w", err)
	}

	return nil
}
