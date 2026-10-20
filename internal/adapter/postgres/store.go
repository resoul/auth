package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/quota"
)

var _ port.UnitOfWork = (*Store)(nil)

// RecordIDs creates identifiers for rows that have no domain type, such as outbox jobs.
type RecordIDs interface {
	NewRecordID() (uuid.UUID, error)
}

// Store is the PostgreSQL UnitOfWork. Each Do call is one transaction at READ
// COMMITTED; ordering between concurrent requests comes from row locks
// (GetForUpdate) and unique constraints, not from a stronger isolation level.
type Store struct {
	pool     *pgxpool.Pool
	ids      RecordIDs
	profile  quota.Profile
	maxConns int32
	schema   string
}

// Option configures a Store.
type Option func(*Store)

// WithQuota replaces the default quota profile.
func WithQuota(p quota.Profile) Option { return func(s *Store) { s.profile = p } }

// WithMaxConns caps the connection pool; the default of pgx is the larger of 4 and the
// number of CPUs. Tests that run many stores at once lower it to stay inside the server's
// connection limit.
func WithMaxConns(n int32) Option { return func(s *Store) { s.maxConns = n } }

// WithSchema sets the search_path of every connection to schema, so tables are found there and
// nowhere else. An empty name keeps the search_path of the connection string and of the role.
func WithSchema(name string) Option { return func(s *Store) { s.schema = name } }

// Open connects to the database and checks it answers. Error messages never
// contain the connection string, which holds a password.
func Open(ctx context.Context, dsn string, ids RecordIDs, opts ...Option) (*Store, error) {
	if ids == nil {
		return nil, errors.New("open postgres: record id generator is required")
	}

	s := &Store{ids: ids, profile: quota.DefaultProfile()}
	for _, opt := range opts {
		opt(s)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("open postgres: invalid connection string")
	}

	if s.maxConns > 0 {
		cfg.MaxConns = s.maxConns
	}

	if s.schema != "" {
		if err := ValidateSchemaName(s.schema); err != nil {
			return nil, fmt.Errorf("open postgres: %w", err)
		}

		cfg.ConnConfig.RuntimeParams["search_path"] = s.schema
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("open postgres: ping: %w", err)
	}

	s.pool = pool

	return s, nil
}

// Close releases every connection. Call it after all transactions finished.
func (s *Store) Close() { s.pool.Close() }

// Ping checks that the database answers; readiness uses it.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Do runs fn in one transaction: a nil result commits, an error or panic rolls back.
func (s *Store) Do(ctx context.Context, fn func(ctx context.Context, st port.Stores) error) (err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	finished := false
	defer func() {
		if finished {
			return
		}
		// A cancelled request must still release the transaction.
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()

		_ = tx.Rollback(rollbackCtx) // the original error or panic is what the caller needs
	}()

	q := sqlc.New(tx)
	if err := fn(ctx, port.Stores{
		AccountStores: port.AccountStores{
			Flows:       &flows{q: q},
			Users:       &users{q: q},
			Recognized:  &recognized{q: q},
			Sessions:    &sessions{q: q},
			Tokens:      &tokens{q: q},
			Credentials: &credentials{q: q},
			Challenges:  &challenges{q: q},
			Tickets:     &tickets{q: q},
			Recovery:    &recovery{q: q},
			Invitations: &invitations{q: q},
			Devices:     &devices{q: q},
		},
		InfraStores: port.InfraStores{
			Outbox:     &outbox{q: q, ids: s.ids},
			Audit:      &audit{q: q, ids: s.ids},
			AuditReads: &audit{q: q, ids: s.ids},
			Limiter:    &limiter{q: q, profile: s.profile},
		},
		AdminStores: port.AdminStores{
			Operators:          &operators{q: q},
			OperatorSessions:   &operatorSessions{q: q},
			OperatorChallenges: &operatorChallenges{q: q},
		},
		OIDCStores: port.OIDCStores{
			OIDCClients:   &oidcClients{q: q},
			OIDCRequests:  &oidcRequests{q: q},
			OPSessions:    &oidcSessions{q: q},
			OIDCGrants:    &oidcGrants{q: q},
			OIDCCodes:     &oidcCodes{q: q},
			OIDCRefresh:   &oidcRefresh{q: q},
			OIDCLogout:    &oidcLogout{q: q},
			OIDCResources: &oidcResources{q: q},
			OIDCApps:      &oidcApps{q: q},
		},
	}); err != nil {
		return err
	}

	finished = true

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
