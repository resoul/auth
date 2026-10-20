//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"go.airlance.org/auth/internal/adapter/postgres"
)

const (
	flowID  = "AAECAwQFBgcICQoLDA0ODw"
	binding = `decode(repeat('ab', 32), 'hex')`
	salt    = `decode(repeat('cd', 16), 'hex')`
	userID  = "3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	userID2 = "4f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	client1 = "5f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	client2 = "6f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	job1    = "7f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
)

// schemaDSN returns a DSN whose search_path is a fresh schema, dropped at cleanup,
// so tests do not see each other's tables.
func schemaDSN(t *testing.T) string {
	t.Helper()

	base := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("AIRLANCE_AUTH_TEST_DATABASE_URL is not set; run `make up` and `make test-int`")
	}

	admin, err := postgres.OpenMigrationDB(base)
	if err != nil {
		t.Fatal(err)
	}

	schema := fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	return u.String()
}

func openDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	db, err := postgres.OpenMigrationDB(dsn)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = db.Close() })

	return db
}

func migratedDB(t *testing.T) *sql.DB {
	t.Helper()

	db := openDB(t, schemaDSN(t))
	if _, err := postgres.MigrateUp(context.Background(), db); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	return db
}

func exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()

	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("%s\n%v", query, err)
	}
}

// mustViolate runs query and requires it to fail on the named constraint.
func mustViolate(t *testing.T, db *sql.DB, constraint, query string, args ...any) {
	t.Helper()

	_, err := db.Exec(query, args...)

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected a violation of %s, got %v\n%s", constraint, err, query)
	}

	if pgErr.ConstraintName != constraint {
		t.Fatalf("violated %q (%s), want %q\n%s", pgErr.ConstraintName, pgErr.Message, constraint, query)
	}
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()

	var exists bool

	err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, column).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}

	return exists
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var exists bool

	err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)`, table).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}

	return exists
}

var tables = []string{"users", "recognized_clients", "auth_flows", "outbox", "sessions", "refresh_tokens", "audit_events", "quota_events",
	"passkey_credentials", "passkey_challenges", "auth_tickets", "recovery_codes", "invitations",
	"operators", "operator_credentials", "operator_enrollments", "operator_challenges", "operator_sessions", "device_requests"}

func TestMigrateUpDownUp(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, schemaDSN(t))

	known, err := postgres.KnownMigrations()
	if err != nil {
		t.Fatal(err)
	}

	steps, err := postgres.MigrateUp(ctx, db)
	if err != nil || len(steps) != len(known) {
		t.Fatalf("MigrateUp = %+v, %v; want %d migrations", steps, err, len(known))
	}

	for _, table := range tables {
		if !tableExists(t, db, table) {
			t.Errorf("table %s missing after up", table)
		}
	}

	status, err := postgres.MigrationStatus(ctx, db)
	if err != nil || len(status) != len(known) {
		t.Fatalf("status after up = %+v, %v", status, err)
	}

	for _, s := range status {
		if s.AppliedAt.IsZero() {
			t.Errorf("%s is not applied after up", s.Name)
		}
	}

	if again, err := postgres.MigrateUp(ctx, db); err != nil || len(again) != 0 {
		t.Errorf("second MigrateUp = %+v, %v; want a no-op", again, err)
	}

	// Roll back one migration at a time, newest first; each step must succeed.
	for version := int64(len(known)); version >= 1; version-- {
		step, rolledBack, err := postgres.MigrateDown(ctx, db)
		if err != nil || !rolledBack || step.Version != version {
			t.Fatalf("MigrateDown to below %d = %+v, %v, %v", version, step, rolledBack, err)
		}

		switch version {
		case 12:
			for _, column := range []string{"user_id", "device_name", "client_ip", "event_at"} {
				if columnExists(t, db, "outbox", column) {
					t.Errorf("the rollback of the new device mail migration left outbox.%s", column)
				}
			}

			if _, err := db.Exec(`INSERT INTO outbox (id, flow_id, generation, quota_class, kind, available_at) VALUES ($1, NULL, 1, 'recognized', 'new_device', now())`, job1); err == nil {
				t.Error("outbox still accepts a new device job after the rollback")
			}

			if !tableExists(t, db, "device_requests") || !columnExists(t, db, "outbox", "recipient") {
				t.Error("the rollback of the new device mail migration removed more than its own")
			}
		case 11:
			if tableExists(t, db, "device_requests") {
				t.Error("the rollback of the device migration left device_requests")
			}
			// The step-up operations are back to the five of before: approve_device is no longer accepted.
			if _, err := db.Exec(`INSERT INTO passkey_challenges (id, purpose, user_id, data, created_at, expires_at, session_id, operation)
				VALUES ('0199c0de-0000-7000-8000-0000000000a1', 'step_up', NULL, '\x01', now(), now() + interval '1 minute', NULL, 'approve_device')`); err == nil {
				t.Error("passkey_challenges still accepts approve_device after the rollback")
			}

			if !tableExists(t, db, "operators") || !tableExists(t, db, "passkey_challenges") {
				t.Error("the rollback of the device migration removed more than its own")
			}
		case 10:
			for _, table := range []string{"operators", "operator_credentials", "operator_enrollments", "operator_challenges", "operator_sessions"} {
				if tableExists(t, db, table) {
					t.Errorf("the rollback of the admin migration left %s", table)
				}
			}

			if columnExists(t, db, "users", "blocked_at") || columnExists(t, db, "audit_events", "operator_id") {
				t.Error("the rollback of the admin migration left a column")
			}

			if !tableExists(t, db, "invitations") || !tableExists(t, db, "audit_events") || !tableExists(t, db, "users") {
				t.Error("the rollback of the admin migration removed more than its own")
			}
		case 9:
			var nullable string
			if err := db.QueryRow(`SELECT is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'outbox' AND column_name = 'flow_id'`).Scan(&nullable); err != nil || nullable != "NO" {
				t.Errorf("outbox.flow_id is nullable after the rollback of the invitation mail migration: %q, %v", nullable, err)
			}

			if !tableExists(t, db, "invitations") {
				t.Error("the rollback of the invitation mail migration removed the invitations table")
			}
		case 8:
			if tableExists(t, db, "invitations") {
				t.Error("the rollback of the invitations migration left the table")
			}

			if !tableExists(t, db, "users") || !columnExists(t, db, "auth_flows", "user_id") {
				t.Error("the invitations rollback removed more than its table")
			}
		case 7:
			var exists bool
			if err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'auth_flows_email')").Scan(&exists); err != nil {
				t.Fatal(err)
			}

			if exists {
				t.Error("account deletion index survived rollback")
			}

			if !columnExists(t, db, "auth_flows", "user_id") {
				t.Error("index rollback removed email-change schema")
			}
		case 6:
			// The email-change migration adds columns, not tables: only they go.
			for _, c := range [][2]string{{"auth_flows", "user_id"}, {"outbox", "kind"}, {"outbox", "recipient"}} {
				if columnExists(t, db, c[0], c[1]) {
					t.Errorf("the first rollback left %s.%s", c[0], c[1])
				}
			}

			if !tableExists(t, db, "passkey_credentials") || !tableExists(t, db, "outbox") {
				t.Error("the first rollback must remove only the newest migration's changes")
			}
		case 5:
			for _, table := range []string{"passkey_credentials", "passkey_challenges", "auth_tickets", "recovery_codes"} {
				if tableExists(t, db, table) {
					t.Errorf("the rollback of the passkey migration left %s", table)
				}
			}

			if !tableExists(t, db, "quota_events") || !tableExists(t, db, "audit_events") {
				t.Error("the rollback of the passkey migration must remove only its tables")
			}
		}
	}

	for _, table := range tables {
		if tableExists(t, db, table) {
			t.Errorf("table %s survived the rollbacks", table)
		}
	}

	if _, rolledBack, err := postgres.MigrateDown(ctx, db); err != nil || rolledBack {
		t.Errorf("MigrateDown on an empty schema = %v, %v; want nothing to roll back", rolledBack, err)
	}

	if _, err := postgres.MigrateUp(ctx, db); err != nil {
		t.Errorf("MigrateUp after the rollbacks: %v", err)
	}
}

func TestConcurrentMigrateUpIsSafe(t *testing.T) {
	dsn := schemaDSN(t)

	const runners = 4

	var wg sync.WaitGroup

	errs := make([]error, runners)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()

			db, err := postgres.OpenMigrationDB(dsn)
			if err != nil {
				errs[i] = err
				return
			}

			defer func() { _ = db.Close() }()

			_, errs[i] = postgres.MigrateUp(context.Background(), db)
		}()
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}

	db := openDB(t, dsn)
	if !tableExists(t, db, "users") {
		t.Error("schema was not created")
	}
}

func insertUser(t *testing.T, db *sql.DB, id, email string) {
	t.Helper()
	exec(t, db, `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, $2, now(), now(), now())`, id, email)
}

func insertClient(t *testing.T, db *sql.DB, id, user, email, bindingExpr string) {
	t.Helper()
	exec(t, db, `INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, $3, `+bindingExpr+`, now(), now() + interval '90 days')`, id, user, email)
}

func TestEmailChangeConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")

	flow := func(id, purpose string, user any) (string, []any) {
		return `INSERT INTO auth_flows (id, email, purpose, generation, salt, key_id, binding_hash, state, created_at, expires_at, attempts, resend_after, quota_class, user_id)
			VALUES ($1, 'new@example.test', $2, 1, ` + salt + `, 'otp-a', ` + binding + `, 'pending', now(), now() + interval '10 minutes', 0, now() + interval '1 minute', 'unknown', $3)`,
			[]any{id, purpose, user}
	}

	q, args := flow(flowID, "change_email", userID)
	exec(t, db, q, args...)
	q, args = flow("AAECAwQFBgcICQoLDA0OPQ", "change_email", nil)
	mustViolate(t, db, "auth_flows_user", q, args...)
	q, args = flow("AAECAwQFBgcICQoLDA0OPg", "login", userID)
	mustViolate(t, db, "auth_flows_user", q, args...)
	q, args = flow("AAECAwQFBgcICQoLDA0OPw", "step_up", userID)
	mustViolate(t, db, "auth_flows_user", q, args...)

	notice := func(id, kind string, recipient any) (string, []any) {
		return `INSERT INTO outbox (id, flow_id, generation, quota_class, kind, recipient, available_at) VALUES ($1, $2, 1, 'unknown', $3, $4, now())`,
			[]any{id, flowID, kind, recipient}
	}
	q, args = notice(job1, "email_changed", "old@example.test")
	exec(t, db, q, args...)

	other := "8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	q, args = notice(other, "email_changed", "again@example.test")
	mustViolate(t, db, "outbox_flow_generation_kind_unique", q, args...)
	q, args = notice(other, "email_changed", nil)
	mustViolate(t, db, "outbox_recipient", q, args...)
	q, args = notice(other, "code", "old@example.test")
	mustViolate(t, db, "outbox_recipient", q, args...)
	q, args = notice(other, "email_changed", " Old@Example.test")
	mustViolate(t, db, "outbox_recipient", q, args...)
	q, args = notice(other, "newsletter", nil)
	mustViolate(t, db, "outbox_kind", q, args...)
	// The code job of the same flow generation does not collide with the notice.
	q, args = notice(other, "code", nil)
	exec(t, db, q, args...)

	// Deleting the account takes its change flows and their jobs with it: no address stays behind.
	exec(t, db, `DELETE FROM users WHERE id = $1`, userID)

	if count(t, db, "auth_flows") != 0 || count(t, db, "outbox") != 0 {
		t.Errorf("flows = %d, jobs = %d after the account was deleted", count(t, db, "auth_flows"), count(t, db, "outbox"))
	}
}

func insertFlow(t *testing.T, db *sql.DB, id, class, clientID string) {
	t.Helper()

	var client any
	if clientID != "" {
		client = clientID
	}

	exec(t, db, `INSERT INTO auth_flows (id, email, purpose, generation, salt, key_id, binding_hash, state, created_at, expires_at, attempts, resend_after, quota_class, recognized_client_id)
		VALUES ($1, 'a@example.test', 'login', 1, `+salt+`, 'otp-a', `+binding+`, 'pending', now(), now() + interval '10 minutes', 0, now() + interval '1 minute', $2, $3)`, id, class, client)
}

func TestUserConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")

	mustViolate(t, db, "users_email_unique", `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'alice@example.test', now(), now(), now())`, userID2)
	mustViolate(t, db, "users_email_normalized", `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'Bob@Example.test', now(), now(), now())`, userID2)
	mustViolate(t, db, "users_email_normalized", `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, ' bob@example.test', now(), now(), now())`, userID2)
	mustViolate(t, db, "users_email_normalized", `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, '', now(), now(), now())`, userID2)
}

func TestRecognizedClientConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertClient(t, db, client1, userID, "alice@example.test", binding)

	mustViolate(t, db, "recognized_clients_pair_unique",
		`INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, 'alice@example.test', `+binding+`, now(), now() + interval '1 day')`, client2, userID)
	mustViolate(t, db, "recognized_clients_binding_length",
		`INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, 'alice@example.test', decode('abab', 'hex'), now(), now() + interval '1 day')`, client2, userID)
	mustViolate(t, db, "recognized_clients_period",
		`INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, 'alice@example.test', decode(repeat('ef', 32), 'hex'), now(), now())`, client2, userID)
	mustViolate(t, db, "recognized_clients_email_normalized",
		`INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, 'ALICE@example.test', decode(repeat('ef', 32), 'hex'), now(), now() + interval '1 day')`, client2, userID)

	var fkErr *pgconn.PgError

	_, err := db.Exec(`INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at) VALUES ($1, $2, 'x@example.test', decode(repeat('ef', 32), 'hex'), now(), now() + interval '1 day')`, client2, userID2)
	if !errors.As(err, &fkErr) || fkErr.Code != "23503" {
		t.Errorf("a client of a missing user was accepted: %v", err)
	}

	// The same binding may be recognized for another user.
	insertUser(t, db, userID2, "bob@example.test")
	insertClient(t, db, client2, userID2, "bob@example.test", binding)
}

func TestFlowConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertClient(t, db, client1, userID, "alice@example.test", binding)
	insertFlow(t, db, flowID, "unknown", "")

	flow := func(id, purpose string, generation int, saltExpr, state string, attempts int, class, client string) (string, []any) {
		return `INSERT INTO auth_flows (id, email, purpose, generation, salt, key_id, binding_hash, state, created_at, expires_at, attempts, resend_after, quota_class, recognized_client_id)
			VALUES ($1, 'a@example.test', $2, $3, ` + saltExpr + `, 'otp-a', ` + binding + `, $4, now(), now() + interval '10 minutes', $5, now(), $6, NULLIF($7, '')::uuid)`,
			[]any{id, purpose, generation, state, attempts, class, client}
	}
	other := "BBECAwQFBgcICQoLDA0ODw"

	tests := []struct {
		name       string
		constraint string
		id         string
		purpose    string
		generation int
		salt       string
		state      string
		attempts   int
		class      string
		client     string
	}{
		{"duplicate id", "auth_flows_pkey", flowID, "login", 1, salt, "pending", 0, "unknown", ""},
		{"bad id format", "auth_flows_id_format", "short", "login", 1, salt, "pending", 0, "unknown", ""},
		{"unknown purpose", "auth_flows_purpose", other, "signup", 1, salt, "pending", 0, "unknown", ""},
		{"generation zero", "auth_flows_generation", other, "login", 0, salt, "pending", 0, "unknown", ""},
		{"unknown state", "auth_flows_state", other, "login", 1, "NULL", "done", 0, "unknown", ""},
		{"negative attempts", "auth_flows_attempts", other, "login", 1, salt, "pending", -1, "unknown", ""},
		{"unknown quota class", "auth_flows_quota_class", other, "login", 1, salt, "pending", 0, "vip", ""},
		{"pending without salt", "auth_flows_salt", other, "login", 1, "NULL", "pending", 0, "unknown", ""},
		{"consumed keeps salt", "auth_flows_salt", other, "login", 1, salt, "consumed", 1, "unknown", ""},
		{"locked keeps salt", "auth_flows_salt", other, "login", 1, salt, "locked", 5, "unknown", ""},
		{"short salt", "auth_flows_salt", other, "login", 1, `decode('abcd', 'hex')`, "pending", 0, "unknown", ""},
		{"recognized without client", "auth_flows_recognized_client", other, "login", 1, salt, "pending", 0, "recognized", ""},
		{"unknown with client", "auth_flows_recognized_client", other, "login", 1, salt, "pending", 0, "unknown", client1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, args := flow(tt.id, tt.purpose, tt.generation, tt.salt, tt.state, tt.attempts, tt.class, tt.client)
			mustViolate(t, db, tt.constraint, query, args...)
		})
	}

	t.Run("valid shapes are accepted", func(t *testing.T) {
		query, args := flow("CCECAwQFBgcICQoLDA0ODw", "login", 3, "NULL", "consumed", 2, "unknown", "")
		exec(t, db, query, args...)
		query, args = flow("DDECAwQFBgcICQoLDA0ODw", "step_up", 1, salt, "pending", 0, "recognized", client1)
		exec(t, db, query, args...)
	})
	t.Run("expiry must follow creation", func(t *testing.T) {
		mustViolate(t, db, "auth_flows_period", `INSERT INTO auth_flows (id, email, purpose, generation, salt, key_id, binding_hash, state, created_at, expires_at, attempts, resend_after, quota_class)
			VALUES ('EEECAwQFBgcICQoLDA0ODw', 'a@example.test', 'login', 1, `+salt+`, 'otp-a', `+binding+`, 'pending', now(), now(), 0, now(), 'unknown')`)
	})
	t.Run("binding hash has the fixed length", func(t *testing.T) {
		mustViolate(t, db, "auth_flows_binding_length", `INSERT INTO auth_flows (id, email, purpose, generation, salt, key_id, binding_hash, state, created_at, expires_at, attempts, resend_after, quota_class)
			VALUES ('FFECAwQFBgcICQoLDA0ODw', 'a@example.test', 'login', 1, `+salt+`, 'otp-a', decode('abab', 'hex'), 'pending', now(), now() + interval '1 minute', 0, now(), 'unknown')`)
	})
}

func TestOutboxConstraints(t *testing.T) {
	db := migratedDB(t)
	insertFlow(t, db, flowID, "unknown", "")

	insertJob := func(id string, generation int, status string) (string, []any) {
		return `INSERT INTO outbox (id, flow_id, generation, quota_class, status, available_at) VALUES ($1, $2, $3, 'unknown', $4, now())`, []any{id, flowID, generation, status}
	}

	query, args := insertJob(job1, 1, "queued")
	exec(t, db, query, args...)

	query, args = insertJob("8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f", 1, "queued")
	mustViolate(t, db, "outbox_flow_generation_kind_unique", query, args...)
	query, args = insertJob("8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f", 0, "queued")
	mustViolate(t, db, "outbox_generation", query, args...)
	query, args = insertJob("8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f", 2, "stuck")
	mustViolate(t, db, "outbox_status", query, args...)
	mustViolate(t, db, "outbox_last_error", `UPDATE outbox SET last_error = repeat('x', 65) WHERE id = $1`, job1)
	exec(t, db, `UPDATE outbox SET last_error = 'smtp_timeout', attempts = 1 WHERE id = $1`, job1)

	var fkErr *pgconn.PgError

	_, err := db.Exec(`INSERT INTO outbox (id, flow_id, generation, quota_class, available_at) VALUES ($1, 'ZZECAwQFBgcICQoLDA0ODw', 1, 'unknown', now())`, "9f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f")
	if !errors.As(err, &fkErr) || fkErr.Code != "23503" {
		t.Errorf("a job of a missing flow was accepted: %v", err)
	}
}

func TestDeletionCascadesFollowTheRetentionPolicy(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertClient(t, db, client1, userID, "alice@example.test", binding)
	insertFlow(t, db, flowID, "recognized", client1)
	insertFlow(t, db, "GGECAwQFBgcICQoLDA0ODw", "unknown", "")
	exec(t, db, `INSERT INTO outbox (id, flow_id, generation, quota_class, available_at) VALUES ($1, $2, 1, 'recognized', now())`, job1, flowID)

	t.Run("deleting a flow deletes its jobs", func(t *testing.T) {
		exec(t, db, `DELETE FROM auth_flows WHERE id = 'GGECAwQFBgcICQoLDA0ODw'`)

		if count(t, db, "auth_flows") != 1 {
			t.Error("deleted the wrong flow")
		}
	})

	t.Run("deleting a user deletes recognition, its flows and their jobs", func(t *testing.T) {
		exec(t, db, `DELETE FROM users WHERE id = $1`, userID)

		for _, table := range []string{"users", "recognized_clients", "auth_flows", "outbox"} {
			if n := count(t, db, table); n != 0 {
				t.Errorf("%s still has %d rows", table, n)
			}
		}
	})
}

func TestRetentionIndexesExist(t *testing.T) {
	db := migratedDB(t)

	for _, index := range []string{
		"auth_flows_expires_at", "recognized_clients_expires_at", "recognized_clients_revoked_at",
		"recognized_clients_lookup", "outbox_ready", "auth_flows_recognized_client",
		"sessions_user_id", "sessions_expires_at", "sessions_idle_expires_at", "sessions_revoked_at",
		"refresh_one_live_child", "refresh_tokens_session_id", "refresh_tokens_family_id", "refresh_tokens_parent_id",
		"audit_events_occurred_at", "audit_events_user_id", "audit_events_session_id",
	} {
		var exists bool

		err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)`, index).Scan(&exists)
		if err != nil || !exists {
			t.Errorf("index %s missing (%v)", index, err)
		}
	}
}

func TestInvitationMailConstraints(t *testing.T) {
	db := migratedDB(t)
	insertFlow(t, db, flowID, "unknown", "")

	job := func(id, kind string, flow, recipient any) (string, []any) {
		return `INSERT INTO outbox (id, flow_id, generation, quota_class, kind, recipient, available_at) VALUES ($1, $2, 1, 'unknown', $3, $4, now())`,
			[]any{id, flow, kind, recipient}
	}
	second := "8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	third := "9f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"

	// An invitation has no flow and an address; the same address may be invited again.
	q, args := job(job1, "invitation", nil, "guest@example.test")
	exec(t, db, q, args...)
	q, args = job(second, "invitation", nil, "guest@example.test")
	exec(t, db, q, args...)

	q, args = job(third, "invitation", flowID, "guest@example.test")
	mustViolate(t, db, "outbox_flow", q, args...)
	q, args = job(third, "invitation", nil, nil)
	mustViolate(t, db, "outbox_recipient", q, args...)
	q, args = job(third, "invitation", nil, " Guest@Example.test")
	mustViolate(t, db, "outbox_recipient", q, args...)
	q, args = job(third, "code", nil, nil)
	mustViolate(t, db, "outbox_flow", q, args...) // a code job needs its flow
	q, args = job(third, "code", flowID, "guest@example.test")
	mustViolate(t, db, "outbox_recipient", q, args...)
}

// A new device job names its user and the time, has no flow and no address, keeps the label and the client address
// only for this kind, and goes with its user.
func TestNewDeviceMailConstraints(t *testing.T) {
	db := migratedDB(t)
	insertFlow(t, db, flowID, "unknown", "")
	insertUser(t, db, userID, "owner@example.test")

	job := func(id string, kind string, flow, user, at, name, ip any) (string, []any) {
		return `INSERT INTO outbox (id, flow_id, generation, quota_class, kind, available_at, user_id, event_at, device_name, client_ip)
			VALUES ($1, $2, 1, 'recognized', $3, now(), $4, $5, $6, $7)`, []any{id, flow, kind, user, at, name, ip}
	}
	second := "8f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	third := "9f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"

	q, args := job(job1, "new_device", nil, userID, time.Now(), "Office laptop", "203.0.113.7")
	exec(t, db, q, args...)
	// The address may be unknown, the label empty, and a user may have many notices.
	q, args = job(second, "new_device", nil, userID, time.Now(), "", nil)
	exec(t, db, q, args...)

	q, args = job(third, "new_device", flowID, userID, time.Now(), "x", nil)
	mustViolate(t, db, "outbox_flow", q, args...)
	q, args = job(third, "new_device", nil, nil, time.Now(), "x", nil)
	mustViolate(t, db, "outbox_new_device", q, args...)
	q, args = job(third, "new_device", nil, userID, nil, "x", nil)
	mustViolate(t, db, "outbox_new_device", q, args...)
	q, args = job(third, "new_device", nil, userID, time.Now(), strings.Repeat("x", 65), nil)
	mustViolate(t, db, "outbox_new_device", q, args...)
	q, args = job(third, "new_device", nil, userID, time.Now(), "x", strings.Repeat("1", 46))
	mustViolate(t, db, "outbox_new_device", q, args...)
	// The fields of this kind do not belong to another.
	q, args = job(third, "code", flowID, userID, nil, nil, nil)
	mustViolate(t, db, "outbox_new_device", q, args...)
	q, args = job(third, "code", flowID, nil, nil, "x", nil)
	mustViolate(t, db, "outbox_new_device", q, args...)

	exec(t, db, `DELETE FROM users WHERE id = $1`, userID)

	if n := count(t, db, "outbox"); n != 0 {
		t.Errorf("%d new device jobs outlived their user", n)
	}
}

const (
	operatorID  = "af1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	operatorID2 = "bf1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	rowID1      = "0199c0de-0000-7000-8000-000000000001"
	rowID2      = "0199c0de-0000-7000-8000-000000000002"
	rowID3      = "0199c0de-0000-7000-8000-000000000003"
)

func TestAdminConstraints(t *testing.T) {
	db := migratedDB(t)
	hash := `decode(repeat('ab', 32), 'hex')`

	exec(t, db, `INSERT INTO operators (id, email, created_at) VALUES ($1, 'ops@example.test', now())`, operatorID)

	t.Run("operators", func(t *testing.T) {
		mustViolate(t, db, "operators_email_unique", `INSERT INTO operators (id, email, created_at) VALUES ($1, 'ops@example.test', now())`, operatorID2)
		mustViolate(t, db, "operators_email_normalized", `INSERT INTO operators (id, email, created_at) VALUES ($1, 'Ops2@Example.test', now())`, operatorID2)
		mustViolate(t, db, "operators_email_normalized", `INSERT INTO operators (id, email, created_at) VALUES ($1, '', now())`, operatorID2)
	})

	t.Run("users", func(t *testing.T) {
		exec(t, db, `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'u@example.test', now(), now(), now())`, userID)

		var blocked sql.NullTime
		if err := db.QueryRow(`SELECT blocked_at FROM users WHERE id = $1`, userID).Scan(&blocked); err != nil || blocked.Valid {
			t.Errorf("a new user's blocked_at = %v, %v; want NULL", blocked, err)
		}
	})

	t.Run("enrollments", func(t *testing.T) {
		insert := `INSERT INTO operator_enrollments (id, operator_id, code_hash, created_at, expires_at) VALUES ($1, $2, ` + hash + `, now(), now() + interval '1 hour')`
		exec(t, db, insert, rowID1, operatorID)
		mustViolate(t, db, "operator_enrollments_code_hash_unique", insert, rowID2, operatorID)
		mustViolate(t, db, "operator_enrollments_code_hash_length", `INSERT INTO operator_enrollments (id, operator_id, code_hash, created_at, expires_at) VALUES ($1, $2, '\x00', now(), now() + interval '1 hour')`, rowID2, operatorID)
		mustViolate(t, db, "operator_enrollments_period", `INSERT INTO operator_enrollments (id, operator_id, code_hash, created_at, expires_at) VALUES ($1, $2, decode(repeat('cd', 32), 'hex'), now(), now())`, rowID2, operatorID)
	})

	t.Run("challenges", func(t *testing.T) {
		insert := func(id, purpose string, operator, enrollment any) (string, []any) {
			return `INSERT INTO operator_challenges (id, purpose, operator_id, enrollment_id, data, created_at, expires_at) VALUES ($1, $2, $3, $4, '\x01', now(), now() + interval '5 minutes')`,
				[]any{id, purpose, operator, enrollment}
		}
		q, args := insert(rowID2, "registration", operatorID, rowID1)
		exec(t, db, q, args...)
		q, args = insert(rowID3, "login", nil, nil)
		exec(t, db, q, args...)

		for name, c := range map[string]struct {
			purpose              string
			operator, enrollment any
		}{
			"registration without an operator":   {"registration", nil, rowID1},
			"registration without an enrollment": {"registration", operatorID, nil},
			"login that names an operator":       {"login", operatorID, nil},
			"login that names an enrollment":     {"login", nil, rowID1},
			"a step-up ceremony":                 {"step_up", operatorID, rowID1},
		} {
			q, args := insert("0199c0de-0000-7000-8000-0000000000ff", c.purpose, c.operator, c.enrollment)
			if _, err := db.Exec(q, args...); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}

		mustViolate(t, db, "operator_challenges_data", `INSERT INTO operator_challenges (id, purpose, operator_id, enrollment_id, data, created_at, expires_at) VALUES ($1, 'login', NULL, NULL, '\x', now(), now() + interval '5 minutes')`, "0199c0de-0000-7000-8000-0000000000fe")
	})

	t.Run("sessions", func(t *testing.T) {
		insert := `INSERT INTO operator_sessions (id, operator_id, secret_hash, created_at, last_seen_at, expires_at) VALUES ($1, $2, ` + hash + `, now(), now(), now() + interval '8 hours')`
		exec(t, db, insert, rowID1, operatorID)
		mustViolate(t, db, "operator_sessions_secret_hash_unique", insert, rowID2, operatorID)
		mustViolate(t, db, "operator_sessions_seen", `INSERT INTO operator_sessions (id, operator_id, secret_hash, created_at, last_seen_at, expires_at) VALUES ($1, $2, decode(repeat('ee', 32), 'hex'), now(), now() - interval '1 minute', now() + interval '8 hours')`, rowID2, operatorID)
		mustViolate(t, db, "operator_sessions_period", `INSERT INTO operator_sessions (id, operator_id, secret_hash, created_at, last_seen_at, expires_at) VALUES ($1, $2, decode(repeat('ee', 32), 'hex'), now(), now(), now())`, rowID2, operatorID)
	})

	t.Run("credentials", func(t *testing.T) {
		insert := func(id, credential string) (string, []any) {
			return `INSERT INTO operator_credentials (id, operator_id, credential_id, public_key, backup_eligible, backup_state, name, created_at)
				VALUES ($1, $2, $3::bytea, '\x01', true, false, 'key', now())`, []any{id, operatorID, []byte(credential)}
		}
		q, args := insert(rowID1, "credential-one")
		exec(t, db, q, args...)
		q, args = insert(rowID2, "credential-one")
		mustViolate(t, db, "operator_credentials_credential_id_unique", q, args...)
		mustViolate(t, db, "operator_credentials_name", `INSERT INTO operator_credentials (id, operator_id, credential_id, public_key, backup_eligible, backup_state, name, created_at)
			VALUES ($1, $2, '\x02', '\x01', true, false, '', now())`, rowID2, operatorID)
		mustViolate(t, db, "operator_credentials_backup", `INSERT INTO operator_credentials (id, operator_id, credential_id, public_key, backup_eligible, backup_state, name, created_at)
			VALUES ($1, $2, '\x03', '\x01', false, true, 'key', now())`, rowID2, operatorID)
	})

	t.Run("deleting an operator removes theirs and keeps the audit trail", func(t *testing.T) {
		exec(t, db, `INSERT INTO audit_events (id, operator_id, event, result, occurred_at) VALUES ($1, $2, 'admin.action', 'success', now())`, rowID1, operatorID)
		exec(t, db, `DELETE FROM operators WHERE id = $1`, operatorID)

		for _, table := range []string{"operator_credentials", "operator_enrollments", "operator_sessions"} {
			if n := count(t, db, table); n != 0 {
				t.Errorf("%s keeps %d rows of a deleted operator", table, n)
			}
		}
		// A login challenge names nobody, so it stays until it expires; a registration goes with its operator.
		var registrations int
		if err := db.QueryRow(`SELECT count(*) FROM operator_challenges WHERE purpose = 'registration'`).Scan(&registrations); err != nil || registrations != 0 {
			t.Errorf("%d registration challenges of a deleted operator remain, %v", registrations, err)
		}

		var operator sql.NullString
		if err := db.QueryRow(`SELECT operator_id FROM audit_events WHERE id = $1`, rowID1).Scan(&operator); err != nil || operator.Valid {
			t.Errorf("the audit event after the operator went: operator_id = %v, %v; want it cleared and the event kept", operator, err)
		}
	})
}

func TestUserSearchUsesThePrefixIndex(t *testing.T) {
	db := migratedDB(t)

	var found int
	if err := db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'users_email_prefix'`).Scan(&found); err != nil || found != 1 {
		t.Errorf("users_email_prefix: %d, %v", found, err)
	}
}

func TestDeviceRequestConstraints(t *testing.T) {
	db := migratedDB(t)

	const (
		id1 = "AAECAwQFBgcICQoLDA0ODw"
		id2 = "AAECAwQFBgcICQoLDA0ODx"
	)

	pending := func(id string, extra string) string {
		return `INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, attempts, created_at, expires_at` + extra + `)`
	}
	hashes := `decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex')`
	insert := func(id, name, code, state string, attempts int) (string, []any) {
		return pending(id, "") + ` VALUES ($1, ` + hashes + `, $2, $3, $4, $5, now(), now() + interval '5 minutes')`, []any{id, name, code, state, attempts}
	}
	q, args := insert(id1, "laptop", "123456", "pending", 0)
	exec(t, db, q, args...)

	q, args = insert(id1, "laptop", "123456", "pending", 0)
	if _, err := db.Exec(q, args...); err == nil {
		t.Error("a repeated request id was accepted")
	}

	for name, c := range map[string]struct {
		id, name, code, state string
		attempts              int
		constraint            string
	}{
		"short id":       {"abc", "x", "123456", "pending", 0, "device_requests_id"},
		"id with a dot":  {"AAECAwQFBgcICQoLDA0OD.", "x", "123456", "pending", 0, "device_requests_id"},
		"long name":      {id2, strings.Repeat("x", 65), "123456", "pending", 0, "device_requests_device_name"},
		"short code":     {id2, "x", "12345", "pending", 0, "device_requests_pairing_code"},
		"lettered code":  {id2, "x", "12345a", "pending", 0, "device_requests_pairing_code"},
		"unknown state":  {id2, "x", "123456", "weird", 0, "device_requests_state"},
		"attempts":       {id2, "x", "123456", "pending", 4, "device_requests_attempts"},
		"approved alone": {id2, "x", "123456", "approved", 0, "device_requests_approver"},
		"redeemed alone": {id2, "x", "123456", "redeemed", 0, "device_requests_approver"},
	} {
		q, args := insert(c.id, c.name, c.code, c.state, c.attempts)
		mustViolate(t, db, c.constraint, q, args...)

		_ = name
	}

	mustViolate(t, db, "device_requests_poll_hash", `INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, created_at, expires_at)
		VALUES ($1, '\x00', decode(repeat('cd', 32), 'hex'), 'x', '123456', 'pending', now(), now() + interval '5 minutes')`, id2)
	mustViolate(t, db, "device_requests_period", `INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, created_at, expires_at)
		VALUES ($1, `+hashes+`, 'x', '123456', 'pending', now(), now())`, id2)

	// An approver is for an approved or redeemed request only, and the approving session may go.
	exec(t, db, `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'u@example.test', now(), now(), now())`, userID)
	mustViolate(t, db, "device_requests_approver_only_when_approved", `INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, user_id, created_at, expires_at)
		VALUES ($1, `+hashes+`, 'x', '123456', 'pending', $2, now(), now() + interval '5 minutes')`, id2, userID)
	exec(t, db, `INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, user_id, decided_at, created_at, expires_at)
		VALUES ($1, `+hashes+`, 'x', '123456', 'approved', $2, now(), now(), now() + interval '5 minutes')`, id2, userID)
	mustViolate(t, db, "device_requests_redeemed", `UPDATE device_requests SET state = 'redeemed' WHERE id = $1`, id2)
	exec(t, db, `UPDATE device_requests SET state = 'redeemed', redeemed_at = now() WHERE id = $1`, id2)

	// Deleting the approving user removes the request, and only theirs.
	exec(t, db, `DELETE FROM users WHERE id = $1`, userID)

	if n := count(t, db, "device_requests"); n != 1 {
		t.Errorf("%d requests after the approver was deleted, want only the pending one", n)
	}

	// The step-up operations accept approve_device now.
	exec(t, db, `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'v@example.test', now(), now(), now())`, userID2)
}
