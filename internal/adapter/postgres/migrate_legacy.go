package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// legacyVersionTable is goose's default table name, which earlier releases used.
const legacyVersionTable = "goose_db_version"

// legacyFingerprint is a table only this service creates. A goose_db_version next to it is
// ours; without it the table may belong to another service in a shared schema.
const legacyFingerprint = "auth_flows"

// migrationLockKey serializes the adoption between concurrent migrate processes.
const migrationLockKey int64 = 0x61697261757468 // "airauth"

// adoptLegacyVersionTable carries the history of earlier releases over to VersionTable. Without
// it a database migrated before the rename would look unmigrated, and the first migration
// would fail on tables that already exist. The old table is copied, not renamed or dropped: it
// may be shared, and an older binary keeps working against it.
func adoptLegacyVersionTable(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("adopt version table: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("adopt version table: lock: %w", err)
	}

	has := func(table string) (bool, error) {
		var ok bool

		err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND tablename = $1)`, table).Scan(&ok)

		return ok, err
	}

	current, err := has(VersionTable)
	if err != nil {
		return fmt.Errorf("adopt version table: %w", err)
	}

	if current {
		return nil
	}

	legacy, err := has(legacyVersionTable)
	if err != nil {
		return fmt.Errorf("adopt version table: %w", err)
	}

	ours, err := has(legacyFingerprint)
	if err != nil {
		return fmt.Errorf("adopt version table: %w", err)
	}

	if !legacy || !ours {
		return nil
	}
	// The layout is the one goose creates itself.
	if _, err := tx.ExecContext(ctx, `CREATE TABLE `+VersionTable+` (
		id         serial    NOT NULL PRIMARY KEY,
		version_id bigint    NOT NULL,
		is_applied boolean   NOT NULL,
		tstamp     timestamp NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("adopt version table: create: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO `+VersionTable+` (version_id, is_applied, tstamp)
		SELECT version_id, is_applied, tstamp FROM `+legacyVersionTable+` ORDER BY id`); err != nil {
		return fmt.Errorf("adopt version table: copy: %w", err)
	}

	return tx.Commit()
}
