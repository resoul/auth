-- +goose Up
-- Operators are separate from users and share no table
-- with them. Secrets are never stored: an enrollment code and a session keep a SHA-256 of the secret.

-- A blocked user keeps the account and loses every session; no new session is issued until unblocked.
ALTER TABLE users ADD COLUMN blocked_at timestamptz;

-- The operator's search by the start of an address; ordering uses the C collation, so the index only narrows it.
CREATE INDEX users_email_prefix ON users (email text_pattern_ops);

CREATE TABLE operators (
    id          uuid        PRIMARY KEY,
    -- A label for lists and the audit log; nothing is sent to it.
    email       text        NOT NULL,
    created_at  timestamptz NOT NULL,
    disabled_at timestamptz,
    CONSTRAINT operators_email_normalized CHECK (email = lower(btrim(email)) AND email <> ''),
    CONSTRAINT operators_email_unique UNIQUE (email)
);

CREATE TABLE operator_credentials (
    id              uuid        PRIMARY KEY,
    operator_id     uuid        NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    credential_id   bytea       NOT NULL,
    public_key      bytea       NOT NULL,
    aaguid          bytea,
    transports      text[]      NOT NULL DEFAULT '{}',
    sign_count      bigint      NOT NULL DEFAULT 0,
    backup_eligible boolean     NOT NULL,
    backup_state    boolean     NOT NULL,
    name            text        NOT NULL,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    CONSTRAINT operator_credentials_credential_id_unique UNIQUE (credential_id),
    CONSTRAINT operator_credentials_credential_id_length CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT operator_credentials_public_key CHECK (octet_length(public_key) > 0),
    CONSTRAINT operator_credentials_aaguid CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
    CONSTRAINT operator_credentials_sign_count CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT operator_credentials_backup CHECK (backup_eligible OR NOT backup_state),
    CONSTRAINT operator_credentials_name CHECK (char_length(name) BETWEEN 1 AND 64)
);

CREATE INDEX operator_credentials_operator ON operator_credentials (operator_id, created_at, id);

-- The one-time code that registers a key, printed once on the server.
CREATE TABLE operator_enrollments (
    id          uuid        PRIMARY KEY,
    operator_id uuid        NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    code_hash   bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT operator_enrollments_code_hash_unique UNIQUE (code_hash),
    CONSTRAINT operator_enrollments_code_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT operator_enrollments_period CHECK (expires_at > created_at)
);

CREATE INDEX operator_enrollments_operator ON operator_enrollments (operator_id);
CREATE INDEX operator_enrollments_expires_at ON operator_enrollments (expires_at);

-- The state of a ceremony between its two requests. A registration is for one operator and one
-- enrollment; a login names no operator until the assertion names the key.
CREATE TABLE operator_challenges (
    id            uuid        PRIMARY KEY,
    purpose       text        NOT NULL,
    operator_id   uuid        REFERENCES operators (id) ON DELETE CASCADE,
    enrollment_id uuid        REFERENCES operator_enrollments (id) ON DELETE CASCADE,
    data          bytea       NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    CONSTRAINT operator_challenges_shape CHECK (
        (purpose = 'registration' AND operator_id IS NOT NULL AND enrollment_id IS NOT NULL)
        OR (purpose = 'login' AND operator_id IS NULL AND enrollment_id IS NULL)
    ),
    CONSTRAINT operator_challenges_data CHECK (octet_length(data) BETWEEN 1 AND 8192),
    CONSTRAINT operator_challenges_period CHECK (expires_at > created_at)
);

CREATE INDEX operator_challenges_expires_at ON operator_challenges (expires_at);
CREATE INDEX operator_challenges_enrollment ON operator_challenges (enrollment_id) WHERE enrollment_id IS NOT NULL;
CREATE INDEX operator_challenges_operator ON operator_challenges (operator_id) WHERE operator_id IS NOT NULL;

CREATE TABLE operator_sessions (
    id           uuid        PRIMARY KEY,
    operator_id  uuid        NOT NULL REFERENCES operators (id) ON DELETE CASCADE,
    secret_hash  bytea       NOT NULL,
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    CONSTRAINT operator_sessions_secret_hash_unique UNIQUE (secret_hash),
    CONSTRAINT operator_sessions_secret_hash_length CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT operator_sessions_seen CHECK (last_seen_at >= created_at),
    CONSTRAINT operator_sessions_period CHECK (expires_at > created_at)
);

CREATE INDEX operator_sessions_operator ON operator_sessions (operator_id);
-- The retention sweep.
CREATE INDEX operator_sessions_created_at ON operator_sessions (created_at);

-- Who did an administrative act. Like the other references it is cleared, not cascaded, when the row goes.
ALTER TABLE audit_events ADD COLUMN operator_id uuid REFERENCES operators (id) ON DELETE SET NULL;
CREATE INDEX audit_events_operator_id ON audit_events (operator_id) WHERE operator_id IS NOT NULL;
-- The admin listing: newest first, with the ID as the tie-breaker of the cursor.
CREATE INDEX audit_events_listing ON audit_events (occurred_at DESC, id DESC);

-- +goose Down
DROP INDEX audit_events_listing;
DROP INDEX audit_events_operator_id;
ALTER TABLE audit_events DROP COLUMN operator_id;
DROP TABLE operator_sessions;
DROP TABLE operator_challenges;
DROP TABLE operator_enrollments;
DROP TABLE operator_credentials;
DROP TABLE operators;
DROP INDEX users_email_prefix;
ALTER TABLE users DROP COLUMN blocked_at;
