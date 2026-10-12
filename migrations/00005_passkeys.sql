-- +goose Up
-- The strong factor: WebAuthn credentials, the state of ceremonies, the tickets that carry a
-- sign-in between two requests and the recovery codes.
-- Secrets are never stored: a ticket and a recovery code keep a SHA-256 of the secret.

CREATE TABLE passkey_credentials (
    id              uuid        PRIMARY KEY,
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The WebAuthn credential ID; unique across all users.
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
    CONSTRAINT passkey_credentials_credential_id_unique UNIQUE (credential_id),
    CONSTRAINT passkey_credentials_credential_id_length CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT passkey_credentials_public_key CHECK (octet_length(public_key) > 0),
    CONSTRAINT passkey_credentials_aaguid CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
    CONSTRAINT passkey_credentials_sign_count CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT passkey_credentials_backup CHECK (backup_eligible OR NOT backup_state),
    CONSTRAINT passkey_credentials_name CHECK (char_length(name) BETWEEN 1 AND 64)
);

-- Listing a user's keys, oldest first.
CREATE INDEX passkey_credentials_user ON passkey_credentials (user_id, created_at, id);

CREATE TABLE passkey_challenges (
    id          uuid        PRIMARY KEY,
    purpose     text        NOT NULL,
    -- NULL only for a discoverable login, which learns the user from the assertion.
    user_id     uuid        REFERENCES users (id) ON DELETE CASCADE,
    ticket_id   uuid,
    -- Only a step-up challenge has a session and an operation: the proof is good for that pair alone.
    session_id  uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    operation   text,
    data        bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT passkey_challenges_purpose CHECK (purpose IN ('registration', 'login', 'step_up')),
    CONSTRAINT passkey_challenges_user CHECK (purpose = 'login' OR user_id IS NOT NULL),
    CONSTRAINT passkey_challenges_step_up CHECK (
        (purpose = 'step_up' AND session_id IS NOT NULL AND operation IS NOT NULL)
        OR (purpose <> 'step_up' AND session_id IS NULL AND operation IS NULL)
    ),
    CONSTRAINT passkey_challenges_operation CHECK (operation IS NULL OR operation IN
        ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account')),
    CONSTRAINT passkey_challenges_data CHECK (octet_length(data) BETWEEN 1 AND 8192),
    CONSTRAINT passkey_challenges_period CHECK (expires_at > created_at)
);

-- The retention sweep.
CREATE INDEX passkey_challenges_expires_at ON passkey_challenges (expires_at);
-- Lets the cascade from a deleted session find its step-up challenges.
CREATE INDEX passkey_challenges_session ON passkey_challenges (session_id) WHERE session_id IS NOT NULL;

CREATE TABLE auth_tickets (
    id           uuid        PRIMARY KEY,
    kind         text        NOT NULL,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Only a step-up ticket has a session and an operation; only the others have a binding.
    session_id   uuid        REFERENCES sessions (id) ON DELETE CASCADE,
    operation    text,
    binding_hash bytea,
    secret_hash  bytea       NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    CONSTRAINT auth_tickets_secret_hash_unique UNIQUE (secret_hash),
    CONSTRAINT auth_tickets_secret_hash_length CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT auth_tickets_binding_length CHECK (binding_hash IS NULL OR octet_length(binding_hash) = 32),
    CONSTRAINT auth_tickets_kind CHECK (kind IN ('enroll', 'second_factor', 'recovery_enroll', 'step_up')),
    CONSTRAINT auth_tickets_shape CHECK (
        (kind = 'step_up' AND session_id IS NOT NULL AND operation IS NOT NULL AND binding_hash IS NULL)
        OR (kind <> 'step_up' AND session_id IS NULL AND operation IS NULL AND binding_hash IS NOT NULL)
    ),
    CONSTRAINT auth_tickets_operation CHECK (operation IS NULL OR operation IN
        ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account')),
    CONSTRAINT auth_tickets_period CHECK (expires_at > created_at)
);

CREATE INDEX auth_tickets_user ON auth_tickets (user_id);
CREATE INDEX auth_tickets_expires_at ON auth_tickets (expires_at);
-- Lets the cascade from a deleted session find its step-up tickets.
CREATE INDEX auth_tickets_session ON auth_tickets (session_id) WHERE session_id IS NOT NULL;

CREATE TABLE recovery_codes (
    id         uuid        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  bytea       NOT NULL,
    created_at timestamptz NOT NULL,
    used_at    timestamptz,
    CONSTRAINT recovery_codes_hash_unique UNIQUE (code_hash),
    CONSTRAINT recovery_codes_hash_length CHECK (octet_length(code_hash) = 32)
);

CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

-- +goose Down
DROP TABLE recovery_codes;
DROP TABLE auth_tickets;
DROP TABLE passkey_challenges;
DROP TABLE passkey_credentials;
