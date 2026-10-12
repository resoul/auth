-- +goose Up
-- Sessions and refresh tokens. Ended sessions are retained for seven days.

CREATE TABLE sessions (
    id              uuid        PRIMARY KEY,
    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    binding_hash    bytea       NOT NULL,
    amr             text[]      NOT NULL,
    auth_time       timestamptz NOT NULL,
    -- A label chosen by the client. No IP or User-Agent is stored.
    device_name     text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL,
    last_active_at  timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    CONSTRAINT sessions_binding_length CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT sessions_amr CHECK (cardinality(amr) >= 1 AND '' <> ALL (amr)),
    CONSTRAINT sessions_device_name CHECK (char_length(device_name) <= 64),
    CONSTRAINT sessions_auth_time CHECK (auth_time <= created_at),
    CONSTRAINT sessions_activity CHECK (last_active_at >= created_at),
    -- The idle limit never passes the absolute limit.
    CONSTRAINT sessions_lifetimes CHECK (expires_at > created_at AND idle_expires_at > created_at AND idle_expires_at <= expires_at)
);

CREATE INDEX sessions_user_id ON sessions (user_id);
-- Cleanup: a session has ended at the earliest of these; each is indexed for the sweeper.
CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX sessions_idle_expires_at ON sessions (idle_expires_at);
CREATE INDEX sessions_revoked_at ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY,
    session_id uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    family_id  uuid        NOT NULL,
    -- The token this one replaced; NULL for the first token of a family.
    parent_id  uuid        REFERENCES refresh_tokens (id) ON DELETE CASCADE,
    -- SHA-256 of the secret; the secret itself is never stored.
    token_hash bytea       NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    CONSTRAINT refresh_tokens_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_hash_unique UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_period CHECK (expires_at > created_at),
    CONSTRAINT refresh_tokens_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id)
);

-- A parent may have only one child that is not revoked: two live children would
-- mean a token was exchanged twice.
CREATE UNIQUE INDEX refresh_one_live_child ON refresh_tokens (parent_id) WHERE revoked_at IS NULL;

CREATE INDEX refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_family_id ON refresh_tokens (family_id);
-- Lets the cascade from a deleted parent find its children.
CREATE INDEX refresh_tokens_parent_id ON refresh_tokens (parent_id) WHERE parent_id IS NOT NULL;

-- +goose Down
DROP TABLE refresh_tokens;
DROP TABLE sessions;
