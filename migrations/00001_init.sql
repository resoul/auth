-- +goose Up
-- Retention and delete policies are enforced by the periodic cleanup process.
-- Sessions, refresh tokens, audit and rate-limit tables arrive with the tasks that own them.

CREATE TABLE users (
    id                uuid        PRIMARY KEY,
    email             text        NOT NULL,
    email_verified_at timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    -- Emails are stored normalized: trimmed and lower-case.
    CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email)) AND email <> ''),
    CONSTRAINT users_email_unique UNIQUE (email)
);

-- One record per (user, binding). Deleting a user deletes the records.
CREATE TABLE recognized_clients (
    id           uuid        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email        text        NOT NULL,
    binding_hash bytea       NOT NULL,
    verified_at  timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    CONSTRAINT recognized_clients_email_normalized CHECK (email = lower(btrim(email)) AND email <> ''),
    CONSTRAINT recognized_clients_binding_length CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT recognized_clients_period CHECK (expires_at > verified_at),
    CONSTRAINT recognized_clients_pair_unique UNIQUE (user_id, binding_hash)
);

-- Start looks a client up by confirmed email and binding.
CREATE INDEX recognized_clients_lookup ON recognized_clients (email, binding_hash);
-- Cleanup: records ended long enough ago (expiry or revocation, whichever is earlier).
CREATE INDEX recognized_clients_expires_at ON recognized_clients (expires_at);
CREATE INDEX recognized_clients_revoked_at ON recognized_clients (revoked_at) WHERE revoked_at IS NOT NULL;

-- A flow exists before any user does, so it references an email, not a user.
CREATE TABLE auth_flows (
    id                   text        PRIMARY KEY,
    email                text        NOT NULL,
    purpose              text        NOT NULL,
    generation           bigint      NOT NULL,
    salt                 bytea,
    key_id               text        NOT NULL,
    binding_hash         bytea       NOT NULL,
    state                text        NOT NULL,
    created_at           timestamptz NOT NULL,
    expires_at           timestamptz NOT NULL,
    attempts             integer     NOT NULL,
    resend_after         timestamptz NOT NULL,
    quota_class          text        NOT NULL,
    recognized_client_id uuid        REFERENCES recognized_clients (id) ON DELETE CASCADE,
    -- Flow IDs are 16 random bytes in unpadded base64url.
    CONSTRAINT auth_flows_id_format CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
    CONSTRAINT auth_flows_email_normalized CHECK (email = lower(btrim(email)) AND email <> ''),
    CONSTRAINT auth_flows_purpose CHECK (purpose IN ('login', 'step_up', 'change_email')),
    CONSTRAINT auth_flows_generation CHECK (generation >= 1),
    CONSTRAINT auth_flows_key_id CHECK (key_id <> ''),
    CONSTRAINT auth_flows_binding_length CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT auth_flows_state CHECK (state IN ('pending', 'consumed', 'locked', 'expired')),
    CONSTRAINT auth_flows_period CHECK (expires_at > created_at),
    CONSTRAINT auth_flows_attempts CHECK (attempts >= 0),
    CONSTRAINT auth_flows_quota_class CHECK (quota_class IN ('unknown', 'recognized')),
    -- The salt exists exactly while the flow is pending, and has the fixed length.
    CONSTRAINT auth_flows_salt CHECK ((state = 'pending') = (salt IS NOT NULL) AND (salt IS NULL OR octet_length(salt) = 16)),
    -- A recognized flow names its recognized client; an unknown flow does not.
    CONSTRAINT auth_flows_recognized_client CHECK ((quota_class = 'recognized') = (recognized_client_id IS NOT NULL))
);

-- Cleanup deletes flows of every state once expires_at is old enough.
CREATE INDEX auth_flows_expires_at ON auth_flows (expires_at);
CREATE INDEX auth_flows_recognized_client ON auth_flows (recognized_client_id) WHERE recognized_client_id IS NOT NULL;

-- Mail jobs. The code is never stored: the worker derives it from the flow.
-- The worker task may extend job statuses and retry columns with a new migration.
CREATE TABLE outbox (
    id          uuid        PRIMARY KEY,
    flow_id     text        NOT NULL REFERENCES auth_flows (id) ON DELETE CASCADE,
    generation  bigint      NOT NULL,
    quota_class text        NOT NULL,
    status      text        NOT NULL DEFAULT 'queued',
    attempts    integer     NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL,
    lease_until timestamptz,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT outbox_generation CHECK (generation >= 1),
    CONSTRAINT outbox_quota_class CHECK (quota_class IN ('unknown', 'recognized')),
    CONSTRAINT outbox_status CHECK (status IN ('queued', 'sent', 'dead')),
    CONSTRAINT outbox_attempts CHECK (attempts >= 0),
    -- Only a safe reason code is kept, never a message that could contain a code or address.
    CONSTRAINT outbox_last_error CHECK (last_error IS NULL OR length(last_error) <= 64),
    -- One job per flow generation: enqueueing the same generation twice is a conflict.
    CONSTRAINT outbox_flow_generation_unique UNIQUE (flow_id, generation)
);

-- Ready jobs, ordered for the worker, split by quota class so recognized clients keep their reserve.
CREATE INDEX outbox_ready ON outbox (quota_class, available_at) WHERE status = 'queued';

-- +goose Down
DROP TABLE outbox;
DROP TABLE auth_flows;
DROP TABLE recognized_clients;
DROP TABLE users;
