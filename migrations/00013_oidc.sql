-- +goose Up
-- The OpenID Provider: registered clients, the browser's pending authorization requests, the shared sign-in
-- session (OP session), the grants a client holds on it, one-time authorization codes and rotating refresh tokens.
-- Secrets (client secrets, request ids, SSO cookies, codes, refresh tokens) are random 256-bit values stored only as
-- their SHA-256. Deleting a user removes everything of theirs; disabling or deleting a client removes its grants.

CREATE TABLE oidc_clients (
    -- The public identifier: lower-case letters, digits, '-' and '_' only, so it can also be an audit value.
    id             text        PRIMARY KEY,
    name           text        NOT NULL,
    status         text        NOT NULL DEFAULT 'active',
    redirect_uris  text[]      NOT NULL,
    allowed_scopes text[]      NOT NULL,
    -- A first-party client: the user's consent is implied. Third-party consent is not implemented, so a client
    -- that is not trusted is refused at registration; the column keeps the decision visible.
    trusted        boolean     NOT NULL,
    -- Raised whenever the client's rights change; a grant made under an older version keeps its own scopes.
    policy_version integer     NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    CONSTRAINT oidc_clients_id CHECK (id ~ '^[a-z][a-z0-9_-]{2,63}$'),
    CONSTRAINT oidc_clients_name CHECK (name <> '' AND char_length(name) <= 100),
    CONSTRAINT oidc_clients_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oidc_clients_redirects CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
    CONSTRAINT oidc_clients_scopes CHECK (cardinality(allowed_scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (allowed_scopes)),
    CONSTRAINT oidc_clients_trusted CHECK (trusted),
    CONSTRAINT oidc_clients_policy CHECK (policy_version >= 1)
);

-- At most two live secrets per client, so a rotation can overlap the old and the new one.
CREATE TABLE oidc_client_secrets (
    id          uuid        PRIMARY KEY,
    client_id   text        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    secret_hash bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    -- The end of an overlap during a rotation; NULL until one is set.
    expires_at  timestamptz,
    revoked_at  timestamptz,
    CONSTRAINT oidc_client_secrets_hash CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT oidc_client_secrets_hash_unique UNIQUE (secret_hash)
);
CREATE INDEX oidc_client_secrets_client ON oidc_client_secrets (client_id);

-- What a browser asked for, kept on the server while the user signs in. The page that signs the user in carries
-- only the opaque id (stored as a hash), and the request is usable only by the browser that holds the cookie
-- whose hash is binding_hash.
CREATE TABLE oidc_authorization_requests (
    id_hash        bytea       PRIMARY KEY,
    binding_hash   bytea       NOT NULL,
    client_id      text        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    scopes         text[]      NOT NULL,
    state          text        NOT NULL,
    nonce          text        NOT NULL,
    code_challenge text        NOT NULL,
    -- prompt=login or max_age=0: only an authentication after created_at will do.
    fresh_login    boolean     NOT NULL,
    max_age        integer,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    completed_at   timestamptz,
    CONSTRAINT oidc_requests_id_hash CHECK (octet_length(id_hash) = 32),
    CONSTRAINT oidc_requests_binding_hash CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT oidc_requests_challenge CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT oidc_requests_max_age CHECK (max_age IS NULL OR max_age >= 0),
    CONSTRAINT oidc_requests_period CHECK (expires_at > created_at)
);
CREATE INDEX oidc_requests_expires_at ON oidc_authorization_requests (expires_at);

-- The sign-in shared by every application: proved once, remembered by a cookie of the auth host only.
CREATE TABLE oidc_op_sessions (
    id           uuid        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    secret_hash  bytea       NOT NULL,
    -- When the user really authenticated, and how; carried into every ID Token of this session.
    auth_time    timestamptz NOT NULL,
    amr          text[]      NOT NULL,
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    CONSTRAINT oidc_op_sessions_hash CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT oidc_op_sessions_hash_unique UNIQUE (secret_hash),
    CONSTRAINT oidc_op_sessions_amr CHECK (cardinality(amr) BETWEEN 1 AND 8),
    CONSTRAINT oidc_op_sessions_period CHECK (expires_at > created_at)
);
CREATE INDEX oidc_op_sessions_user ON oidc_op_sessions (user_id);
CREATE INDEX oidc_op_sessions_expires_at ON oidc_op_sessions (expires_at);

-- What one client may do for one user on one OP session. Refresh tokens belong to the grant, so ending the grant
-- ends them; a grant never outlives its OP session.
CREATE TABLE oidc_grants (
    id             uuid        PRIMARY KEY,
    client_id      text        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    op_session_id  uuid        NOT NULL REFERENCES oidc_op_sessions (id) ON DELETE CASCADE,
    scopes         text[]      NOT NULL,
    policy_version integer     NOT NULL,
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    CONSTRAINT oidc_grants_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 10),
    CONSTRAINT oidc_grants_period CHECK (expires_at > created_at)
);
-- A client holds one live grant per OP session: a second sign-in of the same session reuses it.
CREATE UNIQUE INDEX oidc_grants_live ON oidc_grants (client_id, op_session_id) WHERE revoked_at IS NULL;
CREATE INDEX oidc_grants_user ON oidc_grants (user_id);
CREATE INDEX oidc_grants_op_session ON oidc_grants (op_session_id);

CREATE TABLE oidc_authorization_codes (
    code_hash      bytea       PRIMARY KEY,
    grant_id       uuid        NOT NULL REFERENCES oidc_grants (id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    code_challenge text        NOT NULL,
    nonce          text        NOT NULL,
    scopes         text[]      NOT NULL,
    auth_time      timestamptz NOT NULL,
    amr            text[]      NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CONSTRAINT oidc_codes_hash CHECK (octet_length(code_hash) = 32),
    CONSTRAINT oidc_codes_challenge CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT oidc_codes_period CHECK (expires_at > created_at)
);
CREATE INDEX oidc_codes_grant ON oidc_authorization_codes (grant_id);
CREATE INDEX oidc_codes_expires_at ON oidc_authorization_codes (expires_at);

-- The refresh tokens of a grant form one chain: each is exchanged once for its single successor. A token that is
-- exchanged again is a replay, and the grant is revoked.
CREATE TABLE oidc_refresh_tokens (
    id         uuid        PRIMARY KEY,
    grant_id   uuid        NOT NULL REFERENCES oidc_grants (id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    parent_id  uuid        REFERENCES oidc_refresh_tokens (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    CONSTRAINT oidc_refresh_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT oidc_refresh_hash_unique UNIQUE (token_hash),
    CONSTRAINT oidc_refresh_period CHECK (expires_at > created_at)
);
-- One successor per token, whatever the interleaving.
CREATE UNIQUE INDEX oidc_refresh_one_child ON oidc_refresh_tokens (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX oidc_refresh_grant ON oidc_refresh_tokens (grant_id);
CREATE INDEX oidc_refresh_expires_at ON oidc_refresh_tokens (expires_at);

-- +goose Down
DROP TABLE oidc_refresh_tokens;
DROP TABLE oidc_authorization_codes;
DROP TABLE oidc_grants;
DROP TABLE oidc_op_sessions;
DROP TABLE oidc_authorization_requests;
DROP TABLE oidc_client_secrets;
DROP TABLE oidc_clients;
