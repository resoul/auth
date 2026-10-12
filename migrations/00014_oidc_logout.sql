-- +goose Up
-- Ending a sign-in: where a client is sent back after RP-initiated logout, where the provider tells it that a sign-in
-- ended (back-channel logout), which device session of the /v1 API a shared sign-in grew from, and the queue of those
-- notices. A notice is queued in the same transaction that revokes the grants, so it exists exactly when they were ended;
-- it is delivered after the commit, and again if the client was down.

ALTER TABLE oidc_clients
    ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    ADD COLUMN backchannel_logout_uri    text,
    ADD CONSTRAINT oidc_clients_post_logout CHECK (cardinality(post_logout_redirect_uris) <= 10),
    ADD CONSTRAINT oidc_clients_backchannel CHECK (backchannel_logout_uri IS NULL OR char_length(backchannel_logout_uri) <= 2048);

-- The device session (of the /v1 API) whose access token proved the sign-in. Ending the shared sign-in ends it too, so
-- a browser that signed out of everything is not left with a live session of the sign-in page. A deleted session blanks
-- the link and nothing more.
ALTER TABLE oidc_op_sessions
    ADD COLUMN device_session_id uuid REFERENCES sessions (id) ON DELETE SET NULL;

CREATE TABLE oidc_logout_outbox (
    -- Also the jti of the logout token, so a client that gets the notice twice can tell it is the same one.
    id            uuid        PRIMARY KEY,
    client_id     text        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The sid of the ended sign-in. No foreign key: the session may be cleaned up before the notice is delivered.
    op_session_id uuid        NOT NULL,
    status        text        NOT NULL DEFAULT 'queued',
    attempts      integer     NOT NULL DEFAULT 0,
    available_at  timestamptz NOT NULL,
    lease_until   timestamptz,
    -- After this the notice is given up on: the client's own session has outlived its usefulness by then.
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL,
    -- A short code, never a response body or an address.
    last_error    text,
    CONSTRAINT oidc_logout_status CHECK (status IN ('queued', 'sent', 'dead')),
    CONSTRAINT oidc_logout_attempts CHECK (attempts >= 0),
    CONSTRAINT oidc_logout_period CHECK (expires_at > created_at),
    CONSTRAINT oidc_logout_error CHECK (last_error IS NULL OR last_error ~ '^[a-z][a-z0-9_]{0,63}$')
);
CREATE INDEX oidc_logout_due ON oidc_logout_outbox (available_at) WHERE status = 'queued';
CREATE INDEX oidc_logout_finished ON oidc_logout_outbox (created_at) WHERE status <> 'queued';

-- +goose Down
DROP TABLE oidc_logout_outbox;
ALTER TABLE oidc_op_sessions DROP COLUMN device_session_id;
ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_backchannel,
    DROP CONSTRAINT oidc_clients_post_logout,
    DROP COLUMN backchannel_logout_uri,
    DROP COLUMN post_logout_redirect_uris;
