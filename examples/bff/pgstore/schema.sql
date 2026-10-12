-- The tables of the BFF's store. Everything is idempotent: Migrate may run at every start. A tenant that owns its migrations
-- copies this file into them.

-- A sign-in in progress: used once, by the browser that began it, for a few minutes.
CREATE TABLE IF NOT EXISTS bff_logins (
    key        text        PRIMARY KEY,
    state      text        NOT NULL,
    nonce      text        NOT NULL,
    verifier   text        NOT NULL,
    return_to  text        NOT NULL,
    started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS bff_logins_expires ON bff_logins (expires_at);

-- The application's own profile of a person: keyed by the pair (issuer, subject), never by an email.
CREATE TABLE IF NOT EXISTS bff_users (
    id      text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    issuer  text NOT NULL,
    subject text NOT NULL,
    UNIQUE (issuer, subject)
);

-- A signed-in browser. Everything that could be presented to someone else is sealed (the Vault); the key is the hash of the
-- cookie, never the cookie.
CREATE TABLE IF NOT EXISTS bff_sessions (
    key              text        PRIMARY KEY,
    user_id          text        NOT NULL,
    issuer           text        NOT NULL,
    subject          text        NOT NULL,
    provider_session text        NOT NULL,
    id_token_sealed  text        NOT NULL,
    refresh_sealed   text        NOT NULL,
    access           jsonb       NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL,
    sign_in_started  timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    -- Set, and committed, before the provider is asked to rotate the refresh token; cleared with the result. If it is still
    -- set when the next request takes the session, the outcome of that refresh is unknown and the old token must not be used.
    refresh_started_at timestamptz
);
ALTER TABLE bff_sessions ADD COLUMN IF NOT EXISTS refresh_started_at timestamptz;
CREATE INDEX IF NOT EXISTS bff_sessions_provider ON bff_sessions (issuer, provider_session);
CREATE INDEX IF NOT EXISTS bff_sessions_expires ON bff_sessions (expires_at);

-- The logout notices handled, by jti, so a delivery repeated for a day is answered and not applied twice.
CREATE TABLE IF NOT EXISTS bff_logout_seen (
    issuer text        NOT NULL,
    jti    text        NOT NULL,
    until  timestamptz NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE INDEX IF NOT EXISTS bff_logout_seen_until ON bff_logout_seen (until);

-- Sign-ins the provider ended, and when: a sign-in that began at or before that moment must not become a session.
CREATE TABLE IF NOT EXISTS bff_ended (
    issuer text        NOT NULL,
    sid    text        NOT NULL,
    at     timestamptz NOT NULL,
    PRIMARY KEY (issuer, sid)
);
CREATE INDEX IF NOT EXISTS bff_ended_at ON bff_ended (at);
