-- +goose Up
-- Audit events. Policy: kept 90 days, anonymized by clearing the references when a
-- user is deleted; fields hold short codes only.

CREATE TABLE audit_events (
    id          uuid        PRIMARY KEY,
    -- No cascade: deleting a user or a session keeps the event and clears the reference.
    user_id     uuid        REFERENCES users (id) ON DELETE SET NULL,
    session_id  uuid        REFERENCES sessions (id) ON DELETE SET NULL,
    event       text        NOT NULL,
    result      text        NOT NULL,
    occurred_at timestamptz NOT NULL,
    -- Allowed short codes only: never an email, IP, User-Agent or secret.
    fields      jsonb       NOT NULL DEFAULT '{}',
    CONSTRAINT audit_events_event CHECK (event ~ '^[a-z][a-z0-9_.]{0,63}$'),
    CONSTRAINT audit_events_result CHECK (result IN ('success', 'denied')),
    CONSTRAINT audit_events_fields CHECK (jsonb_typeof(fields) = 'object')
);

-- Retention sweep and the foreign keys' SET NULL lookups.
CREATE INDEX audit_events_occurred_at ON audit_events (occurred_at);
CREATE INDEX audit_events_user_id ON audit_events (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX audit_events_session_id ON audit_events (session_id) WHERE session_id IS NOT NULL;

-- +goose Down
DROP TABLE audit_events;
