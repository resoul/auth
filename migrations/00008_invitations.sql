-- +goose Up
-- Invite-only registration grants an address permission to create an account. It carries no
-- secret; the row is removed when the account is created or long after the invitation expires.
CREATE TABLE invitations (
    email      text        PRIMARY KEY,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT invitations_email_normalized CHECK (email = lower(btrim(email)) AND email <> ''),
    CONSTRAINT invitations_period CHECK (expires_at > created_at)
);

CREATE INDEX invitations_expires_at ON invitations (expires_at);

-- +goose Down
DROP TABLE invitations;
