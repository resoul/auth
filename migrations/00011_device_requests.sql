-- +goose Up
-- Sign-in on one device approved by another. The request id is what a QR code
-- carries; the poll secret and the client binding are stored as hashes, the pairing code is not a secret of the
-- server (the new device shows it, the approving device types it, three wrong tries kill the request).

CREATE TABLE device_requests (
    -- 16 random bytes in unpadded base64url.
    id           text        PRIMARY KEY,
    poll_hash    bytea       NOT NULL,
    binding_hash bytea       NOT NULL,
    device_name  text        NOT NULL,
    pairing_code text        NOT NULL,
    state        text        NOT NULL,
    attempts     smallint    NOT NULL DEFAULT 0,
    -- The approver. Deleting the user removes the request; ending the approving session only blanks the link,
    -- and a redemption then finds no live session and is refused.
    user_id      uuid        REFERENCES users (id) ON DELETE CASCADE,
    session_id   uuid        REFERENCES sessions (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    decided_at   timestamptz,
    redeemed_at  timestamptz,
    CONSTRAINT device_requests_id CHECK (id ~ '^[A-Za-z0-9_-]{22}$'),
    CONSTRAINT device_requests_poll_hash CHECK (octet_length(poll_hash) = 32),
    CONSTRAINT device_requests_binding_hash CHECK (octet_length(binding_hash) = 32),
    CONSTRAINT device_requests_device_name CHECK (char_length(device_name) <= 64),
    CONSTRAINT device_requests_pairing_code CHECK (pairing_code ~ '^[0-9]{6}$'),
    CONSTRAINT device_requests_state CHECK (state IN ('pending', 'approved', 'denied', 'redeemed')),
    CONSTRAINT device_requests_attempts CHECK (attempts BETWEEN 0 AND 3),
    CONSTRAINT device_requests_period CHECK (expires_at > created_at),
    -- Only an approved or redeemed request has an approver; only a redeemed one a redemption time. The session
    -- link may be blank after the approving session went away, so it is not part of the shape.
    CONSTRAINT device_requests_approver CHECK (
        (state IN ('approved', 'redeemed')) = (user_id IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT device_requests_approver_only_when_approved CHECK (
        state IN ('approved', 'redeemed') OR (user_id IS NULL AND session_id IS NULL)
    ),
    CONSTRAINT device_requests_redeemed CHECK ((state = 'redeemed') = (redeemed_at IS NOT NULL))
);

-- The retention sweep.
CREATE INDEX device_requests_expires_at ON device_requests (expires_at);
-- Lets the cascade from a deleted user find the requests it approved.
CREATE INDEX device_requests_user ON device_requests (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX device_requests_session ON device_requests (session_id) WHERE session_id IS NOT NULL;

-- A step-up proof may now be for approving a device.
ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_operation;
ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_operation CHECK (operation IS NULL OR operation IN
    ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account', 'approve_device'));
ALTER TABLE auth_tickets DROP CONSTRAINT auth_tickets_operation;
ALTER TABLE auth_tickets ADD CONSTRAINT auth_tickets_operation CHECK (operation IS NULL OR operation IN
    ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account', 'approve_device'));

-- +goose Down
DELETE FROM passkey_challenges WHERE operation = 'approve_device';
DELETE FROM auth_tickets WHERE operation = 'approve_device';
ALTER TABLE auth_tickets DROP CONSTRAINT auth_tickets_operation;
ALTER TABLE auth_tickets ADD CONSTRAINT auth_tickets_operation CHECK (operation IS NULL OR operation IN
    ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account'));
ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_operation;
ALTER TABLE passkey_challenges ADD CONSTRAINT passkey_challenges_operation CHECK (operation IS NULL OR operation IN
    ('add_passkey', 'delete_passkey', 'change_email', 'regenerate_recovery_codes', 'delete_account'));
DROP TABLE device_requests;
