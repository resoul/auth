-- +goose Up
-- The notice that a device or an app the account has not used before signed in. It belongs to no flow: the
-- job names the user, and the worker reads the user's current address when it sends, so a deleted or blocked user
-- gets nothing. The client address is kept only to be put into the mail: the sweep and the end of the job remove it.
ALTER TABLE outbox ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE outbox ADD COLUMN device_name text;
ALTER TABLE outbox ADD COLUMN client_ip text;
ALTER TABLE outbox ADD COLUMN event_at timestamptz;
ALTER TABLE outbox DROP CONSTRAINT outbox_kind;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind CHECK (kind IN ('code', 'email_changed', 'invitation', 'new_device'));
ALTER TABLE outbox DROP CONSTRAINT outbox_flow;
ALTER TABLE outbox ADD CONSTRAINT outbox_flow CHECK ((kind IN ('invitation', 'new_device')) = (flow_id IS NULL));
ALTER TABLE outbox ADD CONSTRAINT outbox_new_device CHECK (
    CASE WHEN kind = 'new_device'
        THEN user_id IS NOT NULL AND event_at IS NOT NULL
        ELSE user_id IS NULL AND event_at IS NULL AND device_name IS NULL AND client_ip IS NULL
    END
    AND (device_name IS NULL OR char_length(device_name) <= 64)
    AND (client_ip IS NULL OR char_length(client_ip) <= 45)
);
-- The sweep of the mail no flow owns.
DROP INDEX outbox_invitation_created;
CREATE INDEX outbox_flowless_created ON outbox (created_at) WHERE kind IN ('invitation', 'new_device');
CREATE INDEX outbox_user ON outbox (user_id) WHERE user_id IS NOT NULL;

-- +goose Down
DELETE FROM outbox WHERE kind = 'new_device';
DROP INDEX outbox_user;
DROP INDEX outbox_flowless_created;
CREATE INDEX outbox_invitation_created ON outbox (created_at) WHERE kind = 'invitation';
ALTER TABLE outbox DROP CONSTRAINT outbox_new_device;
ALTER TABLE outbox DROP CONSTRAINT outbox_flow;
ALTER TABLE outbox ADD CONSTRAINT outbox_flow CHECK ((kind = 'invitation') = (flow_id IS NULL));
ALTER TABLE outbox DROP CONSTRAINT outbox_kind;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind CHECK (kind IN ('code', 'email_changed', 'invitation'));
ALTER TABLE outbox DROP COLUMN event_at;
ALTER TABLE outbox DROP COLUMN client_ip;
ALTER TABLE outbox DROP COLUMN device_name;
ALTER TABLE outbox DROP COLUMN user_id;
