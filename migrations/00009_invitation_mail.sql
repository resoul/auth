-- +goose Up
-- The mail that tells an address it is invited. It belongs
-- to no flow: the operator makes it with the invitation. The job names the address; the worker looks
-- the invitation up when it sends, so a revoked or used invitation sends nothing.
ALTER TABLE outbox ALTER COLUMN flow_id DROP NOT NULL;
ALTER TABLE outbox DROP CONSTRAINT outbox_kind;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind CHECK (kind IN ('code', 'email_changed', 'invitation'));
ALTER TABLE outbox DROP CONSTRAINT outbox_recipient;
ALTER TABLE outbox ADD CONSTRAINT outbox_recipient CHECK (
    (kind IN ('email_changed', 'invitation')) = (recipient IS NOT NULL)
    AND (recipient IS NULL OR (recipient = lower(btrim(recipient)) AND recipient <> ''))
);
-- Only an invitation job has no flow.
ALTER TABLE outbox ADD CONSTRAINT outbox_flow CHECK ((kind = 'invitation') = (flow_id IS NULL));
-- The sweep of the mail no flow owns.
CREATE INDEX outbox_invitation_created ON outbox (created_at) WHERE kind = 'invitation';

-- +goose Down
DELETE FROM outbox WHERE kind = 'invitation';
DROP INDEX outbox_invitation_created;
ALTER TABLE outbox DROP CONSTRAINT outbox_flow;
ALTER TABLE outbox DROP CONSTRAINT outbox_recipient;
ALTER TABLE outbox ADD CONSTRAINT outbox_recipient CHECK (
    (kind = 'email_changed') = (recipient IS NOT NULL)
    AND (recipient IS NULL OR (recipient = lower(btrim(recipient)) AND recipient <> ''))
);
ALTER TABLE outbox DROP CONSTRAINT outbox_kind;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind CHECK (kind IN ('code', 'email_changed'));
ALTER TABLE outbox ALTER COLUMN flow_id SET NOT NULL;
