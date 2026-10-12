-- +goose Up
-- Changing the address of an account. The code goes to the
-- new address through an ordinary flow that now names its account; once the address moved, the
-- old one gets a notice through the same outbox, tied to that flow so its retention covers it.

ALTER TABLE auth_flows ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;
-- A change_email flow names its account; a login or step-up flow does not.
ALTER TABLE auth_flows ADD CONSTRAINT auth_flows_user CHECK ((purpose = 'change_email') = (user_id IS NOT NULL));
CREATE INDEX auth_flows_user ON auth_flows (user_id) WHERE user_id IS NOT NULL;

ALTER TABLE outbox ADD COLUMN kind text NOT NULL DEFAULT 'code';
-- The old address of a notice. The flow's own address is the new one, so it cannot serve.
ALTER TABLE outbox ADD COLUMN recipient text;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind CHECK (kind IN ('code', 'email_changed'));
ALTER TABLE outbox ADD CONSTRAINT outbox_recipient CHECK (
    (kind = 'email_changed') = (recipient IS NOT NULL)
    AND (recipient IS NULL OR (recipient = lower(btrim(recipient)) AND recipient <> ''))
);
ALTER TABLE outbox DROP CONSTRAINT outbox_flow_generation_unique;
-- One job per flow generation and kind: the code and the notice of one flow do not collide.
ALTER TABLE outbox ADD CONSTRAINT outbox_flow_generation_kind_unique UNIQUE (flow_id, generation, kind);

-- +goose Down
DELETE FROM outbox WHERE kind <> 'code';
ALTER TABLE outbox DROP CONSTRAINT outbox_flow_generation_kind_unique;
ALTER TABLE outbox ADD CONSTRAINT outbox_flow_generation_unique UNIQUE (flow_id, generation);
ALTER TABLE outbox DROP CONSTRAINT outbox_recipient;
ALTER TABLE outbox DROP CONSTRAINT outbox_kind;
ALTER TABLE outbox DROP COLUMN recipient;
ALTER TABLE outbox DROP COLUMN kind;

DELETE FROM auth_flows WHERE purpose = 'change_email';
DROP INDEX auth_flows_user;
ALTER TABLE auth_flows DROP CONSTRAINT auth_flows_user;
ALTER TABLE auth_flows DROP COLUMN user_id;
