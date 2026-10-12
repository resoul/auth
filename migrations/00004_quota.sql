-- +goose Up
-- Admitted spends of the quota budgets. A budget is
-- identified by a SHA-256 of its scope and key (an email, a binding, an IP), so a dump
-- of this table names no address. Rows older than the longest window are useless and
-- are deleted after the longest quota window.

CREATE TABLE quota_events (
    key_hash bytea       NOT NULL,
    at       timestamptz NOT NULL,
    CONSTRAINT quota_events_key_hash CHECK (octet_length(key_hash) = 32)
);

-- Counting one budget inside a window, and the retention sweep.
CREATE INDEX quota_events_key_at ON quota_events (key_hash, at);
CREATE INDEX quota_events_at ON quota_events (at);

-- +goose Down
DROP TABLE quota_events;
