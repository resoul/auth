-- name: LockQuotaBudget :exec
-- Serializes the spends of one budget until the transaction ends. Two budgets that
-- collide on the 64-bit key only wait for each other.
SELECT pg_advisory_xact_lock(@lock_id::bigint);

-- name: CountQuotaEvents :one
SELECT count(*) FROM quota_events WHERE key_hash = @key_hash AND at > @after;

-- name: AddQuotaEvent :exec
INSERT INTO quota_events (key_hash, at) VALUES (@key_hash, @at);

-- name: PruneQuotaBudget :exec
DELETE FROM quota_events WHERE key_hash = @key_hash AND at <= @horizon;

-- One bounded batch of rows no window can count any more.
-- name: PurgeQuotaEvents :execrows
DELETE FROM quota_events e
WHERE e.ctid IN (SELECT q.ctid FROM quota_events q WHERE q.at <= @horizon LIMIT @max_rows);
