-- name: EnqueueMail :exec
INSERT INTO outbox (id, flow_id, generation, quota_class, available_at, kind, recipient, user_id, device_name, client_ip, event_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- Claim leases one ready job of a quota class and counts the attempt. SKIP LOCKED
-- makes concurrent workers pass over a job another worker is claiming, so no job
-- is handed out twice. An expired lease makes a job claimable again.
-- name: ClaimMail :one
UPDATE outbox
SET attempts = attempts + 1, lease_until = sqlc.arg(lease_until)::timestamptz
WHERE id = (
    SELECT o.id
    FROM outbox o
    WHERE o.status = 'queued'
      AND o.quota_class = sqlc.arg(quota_class)::text
      AND o.available_at <= sqlc.arg(now)::timestamptz
      AND (o.lease_until IS NULL OR o.lease_until <= sqlc.arg(now)::timestamptz)
    ORDER BY o.available_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id, flow_id, generation, quota_class, attempts, available_at, kind, recipient, user_id, device_name, client_ip, event_at;

-- name: CompleteMail :execrows
UPDATE outbox
SET status = 'sent', lease_until = NULL, last_error = NULL, client_ip = NULL
WHERE id = $1 AND status = 'queued';

-- name: RetryMail :execrows
UPDATE outbox
SET available_at = $2, lease_until = NULL, last_error = $3
WHERE id = $1 AND status = 'queued';

-- name: AbandonMail :execrows
UPDATE outbox
SET status = 'dead', lease_until = NULL, last_error = $2, client_ip = NULL
WHERE id = $1 AND status = 'queued';

-- name: MailQueueStats :many
SELECT quota_class, count(*)::bigint AS queued, min(available_at)::timestamptz AS oldest_due
FROM outbox
WHERE status = 'queued'
GROUP BY quota_class;
