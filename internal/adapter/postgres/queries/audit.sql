-- name: RecordAuditEvent :exec
INSERT INTO audit_events (id, user_id, session_id, operator_id, event, result, occurred_at, fields)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- The admin listing, newest first. A NULL filter does not filter; the cursor is the (time, id) of the
-- last row of the previous page.
-- name: ListAuditEvents :many
SELECT id, user_id, session_id, operator_id, event, result, occurred_at, fields
FROM audit_events
WHERE (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('operator_id')::uuid IS NULL OR operator_id = sqlc.narg('operator_id'))
  AND (sqlc.narg('event')::text IS NULL OR event = sqlc.narg('event'))
  AND (sqlc.narg('before_at')::timestamptz IS NULL OR (occurred_at, id) < (sqlc.narg('before_at')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY occurred_at DESC, id DESC
LIMIT @max_rows;
