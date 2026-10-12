-- One record per (user, binding). Registering again renews it, revoked or not,
-- because the email was just proven again.
-- name: RegisterRecognizedClient :one
INSERT INTO recognized_clients (id, user_id, email, binding_hash, verified_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, binding_hash) DO UPDATE
SET verified_at = EXCLUDED.verified_at,
    expires_at  = EXCLUDED.expires_at,
    revoked_at  = NULL
RETURNING id, user_id, email, binding_hash, verified_at, expires_at, revoked_at;

-- name: FindActiveRecognizedClient :one
SELECT id, user_id, email, binding_hash, verified_at, expires_at, revoked_at
FROM recognized_clients
WHERE email = $1 AND binding_hash = $2 AND revoked_at IS NULL AND expires_at > $3
LIMIT 1;

-- Refresh extends an active record and never shortens it or restores a dead one.
-- name: ExtendRecognizedClient :execrows
UPDATE recognized_clients
SET expires_at = GREATEST(expires_at, sqlc.arg(new_expires_at)::timestamptz)
WHERE user_id = $1 AND binding_hash = $2 AND revoked_at IS NULL AND expires_at > sqlc.arg(now)::timestamptz;

-- name: RevokeRecognizedClient :exec
UPDATE recognized_clients
SET revoked_at = COALESCE(revoked_at, $3)
WHERE user_id = $1 AND binding_hash = $2;

-- name: RevokeAllRecognizedClients :exec
UPDATE recognized_clients
SET revoked_at = COALESCE(revoked_at, $2)
WHERE user_id = $1;
