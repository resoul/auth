-- name: CreateSession :exec
INSERT INTO sessions (
    id, user_id, binding_hash, amr, auth_time, device_name,
    created_at, last_active_at, idle_expires_at, expires_at, revoked_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
);

-- name: GetSessionForUpdate :one
SELECT id, user_id, binding_hash, amr, auth_time, device_name,
       created_at, last_active_at, idle_expires_at, expires_at, revoked_at
FROM sessions
WHERE id = $1
FOR UPDATE;

-- Only what a session operation can change is written. A revocation is never
-- cleared, even by a save from a stale copy.
-- name: UpdateSession :execrows
UPDATE sessions
SET last_active_at = $2, idle_expires_at = $3, revoked_at = COALESCE(revoked_at, $4)
WHERE id = $1;

-- name: RevokeUserSessions :exec
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, $2)
WHERE user_id = $1;

-- name: RevokeOtherUserSessions :exec
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, $3)
WHERE user_id = $1 AND id <> $2;

-- name: GetSession :one
SELECT id, user_id, binding_hash, amr, auth_time, device_name,
       created_at, last_active_at, idle_expires_at, expires_at, revoked_at
FROM sessions
WHERE id = $1;

-- name: ListActiveSessions :many
SELECT id, user_id, binding_hash, amr, auth_time, device_name,
       created_at, last_active_at, idle_expires_at, expires_at, revoked_at
FROM sessions
WHERE user_id = @user_id
  AND revoked_at IS NULL
  AND idle_expires_at > @now
  AND expires_at > @now
ORDER BY last_active_at DESC, id
LIMIT @max_rows;

-- What the sessions the user ever opened and still keep say about a sign-in: whether there is any, and whether
-- one was opened from this client binding.
-- name: SessionHistory :one
SELECT EXISTS (SELECT 1 FROM sessions a WHERE a.user_id = sqlc.arg(user_id)::uuid) AS any_session,
       EXISTS (SELECT 1 FROM sessions b WHERE b.user_id = sqlc.arg(user_id)::uuid AND b.binding_hash = sqlc.arg(binding_hash)::bytea) AS this_binding;
