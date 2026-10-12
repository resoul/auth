-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, session_id, family_id, parent_id, token_hash, created_at, expires_at, used_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: FindRefreshTokenByHash :one
SELECT id, session_id, family_id, parent_id, token_hash, created_at, expires_at, used_at, revoked_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: GetRefreshTokenForUpdate :one
SELECT id, session_id, family_id, parent_id, token_hash, created_at, expires_at, used_at, revoked_at
FROM refresh_tokens
WHERE id = $1
FOR UPDATE;

-- The used and revoked marks are never cleared, even by a save from a stale copy.
-- name: UpdateRefreshToken :execrows
UPDATE refresh_tokens
SET used_at = COALESCE(used_at, $2), revoked_at = COALESCE(revoked_at, $3)
WHERE id = $1;

-- name: RevokeSessionTokens :exec
UPDATE refresh_tokens
SET revoked_at = COALESCE(revoked_at, $2)
WHERE session_id = $1;

-- name: RevokeOtherUserTokens :exec
UPDATE refresh_tokens AS t
SET revoked_at = COALESCE(t.revoked_at, $3)
WHERE t.session_id IN (SELECT s.id FROM sessions AS s WHERE s.user_id = $1 AND s.id <> $2);

-- name: RevokeUserTokens :exec
UPDATE refresh_tokens
SET revoked_at = COALESCE(revoked_at, $2)
WHERE session_id IN (SELECT id FROM sessions WHERE user_id = $1);
