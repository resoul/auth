-- Ensure is two statements: the insert waits for a concurrent insert of the same
-- email to finish and then does nothing, and the select that follows sees the winner.

-- name: InsertUserIfAbsent :execrows
INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (email) DO NOTHING;

-- name: GetUserByEmail :one
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users
WHERE id = $1;

-- name: GetUserForUpdate :one
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users WHERE id = $1 FOR UPDATE;

-- Every change of what a user can sign in with, and every revocation of what they are signed in with, queues on
-- this row; issuing a session shares it (GetUserForShare). That is what orders the two.
-- name: LockUser :one
SELECT id FROM users WHERE id = $1 FOR UPDATE;

-- name: LockUserShare :one
SELECT id FROM users WHERE id = $1 FOR SHARE;

-- name: GetUserForShare :one
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users WHERE id = $1 FOR SHARE;

-- The new address is taken when another user has it; the row is then left alone, so the
-- transaction is not aborted by a unique violation in the usual case.
-- name: UpdateUserEmail :execrows
UPDATE users AS u
SET email = $2, email_verified_at = $3, updated_at = $4
WHERE u.id = $1
  AND NOT EXISTS (SELECT 1 FROM users AS other WHERE other.email = $2 AND other.id <> $1);

-- name: GetUserForDeletion :one
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users WHERE id = $1 FOR UPDATE;

-- name: DeleteAccountFlows :exec
DELETE FROM auth_flows WHERE user_id = $1 OR email = $2;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- name: SetUserBlocked :execrows
UPDATE users SET blocked_at = $2, updated_at = $3 WHERE id = $1;

-- The operator's list: addresses that start with a prefix (@pattern is escaped LIKE text), in byte order,
-- after the address of the previous page. C collation keeps the order the same on every server.
-- name: ListUsers :many
SELECT id, email, email_verified_at, created_at, updated_at, blocked_at
FROM users
WHERE email LIKE @pattern::text ESCAPE '\'
  AND email COLLATE "C" > @after::text
ORDER BY email COLLATE "C"
LIMIT @max_rows;
