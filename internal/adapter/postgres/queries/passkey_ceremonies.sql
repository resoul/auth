-- name: CreatePasskeyChallenge :exec
INSERT INTO passkey_challenges (id, purpose, user_id, ticket_id, session_id, operation, data, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetPasskeyChallengeForUpdate :one
SELECT id, purpose, user_id, ticket_id, session_id, operation, data, created_at, expires_at, consumed_at
FROM passkey_challenges
WHERE id = $1
FOR UPDATE;

-- name: UpdatePasskeyChallenge :execrows
UPDATE passkey_challenges SET consumed_at = $2 WHERE id = $1;

-- name: CreateAuthTicket :exec
INSERT INTO auth_tickets (id, kind, user_id, session_id, operation, binding_hash, secret_hash,
                          created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetAuthTicketByHashForUpdate :one
SELECT id, kind, user_id, session_id, operation, binding_hash, secret_hash, created_at, expires_at, consumed_at
FROM auth_tickets
WHERE secret_hash = $1
FOR UPDATE;

-- name: GetAuthTicketForUpdate :one
SELECT id, kind, user_id, session_id, operation, binding_hash, secret_hash, created_at, expires_at, consumed_at
FROM auth_tickets
WHERE id = $1
FOR UPDATE;

-- name: UpdateAuthTicket :execrows
UPDATE auth_tickets SET consumed_at = $2 WHERE id = $1;

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = $1;

-- name: CreateRecoveryCode :exec
INSERT INTO recovery_codes (id, user_id, code_hash, created_at, used_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetRecoveryCodeByHashForUpdate :one
SELECT id, user_id, code_hash, created_at, used_at
FROM recovery_codes
WHERE code_hash = $1
FOR UPDATE;

-- name: UpdateRecoveryCode :execrows
UPDATE recovery_codes SET used_at = $2 WHERE id = $1;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*)::bigint FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL;
