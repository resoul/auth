-- The admin API's data.

-- name: CreateOperator :exec
INSERT INTO operators (id, email, created_at, disabled_at) VALUES ($1, $2, $3, $4);

-- name: GetOperatorByID :one
SELECT id, email, created_at, disabled_at FROM operators WHERE id = $1;

-- Enrolling a key holds the operator while it counts the keys, so two enrollments of one operator run one after the
-- other.
-- name: GetOperatorForUpdate :one
SELECT id, email, created_at, disabled_at FROM operators WHERE id = $1 FOR UPDATE;

-- name: GetOperatorByEmail :one
SELECT id, email, created_at, disabled_at FROM operators WHERE email = $1;

-- name: ListOperators :many
SELECT id, email, created_at, disabled_at FROM operators ORDER BY created_at, id;

-- name: UpdateOperator :execrows
UPDATE operators SET disabled_at = $2 WHERE id = $1;

-- name: CreateOperatorEnrollment :exec
INSERT INTO operator_enrollments (id, operator_id, code_hash, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetOperatorEnrollmentByHashForUpdate :one
SELECT id, operator_id, code_hash, created_at, expires_at, consumed_at
FROM operator_enrollments WHERE code_hash = $1 FOR UPDATE;

-- name: GetOperatorEnrollmentForUpdate :one
SELECT id, operator_id, code_hash, created_at, expires_at, consumed_at
FROM operator_enrollments WHERE id = $1 FOR UPDATE;

-- name: UpdateOperatorEnrollment :execrows
UPDATE operator_enrollments SET consumed_at = $2 WHERE id = $1;

-- A credential ID that is registered already inserts nothing (no rows), instead of a unique violation that would
-- abort the transaction: the refusal of such an enrollment must still commit its spent challenge.
-- name: CreateOperatorCredential :execrows
INSERT INTO operator_credentials (id, operator_id, credential_id, public_key, aaguid, transports, sign_count,
                                  backup_eligible, backup_state, name, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (credential_id) DO NOTHING;

-- name: ListOperatorCredentials :many
SELECT id, operator_id, credential_id, public_key, aaguid, transports, sign_count,
       backup_eligible, backup_state, name, created_at, last_used_at
FROM operator_credentials
WHERE operator_id = $1
ORDER BY created_at, id;

-- name: GetOperatorCredentialForUpdate :one
SELECT id, operator_id, credential_id, public_key, aaguid, transports, sign_count,
       backup_eligible, backup_state, name, created_at, last_used_at
FROM operator_credentials
WHERE credential_id = $1
FOR UPDATE;

-- name: UpdateOperatorCredential :execrows
UPDATE operator_credentials
SET sign_count = $2, backup_state = $3, name = $4, last_used_at = $5
WHERE credential_id = $1;

-- name: CreateOperatorChallenge :exec
INSERT INTO operator_challenges (id, purpose, operator_id, enrollment_id, data, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetOperatorChallengeForUpdate :one
SELECT id, purpose, operator_id, enrollment_id, data, created_at, expires_at, consumed_at
FROM operator_challenges WHERE id = $1 FOR UPDATE;

-- name: UpdateOperatorChallenge :execrows
UPDATE operator_challenges SET consumed_at = $2 WHERE id = $1;

-- name: CreateOperatorSession :exec
INSERT INTO operator_sessions (id, operator_id, secret_hash, created_at, last_seen_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOperatorSessionByHashForUpdate :one
SELECT id, operator_id, secret_hash, created_at, last_seen_at, expires_at, revoked_at
FROM operator_sessions WHERE secret_hash = $1 FOR UPDATE;

-- name: GetOperatorSessionForUpdate :one
SELECT id, operator_id, secret_hash, created_at, last_seen_at, expires_at, revoked_at
FROM operator_sessions WHERE id = $1 FOR UPDATE;

-- name: UpdateOperatorSession :execrows
UPDATE operator_sessions SET last_seen_at = $2, revoked_at = $3 WHERE id = $1;

-- name: RevokeOperatorSessions :exec
UPDATE operator_sessions SET revoked_at = $2 WHERE operator_id = $1 AND revoked_at IS NULL;
