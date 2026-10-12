-- name: CreateFlow :exec
INSERT INTO auth_flows (
    id, email, purpose, generation, salt, key_id, binding_hash, state,
    created_at, expires_at, attempts, resend_after, quota_class, recognized_client_id, user_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
);

-- name: GetFlowForUpdate :one
SELECT id, email, purpose, generation, salt, key_id, binding_hash, state,
       created_at, expires_at, attempts, resend_after, quota_class, recognized_client_id, user_id
FROM auth_flows
WHERE id = $1
FOR UPDATE;

-- Only the fields a flow operation can change are written; the rest is fixed at start.
-- name: UpdateFlow :execrows
UPDATE auth_flows
SET generation = $2, salt = $3, key_id = $4, state = $5, attempts = $6, resend_after = $7
WHERE id = $1;

-- name: GetFlow :one
SELECT id, email, purpose, generation, salt, key_id, binding_hash, state,
       created_at, expires_at, attempts, resend_after, quota_class, recognized_client_id, user_id
FROM auth_flows
WHERE id = $1;
