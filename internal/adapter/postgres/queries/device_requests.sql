-- Sign-in on one device approved by another.

-- name: CreateDeviceRequest :exec
INSERT INTO device_requests (id, poll_hash, binding_hash, device_name, pairing_code, state, attempts, user_id, session_id,
                             created_at, expires_at, decided_at, redeemed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: GetDeviceRequest :one
SELECT id, poll_hash, binding_hash, device_name, pairing_code, state, attempts, user_id, session_id,
       created_at, expires_at, decided_at, redeemed_at
FROM device_requests WHERE id = $1;

-- name: GetDeviceRequestForUpdate :one
SELECT id, poll_hash, binding_hash, device_name, pairing_code, state, attempts, user_id, session_id,
       created_at, expires_at, decided_at, redeemed_at
FROM device_requests WHERE id = $1 FOR UPDATE;

-- name: UpdateDeviceRequest :execrows
UPDATE device_requests
SET state = $2, attempts = $3, user_id = $4, session_id = $5, decided_at = $6, redeemed_at = $7
WHERE id = $1;
