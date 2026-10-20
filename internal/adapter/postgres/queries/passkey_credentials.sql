-- A credential ID that is registered already inserts nothing (no rows), instead of a unique violation that would
-- abort the transaction: the refusal of such a registration must still commit its audit and its spent challenge.
-- name: CreatePasskeyCredential :execrows
INSERT INTO passkey_credentials (id, user_id, credential_id, public_key, aaguid, transports, sign_count,
                                 backup_eligible, backup_state, name, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (credential_id) DO NOTHING;

-- name: ListPasskeyCredentials :many
SELECT id, user_id, credential_id, public_key, aaguid, transports, sign_count,
       backup_eligible, backup_state, name, created_at, last_used_at
FROM passkey_credentials
WHERE user_id = $1
ORDER BY created_at, id;

-- name: GetPasskeyCredentialForUpdate :one
SELECT id, user_id, credential_id, public_key, aaguid, transports, sign_count,
       backup_eligible, backup_state, name, created_at, last_used_at
FROM passkey_credentials
WHERE credential_id = $1
FOR UPDATE;

-- name: UpdatePasskeyCredential :execrows
UPDATE passkey_credentials
SET sign_count = $2, backup_state = $3, name = $4, last_used_at = $5
WHERE credential_id = $1;

-- The owner of a credential, read without a lock: the user row is locked first, then the credential row, the order
-- every other statement uses.
-- name: GetPasskeyCredentialOwner :one
SELECT user_id FROM passkey_credentials WHERE credential_id = $1;

-- name: DeletePasskeyCredentialsOfUser :execrows
DELETE FROM passkey_credentials WHERE user_id = $1;

-- name: CountPasskeyCredentials :one
SELECT count(*)::bigint FROM passkey_credentials WHERE user_id = $1;

-- name: PasskeyCredentialOwned :one
SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE id = $1 AND user_id = $2);

-- name: DeletePasskeyCredential :execrows
DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2;
