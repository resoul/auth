-- name: SaveInvitation :exec
INSERT INTO invitations (email, created_at, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (email) DO UPDATE SET created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at;

-- name: FindActiveInvitation :one
SELECT email, created_at, expires_at
FROM invitations
WHERE email = $1 AND expires_at > $2;

-- One statement removes it, so of two concurrent registrations only one gets the row.
-- name: ConsumeInvitation :execrows
DELETE FROM invitations
WHERE email = $1 AND expires_at > $2;

-- name: DeleteInvitation :execrows
DELETE FROM invitations
WHERE email = $1;

-- name: ListInvitations :many
SELECT email, created_at, expires_at
FROM invitations
ORDER BY created_at, email;
