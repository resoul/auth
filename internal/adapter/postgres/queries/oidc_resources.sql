-- name: CreateOIDCResource :exec
INSERT INTO oidc_resources (id, name, status, uri, audience, scopes, policy_version, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetOIDCResource :one
SELECT id, name, status, uri, audience, scopes, policy_version, created_at, updated_at
FROM oidc_resources WHERE id = $1;

-- Issuing a token for a resource shares its row; changing the rights of a resource, or of a client on it, takes it
-- exclusively. That is the one order of the two, and it comes before the user and the grant in every transaction.
-- name: GetOIDCResourceForUpdate :one
SELECT id, name, status, uri, audience, scopes, policy_version, created_at, updated_at
FROM oidc_resources WHERE id = $1 FOR UPDATE;

-- name: ListOIDCResourcesByURIForShare :many
SELECT id, name, status, uri, audience, scopes, policy_version, created_at, updated_at
FROM oidc_resources WHERE uri = ANY (sqlc.arg(uris)::text[]) ORDER BY id FOR SHARE;

-- name: ListOIDCResourcesByIDForShare :many
SELECT id, name, status, uri, audience, scopes, policy_version, created_at, updated_at
FROM oidc_resources WHERE id = ANY (sqlc.arg(ids)::text[]) ORDER BY id FOR SHARE;

-- name: ListOIDCResources :many
SELECT id, name, status, uri, audience, scopes, policy_version, created_at, updated_at
FROM oidc_resources ORDER BY id;

-- name: SetOIDCResourceStatus :execrows
UPDATE oidc_resources SET status = $2, policy_version = policy_version + 1, updated_at = $3 WHERE id = $1;

-- name: SetOIDCResourceScopes :execrows
UPDATE oidc_resources SET scopes = $2, policy_version = policy_version + 1, updated_at = $3 WHERE id = $1;

-- name: OIDCAudienceTaken :one
SELECT EXISTS (SELECT 1 FROM oidc_resources WHERE audience = $1);

-- name: GetOIDCClientResourceForUpdate :one
SELECT client_id, resource_id, scopes, created_at, updated_at FROM oidc_client_resources WHERE client_id = $1 AND resource_id = $2 FOR UPDATE;

-- name: UpsertOIDCClientResource :exec
INSERT INTO oidc_client_resources (client_id, resource_id, scopes, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (client_id, resource_id) DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at;

-- name: DeleteOIDCClientResource :execrows
DELETE FROM oidc_client_resources WHERE client_id = $1 AND resource_id = $2;

-- name: ListOIDCClientResources :many
SELECT client_id, resource_id, scopes, created_at, updated_at FROM oidc_client_resources WHERE client_id = $1 ORDER BY resource_id;

-- name: ListOIDCClientResourcesOf :many
SELECT client_id, resource_id, scopes, created_at, updated_at FROM oidc_client_resources
WHERE client_id = $1 AND resource_id = ANY (sqlc.arg(resource_ids)::text[]) ORDER BY resource_id;

-- name: ListOIDCResourceClients :many
SELECT client_id, resource_id, scopes, created_at, updated_at FROM oidc_client_resources WHERE resource_id = $1 ORDER BY client_id;

-- name: CreateOIDCRequestResource :exec
INSERT INTO oidc_request_resources (request_hash, resource_id, scopes, policy_version) VALUES ($1, $2, $3, $4);

-- name: ListOIDCRequestResources :many
SELECT resource_id, scopes, policy_version FROM oidc_request_resources WHERE request_hash = $1 ORDER BY resource_id;

-- name: CreateOIDCCodeResource :exec
INSERT INTO oidc_code_resources (code_hash, resource_id, scopes, policy_version) VALUES ($1, $2, $3, $4);

-- name: ListOIDCCodeResources :many
SELECT resource_id, scopes, policy_version FROM oidc_code_resources WHERE code_hash = $1 ORDER BY resource_id;

-- name: CreateOIDCGrantResource :exec
INSERT INTO oidc_grant_resources (grant_id, resource_id, scopes, policy_version) VALUES ($1, $2, $3, $4);

-- name: ListOIDCGrantResources :many
SELECT resource_id, scopes, policy_version FROM oidc_grant_resources WHERE grant_id = $1 ORDER BY resource_id;

-- The live grants that hold a resource, optionally of one client, optionally only those that hold one of the scopes. They
-- are listed in the order their users and then they are locked, which is the order every statement uses.
-- name: ListLiveOIDCGrantsOfResource :many
SELECT g.id, g.user_id FROM oidc_grants g JOIN oidc_grant_resources gr ON gr.grant_id = g.id
WHERE gr.resource_id = sqlc.arg(resource_id)::text AND g.revoked_at IS NULL
  AND (sqlc.narg(client_id)::text IS NULL OR g.client_id = sqlc.narg(client_id)::text)
  AND (sqlc.narg(scopes)::text[] IS NULL OR gr.scopes && sqlc.narg(scopes)::text[])
ORDER BY g.user_id, g.id;

-- A notice for one grant that is about to be revoked: the client closes the sign-in it holds on that session.
-- name: QueueOIDCLogoutOfGrant :exec
INSERT INTO oidc_logout_outbox (id, client_id, user_id, op_session_id, available_at, expires_at, created_at)
SELECT gen_random_uuid(), g.client_id, g.user_id, g.op_session_id, sqlc.arg(now)::timestamptz, sqlc.arg(expires_at)::timestamptz, sqlc.arg(now)::timestamptz
FROM oidc_grants g JOIN oidc_clients c ON c.id = g.client_id
WHERE g.id = sqlc.arg(grant_id)::uuid AND g.revoked_at IS NULL AND c.status = 'active' AND c.backchannel_logout_uri IS NOT NULL;

-- The applications a user has connected: live grants on live sign-ins, newest use first.
-- name: ListLiveOIDCGrantsOfUser :many
SELECT g.id, g.client_id, c.name AS client_name, g.scopes, g.created_at, g.last_used_at, g.expires_at
FROM oidc_grants g
JOIN oidc_clients c ON c.id = g.client_id
JOIN oidc_op_sessions o ON o.id = g.op_session_id
WHERE g.user_id = sqlc.arg(user_id)::uuid AND g.revoked_at IS NULL AND g.expires_at > sqlc.arg(now)::timestamptz
  AND o.revoked_at IS NULL AND o.expires_at > sqlc.arg(now)::timestamptz
ORDER BY c.name, g.last_used_at DESC, g.id
LIMIT 200;

-- name: ListOIDCGrantResourcesOfGrants :many
SELECT gr.grant_id, gr.resource_id, r.name AS resource_name, gr.scopes
FROM oidc_grant_resources gr JOIN oidc_resources r ON r.id = gr.resource_id
WHERE gr.grant_id = ANY (sqlc.arg(grant_ids)::uuid[]) ORDER BY gr.grant_id, gr.resource_id;

-- name: ListLiveOIDCGrantIDsOfUserClient :many
SELECT id FROM oidc_grants WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL ORDER BY id;

-- name: InsertOIDCResourceSecret :exec
INSERT INTO oidc_resource_secrets (id, resource_id, secret_hash, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- A rotation: what ended an earlier overlap goes at once, what is live now ends at the new time.
-- name: RetireOIDCResourceSecrets :exec
UPDATE oidc_resource_secrets SET revoked_at = $2
WHERE resource_id = $1 AND revoked_at IS NULL AND expires_at IS NOT NULL;

-- name: EndOIDCResourceSecretsAt :exec
UPDATE oidc_resource_secrets SET expires_at = $2
WHERE resource_id = $1 AND revoked_at IS NULL AND expires_at IS NULL;

-- name: OIDCResourceSecretValid :one
SELECT EXISTS (
    SELECT 1 FROM oidc_resource_secrets
    WHERE resource_id = $1 AND secret_hash = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $3)
);
