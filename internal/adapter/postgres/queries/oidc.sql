-- name: CreateOIDCClient :exec
INSERT INTO oidc_clients (id, name, status, redirect_uris, allowed_scopes, trusted, policy_version, created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri, kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: InsertOIDCClientSecret :exec
INSERT INTO oidc_client_secrets (id, client_id, secret_hash, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetOIDCClient :one
SELECT id, name, status, redirect_uris, allowed_scopes, trusted, policy_version, created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri, kind
FROM oidc_clients WHERE id = $1;

-- name: ListOIDCClients :many
SELECT id, name, status, redirect_uris, allowed_scopes, trusted, policy_version, created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri, kind
FROM oidc_clients ORDER BY id;

-- name: SetOIDCClientStatus :execrows
UPDATE oidc_clients SET status = $2, policy_version = policy_version + 1, updated_at = $3 WHERE id = $1;

-- name: SetOIDCClientLogout :execrows
UPDATE oidc_clients
SET post_logout_redirect_uris = $2, backchannel_logout_uri = $3, policy_version = policy_version + 1, updated_at = $4
WHERE id = $1;

-- A rotation: what ended an earlier overlap goes at once, what is live now ends at the new time.
-- name: RetireOIDCClientSecrets :exec
UPDATE oidc_client_secrets SET revoked_at = $2
WHERE client_id = $1 AND revoked_at IS NULL AND expires_at IS NOT NULL;

-- name: EndOIDCClientSecretsAt :exec
UPDATE oidc_client_secrets SET expires_at = $2
WHERE client_id = $1 AND revoked_at IS NULL AND expires_at IS NULL;

-- name: OIDCClientSecretValid :one
SELECT EXISTS (
    SELECT 1 FROM oidc_client_secrets
    WHERE client_id = $1 AND secret_hash = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $3)
);

-- name: CreateOIDCRequest :exec
INSERT INTO oidc_authorization_requests
    (id_hash, binding_hash, client_id, redirect_uri, scopes, state, nonce, code_challenge, fresh_login, max_age, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetOIDCRequestForUpdate :one
SELECT id_hash, binding_hash, client_id, redirect_uri, scopes, state, nonce, code_challenge, fresh_login, max_age,
       created_at, expires_at, completed_at
FROM oidc_authorization_requests WHERE id_hash = $1 FOR UPDATE;

-- name: CompleteOIDCRequest :execrows
UPDATE oidc_authorization_requests SET completed_at = $2 WHERE id_hash = $1 AND completed_at IS NULL;

-- name: CreateOIDCOPSession :exec
INSERT INTO oidc_op_sessions (id, user_id, secret_hash, auth_time, amr, created_at, last_seen_at, expires_at, device_session_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetOIDCOPSessionBySecret :one
SELECT id, user_id, secret_hash, auth_time, amr, created_at, last_seen_at, expires_at, revoked_at, device_session_id
FROM oidc_op_sessions WHERE secret_hash = $1;

-- name: GetOIDCOPSession :one
SELECT id, user_id, secret_hash, auth_time, amr, created_at, last_seen_at, expires_at, revoked_at, device_session_id
FROM oidc_op_sessions WHERE id = $1;

-- name: TouchOIDCOPSession :exec
UPDATE oidc_op_sessions SET last_seen_at = $2 WHERE id = $1 AND last_seen_at < $2;

-- name: RevokeOIDCOPSessionsOfUser :exec
UPDATE oidc_op_sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCGrantsOfUser :exec
UPDATE oidc_grants SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCRefreshOfUser :exec
UPDATE oidc_refresh_tokens SET revoked_at = $2
WHERE revoked_at IS NULL AND grant_id IN (SELECT id FROM oidc_grants WHERE user_id = $1);

-- The sign-ins of a user except the one that grew from the device session keep (nil keeps none): what a deleted key or a
-- moved address cuts off. A sign-in with no device session is not the keeper's, so it goes.
-- name: RevokeOIDCOPSessionsOfUserExcept :exec
UPDATE oidc_op_sessions SET revoked_at = sqlc.arg(revoked_at) WHERE user_id = sqlc.arg(user_id)::uuid AND revoked_at IS NULL
  AND device_session_id IS DISTINCT FROM sqlc.narg(keep)::uuid;

-- name: RevokeOIDCGrantsOfUserExcept :exec
UPDATE oidc_grants SET revoked_at = sqlc.arg(revoked_at) WHERE user_id = sqlc.arg(user_id)::uuid AND revoked_at IS NULL
  AND op_session_id IN (SELECT o.id FROM oidc_op_sessions o WHERE o.user_id = sqlc.arg(user_id)::uuid AND o.device_session_id IS DISTINCT FROM sqlc.narg(keep)::uuid);

-- name: RevokeOIDCRefreshOfUserExcept :exec
UPDATE oidc_refresh_tokens SET revoked_at = sqlc.arg(revoked_at)
WHERE revoked_at IS NULL AND grant_id IN (
    SELECT g.id FROM oidc_grants g JOIN oidc_op_sessions o ON o.id = g.op_session_id
    WHERE g.user_id = sqlc.arg(user_id)::uuid AND o.device_session_id IS DISTINCT FROM sqlc.narg(keep)::uuid);

-- name: QueueOIDCLogoutOfUserExcept :exec
INSERT INTO oidc_logout_outbox (id, client_id, user_id, op_session_id, available_at, expires_at, created_at)
SELECT gen_random_uuid(), g.client_id, g.user_id, g.op_session_id, sqlc.arg(now)::timestamptz, sqlc.arg(expires_at)::timestamptz, sqlc.arg(now)::timestamptz
FROM oidc_grants g JOIN oidc_clients c ON c.id = g.client_id JOIN oidc_op_sessions o ON o.id = g.op_session_id
WHERE g.user_id = sqlc.arg(user_id)::uuid AND g.revoked_at IS NULL AND c.status = 'active' AND c.backchannel_logout_uri IS NOT NULL
  AND o.device_session_id IS DISTINCT FROM sqlc.narg(keep)::uuid;

-- name: FindLiveOIDCGrant :one
SELECT id, client_id, user_id, op_session_id, scopes, policy_version, created_at, last_used_at, expires_at, revoked_at
FROM oidc_grants WHERE client_id = $1 AND op_session_id = $2 AND revoked_at IS NULL;

-- name: CreateOIDCGrant :exec
INSERT INTO oidc_grants (id, client_id, user_id, op_session_id, scopes, policy_version, created_at, last_used_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetOIDCGrant :one
SELECT id, client_id, user_id, op_session_id, scopes, policy_version, created_at, last_used_at, expires_at, revoked_at
FROM oidc_grants WHERE id = $1;

-- name: GetOIDCGrantForUpdate :one
SELECT id, client_id, user_id, op_session_id, scopes, policy_version, created_at, last_used_at, expires_at, revoked_at
FROM oidc_grants WHERE id = $1 FOR UPDATE;

-- name: TouchOIDCGrant :exec
UPDATE oidc_grants SET last_used_at = $2 WHERE id = $1 AND last_used_at < $2;

-- name: RevokeOIDCGrant :exec
UPDATE oidc_grants SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCGrantRefresh :exec
UPDATE oidc_refresh_tokens SET revoked_at = $2 WHERE grant_id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCGrantsOfClient :exec
UPDATE oidc_grants SET revoked_at = $2 WHERE client_id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCRefreshOfClient :exec
UPDATE oidc_refresh_tokens SET revoked_at = $2
WHERE revoked_at IS NULL AND grant_id IN (SELECT id FROM oidc_grants WHERE client_id = $1);

-- name: CreateOIDCCode :exec
INSERT INTO oidc_authorization_codes
    (code_hash, grant_id, redirect_uri, code_challenge, nonce, scopes, auth_time, amr, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- The grant of a code, read without a lock: the user and the grant are locked first, then the code.
-- name: GetOIDCCodeGrantID :one
SELECT grant_id FROM oidc_authorization_codes WHERE code_hash = $1;

-- name: GetOIDCCodeForUpdate :one
SELECT code_hash, grant_id, redirect_uri, code_challenge, nonce, scopes, auth_time, amr, created_at, expires_at, consumed_at
FROM oidc_authorization_codes WHERE code_hash = $1 FOR UPDATE;

-- name: ConsumeOIDCCode :execrows
UPDATE oidc_authorization_codes SET consumed_at = $2 WHERE code_hash = $1 AND consumed_at IS NULL;

-- name: CreateOIDCRefresh :exec
INSERT INTO oidc_refresh_tokens (id, grant_id, token_hash, parent_id, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetOIDCRefreshGrantID :one
SELECT grant_id FROM oidc_refresh_tokens WHERE token_hash = $1;

-- name: GetOIDCRefreshForUpdate :one
SELECT id, grant_id, token_hash, parent_id, created_at, expires_at, used_at, revoked_at
FROM oidc_refresh_tokens WHERE token_hash = $1 FOR UPDATE;

-- name: MarkOIDCRefreshUsed :execrows
UPDATE oidc_refresh_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL;

-- Ending one sign-in. The user is locked first, from the id, so an issuer that holds the user (shared) finishes before the
-- grants are listed.
-- name: GetOIDCOPSessionUserID :one
SELECT user_id FROM oidc_op_sessions WHERE id = $1;

-- name: EndOIDCOPSession :exec
UPDATE oidc_op_sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCGrantsOfSession :exec
UPDATE oidc_grants SET revoked_at = $2 WHERE op_session_id = $1 AND revoked_at IS NULL;

-- name: RevokeOIDCRefreshOfSession :exec
UPDATE oidc_refresh_tokens SET revoked_at = $2
WHERE revoked_at IS NULL AND grant_id IN (SELECT id FROM oidc_grants WHERE op_session_id = $1);

-- The notices of an ended sign-in: one per live grant whose client takes them. Queued before the grants are revoked, in the
-- transaction that revokes them.
-- name: QueueOIDCLogoutOfUser :exec
INSERT INTO oidc_logout_outbox (id, client_id, user_id, op_session_id, available_at, expires_at, created_at)
SELECT gen_random_uuid(), g.client_id, g.user_id, g.op_session_id, sqlc.arg(now)::timestamptz, sqlc.arg(expires_at)::timestamptz, sqlc.arg(now)::timestamptz
FROM oidc_grants g JOIN oidc_clients c ON c.id = g.client_id
WHERE g.user_id = sqlc.arg(user_id)::uuid AND g.revoked_at IS NULL AND c.status = 'active' AND c.backchannel_logout_uri IS NOT NULL;

-- name: QueueOIDCLogoutOfSession :exec
INSERT INTO oidc_logout_outbox (id, client_id, user_id, op_session_id, available_at, expires_at, created_at)
SELECT gen_random_uuid(), g.client_id, g.user_id, g.op_session_id, sqlc.arg(now)::timestamptz, sqlc.arg(expires_at)::timestamptz, sqlc.arg(now)::timestamptz
FROM oidc_grants g JOIN oidc_clients c ON c.id = g.client_id
WHERE g.op_session_id = sqlc.arg(op_session_id)::uuid AND g.revoked_at IS NULL AND c.status = 'active' AND c.backchannel_logout_uri IS NOT NULL;

-- name: EnqueueOIDCLogout :exec
INSERT INTO oidc_logout_outbox (id, client_id, user_id, op_session_id, available_at, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- Claim leases one due notice and counts the attempt. SKIP LOCKED passes over a notice another worker is claiming; an
-- expired lease makes a notice claimable again. The client's endpoint is read now, not when the notice was queued.
-- name: ClaimOIDCLogout :one
WITH claimed AS (
    UPDATE oidc_logout_outbox
    SET attempts = attempts + 1, lease_until = sqlc.arg(lease_until)::timestamptz
    WHERE oidc_logout_outbox.id = (
        SELECT o.id FROM oidc_logout_outbox o
        WHERE o.status = 'queued'
          AND o.available_at <= sqlc.arg(now)::timestamptz
          AND (o.lease_until IS NULL OR o.lease_until <= sqlc.arg(now)::timestamptz)
        ORDER BY o.available_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id, client_id, user_id, op_session_id, attempts, created_at, expires_at
)
SELECT c.id, c.client_id, c.user_id, c.op_session_id, c.attempts, c.created_at, c.expires_at,
       COALESCE(cl.backchannel_logout_uri, '')::text AS backchannel_uri, COALESCE(cl.status, '')::text AS client_status
FROM claimed c LEFT JOIN oidc_clients cl ON cl.id = c.client_id;

-- name: CompleteOIDCLogout :execrows
UPDATE oidc_logout_outbox SET status = 'sent', lease_until = NULL, last_error = NULL WHERE id = $1 AND status = 'queued';

-- name: RetryOIDCLogout :execrows
UPDATE oidc_logout_outbox SET available_at = $2, lease_until = NULL, last_error = $3 WHERE id = $1 AND status = 'queued';

-- name: AbandonOIDCLogout :execrows
UPDATE oidc_logout_outbox SET status = 'dead', lease_until = NULL, last_error = $2 WHERE id = $1 AND status = 'queued';
