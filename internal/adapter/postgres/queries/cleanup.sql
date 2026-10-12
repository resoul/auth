-- Retention sweeps. Each statement deletes
-- one bounded batch; SKIP LOCKED lets two sweepers run without waiting for each other.

-- A flow goes once expires_at is old enough, unless a worker still holds its mail
-- under a live lease. Its outbox rows follow by cascade.
-- name: DeleteExpiredFlows :execrows
DELETE FROM auth_flows
WHERE id IN (
    SELECT f.id FROM auth_flows f
    WHERE f.expires_at < @horizon
      AND NOT EXISTS (
          SELECT 1 FROM outbox o
          WHERE o.flow_id = f.id AND o.lease_until IS NOT NULL AND o.lease_until > @now
      )
    ORDER BY f.expires_at
    LIMIT @max_rows
    FOR UPDATE OF f SKIP LOCKED
);

-- name: DeleteEndedRecognizedClients :execrows
DELETE FROM recognized_clients
WHERE id IN (
    SELECT r.id FROM recognized_clients r
    WHERE r.expires_at < @horizon OR r.revoked_at < @horizon
    ORDER BY r.expires_at
    LIMIT @max_rows
    FOR UPDATE OF r SKIP LOCKED
);

-- A session has ended at the earliest of its revocation, idle limit and absolute limit.
-- Its refresh tokens follow by cascade; audit rows keep their event and lose the reference.
-- name: DeleteEndedSessions :execrows
DELETE FROM sessions
WHERE id IN (
    SELECT x.id FROM sessions x
    WHERE x.revoked_at < @horizon OR x.idle_expires_at < @horizon OR x.expires_at < @horizon
    ORDER BY x.idle_expires_at
    LIMIT @max_rows
    FOR UPDATE OF x SKIP LOCKED
);

-- Events that matter after a takeover claim (@lasting_events, and the refusal of a key whose counter did
-- not grow) wait for the longer horizon. The condition is in the WHERE, not in the ordering, so a batch
-- never fills up with rows that must stay while deletable ones wait behind them.
-- name: DeleteOldAuditEvents :execrows
DELETE FROM audit_events
WHERE id IN (
    SELECT a.id FROM audit_events a
    WHERE a.occurred_at < @horizon
      AND (a.occurred_at < @lasting_horizon
           OR NOT (a.event = ANY(@lasting_events::text[]) OR (a.event IN ('passkey.refused', 'operator.login') AND COALESCE(a.fields ->> 'reason' = @clone_reason::text, false))))
    ORDER BY a.occurred_at
    LIMIT @max_rows
    FOR UPDATE OF a SKIP LOCKED
);

-- A ceremony lives minutes; its state is useless once the challenge expired.
-- The mail of an invitation or of a new device belongs to no flow, so no cascade removes it (a deleted user's
-- notices go with the user). It goes a grace period after it
-- was made, whatever became of it, unless a worker holds it under a live lease.
-- name: DeleteOldInvitationMail :execrows
DELETE FROM outbox
WHERE id IN (
    SELECT o.id FROM outbox o
    WHERE o.kind IN ('invitation', 'new_device')
      AND o.created_at < @horizon
      AND (o.lease_until IS NULL OR o.lease_until <= @now)
    ORDER BY o.created_at
    LIMIT @max_rows
    FOR UPDATE OF o SKIP LOCKED
);

-- An invitation that nobody used is useless once it expired.
-- name: DeleteExpiredInvitations :execrows
DELETE FROM invitations
WHERE email IN (
    SELECT i.email FROM invitations i
    WHERE i.expires_at < @horizon
    ORDER BY i.expires_at
    LIMIT @max_rows
    FOR UPDATE OF i SKIP LOCKED
);

-- name: DeleteExpiredChallenges :execrows
DELETE FROM passkey_challenges
WHERE id IN (
    SELECT c.id FROM passkey_challenges c
    WHERE c.expires_at < @horizon
    ORDER BY c.expires_at
    LIMIT @max_rows
    FOR UPDATE OF c SKIP LOCKED
);

-- A ticket, used or not, is useless once it expired. Recovery codes are not swept: they live
-- as long as their user and a new set replaces the old one.
-- name: DeleteExpiredTickets :execrows
DELETE FROM auth_tickets
WHERE id IN (
    SELECT t.id FROM auth_tickets t
    WHERE t.expires_at < @horizon
    ORDER BY t.expires_at
    LIMIT @max_rows
    FOR UPDATE OF t SKIP LOCKED
);

-- The admin API's short-lived rows. A session lives at most eight hours, so one created before the
-- horizon is over whatever became of it; a ceremony and an enrollment code are useless once expired.
-- name: DeleteOldOperatorSessions :execrows
DELETE FROM operator_sessions
WHERE id IN (
    SELECT s.id FROM operator_sessions s
    WHERE s.created_at < @horizon
    ORDER BY s.created_at
    LIMIT @max_rows
    FOR UPDATE OF s SKIP LOCKED
);

-- name: DeleteExpiredOperatorChallenges :execrows
DELETE FROM operator_challenges
WHERE id IN (
    SELECT c.id FROM operator_challenges c
    WHERE c.expires_at < @horizon
    ORDER BY c.expires_at
    LIMIT @max_rows
    FOR UPDATE OF c SKIP LOCKED
);

-- name: DeleteExpiredOperatorEnrollments :execrows
DELETE FROM operator_enrollments
WHERE id IN (
    SELECT e.id FROM operator_enrollments e
    WHERE e.expires_at < @horizon
    ORDER BY e.expires_at
    LIMIT @max_rows
    FOR UPDATE OF e SKIP LOCKED
);

-- A device request is useless once it expired, whatever became of it.
-- name: DeleteExpiredDeviceRequests :execrows
DELETE FROM device_requests
WHERE id IN (
    SELECT d.id FROM device_requests d
    WHERE d.expires_at < @horizon
    ORDER BY d.expires_at
    LIMIT @max_rows
    FOR UPDATE OF d SKIP LOCKED
);

-- The OpenID Provider's short-lived rows. A request or a code is useless once it expired; an OP session that ended or
-- expired takes its grants, codes and refresh tokens with it (they cascade).
-- name: DeleteExpiredOIDCRequests :execrows
DELETE FROM oidc_authorization_requests
WHERE id_hash IN (
    SELECT r.id_hash FROM oidc_authorization_requests r
    WHERE r.expires_at < @horizon
    ORDER BY r.expires_at
    LIMIT @max_rows
    FOR UPDATE OF r SKIP LOCKED
);

-- name: DeleteExpiredOIDCCodes :execrows
DELETE FROM oidc_authorization_codes
WHERE code_hash IN (
    SELECT c.code_hash FROM oidc_authorization_codes c
    WHERE c.expires_at < @horizon
      -- A spent code is what shows a copy of it for a replay, and the replay ends the grant: it stays as long as the grant
      -- can still hold tokens. A code nobody exchanged is worth nothing once it expired.
      AND (c.consumed_at IS NULL OR NOT EXISTS (
          SELECT 1 FROM oidc_grants g WHERE g.id = c.grant_id AND g.revoked_at IS NULL AND g.expires_at > sqlc.arg(now)::timestamptz))
    ORDER BY c.expires_at
    LIMIT @max_rows
    FOR UPDATE OF c SKIP LOCKED
);

-- name: DeleteEndedOIDCSessions :execrows
DELETE FROM oidc_op_sessions
WHERE id IN (
    SELECT s.id FROM oidc_op_sessions s
    WHERE LEAST(s.expires_at, COALESCE(s.revoked_at, s.expires_at)) < @horizon
    ORDER BY s.expires_at
    LIMIT @max_rows
    FOR UPDATE OF s SKIP LOCKED
);

-- name: DeleteOldOIDCLogout :execrows
DELETE FROM oidc_logout_outbox
WHERE id IN (
    SELECT o.id FROM oidc_logout_outbox o
    WHERE o.status <> 'queued' AND o.created_at < @horizon
    ORDER BY o.created_at
    LIMIT @max_rows
    FOR UPDATE OF o SKIP LOCKED
);
