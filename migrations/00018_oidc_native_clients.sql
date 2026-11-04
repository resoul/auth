-- +goose Up
-- Native clients: an application on a person's device. It has no secret, so it has no row in oidc_client_secrets, and PKCE
-- ties a code to it. Its refresh answers can be lost on a mobile network, so within a short window a token may be presented
-- again: the successor nobody received is superseded and a new one takes its place. A superseded token that comes back
-- afterwards is a replay.
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_kind;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_kind CHECK (kind IN ('application', 'service', 'native'));

ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_redirects;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_redirects CHECK (
    (kind IN ('application', 'native') AND cardinality(redirect_uris) BETWEEN 1 AND 10) OR (kind = 'service' AND cardinality(redirect_uris) = 0)
);
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_scopes;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_scopes CHECK (
    (kind IN ('application', 'native') AND cardinality(allowed_scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (allowed_scopes))
    OR (kind = 'service' AND cardinality(allowed_scopes) = 0)
);

ALTER TABLE oidc_refresh_tokens ADD COLUMN superseded_at timestamptz;
DROP INDEX oidc_refresh_one_child;
CREATE UNIQUE INDEX oidc_refresh_one_child ON oidc_refresh_tokens (parent_id) WHERE parent_id IS NOT NULL AND superseded_at IS NULL;

-- +goose Down
DELETE FROM oidc_refresh_tokens WHERE superseded_at IS NOT NULL;
DROP INDEX oidc_refresh_one_child;
CREATE UNIQUE INDEX oidc_refresh_one_child ON oidc_refresh_tokens (parent_id) WHERE parent_id IS NOT NULL;
ALTER TABLE oidc_refresh_tokens DROP COLUMN superseded_at;

DELETE FROM oidc_clients WHERE kind = 'native';
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_scopes;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_scopes CHECK (
    (kind = 'application' AND cardinality(allowed_scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (allowed_scopes))
    OR (kind = 'service' AND cardinality(allowed_scopes) = 0)
);
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_redirects;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_redirects CHECK (
    (kind = 'application' AND cardinality(redirect_uris) BETWEEN 1 AND 10) OR (kind = 'service' AND cardinality(redirect_uris) = 0)
);
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_kind;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_kind CHECK (kind IN ('application', 'service'));
