-- +goose Up
-- Service identities: a client that is not an application a person signs in to, but a service that calls an API in its own
-- name (the client_credentials grant). It has a secret like any client, no redirect addresses, and no protocol scopes: it
-- gets no ID token and signs nobody in. What it may ask of an API is stored apart, per client and resource, as for any
-- other client. Disabling it, or rotating its secret without an overlap, is how its credentials are revoked.
ALTER TABLE oidc_clients ADD COLUMN kind text NOT NULL DEFAULT 'application';
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_kind CHECK (kind IN ('application', 'service'));

ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_redirects;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_redirects CHECK (
    (kind = 'application' AND cardinality(redirect_uris) BETWEEN 1 AND 10) OR (kind = 'service' AND cardinality(redirect_uris) = 0)
);
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_scopes;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_scopes CHECK (
    (kind = 'application' AND cardinality(allowed_scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (allowed_scopes))
    OR (kind = 'service' AND cardinality(allowed_scopes) = 0)
);

-- +goose Down
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_scopes;
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_redirects;
DELETE FROM oidc_clients WHERE kind = 'service';
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_redirects CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10);
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_scopes CHECK (cardinality(allowed_scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (allowed_scopes));
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_kind;
ALTER TABLE oidc_clients DROP COLUMN kind;
