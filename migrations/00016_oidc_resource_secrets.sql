-- +goose Up
-- The credentials of an API: with them it asks the provider whether an access token for it is still good (token
-- introspection, RFC 7662). They belong to the resource, not to an application, and they open nothing else. At most two
-- are live at a time, so a rotation can overlap the old and the new one, as with client secrets.
CREATE TABLE oidc_resource_secrets (
    id          uuid        PRIMARY KEY,
    resource_id text        NOT NULL REFERENCES oidc_resources (id) ON DELETE CASCADE,
    secret_hash bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz,
    revoked_at  timestamptz,
    CONSTRAINT oidc_resource_secrets_hash CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT oidc_resource_secrets_hash_unique UNIQUE (secret_hash)
);
CREATE INDEX oidc_resource_secrets_resource ON oidc_resource_secrets (resource_id);

-- +goose Down
DROP TABLE oidc_resource_secrets;
