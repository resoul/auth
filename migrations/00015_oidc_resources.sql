-- +goose Up
-- API resources: the logical recipients of access tokens. An OIDC client is the application that asks for a sign-in; a
-- resource is the API its tokens are for, with its own audience and the rights (scopes) its owner defined. What a
-- client may ask of a resource is stored apart, per client and resource. A request, a code and a grant each remember
-- which resources were agreed and with which rights; a grant never gains one.
--
-- Changing the rights of a resource, or of a client on it, takes the resource row exclusively, and issuing a token for
-- it takes the row shared: so once a change has completed, nothing issued under the old rights is still being made.

CREATE TABLE oidc_resources (
    -- The identifier: lower-case letters, digits, '-' and '_' only, so it can also be an audit value.
    id             text        PRIMARY KEY,
    name           text        NOT NULL,
    status         text        NOT NULL DEFAULT 'active',
    -- The value of the RFC 8707 resource parameter that selects the resource; it identifies, and is never fetched.
    uri            text        NOT NULL,
    -- The aud of every access token issued for the resource.
    audience       text        NOT NULL,
    -- The rights the owner of the API defined, such as messages:send.
    scopes         text[]      NOT NULL,
    -- Raised whenever the rights of the resource change.
    policy_version integer     NOT NULL DEFAULT 1,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    CONSTRAINT oidc_resources_id CHECK (id ~ '^[a-z][a-z0-9_-]{2,63}$'),
    CONSTRAINT oidc_resources_name CHECK (name <> '' AND char_length(name) <= 100),
    CONSTRAINT oidc_resources_status CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oidc_resources_uri CHECK (uri <> '' AND char_length(uri) <= 2048 AND uri !~ '[#?]'),
    CONSTRAINT oidc_resources_audience CHECK (audience <> '' AND char_length(audience) <= 256),
    CONSTRAINT oidc_resources_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 32),
    CONSTRAINT oidc_resources_policy CHECK (policy_version >= 1),
    -- Two logical resources never share an address or an audience; a disabled one keeps its names.
    CONSTRAINT oidc_resources_uri_unique UNIQUE (uri),
    CONSTRAINT oidc_resources_audience_unique UNIQUE (audience)
);

-- What a client may ask of a resource. A client without a row for a resource may not ask for it.
CREATE TABLE oidc_client_resources (
    client_id   text        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    resource_id text        NOT NULL REFERENCES oidc_resources (id) ON DELETE CASCADE,
    scopes      text[]      NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (client_id, resource_id),
    CONSTRAINT oidc_client_resources_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);
CREATE INDEX oidc_client_resources_resource ON oidc_client_resources (resource_id);

-- The resources of an authorization request that is waiting for the browser to sign in.
CREATE TABLE oidc_request_resources (
    request_hash   bytea   NOT NULL REFERENCES oidc_authorization_requests (id_hash) ON DELETE CASCADE,
    resource_id    text    NOT NULL REFERENCES oidc_resources (id) ON DELETE CASCADE,
    scopes         text[]  NOT NULL,
    policy_version integer NOT NULL,
    PRIMARY KEY (request_hash, resource_id),
    CONSTRAINT oidc_request_resources_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);

-- The resources an authorization code was issued for: a token request may select one of them.
CREATE TABLE oidc_code_resources (
    code_hash      bytea   NOT NULL REFERENCES oidc_authorization_codes (code_hash) ON DELETE CASCADE,
    resource_id    text    NOT NULL REFERENCES oidc_resources (id) ON DELETE CASCADE,
    scopes         text[]  NOT NULL,
    policy_version integer NOT NULL,
    PRIMARY KEY (code_hash, resource_id),
    CONSTRAINT oidc_code_resources_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);

-- What a grant holds of each resource. It is written when the grant is made and never widened.
CREATE TABLE oidc_grant_resources (
    grant_id       uuid    NOT NULL REFERENCES oidc_grants (id) ON DELETE CASCADE,
    resource_id    text    NOT NULL REFERENCES oidc_resources (id) ON DELETE CASCADE,
    scopes         text[]  NOT NULL,
    policy_version integer NOT NULL,
    PRIMARY KEY (grant_id, resource_id),
    CONSTRAINT oidc_grant_resources_scopes CHECK (cardinality(scopes) BETWEEN 1 AND 32)
);
-- Ending the grants of a resource, or of a client on it, finds them here.
CREATE INDEX oidc_grant_resources_resource ON oidc_grant_resources (resource_id);

-- +goose Down
DROP TABLE oidc_grant_resources;
DROP TABLE oidc_code_resources;
DROP TABLE oidc_request_resources;
DROP TABLE oidc_client_resources;
DROP TABLE oidc_resources;
