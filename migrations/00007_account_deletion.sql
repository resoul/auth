-- +goose Up
-- Deletion also removes login flows by the account's current email.
CREATE INDEX auth_flows_email ON auth_flows (email);

-- +goose Down
DROP INDEX auth_flows_email;
