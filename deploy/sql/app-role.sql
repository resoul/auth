-- Two database roles for the service, on any PostgreSQL (the bundled container, a managed service, your own server):
--   owner  creates and changes tables; only `airlance-auth migrate` connects as it.
--   app    what the running service connects as: reads and writes rows, nothing else. A compromised service
--          cannot drop tables, change the schema or touch other schemas.
-- Run once, as a role that may create roles and schemas, before the first `migrate`:
--
--   psql -v owner=airlance_auth -v app=airlance_auth_app -v schema=auth -v app_password='...' \
--        -d airlance_auth -f deploy/sql/app-role.sql
--
-- The default privileges make every table the owner creates later (each migration) usable by the app role.
\set ON_ERROR_STOP on

CREATE ROLE :"app" LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
-- Created here, not by `migrate`, because default privileges need the schema to exist.
CREATE SCHEMA IF NOT EXISTS :"schema" AUTHORIZATION :"owner";
ALTER ROLE :"app" SET search_path = :"schema";
GRANT USAGE ON SCHEMA :"schema" TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA :"schema" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA :"schema" GRANT USAGE, SELECT ON SEQUENCES TO :"app";
