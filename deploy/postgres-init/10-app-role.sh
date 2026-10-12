#!/bin/sh
# Runs once, when the data volume is empty (docker-entrypoint-initdb.d): creates the service's unprivileged
# role from deploy/sql/app-role.sql, mounted next to this script. See that file for what the roles are.
set -eu

APP_PASSWORD=$(cat /run/secrets/postgres_app_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	-v owner="$POSTGRES_USER" -v app=airlance_auth_app -v schema=auth -v app_password="$APP_PASSWORD" \
	-f /opt/airlance-auth/app-role.sql
