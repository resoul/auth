#!/usr/bin/env bash
# Makes the secrets directory of the one-server stack (deploy/compose.prod.yaml): the passwords of the two
# database roles (the schema owner for the migration, an unprivileged one for the service), the keyring with
# its first keys and the env files. It never overwrites what exists, and prints no secret.
#
#   scripts/init_production.sh [DIRECTORY]      default: .secrets/production
#
# AIRLANCE_AUTH_DOMAIN      the public host name (default auth.airlance.org); the passkeys are bound to it
# AIRLANCE_AUTH_AUDIENCE    the aud claim of access tokens (default airlance)
# AIRLANCE_AUTH_COMPOSE_ENV the file for the Compose variables (default deploy/.env); "none" writes none
# AIRLANCE_AUTH_OIDC        1 to turn on the OpenID Provider (single sign-on for your applications): makes an RSA signing
#                           key and sets AIRLANCE_AUTH_OIDC_ISSUER to https://DOMAIN. Default: off.
# AIRLANCE_AUTH_KEYS_PATH   where the key files will be when the service runs, if not in DIRECTORY/keys: set it
#                           to /etc/airlance-auth/keys for Kubernetes (deploy/kubernetes/README.md)
#
# What you still fill in by hand: the SMTP settings in airlance_auth.env and, only if you use the tunnel
# profile, the tunnel token in cloudflared.env.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR=${1:-$ROOT/.secrets/production}
case $DIR in /*) ;; *) DIR=$PWD/$DIR ;; esac
DOMAIN=${AIRLANCE_AUTH_DOMAIN:-auth.airlance.org}
AUDIENCE=${AIRLANCE_AUTH_AUDIENCE:-airlance}
KEYS=${AIRLANCE_AUTH_KEYS_PATH:-$DIR/keys}
OIDC=${AIRLANCE_AUTH_OIDC:-0}
case $OIDC in 0 | 1) ;; *) echo "AIRLANCE_AUTH_OIDC must be 0 or 1" >&2; exit 1 ;; esac

for tool in openssl; do
	command -v "$tool" >/dev/null || { echo "init needs $tool" >&2; exit 1; }
done
if [[ -e $DIR/airlance_auth.env ]]; then
	echo "$DIR/airlance_auth.env exists: refusing to touch an initialized directory" >&2
	exit 1
fi

umask 077
mkdir -p "$DIR/keys"
chmod 700 "$DIR" "$DIR/keys"

# URL-safe, so they can sit inside the database URL as they are.
PASSWORD=$(openssl rand -hex 24)
APP_PASSWORD=$(openssl rand -hex 24)
printf '%s' "$PASSWORD" >"$DIR/postgres_password"
printf '%s' "$APP_PASSWORD" >"$DIR/postgres_app_password"

openssl rand -base64 32 >"$DIR/keys/otp-a"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/keys/sign-a.pem" 2>/dev/null
if [[ $OIDC == 1 ]]; then
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$DIR/keys/oidc-a.pem" 2>/dev/null
	chmod 600 "$DIR/keys/oidc-a.pem"
fi
chmod 600 "$DIR/keys/otp-a" "$DIR/keys/sign-a.pem"
OIDC_KEYS=
if [[ $OIDC == 1 ]]; then
	OIDC_KEYS=",
  \"oidc_signing\": {\"active_kid\": \"oidc-a\", \"keys\": {\"oidc-a\": {\"key_file\": \"$KEYS/oidc-a.pem\"}}}"
fi
cat >"$DIR/keys/keyring.json" <<JSON
{
  "format_version": 1,
  "otp_hmac": {"active_kid": "otp-a", "keys": {"otp-a": {"key_file": "$KEYS/otp-a"}}},
  "jwt_signing": {"active_kid": "sign-a", "keys": {"sign-a": {"key_file": "$KEYS/sign-a.pem"}}}$OIDC_KEYS
}
JSON
chmod 600 "$DIR/keys/keyring.json"

if [[ $OIDC == 1 ]]; then
	OIDC_ENV="AIRLANCE_AUTH_OIDC_ISSUER=https://$DOMAIN"
else
	OIDC_ENV="# AIRLANCE_AUTH_OIDC_ISSUER=https://$DOMAIN"
fi
cat >"$DIR/airlance_auth.env" <<ENV
# Read by the migration and the service (docker compose env_file): no quotes, one KEY=value per line.
AIRLANCE_AUTH_LOG_FORMAT=json
AIRLANCE_AUTH_LOG_LEVEL=info
# The service's role: rows only. The migration overrides this with the owner (airlance_auth_migrate.env).
AIRLANCE_AUTH_DATABASE_URL=postgres://airlance_auth_app:$APP_PASSWORD@postgres:5432/airlance_auth?sslmode=disable
AIRLANCE_AUTH_DATABASE_MAX_CONNS=20
AIRLANCE_AUTH_KEYRING_FILE=$KEYS/keyring.json
AIRLANCE_AUTH_JWT_ISSUER=https://$DOMAIN
AIRLANCE_AUTH_JWT_AUDIENCE=$AUDIENCE
# The relying party of every passkey. Changing it later loses every passkey.
AIRLANCE_AUTH_WEBAUTHN_RP_ID=$DOMAIN
AIRLANCE_AUTH_WEBAUTHN_RP_NAME=Airlance
AIRLANCE_AUTH_WEBAUTHN_ORIGINS=https://$DOMAIN
# Pages of your products that call the browser profile with cookies, as exact origins:
# AIRLANCE_AUTH_BROWSER_ORIGINS=https://app.airlance.org
AIRLANCE_AUTH_BROWSER_ORIGINS=
# The OpenID Provider: single sign-on for your applications, which are registered with
# "airlance-auth oidc client create". Needs the oidc_signing key of the keyring. The issuer is one of the WebAuthn origins.
$OIDC_ENV
# Who may open an account: open, or invite (only invited addresses; made with: airlance-auth invite create EMAIL).
AIRLANCE_AUTH_REGISTRATION=open
# The page an invitation email points to (your product's sign-in page). Unset, it is the service address.
# AIRLANCE_AUTH_INVITATION_URL=https://app.airlance.org/login
# The admin API is off until you uncomment these settings. It listens inside the compose network; publish it
# as a second hostname (deploy/Caddyfile has the block, or point a tunnel hostname at http://airlance-auth:8081).
# Its relying party must differ from the users': an operator's passkey is bound to the admin hostname.
# AIRLANCE_AUTH_ADMIN_ADDR=0.0.0.0:8081
# AIRLANCE_AUTH_ADMIN_RP_ID=admin.${DOMAIN#*.}
# AIRLANCE_AUTH_ADMIN_ORIGINS=https://admin.${DOMAIN#*.}
# Mail: fill in your provider. TLS is starttls (port 587) or tls (port 465); never none.
AIRLANCE_AUTH_SMTP_ADDR=
AIRLANCE_AUTH_SMTP_TLS=starttls
AIRLANCE_AUTH_SMTP_USERNAME=
AIRLANCE_AUTH_SMTP_PASSWORD=
AIRLANCE_AUTH_MAIL_FROM=no-reply@airlance.org
AIRLANCE_AUTH_MAIL_FROM_NAME=Airlance
ENV
cat >"$DIR/airlance_auth_migrate.env" <<ENV
# Read after airlance_auth.env by the migration only: it changes tables, so it connects as their owner.
AIRLANCE_AUTH_DATABASE_URL=postgres://airlance_auth:$PASSWORD@postgres:5432/airlance_auth?sslmode=disable
ENV
cat >"$DIR/cloudflared.env" <<ENV
# Only for the "tunnel" profile. The token of the tunnel from Cloudflare Zero Trust (Networks > Tunnels). Its
# public hostname $DOMAIN must point at http://airlance-auth:8080.
TUNNEL_TOKEN=
ENV
chmod 600 "$DIR/airlance_auth.env" "$DIR/airlance_auth_migrate.env" "$DIR/cloudflared.env" "$DIR/postgres_password" "$DIR/postgres_app_password"

# Variables of the compose file: where the secrets are and who reads them. No secret in it.
COMPOSE_ENV=${AIRLANCE_AUTH_COMPOSE_ENV:-$ROOT/deploy/.env}
if [[ $COMPOSE_ENV == none ]]; then
	:  # Kubernetes and other runtimes that do not read it
elif [[ ! -e $COMPOSE_ENV ]]; then
	# caddy: a TLS proxy with an automatic certificate for $DOMAIN. Use "tunnel" for a Cloudflare Tunnel instead,
	# or no profile to bring your own proxy; add "monitoring" for Prometheus.
	printf 'AIRLANCE_AUTH_SECRETS_DIR=%s\nAIRLANCE_AUTH_UID=%s\nAIRLANCE_AUTH_GID=%s\nAIRLANCE_AUTH_DOMAIN=%s\nCOMPOSE_PROFILES=caddy\n' "$DIR" "$(id -u)" "$(id -g)" "$DOMAIN" >"$COMPOSE_ENV"
	chmod 600 "$COMPOSE_ENV"
	echo "wrote $COMPOSE_ENV"
else
	echo "$COMPOSE_ENV exists: make sure it names AIRLANCE_AUTH_SECRETS_DIR=$DIR and your AIRLANCE_AUTH_UID and AIRLANCE_AUTH_GID"
fi

cat <<MSG
Made $DIR (secrets are in it, not here).
Next:
  1. edit $DIR/airlance_auth.env (SMTP); with the tunnel profile also $DIR/cloudflared.env (tunnel token)
  2. docker compose -f deploy/compose.prod.yaml up -d --build   (profile caddy: ports 80 and 443 must reach this host)
  3. back up $DIR/keys and the database together.
MSG
