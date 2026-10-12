#!/usr/bin/env bash
# Prototype demo: one local process with
# PostgreSQL, real crypto/JWT and Mailpit. Run `make up` first, then `make demo`.
#
# Demo keys are generated once under .secrets/demo (ignored by Git) and reused.
# Tokens are printed shortened; the full values never leave this script.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEMO=$ROOT/.secrets/demo
BIN=$ROOT/bin/airlance-auth
ADDR=${AIRLANCE_AUTH_DEMO_ADDR:-127.0.0.1:8080}
API=http://$ADDR
MAILPIT=${AIRLANCE_AUTH_DEMO_MAILPIT:-http://127.0.0.1:8025}

export AIRLANCE_AUTH_DATABASE_URL=${DATABASE_URL:-postgres://airlance_auth:airlance_auth@127.0.0.1:5432/airlance_auth?sslmode=disable}
export AIRLANCE_AUTH_KEYRING_FILE=$DEMO/keyring.json
export AIRLANCE_AUTH_JWT_ISSUER=http://$ADDR
export AIRLANCE_AUTH_JWT_AUDIENCE=demo
export AIRLANCE_AUTH_SMTP_ADDR=127.0.0.1:1025
export AIRLANCE_AUTH_SMTP_TLS=none
export AIRLANCE_AUTH_MAIL_FROM=no-reply@auth.example.test
export AIRLANCE_AUTH_LOG_FORMAT=text
# The relying party of the demo passkey. The software authenticator claims this origin, as a
# page of the site would; the API itself answers on the loopback address.
RPID=localhost
ORIGIN=http://localhost:8080
export AIRLANCE_AUTH_WEBAUTHN_RP_ID=$RPID
export AIRLANCE_AUTH_WEBAUTHN_ORIGINS=$ORIGIN
PASSKEY=$DEMO/passkey.json

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
short() { printf '%s…' "${1:0:12}"; }
# field FILE PATH prints a JSON field such as user.id; missing fields print nothing.
field() {
	python3 -c 'import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value.get(key, "") if isinstance(value, dict) else ""
print(value)' "$1" "$2"
}
# call METHOD PATH [BODY] stores the body in $OUT and the status in $STATUS. BEARER, when set,
# is the access token of the call, and STEPUP the step-up token.
OUT=$(mktemp)
BEARER=
STEPUP=
call() {
	STATUS=$(curl -sS -o "$OUT" -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' \
		${BEARER:+-H "Authorization: Bearer $BEARER"} ${STEPUP:+-H "X-Step-Up: $STEPUP"} ${3:+--data "$3"} "$API$2")
}
expect() {
	if [[ $STATUS != "$1" ]]; then
		echo "unexpected HTTP $STATUS, want $1: $(cat "$OUT")" >&2
		exit 1
	fi
}

for tool in curl openssl python3; do
	command -v "$tool" >/dev/null || { echo "demo needs $tool" >&2; exit 1; }
done
curl -sf "$MAILPIT/api/v1/info" >/dev/null || { echo "Mailpit is not reachable at $MAILPIT: run make up" >&2; exit 1; }

mkdir -p "$DEMO"
chmod 700 "$DEMO"
rm -f "$PASSKEY" # a new user gets a new passkey on every run
if [[ ! -f $DEMO/keyring.json ]]; then
	openssl rand -base64 32 >"$DEMO/otp-a"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DEMO/sign-a.pem" 2>/dev/null
	chmod 600 "$DEMO/otp-a" "$DEMO/sign-a.pem"
	cat >"$DEMO/keyring.json" <<EOF
{
  "format_version": 1,
  "otp_hmac": {"active_kid": "otp-a", "keys": {"otp-a": {"key_file": "$DEMO/otp-a"}}},
  "jwt_signing": {"active_kid": "sign-a", "keys": {"sign-a": {"key_file": "$DEMO/sign-a.pem"}}}
}
EOF
fi

step "1. Schema, loopback-only listener"
"$BIN" migrate up
for wide in ":8080" "0.0.0.0:8080" "[::]:8080"; do
	if AIRLANCE_AUTH_HTTP_ADDR=$wide "$BIN" serve 2>"$OUT"; then
		echo "serve accepted $wide" >&2
		exit 1
	fi
	echo "refused $wide: $(grep -o 'AIRLANCE_AUTH_HTTP_ADDR[^;]*' "$OUT" | head -n1)"
done
AIRLANCE_AUTH_HTTP_ADDR=$ADDR "$BIN" serve 2>"$DEMO/serve.log" &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null; wait "$SERVER" 2>/dev/null; rm -f "$OUT"' EXIT
for _ in $(seq 1 50); do
	curl -sf "$API/health/ready" >/dev/null 2>&1 && break
	sleep 0.2
done
call GET /health/ready
expect 200
echo "serving on $API (log: .secrets/demo/serve.log)"

step "2. Native start for a new email"
EMAIL="demo-$(date +%s)@example.test"
call POST /v1/native/auth/email/start "{\"email\": \"$EMAIL\"}"
expect 202
FLOW=$(field "$OUT" flow_id)
BINDING=$(field "$OUT" client_binding)
echo "$EMAIL → flow $FLOW, expires $(field "$OUT" expires_at), client_binding $(short "$BINDING")"

# mailed_code EMAIL N prints the 8-digit code of the newest mail to EMAIL once N mails to it
# have arrived, so a code of an earlier sign-in is never mistaken for the new one.
mailed_code() {
	local id code=""
	for _ in $(seq 1 50); do
		curl -sS -G "$MAILPIT/api/v1/search" --data-urlencode "query=to:\"$1\"" -o "$OUT"
		id=$(python3 -c 'import json, sys; m = json.load(open(sys.argv[1]))["messages"]; print(m[0]["ID"] if len(m) >= int(sys.argv[2]) else "")' "$OUT" "$2")
		if [[ -n $id ]]; then
			curl -sS "$MAILPIT/api/v1/message/$id" -o "$OUT"
			code=$(field "$OUT" Text | grep -oE '[0-9]{4} [0-9]{4}' | head -n1 | tr -d ' ')
			break
		fi
		sleep 0.2
	done
	[[ -n $code ]] || { echo "no mail for $1" >&2; exit 1; }
	printf '%s' "$code"
}
# ceremony OPERATION BODY runs a begin route and leaves the challenge in CHALLENGE and the
# software authenticator's answer in CREDENTIAL; kind is register or assert.
ceremony() {
	call POST "$1" "$2"
	expect 200
	CHALLENGE=$(field "$OUT" challenge_id)
	CREDENTIAL=$("$ROOT/scripts/passkey_client.py" "$PASSKEY" "$RPID" "$ORIGIN" "$3" "$OUT")
}

step "3. Code from Mailpit, verify: the email is proven, there is no session yet"
CODE=$(mailed_code "$EMAIL" 1)
echo "mail delivered (open $MAILPIT to read it)"
VERIFY="{\"flow_id\": \"$FLOW\", \"code\": \"$CODE\", \"client_binding\": \"$BINDING\"}"
call POST /v1/native/auth/email/verify "$VERIFY"
expect 200
TICKET=$(field "$OUT" ticket)
[[ $(field "$OUT" next) == enroll_passkey && -n $TICKET && -z $(field "$OUT" access_token) ]] || { echo "unexpected verify answer: $(cat "$OUT")" >&2; exit 1; }
echo "next step: $(field "$OUT" next), ticket $(short "$TICKET") until $(field "$OUT" expires_at); no token was issued"

step "3b. Register a passkey with the ticket: that opens the session"
ceremony /v1/native/auth/passkey/register/options "{\"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\"}" register
call POST /v1/native/auth/passkey/register/verify "{\"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\", \"challenge_id\": \"$CHALLENGE\", \"credential\": $CREDENTIAL, \"device_name\": \"demo\"}"
expect 200
ACCESS=$(field "$OUT" access_token)
REFRESH=$(field "$OUT" refresh_token)
CODES=$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["recovery_codes"]))' "$OUT")
echo "user $(field "$OUT" user.id), access $(short "$ACCESS") until $(field "$OUT" expires_at), refresh $(short "$REFRESH"), $CODES recovery codes (shown once)"

step "4. Native refresh: a new pair, the old token is used up"
call POST /v1/native/token/refresh "{\"refresh_token\": \"$REFRESH\"}"
expect 200
echo "new access $(short "$(field "$OUT" access_token)"), new refresh $(short "$(field "$OUT" refresh_token)")"
call POST /v1/native/token/refresh "{\"refresh_token\": \"$REFRESH\"}"
expect 401
echo "old refresh → $STATUS $(field "$OUT" code) (the replay also revoked the session)"

step "5. The same flow does not verify again"
call POST /v1/native/auth/email/verify "$VERIFY"
expect 400
echo "second verify → $STATUS $(field "$OUT" code)"

step "6. The passkey alone signs in, from a client with no binding"
ceremony /v1/native/auth/passkey/login/options "" assert
call POST /v1/native/auth/passkey/login/verify "{\"challenge_id\": \"$CHALLENGE\", \"credential\": $CREDENTIAL}"
expect 200
echo "signed in without email: access $(short "$(field "$OUT" access_token)"), new client_binding $(short "$(field "$OUT" client_binding)")"

step "7. The email code of a user with a passkey asks for the second factor"
call POST /v1/native/auth/email/start "{\"email\": \"$EMAIL\"}"
expect 202
FLOW2=$(field "$OUT" flow_id)
BINDING2=$(field "$OUT" client_binding)
CODE2=$(mailed_code "$EMAIL" 2)
call POST /v1/native/auth/email/verify "{\"flow_id\": \"$FLOW2\", \"code\": \"$CODE2\", \"client_binding\": \"$BINDING2\"}"
expect 200
TICKET2=$(field "$OUT" ticket)
[[ $(field "$OUT" next) == second_factor && -z $(field "$OUT" access_token) ]] || { echo "unexpected verify answer: $(cat "$OUT")" >&2; exit 1; }
echo "next step: $(field "$OUT" next): the mailbox alone opens nothing"
ceremony /v1/native/auth/passkey/login/options "" assert
call POST /v1/native/auth/passkey/login/verify "{\"challenge_id\": \"$CHALLENGE\", \"credential\": $CREDENTIAL, \"ticket\": \"$TICKET2\", \"client_binding\": \"$BINDING2\"}"
expect 200
echo "second factor proven: access $(short "$(field "$OUT" access_token)")"
SIGNED_IN=$(field "$OUT" access_token)

step "8. Change the email: a fresh passkey proof, a code to the new address, a notice to the old one"
NEW_EMAIL="demo-new-$(date +%s)@example.test"
BEARER=$SIGNED_IN
call POST /v1/native/me/email/change "{\"email\": \"$NEW_EMAIL\"}"
expect 403
echo "a session alone is not enough: $STATUS $(field "$OUT" code)"
ceremony /v1/native/me/step-up/options '{"operation": "change_email"}' assert
call POST /v1/native/me/step-up/verify "{\"challenge_id\": \"$CHALLENGE\", \"credential\": $CREDENTIAL}"
expect 200
STEPUP=$(field "$OUT" step_up_token)
call POST /v1/native/me/email/change "{\"email\": \"$NEW_EMAIL\"}"
expect 202
CHANGE_FLOW=$(field "$OUT" flow_id)
STEPUP=
echo "the step-up bought one request; the code is on its way to $NEW_EMAIL"
CODE3=$(mailed_code "$NEW_EMAIL" 1)
call POST /v1/native/me/email/change/confirm "{\"flow_id\": \"$CHANGE_FLOW\", \"code\": \"$CODE3\"}"
expect 200
echo "the account now has $(field "$OUT" email)"
call GET /v1/native/me
expect 200
[[ $(field "$OUT" user.email) == "$NEW_EMAIL" ]] || { echo "the profile shows the old address: $(cat "$OUT")" >&2; exit 1; }
call POST /v1/native/me/email/change/confirm "{\"flow_id\": \"$CHANGE_FLOW\", \"code\": \"$CODE3\"}"
expect 400
echo "the code works once: $STATUS $(field "$OUT" code)"
BEARER=
for _ in $(seq 1 50); do
	curl -sS -G "$MAILPIT/api/v1/search" --data-urlencode "query=to:\"$EMAIL\"" -o "$OUT"
	[[ $(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["messages"]))' "$OUT") -ge 3 ]] && break
	sleep 0.2
done
echo "the old address was told: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["messages"][0]["Subject"])' "$OUT")"

step "Key set and metrics"
call GET /.well-known/jwks.json
expect 200
echo "jwks kids: $(python3 -c 'import json, sys; print(", ".join(k["kid"] for k in json.load(open(sys.argv[1]))["keys"]))' "$OUT")"
curl -sS "$API/metrics" | grep -E '^airlance_auth_(mail_jobs_total\{outcome="sent"|refresh_reuse_total)' || true

step "Done: demo passed"
