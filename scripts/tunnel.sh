#!/usr/bin/env bash
# Real-device tests: the browser example and the API behind one HTTPS host, through Cloudflare
# Tunnel. Run `make up` first, then `make tunnel`.
#
# Two modes:
#   quick (default)  a random https://<words>.trycloudflare.com host, no account. The host, and so
#                    every passkey made on it, is gone when the script stops.
#   named            your own host. Create a tunnel in the Cloudflare Zero Trust dashboard
#                    (Networks > Tunnels), add a public hostname for it pointing at
#                    http://localhost:5173, and pass:
#                      AIRLANCE_AUTH_TUNNEL_HOST=auth.example.com CLOUDFLARED_TUNNEL_TOKEN=<token> make tunnel
#                    The token stays in your environment; nothing here writes it down or prints it.
#                    Without the token the script assumes a connector for that tunnel already runs
#                    (for example the cloudflared system service) and only serves the origin.
#
# The service listens on loopback only; only cloudflared reaches it, through scripts/devfront.py,
# which serves the page and forwards the API routes on one origin. Mailpit stays local: read the code
# at http://127.0.0.1:8025 and type it on the phone. Everything is throwaway data in the local
# database, but the URL is public while this runs: stop it with Ctrl+C when you are done.
set -euo pipefail
# real.py loads .env without shell evaluation and selects real delivery explicitly.
REAL_SMTP=false
case "${1:-}" in
    "") ;;
    --real-smtp) REAL_SMTP=true ;;
    *) echo "usage: tunnel.sh [--real-smtp]" >&2; exit 1 ;;
esac
if $REAL_SMTP; then
    for key in AIRLANCE_AUTH_SMTP_ADDR AIRLANCE_AUTH_SMTP_USERNAME AIRLANCE_AUTH_SMTP_PASSWORD AIRLANCE_AUTH_MAIL_FROM; do
        [[ -n ${!key:-} ]] || { echo "$key is required for real SMTP" >&2; exit 1; }
    done
    case "${AIRLANCE_AUTH_SMTP_TLS:-starttls}" in
        starttls|tls) ;;
        *) echo "real SMTP requires starttls or tls" >&2; exit 1 ;;
    esac
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATE=$ROOT/.secrets/tunnel
if $REAL_SMTP; then STATE=$ROOT/.secrets/real; fi
BIN=$ROOT/bin/airlance-auth
API_ADDR=127.0.0.1:8080
FRONT_ADDR=127.0.0.1:5173
MAILPIT=${AIRLANCE_AUTH_DEMO_MAILPIT:-http://127.0.0.1:8025}

for tool in cloudflared curl openssl python3; do
	command -v "$tool" >/dev/null || { echo "tunnel needs $tool" >&2; exit 1; }
done
if ! $REAL_SMTP; then
    curl -sf "$MAILPIT/api/v1/info" >/dev/null || { echo "Mailpit is not reachable at $MAILPIT: run make up" >&2; exit 1; }
fi
for addr in "$API_ADDR" "$FRONT_ADDR"; do
	if (exec 3<>"/dev/tcp/${addr%:*}/${addr#*:}") 2>/dev/null; then
		echo "$addr is already in use: stop what listens there first" >&2
		exit 1
	fi
done

mkdir -p "$STATE"
chmod 700 "$STATE"
LOGS=$STATE/logs
mkdir -p "$LOGS"
if [[ ! -f $STATE/keyring.json ]]; then
	openssl rand -base64 32 >"$STATE/otp-a"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$STATE/sign-a.pem" 2>/dev/null
	chmod 600 "$STATE/otp-a" "$STATE/sign-a.pem"
	cat >"$STATE/keyring.json" <<EOF
{
  "format_version": 1,
  "otp_hmac": {"active_kid": "otp-a", "keys": {"otp-a": {"key_file": "$STATE/otp-a"}}},
  "jwt_signing": {"active_kid": "sign-a", "keys": {"sign-a": {"key_file": "$STATE/sign-a.pem"}}}
}
EOF
fi

PIDS=()
cleanup() {
	trap - EXIT INT TERM
	for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
	for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

echo "building and migrating"
(cd "$ROOT" && go build -o "$BIN" ./cmd/airlance-auth)
export AIRLANCE_AUTH_DATABASE_URL=${AIRLANCE_AUTH_DATABASE_URL:-${DATABASE_URL:-postgres://airlance_auth:airlance_auth@127.0.0.1:5432/airlance_auth?sslmode=disable}}
# migrate loads the full config too; SMTP is not active until the runtime keyring/origin
# are ready. Pass only the database setting in this subshell, keeping secrets in env.
(
    for key in ${!AIRLANCE_AUTH_@}; do
        if [[ $key != AIRLANCE_AUTH_DATABASE_URL ]]; then unset "$key"; fi
    done
    "$BIN" migrate up >/dev/null
)

python3 "$ROOT/scripts/devfront.py" --listen "$FRONT_ADDR" --api "$API_ADDR" 2>"$LOGS/devfront.log" &
PIDS+=($!)

if [[ -n ${AIRLANCE_AUTH_TUNNEL_HOST:-} ]]; then
	HOST=$AIRLANCE_AUTH_TUNNEL_HOST
	if [[ -n ${CLOUDFLARED_TUNNEL_TOKEN:-} ]]; then
		# The token goes by environment, never by argument, so it is not in the process list.
		TUNNEL_TOKEN=$CLOUDFLARED_TUNNEL_TOKEN cloudflared tunnel --no-autoupdate run >"$LOGS/cloudflared.log" 2>&1 &
		PIDS+=($!)
	else
		echo "no CLOUDFLARED_TUNNEL_TOKEN: expecting a running connector for $HOST that points at http://$FRONT_ADDR"
		: >"$LOGS/cloudflared.log"
	fi
else
	cloudflared tunnel --no-autoupdate --url "http://$FRONT_ADDR" >"$LOGS/cloudflared.log" 2>&1 &
	PIDS+=($!)
	CONNECTOR=$!
	HOST=
	for _ in $(seq 1 100); do
		HOST=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOGS/cloudflared.log" | head -n1 | sed 's|https://||' || true)
		[[ -n $HOST ]] && break
		kill -0 "$CONNECTOR" 2>/dev/null || { echo "cloudflared stopped: see $LOGS/cloudflared.log" >&2; exit 1; }
		sleep 0.3
	done
	[[ -n $HOST ]] || { echo "cloudflared gave no host: see $LOGS/cloudflared.log" >&2; exit 1; }
fi
ORIGIN=https://$HOST

# The host is the relying party of every passkey made here; the page and the API share its origin.
export AIRLANCE_AUTH_KEYRING_FILE=${AIRLANCE_AUTH_KEYRING_FILE:-$STATE/keyring.json}
export AIRLANCE_AUTH_JWT_ISSUER=$ORIGIN
export AIRLANCE_AUTH_JWT_AUDIENCE=tunnel
if $REAL_SMTP; then
    export AIRLANCE_AUTH_SMTP_TLS=${AIRLANCE_AUTH_SMTP_TLS:-starttls}
else
    export AIRLANCE_AUTH_SMTP_ADDR=127.0.0.1:1025
    export AIRLANCE_AUTH_SMTP_TLS=none
    export AIRLANCE_AUTH_MAIL_FROM=no-reply@$HOST
fi
export AIRLANCE_AUTH_LOG_FORMAT=text
export AIRLANCE_AUTH_WEBAUTHN_RP_ID=$HOST
export AIRLANCE_AUTH_WEBAUTHN_RP_NAME="airlance-auth test"
export AIRLANCE_AUTH_WEBAUTHN_ORIGINS=$ORIGIN
export AIRLANCE_AUTH_BROWSER_ORIGINS=$ORIGIN
export AIRLANCE_AUTH_TRUSTED_PROXIES=127.0.0.1/32,::1/128
AIRLANCE_AUTH_HTTP_ADDR=$API_ADDR "$BIN" serve 2>"$LOGS/serve.log" &
SERVE=$!
PIDS+=($SERVE)

for _ in $(seq 1 100); do
	curl -sf "http://$API_ADDR/health/ready" >/dev/null 2>&1 && break
	kill -0 "$SERVE" 2>/dev/null || { echo "the service stopped: see $LOGS/serve.log" >&2; exit 1; }
	sleep 0.2
done
# Use the system resolver, just like a browser. Pinning an IP can report success while
# Safari still cannot resolve the newly created host. Give DNS and routing time to settle.
reachable() {
    [[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$ORIGIN/health/ready" 2>/dev/null || true) == 200 ]]
}
READY=
REACHABLE_DEADLINE=$((SECONDS + 180))
echo "waiting for DNS and HTTPS to become reachable"
while (( SECONDS < REACHABLE_DEADLINE )); do
    if reachable; then
        READY=1
        break
    fi
    kill -0 "$SERVE" 2>/dev/null || { echo "the service stopped: see $LOGS/serve.log" >&2; exit 1; }
    sleep 2
done
[[ -n $READY ]] || {
    echo "$ORIGIN is not reachable through system DNS/HTTPS yet: see $LOGS/cloudflared.log" >&2
    exit 1
}

printf '\n\033[1m%s\033[0m\n' "Ready: $ORIGIN"
echo "  open it on the phone or in any browser; passkeys are bound to $HOST"
if $REAL_SMTP; then
    echo "  codes arrive in the real mailbox entered on the page"
else
    echo "  codes arrive in Mailpit on this machine: $MAILPIT"
fi
echo "  logs: $LOGS (the service log carries no codes or tokens)"
echo "  Ctrl+C stops everything"
wait "$SERVE"
