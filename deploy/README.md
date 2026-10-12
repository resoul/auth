# Deploying airlance-auth

The service is one static binary in a container image (`Dockerfile`). Whatever runs it has to give it five things.

| It needs | How |
| --- | --- |
| A TLS-terminating proxy in front | The service speaks plain HTTP and its cookies are `Secure`, so browsers only work through HTTPS. Caddy, nginx, Traefik, an ingress controller or a cloud load balancer all do. |
| To know which proxies to believe | `AIRLANCE_AUTH_TRUSTED_PROXIES` lists their networks. The client address (rate limits) comes from `X-Forwarded-For` only when the connection comes from one of them. **Listening beyond the loopback without it is refused at start.** |
| PostgreSQL, with two roles | One that owns the schema and runs `migrate`, one that only reads and writes rows. [`sql/app-role.sql`](sql/app-role.sql) makes the second. |
| A keyring | The OTP and JWT signing keys, as files. `scripts/init_production.sh` makes the first ones. |
| SMTP | Sign-in codes are sent by email. The service refuses to start with a half-set mail configuration. |

Ports: `8080` is the API (`AIRLANCE_AUTH_HTTP_ADDR=0.0.0.0:8080`). `9090` is the metrics listener (`AIRLANCE_AUTH_METRICS_ADDR`),
which has **no authentication**: keep it inside the compose network or the cluster. `8081` is the optional admin API.
Probes: `GET /health/alive` and `GET /health/ready`; the image also has `/airlance-auth healthcheck` for runtimes that cannot call HTTP.

All settings are environment variables; [`../.env.example`](../.env.example) lists and explains every one.

## Build the image

```sh
docker build --build-arg VERSION=$(git rev-parse HEAD) -t registry.example.com/airlance/auth:1.0 .
docker push registry.example.com/airlance/auth:1.0
```

No image is published for you yet, so build and push your own.

## Docker Compose on one server

```sh
scripts/init_production.sh                                   # secrets, keys, env files, deploy/.env
$EDITOR .secrets/production/airlance_auth.env                # SMTP; the domain is already set
docker compose -f deploy/compose.prod.yaml up -d --build
```

`init_production.sh` takes `AIRLANCE_AUTH_DOMAIN` (default `auth.airlance.org`); passkeys are bound to it and cannot be
moved to another domain later. It writes `deploy/.env` with `COMPOSE_PROFILES=caddy`. The profile decides how the service
meets the internet; the service itself never publishes a port.

| Profile | What it adds |
| --- | --- |
| `caddy` (default) | Caddy on ports 80 and 443 with an automatic certificate for the domain. [`Caddyfile`](Caddyfile). The domain must resolve to this host. |
| `tunnel` | A Cloudflare Tunnel connector; nothing is published. Point the tunnel's public hostname at `http://airlance-auth:8080` and put its token in `cloudflared.env`. |
| `monitoring` | Prometheus with the alert rules on `127.0.0.1:9091`. |
| *(none)* | Bring your own proxy: put it on the `internal` network (or publish `8080` yourself) and make sure its address is inside `AIRLANCE_AUTH_SUBNET` (default `172.29.7.0/24`), which is what the service trusts. |

`AIRLANCE_AUTH_SUBNET` in `deploy/.env` moves that network if it clashes with one of yours.

**Databases.** The stack runs its own PostgreSQL and creates both roles on first start (`postgres-init/`, only when the
volume is new). For a database you already have, run [`sql/app-role.sql`](sql/app-role.sql) on it, put its two URLs in
`airlance_auth.env` (the service's role) and `airlance_auth_migrate.env` (the owner's), run the migration, then start the
service and the proxy without the bundled database:

```sh
docker compose -f deploy/compose.prod.yaml run --rm --no-deps migrate
docker compose -f deploy/compose.prod.yaml up -d --no-deps airlance-auth caddy
```

Use `sslmode=verify-full` in both URLs when the database is not on the same host.

## Kubernetes

[`kubernetes/`](kubernetes/) is a kustomize base: Deployment (2 replicas, restricted pod security, probes), Service,
PodDisruptionBudget, NetworkPolicy, an example Ingress, and a Job for the migration. It does not include PostgreSQL;
use a managed service or an operator, and run [`sql/app-role.sql`](sql/app-role.sql) on it.

1. **Edit `kubernetes/kustomization.yaml`**: the image, and `AIRLANCE_AUTH_TRUSTED_PROXIES` — the pod network of your
   ingress controller, as narrow as you can. Without it the pods refuse to start. Edit the host in `ingress.yaml`
   and the namespace labels in `networkpolicy.yaml`. `migrate/kustomization.yaml` needs the same image.
2. **Make the secrets**, with the key files named for where the pod mounts them:

   ```sh
   AIRLANCE_AUTH_DOMAIN=auth.example.com AIRLANCE_AUTH_KEYS_PATH=/etc/airlance-auth/keys \
     AIRLANCE_AUTH_COMPOSE_ENV=none scripts/init_production.sh .secrets/k8s
   $EDITOR .secrets/k8s/airlance_auth.env      # DATABASE_URL (the app role, your host), SMTP
   kubectl create namespace airlance-auth
   kubectl -n airlance-auth create secret generic airlance-auth-keys --from-file=.secrets/k8s/keys
   kubectl -n airlance-auth create secret generic airlance-auth-env  --from-env-file=.secrets/k8s/airlance_auth.env
   kubectl -n airlance-auth create secret generic airlance-auth-migrate \
     --from-literal=AIRLANCE_AUTH_DATABASE_URL='postgres://OWNER:PASSWORD@db.example.com:5432/airlance_auth?sslmode=verify-full'
   ```

3. **Migrate, then roll out**:

   ```sh
   kubectl apply -k deploy/kubernetes/migrate
   kubectl -n airlance-auth wait --for=condition=complete job/airlance-auth-migrate --timeout=120s
   kubectl apply -k deploy/kubernetes
   ```

Scrape `airlance-auth-metrics:9090` from your Prometheus (the NetworkPolicy admits the `monitoring` namespace).
For a new version, build the new image, change `newTag`, delete the finished migration Job and repeat step 3.
Replicas can run side by side: the migration holds a database lock, and the service keeps its state in PostgreSQL.

## Logs

One JSON object per line on stderr (`AIRLANCE_AUTH_LOG_FORMAT=text` for a terminal), at `AIRLANCE_AUTH_LOG_LEVEL`
(`debug`, `info` by default, `warn`, `error`). Every record carries `version`, and every record written while serving
a request carries its `request_id`, the same id the client gets in its error body and in `X-Request-Id`. No email
address, IP address, code or secret is logged.

- `info`: start and stop, one `http request` line per request (route pattern, status, duration), the cleanup sweeps, the
  mail jobs.
- `warn`: `request denied` with `reason=token_reused` (a refresh token used twice, its session is revoked) or
  `reason=clone_suspected` (a passkey whose counter went backwards): someone may hold a secret they should not. Also
  `not ready` and a failing cleanup. Alert on these.
- `error`: `request failed` (a technical failure; the client saw 503) and the same for the admin API.
- `debug`: every other refusal with its `operation` and `reason` (a wrong code, a rate limit, a blocked user), malformed
  requests and refused cross-origin calls. Turn it on to find out why a sign-in is refused; the reasons are also counted
  in the `airlance_auth_denied_total` metric.

## Single sign-on for your applications

Turn the OpenID Provider on when more than one of your web applications should share one sign-in
([README](../README.md#single-sign-on-openid-connect)).

- **Compose:** `AIRLANCE_AUTH_OIDC=1 scripts/init_production.sh` makes the RSA key and sets `AIRLANCE_AUTH_OIDC_ISSUER`
  to `https://DOMAIN`. On a stack that already exists, add an `oidc_signing` group with an RSA key to the keyring and the
  issuer to `airlance_auth.env`, then restart.
- **Kubernetes:** run the init script with `AIRLANCE_AUTH_OIDC=1` as in step 2 above; the key lands in the `airlance-auth-keys`
  secret as `oidc-a.pem`. The issuer must be the origin of your ingress host and one of the WebAuthn origins.
- **The proxy** must pass `Host`, cookies and `Set-Cookie` as they are (Caddy and ingress-nginx do). The provider's cookies are
  `__Host-` cookies of the auth host and are never shared with your applications.
- **Register an application** on the running service; the secret is printed once:

  ```sh
  docker compose -f deploy/compose.prod.yaml exec airlance-auth /airlance-auth oidc client create example-web \
      --name Example --redirect-uri https://app.example.com/auth/callback
  kubectl -n airlance-auth exec deploy/airlance-auth -- /airlance-auth oidc client create example-web \
      --name Example --redirect-uri https://app.example.com/auth/callback
  ```

- **Logout notices** go from the service to your backends (`oidc client set-logout ID --backchannel-logout-uri ...`). A backend on the
  internet needs nothing more. One on the compose network or in the cluster is on a private address, which the service
  refuses to call unless you list its network in `AIRLANCE_AUTH_OIDC_BACKCHANNEL_ALLOW` (the compose subnet is
  `AIRLANCE_AUTH_SUBNET`, `172.29.7.0/24` by default). On Kubernetes, also allow the egress in your NetworkPolicy; the one shipped here
  governs ingress only.
- **Keys** rotate with `scripts/rotate_keys.py add|activate|retire oidc ...`; applications cache the key set, so publish a new key
  and wait before it signs, as the script enforces.
- Disabling an application (`oidc client disable ID`) ends every grant it holds at once.
- **APIs** are registered on the server with `oidc resource register` and opened to an application with `oidc resource allow`
  (see the README). Take rights away with `oidc resource deny`, `set-scopes` or `disable`: the grants that held them end at
  once and their applications are notified. Migration `00015` adds the tables; it changes nothing for a client that never asks
  for a resource. The audience is published to the API's owners; tokens for it live five minutes. Watch
  `airlance_auth_oidc_resource_tokens_total` for `invalid_target` and `invalid_scope` after a change of rights.
- **Back up** the database with the keyring as before: the resources, the rights of each client and the grants are in the
  database, and the signing keys that verify issued tokens are in the keyring.

## Before real users

- Keep `AIRLANCE_AUTH_REGISTRATION=invite` until passkeys have been tried on the devices your users have.
- Back up the database and the keys together; neither works without the other.
- Rotate keys with `scripts/rotate_keys.py` (Compose) or by replacing the `airlance-auth-keys` secret.
- Alert rules for Prometheus are in [`alerts.yaml`](alerts.yaml).
