# airlance-auth

A passwordless authentication service written in Go. People sign in with an email code and a
passkey, or with a passkey alone. There are no passwords. It issues short-lived signed access tokens
that your own services can verify offline, and long-lived refresh tokens that rotate on every use.
Turned on, it is also an OpenID Connect provider: single sign-on for your own web applications
(see [Single sign-on](#single-sign-on-openid-connect)).

It serves three kinds of clients from one process:

- **Browsers**, with HttpOnly cookies for the refresh token and the client binding.
- **Native and mobile apps**, with the same flows over a JSON API that carries secrets in bodies.
- **Your backend services**, which only need the public key set (`/.well-known/jwks.json`).

> **Status:** the MVP is assembled and runs against real PostgreSQL, a real keyring and real SMTP,
> in Docker Compose or Kubernetes behind a TLS proxy (see [deploy/README.md](deploy/README.md)). Some
> items are still unverified, see [Limitations](#limitations).

## Quick start

New here? Run the service locally in a few minutes, then follow [Using the API with curl](#using-the-api-with-curl)
for a complete sign-in, token refresh and sign-out.

You need Go (the version is in `go.mod`), Docker with Compose, and `make`. The examples also use `curl`, and
`jq` to read fields from JSON responses.

```sh
make up      # PostgreSQL and Mailpit in Docker Compose
make demo    # builds the binary, applies migrations, starts the server and walks through a sign-in
```

The demo creates throwaway keys under `.secrets/demo` (ignored by Git), runs the whole path
start → mail → verify → passkey → refresh, and prints the JWKS and the metrics at the end. Read the
mail in Mailpit at <http://127.0.0.1:8025>. [`scripts/demo.sh`](scripts/demo.sh) runs the sign-in, refresh,
second-factor, step-up and email-change calls of the walkthrough below against the same server.

To run the server yourself, start the services and apply the migrations with `make up && make migrate`. The keyring
file is created by `make demo`, so run that once before this:

```sh
export AIRLANCE_AUTH_DATABASE_URL='postgres://airlance_auth:airlance_auth@127.0.0.1:5432/airlance_auth?sslmode=disable'
export AIRLANCE_AUTH_KEYRING_FILE=$PWD/.secrets/demo/keyring.json
export AIRLANCE_AUTH_JWT_ISSUER=http://127.0.0.1:8080
export AIRLANCE_AUTH_JWT_AUDIENCE=demo
export AIRLANCE_AUTH_WEBAUTHN_RP_ID=localhost
export AIRLANCE_AUTH_WEBAUTHN_ORIGINS=http://localhost:8080
export AIRLANCE_AUTH_SMTP_ADDR=127.0.0.1:1025
export AIRLANCE_AUTH_SMTP_TLS=none
export AIRLANCE_AUTH_MAIL_FROM=no-reply@auth.example.test
export AIRLANCE_AUTH_HTTP_ADDR=127.0.0.1:8080
go run ./cmd/airlance-auth serve
```

Configuration is read only from the process environment. The server needs a database URL, a keyring
file with OTP and JWT keys, a JWT issuer and audience, the WebAuthn relying party ID and origins, and
SMTP settings. Every variable is documented in [.env.example](.env.example).

The server speaks plain HTTP. Anywhere beyond your own machine, put a TLS-terminating proxy or ingress in front
of it and list that proxy in `AIRLANCE_AUTH_TRUSTED_PROXIES`.

To try the browser page on a phone with a real HTTPS host, use `make tunnel` (Cloudflare Tunnel) or `make real`
(real SMTP settings from `.env`). Both need `cloudflared`; see [examples/browser](examples/browser).

## Using the API with curl

This walks through a complete user journey. It uses the **native profile**, `/v1/native/...`, which carries tokens
in JSON bodies and headers, so `curl` can drive it end to end. Browsers use the same operations under `/v1/` with
cookies; see [Browser clients](#browser-clients).

Set the base URL once. Locally it is the address the server listens on; in production it is your public HTTPS origin.

```sh
export AUTH=http://127.0.0.1:8080
```

### Conventions

- Request bodies are JSON: add `-H 'Content-Type: application/json'`.
- Signed-in calls send `-H "Authorization: Bearer $ACCESS_TOKEN"`.
- Every error has the same shape, `{"code": "invalid_code", "request_id": "…"}`. The same ID is in the
  `X-Request-Id` response header. Quote it when you report a problem.
- Some values travel from one call to the next. Each has a short life and one purpose:

| Value | Comes from | Lives | Used for |
| --- | --- | --- | --- |
| `flow_id` | email start | 10 minutes | verifying or resending the email code |
| `client_binding` | the first start call | keep it in secure storage | tying this device's calls together |
| `ticket` | email verify, or recovery verify | 10 minutes | registering a passkey or proving one |
| `challenge_id` | any `options` call | 5 minutes | the verify call of the same ceremony |
| `access_token` | sign-in or refresh | 5 minutes by default (at most 1 hour) | `Authorization: Bearer` on signed-in calls |
| `refresh_token` | sign-in or refresh | single use; each refresh returns a new one | `POST /v1/native/token/refresh` |
| `step_up_token` | step-up verify | 5 minutes, works once, for one operation | the `X-Step-Up` header of a sensitive call |

A session ends after 30 days without a refresh, and at most 90 days after it began.

- **Passkey steps need an authenticator.** A passkey is a key that only a WebAuthn client can create or sign with,
  so `curl` cannot do that part alone. Each passkey step is two calls with a step between them, marked
  **[authenticator]** below: the `options` response goes to `navigator.credentials.create()` or `.get()` in a
  browser (or to the platform passkey API on a device), and the JSON result goes into the next call.
  [`examples/browser`](examples/browser) does this in a page. For scripts and tests,
  [`scripts/passkey_client.py`](scripts/passkey_client.py) is a software authenticator that `make demo` uses. It is
  for development only, and it must use the relying party ID and origin the server is configured with.

### 1. Check that the service is up

```sh
curl -s "$AUTH/health/ready"
# {"status":"ok"}
```

`/health/alive` only shows the process is running. `/health/ready` also checks the database.

### 2. Sign in with an email code

Every sign-in starts with an email code. The answer is the same whether or not the address has an account.

```sh
START=$(curl -s -X POST "$AUTH/v1/native/auth/email/start" \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com"}')
FLOW_ID=$(jq -r .flow_id <<<"$START")
BINDING=$(jq -r .client_binding <<<"$START")
```

```json
{
  "flow_id": "…",
  "expires_at": "2026-10-12T10:10:00Z",
  "resend_after": "2026-10-12T10:01:00Z",
  "client_binding": "…"
}
```

`client_binding` appears only on the call that issues it, so store it and send it with every later call from this
device. The mail carries an 8-digit code, printed as `3099 9009`. Enter it without the space. Locally the mail
lands in Mailpit.

```sh
VERIFY=$(curl -s -X POST "$AUTH/v1/native/auth/email/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"flow_id\": \"$FLOW_ID\", \"code\": \"30999009\", \"client_binding\": \"$BINDING\"}")
TICKET=$(jq -r .ticket <<<"$VERIFY")
jq -r .next <<<"$VERIFY"
```

```json
{"next": "enroll_passkey", "ticket": "…", "expires_at": "2026-10-12T10:20:00Z"}
```

- `"next": "enroll_passkey"`: a new user, or a user with no passkey yet. Go to step 3.
- `"next": "second_factor"`: the user already has a passkey. Go to step 7.

The email proves the mailbox only. No access token is issued here, because a session needs a passkey.

A wrong, expired or used code gets `400 invalid_code`. A flow accepts five wrong codes and then locks. To get a new
code for the same flow, call `POST /v1/native/auth/email/resend` with `flow_id` and `client_binding`. It works once
per 60 seconds, invalidates the previous code, and does not reset the attempts.

### 3. Register a passkey (new user)

Ask for the registration options. The ticket is not spent here, so you can retry this step.

```sh
curl -s -X POST "$AUTH/v1/native/auth/passkey/register/options" \
  -H 'Content-Type: application/json' \
  -d "{\"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\"}" > register-options.json
```

```json
{"challenge_id": "…", "options": { "…": "WebAuthn creation options" }}
```

**[authenticator]** Pass `options` to `navigator.credentials.create()`. Save the JSON result as `credential.json`.
Then finish the registration. This is the call that opens the session:

```sh
curl -s -X POST "$AUTH/v1/native/auth/passkey/register/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\", \"challenge_id\": \"$(jq -r .challenge_id register-options.json)\", \"credential\": $(cat credential.json), \"name\": \"Work laptop\", \"device_name\": \"curl\"}" > signin.json

ACCESS_TOKEN=$(jq -r .access_token signin.json)
REFRESH_TOKEN=$(jq -r .refresh_token signin.json)
```

```json
{
  "user": {"id": "…", "email": "alice@example.com"},
  "access_token": "…",
  "expires_at": "2026-10-12T10:05:00Z",
  "refresh_token": "…",
  "recovery_codes": ["…", "… ten codes in total"]
}
```

The recovery codes are shown once. Store them offline. Each works once, and you need one if you lose the passkey.

### 4. Call the API as a signed-in user

```sh
curl -s "$AUTH/v1/native/me" -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{
  "user": {"id": "…", "email": "alice@example.com"},
  "session": {"id": "…", "device_name": "curl", "created_at": "…", "last_active_at": "…", "current": true}
}
```

Every request is checked against the session store, so once a session is signed out or revoked its access token
stops working at once. A missing, expired or revoked token gets `401 unauthenticated`.

### 5. Refresh the access token

Access tokens last 5 minutes by default, so refresh before they expire:

```sh
TOKENS=$(curl -s -X POST "$AUTH/v1/native/token/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")
ACCESS_TOKEN=$(jq -r .access_token <<<"$TOKENS")
REFRESH_TOKEN=$(jq -r .refresh_token <<<"$TOKENS")
```

Each refresh uses up the token it was given. Presenting an old refresh token again returns `401 invalid_refresh` and
ends the whole session, because a copied token is treated as stolen. Save the new refresh token before anything
else, and never run two refreshes at the same time.

### 6. Sign in with a passkey alone

A user with a passkey does not need an email code. The passkey signs them in by itself:

```sh
curl -s -X POST "$AUTH/v1/native/auth/passkey/login/options" > login-options.json
```

**[authenticator]** Pass `options` to `navigator.credentials.get()`. Save the JSON result as `assertion.json`.

```sh
curl -s -X POST "$AUTH/v1/native/auth/passkey/login/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"challenge_id\": \"$(jq -r .challenge_id login-options.json)\", \"credential\": $(cat assertion.json)}" > signin.json
```

The response has `user`, `access_token`, `expires_at`, `refresh_token`, and a `client_binding`. The server issues
a new binding because the call sent none. Store it: a second-factor sign-in needs it.

### 7. Sign in with an email code and a passkey (second factor)

For a user who already has a passkey, the email proves the mailbox and the passkey proves the key:

```sh
# a. email code, with the binding this device already holds
START=$(curl -s -X POST "$AUTH/v1/native/auth/email/start" \
  -H 'Content-Type: application/json' \
  -d "{\"email\": \"alice@example.com\", \"client_binding\": \"$BINDING\"}")
FLOW_ID=$(jq -r .flow_id <<<"$START")

# b. verify the code; "next" is "second_factor"
VERIFY=$(curl -s -X POST "$AUTH/v1/native/auth/email/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"flow_id\": \"$FLOW_ID\", \"code\": \"<8 digits>\", \"client_binding\": \"$BINDING\"}")
TICKET=$(jq -r .ticket <<<"$VERIFY")

# c. the passkey options, then the authenticator, then the verify with the ticket
curl -s -X POST "$AUTH/v1/native/auth/passkey/login/options" > login-options.json
```

**[authenticator]** Pass `options` to `navigator.credentials.get()`. Save the result as `assertion.json`.

```sh
curl -s -X POST "$AUTH/v1/native/auth/passkey/login/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"challenge_id\": \"$(jq -r .challenge_id login-options.json)\", \"credential\": $(cat assertion.json), \"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\"}"
```

The response is a session, as in step 6. The ticket is bound to the binding of its email flow, so use the same
binding in every call.

### 8. Recover after losing the passkey

Recovery needs the email proof and one recovery code. Start as in step 7 and stop at the `second_factor` ticket:

```sh
curl -s -X POST "$AUTH/v1/native/auth/recovery/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"ticket\": \"$TICKET\", \"client_binding\": \"$BINDING\", \"code\": \"<recovery code>\"}"
```

```json
{"next": "enroll_passkey", "ticket": "…", "expires_at": "…"}
```

Register a new passkey with this ticket, as in step 3. Registering removes every old passkey and ends the old
sessions. Recovery opens no session by itself. A wrong code spends the ticket, so guessing costs a new email proof
each time.

### 9. Sign out

```sh
curl -s -X POST "$AUTH/v1/native/signout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope": "current"}'
# 204 No Content
```

- `"scope": "current"` (the default) ends this session and its refresh tokens. The device stays recognized.
- `"forget_client": true` also ends the recognition of this device.
- `"scope": "all"` ends every session of the user and forgets every device.

Repeating a sign-out succeeds.

### 10. List and end sessions

```sh
curl -s "$AUTH/v1/native/sessions" -H "Authorization: Bearer $ACCESS_TOKEN"

curl -s -X DELETE "$AUTH/v1/native/sessions/$SESSION_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# 204 No Content
```

Each device has its own session, so ending one leaves the others signed in. The list shows only your own sessions,
most recently active first, up to 100. The one that made the call has `"current": true`.

### 11. Sensitive operations need a fresh passkey proof

Adding or deleting a passkey, creating recovery codes, changing the email address, deleting the account and approving
another device each need a **step-up**: a passkey proof for that one operation.

```sh
# a. options for one operation
curl -s -X POST "$AUTH/v1/native/me/step-up/options" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"operation": "delete_passkey"}' > stepup-options.json
```

**[authenticator]** Pass `options` to `navigator.credentials.get()` with user verification. Save the result as
`stepup-assertion.json`.

```sh
# b. exchange the proof for a step-up token
curl -s -X POST "$AUTH/v1/native/me/step-up/verify" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"challenge_id\": \"$(jq -r .challenge_id stepup-options.json)\", \"credential\": $(cat stepup-assertion.json)}" > stepup.json
STEP_UP_TOKEN=$(jq -r .step_up_token stepup.json)

# c. use it once, on that operation
curl -s -X DELETE "$AUTH/v1/native/me/passkeys/$PASSKEY_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Step-Up: $STEP_UP_TOKEN"
# 204 No Content
```

Without a valid step-up token the call answers `403 step_up_required`. The operations are `add_passkey`,
`delete_passkey`, `regenerate_recovery_codes`, `change_email`, `delete_account` and `approve_device`. A token works
for one operation, once, for five minutes. The steps for the others:

- **Rename a passkey** needs no step-up: `PATCH /v1/native/me/passkeys/{id}` with `{"name": "Phone"}`.
- **List passkeys**: `GET /v1/native/me/passkeys`. Credential IDs and public keys are never shown.
- **Add a passkey**: get the options from `POST /v1/native/me/passkeys/options` with `X-Step-Up` for `add_passkey`,
  run `navigator.credentials.create()` **[authenticator]**, then send the result with the same header to
  `POST /v1/native/me/passkeys`, with `{"challenge_id": "…", "credential": {…}, "name": "…"}`. It answers `201`.
  The token is spent by that last call, not by the options call.
- **Delete a passkey**: `DELETE /v1/native/me/passkeys/{id}` with `X-Step-Up` for `delete_passkey`. You cannot delete
  the last passkey (`409 last_passkey`), so add the new key first.
- **New recovery codes**: `POST /v1/native/me/recovery-codes` with `X-Step-Up` for `regenerate_recovery_codes`. It
  returns the new set once, and the old set stops working at once.
- **Change the email address**: with a step-up token for `change_email`, request a code for the new address, then
  confirm it. The confirmation needs no step-up.

  ```sh
  curl -s -X POST "$AUTH/v1/native/me/email/change" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "X-Step-Up: $STEP_UP_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"email": "new@example.com"}'
  # 202 → {"flow_id": "…", "expires_at": "…"}

  curl -s -X POST "$AUTH/v1/native/me/email/change/confirm" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"flow_id\": \"$CHANGE_FLOW_ID\", \"code\": \"<8 digits from the new address>\"}"
  # 200 → {"email": "new@example.com"}
  ```

  The code goes to the new address, and the old address is told by email. The change takes effect only when the
  code is confirmed.
- **Delete the account**: `DELETE /v1/native/me` with `X-Step-Up` for `delete_account` answers `204`. It is
  permanent: access data, pending flows and their mail are removed, and audit events remain for 90 days with their
  references cleared.

### 12. Sign in on another device (QR code)

A device with no session, such as a TV or a browser, asks for one, and a phone that is already signed in approves it.

On the new device:

```sh
curl -s -X POST "$AUTH/v1/native/auth/device/start" \
  -H 'Content-Type: application/json' \
  -d '{"device_name": "Living room TV"}' > device.json

REQUEST_ID=$(jq -r .request_id device.json)
POLL_SECRET=$(jq -r .poll_secret device.json)
BINDING=$(jq -r .client_binding device.json)
jq -r .pairing_code device.json
```

Show a QR code that carries only `request_id`, and show the six-digit `pairing_code` on screen. The QR code never
holds `poll_secret`, which stays on this device. The request lives 5 minutes.

On the signed-in phone:

```sh
# who is asking (the pairing code is not shown here)
curl -s "$AUTH/v1/native/device/requests/$REQUEST_ID" -H "Authorization: Bearer $ACCESS_TOKEN"

# approve: a step-up for approve_device first (step 11), then the six digits from the new device
curl -s -X POST "$AUTH/v1/native/device/requests/$REQUEST_ID/approve" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Step-Up: $STEP_UP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"pairing_code": "123456"}'
# 204 No Content
```

To refuse, call `POST /v1/native/device/requests/{request_id}/deny` with the bearer token. It needs no step-up. A
wrong pairing code uses up one of three attempts, and the third ends the request.

Back on the new device, poll until the request is approved:

```sh
curl -s -X POST "$AUTH/v1/native/auth/device/status" \
  -H 'Content-Type: application/json' \
  -d "{\"request_id\": \"$REQUEST_ID\", \"poll_secret\": \"$POLL_SECRET\", \"client_binding\": \"$BINDING\"}"
# {"state": "pending"}
```

The states are `pending`, `approved`, `denied`, `redeemed` and `expired`. When it reads `approved`, take the session
once:

```sh
curl -s -X POST "$AUTH/v1/native/auth/device/redeem" \
  -H 'Content-Type: application/json' \
  -d "{\"request_id\": \"$REQUEST_ID\", \"poll_secret\": \"$POLL_SECRET\", \"client_binding\": \"$BINDING\"}"
```

The answer has `user`, `access_token` and `refresh_token`, like a passkey sign-in. The device now has its own session,
independent of the phone's, and redeeming works only once.

### 13. Connected applications

Applications that sign users in through this service are listed by `GET /v1/native/me/apps`. To end one application's
access, call `DELETE /v1/native/me/apps/clients/{client_id}`, or `DELETE /v1/native/me/apps/grants/{id}` for a single
grant. Both answer `204`. The sign-in with this service and the user's other applications are not affected. See
[Single sign-on](#single-sign-on-openid-connect).

### Errors

| HTTP | `code` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, or a field of the wrong shape |
| 400 | `invalid_code` | A wrong, expired or used email code |
| 400 | `invalid_proof` | A passkey, step-up, recovery or device proof was refused |
| 401 | `unauthenticated` | No valid access token of an active session |
| 401 | `invalid_refresh` | The refresh token is unknown, used or expired. A replay ends the session |
| 403 | `step_up_required` | A sensitive operation without a valid `X-Step-Up` token |
| 403 | `permission_denied` | A browser request from an origin that is not trusted |
| 404 | `not_found` | A passkey or device request that does not exist, or is not yours |
| 409 | `last_passkey` | The last passkey cannot be deleted |
| 409 | `too_many_passkeys` | The account already has as many passkeys as it may |
| 409 | `email_taken` | Another account has the new address |
| 429 | `rate_limited` | Too many requests. Wait before you retry |
| 503 | `temporarily_unavailable` | An infrastructure failure. Retry later; the input was not at fault |

### Browser clients

The browser routes are the same operations under `/v1/`, without `native/`. The refresh route is `POST /v1/token/refresh`.
The difference is where secrets live:

- The refresh token and the client binding are HttpOnly cookies, `__Secure-px_refresh` and `__Secure-px_binding`.
  Page scripts cannot read them, and JSON responses never carry them. The JSON carries only the access token.
- The access token is only ever held in memory. [`examples/browser`](examples/browser) never writes it to storage or the URL.
- A browser request that carries an `Origin` header must come from the API's own origin or from one listed in
  `AIRLANCE_AUTH_BROWSER_ORIGINS`. Any other state-changing request is refused with `403 permission_denied`. A
  request with neither `Origin` nor `Sec-Fetch-Site`, such as one from `curl`, is not refused by this check.
- Secure cookies need HTTPS, or `localhost`. Test browser flows with [`examples/browser`](examples/browser) rather than
  with `curl`.

## How it works

### Signing in

A session is opened only after a passkey has been proven, so a stolen mailbox alone is never enough.

```text
new user / new browser                      returning user with a passkey
─────────────────────                      ───────────────────────────────
POST email/start    → code sent by email    POST passkey/login/options
POST email/verify   → ticket                POST passkey/login/verify → session
POST passkey/register or login/verify
                    → session (+ recovery codes for a new user)
```

1. **Start.** The client posts an email address. The service creates a *flow* and queues a mail
   with an eight-digit code. The answer is the same whether or not the address has an account.
2. **Verify.** The client posts the code. A correct code does not open a session: it returns a
   short-lived *ticket*. For a new user the ticket says `enroll_passkey`, for a user who already
   has a key it says `second_factor`.
3. **Passkey.** The ticket is exchanged for a session by registering a passkey (new user) or by
   asserting an existing one (second factor). A new user also receives ten recovery codes.
4. **Recovery.** Keys are replaced through a mailbox code plus a recovery code. Every old key
   is removed when the new one is registered, so a lost or copied key cannot open the account again,
   and the old sessions are closed before the new one opens. A recovery that fails changes nothing.

A user who already has a passkey can skip the email entirely and sign in with the key alone.

### Sessions and tokens

- **Access token:** a JWT signed with ES256, five minutes by default (at most one hour), carrying
  the user ID, session ID and the authentication methods used. Verify it with the public JWKS.
- **Refresh token:** opaque, stored only as a hash, and strictly rotated. Using an old token again
  is treated as theft: the session is revoked.
- **Every request is checked against the session store** by this service, so a revoked session
  stops working immediately. A downstream service that verifies tokens offline accepts a token
  until it expires; that window is the access lifetime.
- **Sessions** are per device and independent: signing out on one does not close another.
  `GET /v1/sessions` lists them, `DELETE /v1/sessions/{id}` ends one.

### Sensitive operations need a fresh proof

Adding or deleting a passkey, issuing new recovery codes, changing the email address, deleting the
account and approving another device each need a **step-up**: a passkey assertion with user
verification made in the last five minutes, valid for one operation only.

### Signing in on another device (QR)

A device without a session, for example a computer or a TV, asks for a request and shows a QR code
and a six-digit pairing code. A phone that is already signed in scans the code, shows what is
asking, and the person types the pairing code, then confirms with a passkey. The new device then
collects its own, independent session exactly once.

The QR code carries only a random request ID, which proves nothing. The secret needed to collect
the session stays on the new device. Three wrong pairing codes kill the request; a request lives
five minutes.

### New device notice

When a client the account has not used before signs in, by any path, the owner gets an email with
the device name, the client address and the time. It contains no code and no link, so it opens
nothing. The address is kept only in the queued mail job and is erased once the mail is sent.

### Single sign-on (OpenID Connect)

The service can be the OpenID Provider of your own web applications: a person signs in here once, with a
passkey, and each application that sends them here gets the result without asking for the passkey again.
It is off until `AIRLANCE_AUTH_OIDC_ISSUER` is set.

```sh
AIRLANCE_AUTH_OIDC=1 scripts/init_production.sh        # makes the RSA key and sets the issuer (or add both by hand)
airlance-auth migrate up
airlance-auth oidc client create example-web --name Example \
    --redirect-uri https://app.example.com/auth/callback    # prints the client secret once
```

An application is a confidential web client with a backend (a BFF): it keeps the client secret and the tokens on
its server and gives the browser only its own session cookie. It discovers everything from
`GET /.well-known/openid-configuration`, sends the browser to `/oauth2/authorize` with PKCE (`S256`), `state` and
`nonce`, and exchanges the returned code at `/oauth2/token` with `client_secret_basic`.

| What | Where |
| --- | --- |
| Discovery, keys | `/.well-known/openid-configuration`, `/oauth2/jwks` (RS256; the ES256 keys of the `/v1` API stay in `/.well-known/jwks.json`) |
| Sign in | `GET` or `POST /oauth2/authorize`, then the built-in page at `/oauth2/login` (email code, passkey, recovery) |
| Tokens | `POST /oauth2/token`: `authorization_code` and `refresh_token` (rotating, a replay revokes the grant) for applications, `client_credentials` for services |
| Is this token still good (for an API) | `POST /oauth2/introspect` (RFC 7662), with the credentials of the API's resource |
| Who is this | `GET` or `POST /oauth2/userinfo` with the access token as a Bearer header |
| Sign out | `GET /oauth2/logout` (RP-initiated, with `id_token_hint`; the person confirms on the provider's page), `POST /oauth2/revoke` (RFC 7009) |
| Told when a sign-in ends | back-channel logout: a signed `logout+jwt` posted to the application's backend |
| Applications and services | `airlance-auth oidc client create [--service] / set-logout / list / rotate-secret / disable / enable`, on the server only |
| APIs and their scopes | `airlance-auth oidc resource register / set-scopes / allow / deny / rotate-secret / list / disable / enable`, on the server only |
| What a person connected | `GET /v1/me/apps`, `DELETE /v1/me/apps/grants/{id}`, `DELETE /v1/me/apps/clients/{client_id}` (and the same under `/v1/native/`) |

Three kinds of state are kept apart. The **shared sign-in** (OP session) is proved once and remembered by the
`__Host-airlance_sso` cookie of the auth host only. A **grant** is what one application may do on it, with its own
refresh tokens. The **application's own session** is its business. Ending the shared sign-in (signing out everywhere,
a recovery, a block) ends every grant and refresh token held on it; disabling an application ends all its grants.

**Signing out** has three levels, and they are kept apart. An application ends *its own* grant by calling
`/oauth2/revoke` with its refresh token (its other state is its own business). `GET /oauth2/logout` ends the *shared
sign-in*: the person is asked to confirm on the provider's own page (a link or an image on another site cannot sign them
out), then the sign-in, every grant and refresh token on it and the device session of the sign-in page end, the cookie is
cleared, and a "Signed out" page offers a link back to the registered `post_logout_redirect_uri`, carrying `state`.
The return is an ordinary link, rather than a redirect of the confirmation POST, so the strict `form-action 'self'` CSP
does not block it. With no return address, the page has no link. Signing out everywhere, a recovery, a
block, and cutting off the other devices (a deleted passkey, a changed address) end it too; the device that made the
change keeps its own. The confirmation carries a token derived from the sign-in cookie, so even a frontend the API trusts
cannot post a sign-out that the person did not see.

**Back-channel logout** tells each application's backend, server to server, that its sign-in ended, so it can close its own
session: register the address with `oidc client set-logout ID --backchannel-logout-uri https://app/backchannel`. A notice
is queued in the same transaction that ends the grants and delivered afterwards, again and again for a day if the
application is down, with the same `jti` each time. The call cannot reach internal networks (loopback, private, link-local,
the cloud metadata address) unless `AIRLANCE_AUTH_OIDC_BACKCHANNEL_ALLOW` lists them; it follows no redirect and honours no
proxy setting.

#### APIs, audiences and scopes

An application (a *client*) asks for a sign-in. An **API** (a *resource*) is the recipient of an access token: it has its own
**audience**, and the **scopes** its owner defined, such as `messages:send` or `video:upload`. The client's `client_id` is
never the audience of its API: the audience of an ID token is the client; the audience of an access token is the API. The
provider knows nothing of what an API does: a new messenger or calendar is connected by registering it, not by changing the
provider.

```sh
# the owner of the API defines its rights, the operator registers them and says who may ask for what
airlance-auth oidc resource register platform-api --name Platform \
    --uri https://api.example.com/platform --audience platform-api \
    --scope messages:read --scope messages:send --scope video:read --scope video:upload
airlance-auth oidc resource allow platform-api --client example-web --scope messages:read --scope messages:send
```

One registration is one logical API and one boundary of trust, not one process. A product whose services share a gateway and
a policy registers one resource (`platform-api`, with `messages:*` and `video:*`), and each handler checks its own scope.
Services with separate boundaries are separate resources (`messenger-api`, `video-api`), each with its own audience and its own
set of rights. Both work by configuration alone. A resource has an identifier, a URI (the value of the `resource` parameter:
absolute, https, no query or fragment) and an audience, none of which another resource may share; an audience that is the
provider's own, or the identifier of a client, is refused.

An application asks for the APIs it needs together with the sign-in, and for the tokens of one API at a time:

1. `/oauth2/authorize` with `scope=openid messages:send video:read` and `resource=https://api.example.com/platform` (repeat
   `resource` for each API; at most five). A scope of an API needs its resource and a resource needs a scope. Scopes are a list
   separated by single spaces, compared whole and case-sensitive: a comma is not a separator, and `messages:send:any` is not
   `messages:send`. What is granted of each resource is what the client may ask of it, that the resource defines, that was
   asked: a scope is a request, never a right by itself, and nothing is granted by default.
2. `/oauth2/token` with `resource=https://api.example.com/platform` (one only) returns an access token for that API:
   `aud` is its audience, `scope` holds only its rights, and the ID token still goes to the client. Without `resource` the
   token is the one for UserInfo, as it always was, and an API's token is not accepted by UserInfo.
3. The same `refresh_token` request with another `resource` gives the next API its own token, one refresh token rotating along
   the way. An application serialises these refreshes (two at once is a replay, and a replay ends the grant). A refresh may
   narrow `scope`, never widen it, and may name only a resource the grant was made for: asking for another resource or
   another right is a new authorization.

Errors follow RFC 8707: `invalid_target` for a resource that is malformed, unknown, disabled, or not open to the client (the
answer never says which), `invalid_scope` for a right that was not asked, not allowed, or no longer held. A refusal does not
spend the code or the refresh token.

**Changing rights.** Everything that takes a right away ends the grants that hold it, in the same transaction, and queues the
back-channel notice of their applications: disabling a resource (`disable`), removing a scope from it (`set-scopes`),
narrowing or withdrawing what a client may ask (`allow` with fewer scopes, `deny`). Enabling a resource again, or giving a
right, never widens a grant that exists: the application asks again and is given a new grant. Every change takes the
resource's row first, and issuing a token for it shares that row, so once a change has completed no token is being issued
under the old rights. Changes are in the audit log (`oidc.resource_changed`, `oidc.grant_ended`) and in
`airlance_auth_oidc_permission_changes_total`, `airlance_auth_oidc_grants_ended_total` and
`airlance_auth_oidc_resource_tokens_total{resource,outcome}`.

**Checking tokens in an API.** [`examples/resourcecheck`](examples/resourcecheck) is a verifier and a `net/http` middleware to
copy into a service. It takes the keys from `jwks_uri` of the discovery document (`Discover`), accepts RS256 and the
`at+jwt` type only, and checks the issuer, *its own* audience, the time, and the claims RFC 9068 requires; it refuses ID tokens
and logout tokens, a token for another API whatever its signature, and any header that points at a key (`jku`, `jwk`, `x5u`).
`Require("messages:send")` answers 401 for a bad token, 403 `insufficient_scope` for a good one that lacks the right, and 503
when the keys cannot be had. A scope is the right to an operation; whether *this* user may touch *this* chat, file or
organisation is the API's own rule, and administrative rights are never read from the scopes of a user's token. Keep the key
set in a bounded cache: it is refetched when it is stale or a `kid` is unknown, at most once per `MinRefetch`, and an issuer
outage does not stop a service that holds its keys.

**An application to copy.** [`examples/bff`](examples/bff) is a backend-for-frontend on go-oidc and x/oauth2 (not on anything of this service): one-time sign-in transaction bound to the browser, `state`, `nonce`, PKCE and `iss`; users kept by `(iss, sub)`; tokens sealed in the store and the browser given one opaque cookie; refreshes serialised per session with `invalid_grant` ending the session without a redirect loop; back-channel logout tokens checked and handled once per `jti`; a bounded key-set cache; CSRF protection of its POST routes. It is exercised against the real service by `TestBFFOnTheRealService`. Its `Store` is in memory by default (one process); [`examples/bff/pgstore`](examples/bff/pgstore) is the same on PostgreSQL for several instances and for restarts (`pgstore.Migrate`, `pgstore.New(pool, nil)`): the session lock is an advisory lock held while the refresh runs, a refresh is recorded as begun before the provider is asked and its result is stored with a context the request cannot cancel (so neither a crash nor a cancelled request leaves a spent refresh token to be replayed), a logout notice is one transaction (the `jti`, the ended sign-in and the sessions together) ordered against a session being created by an advisory lock, and a `jti` is remembered for 26 hours. `TestBFFInstancesShareOneStore` runs two instances behind one address.

**How soon a revoked grant stops working in an API.** By default the check is offline, by signature, so an API honours a token
until it expires: **5 minutes** (the provider's access token lifetime) plus the verifier's `Leeway` (30 seconds). An API that
cannot wait that long asks the provider.

**Token introspection (RFC 7662).** `POST /oauth2/introspect` with `token=` answers `{"active": true, scope, client_id, sub, aud, iss,
jti, iat, exp, token_type}` or `{"active": false}`. The caller is the *API*, not an application: it authenticates with HTTP Basic
using the identifier of its resource and a secret the operator issues (`oidc resource rotate-secret ID`; shown once, stored as a
hash, two live at most so a rotation can overlap; they open nothing but this endpoint). It is told about tokens issued for its own
resource only: a token for another API, a UserInfo token, an ID token, a refresh token, an expired or forged one all get the same
`{"active": false}`. Active means the whole chain is alive right now: the signature, the grant (not revoked, not expired), the
client (active), the sign-in (alive), the user (not blocked), the right (still held by the grant, still allowed to the client, still
defined by the resource) and the resource (active). A disabled resource's credentials are refused. The resource's row is read
shared first, as when a token is issued, so an answer is never given halfway through a change of rights. Answers are counted in
`airlance_auth_oidc_introspections_total{resource,outcome}`.
In [`examples/resourcecheck`](examples/resourcecheck) set `Config.Introspection` and call `Check` (`Require` does): the token is
verified offline first, then the issuer is asked, and the answer must be about *this* token (audience, subject, `jti`, client,
scope), or it is no answer. An issuer that cannot be asked is **503**, never a pass, so an outage of the provider stops that API;
an API that prefers to keep serving on the offline check calls `Verify` instead and accepts the five-minute delay. Cache the
answer only for as long as that delay is acceptable; the example does not cache.

**Services (`client_credentials`).** A service that calls an API in its own name, with no person, is a client registered with
`oidc client create ID --name ... --service`: it has a secret (rotated like any client's, `oidc client rotate-secret --overlap 0`
ends the old one at once), no redirect addresses, no scopes and no logout settings, and it signs nobody in (`authorize` treats it
as unregistered, and the code and refresh grants are `unauthorized_client`). What it may ask is what the operator allowed it of
each API (`oidc resource allow RESOURCE --client ID --scope ...`), the same table as for applications. `POST /oauth2/token`
with `grant_type=client_credentials`, `resource=<URI>` (required, one) and optionally a narrower `scope` returns an access token
(`sub` and `client_id` are the service, `aud` is the API, no `sid`, `grant_id` or `auth_time`) and **no** refresh or ID token: a
service asks again, with its secret. There is no grant to end, so the provider asks again too: introspection reads the service's
rights afresh, and a right taken away (`allow` with fewer scopes, `deny`, a scope the API dropped, the service disabled) makes
its tokens inactive at once; an API that checks offline honours them for up to five minutes. Rotating a secret does not recall
tokens already issued. In an API, `Claims.Service` marks such a token and `RequireUser` refuses it: **never read `Subject` of a
token as a person before checking `Service`**.

**Connected applications.** `GET /v1/me/apps` lists the person's live grants: the application, the APIs it may call and the
rights held of each, when it was last used and when it ends. `DELETE /v1/me/apps/grants/{id}` takes one grant back and
`DELETE /v1/me/apps/clients/{client_id}` all the person's grants of one application, with their refresh tokens and a
back-channel notice, so the application closes its own session. It does not end the person's sign-in with the provider, any
other application, or anyone else's grants (a grant of another person is the same 204 as one that does not exist, so ids
cannot be probed). It is also **not a ban**: the sign-in is alive and the application is trusted, so opening it again gives it
a new grant without a question. A lasting refusal is a decision about the application (`oidc client disable`), not about one
grant. Ending access needs no fresh step-up; what widens it (a new authorization) is the application's trusted sign-in.

What it deliberately does not do yet: consent screens for third-party applications (only first-party clients can be
registered), `offline_access`, dynamic registration, public (native) clients, `prompt=consent` and
`select_account`, and a screen for the connected applications in this repository (the API is there; the page that calls it is
the product's). Discovery lists only what exists. A signed access token cannot be recalled before it expires (5 minutes);
UserInfo checks the grant on every call.

### Other features

- **Account deletion** (`DELETE /v1/me`) behind a step-up, with cascading removal of access data.
- **Change of email** with a code sent to the new address and a notice to the old one.
- **Invite-only registration** (optional): only invited addresses can register.
- **Admin API** (optional): a separate listener with operators who sign in with passkeys.
  Operators block and unblock users, revoke sessions, manage invitations and read the audit log.
  The API is complete; the page for it is not in this repository. A build placed in
  `internal/transport/http/admin/ui/dist` before `go build` is embedded and served at `/admin/`;
  without one, `/admin/` answers 503 and the API still works.
- **Rate limits** are counted in PostgreSQL in sliding windows, with separate budgets for unknown
  and recognised clients and per IP behind trusted proxies.
- **Audit log** of security events, with retention by event class and no personal data in the
  fields.
- **Operations:** health endpoints, Prometheus metrics, alert rules, a key rotation runbook, and
  local backup and restore of the database together with the keyring.

## Architecture

A modular monolith with clean layers. Imports point inward and a linter enforces the boundaries.

```text
transport → application → domain
adapter   → application/port + domain
bootstrap → wires everything together
```

```text
cmd/airlance-auth      CLI: serve, migrate, invite, operator, healthcheck, version
internal/domain        entities and state rules (no HTTP, SQL or JWT types)
internal/application   use cases and the ports they need
internal/adapter       PostgreSQL (pgx, sqlc), mail (SMTP worker), crypto, JWT, WebAuthn, metrics;
                       adapter/memory is a test double of the store, never a runtime mode
internal/transport     HTTP API generated from api/openapi/auth.yaml, admin API and UI
internal/bootstrap     assembly of dependencies
migrations             goose SQL migrations (history in the auth_schema_version table)
internal/domain/oidc   the OpenID Provider's rules; internal/application/oidc its use cases; internal/transport/http/oidc its endpoints and sign-in page
examples               a browser page, and service-side verifiers of the /v1 tokens (tokencheck) and of API tokens (resourcecheck)
```

Key choices: PostgreSQL is the only datastore, mail goes through a durable outbox processed by a
worker, one-time proofs are stored as hashes and consumed in transactions, and the in-memory
store used by unit tests satisfies the same contract tests as PostgreSQL.

### Sharing a PostgreSQL server

The tables (`users`, `sessions`, `outbox`, ...) have generic names, so give the service its own
namespace when the database also serves other applications. Set
`AIRLANCE_AUTH_DATABASE_SCHEMA=auth`: `migrate up` creates the schema, the service sets the
`search_path` of every connection to it, and the migration history lives in
`auth.auth_schema_version`, not in goose's default `goose_db_version`, which another goose-based
service in the same schema would also write to.

- Unset, the schema is `auth`. A `search_path` in the connection URL is used instead when the variable
  is unset, which is how the test suites isolate themselves.
- The first `migrate` copies an existing `goose_db_version` into `auth_schema_version` (only when
  `auth_flows` is in the same schema, so a foreign history is not taken for ours). The old table is
  left in place. A database migrated into another schema by an earlier release is a data move
  (`ALTER TABLE ... SET SCHEMA`), not a setting.
- Behind PgBouncer in transaction mode a startup `search_path` may be ignored. Also set it on the
  role (`ALTER ROLE ... SET search_path = auth`) and create the schema once by hand; the service's own
  setting is then redundant but harmless.

## Route reference

The contract is [api/openapi/auth.yaml](api/openapi/auth.yaml), and it is the source of truth for every field. The two
client profiles share their routes: browsers use `/v1/...` and apps use `/v1/native/...`. The walkthrough above shows the
native paths.

| Group | Routes |
|---|---|
| Email sign-in | `POST /v1/auth/email/start`, `verify`, `resend` |
| Passkeys | `POST /v1/auth/passkey/register/options`, `register/verify`, `login/options`, `login/verify`, `POST /v1/auth/recovery/verify` |
| Tokens | `POST /v1/token/refresh`, `POST /v1/signout`, `GET /.well-known/jwks.json` |
| Session | `GET /v1/me`, `GET /v1/sessions`, `DELETE /v1/sessions/{id}` |
| Account | `/v1/me/passkeys`, `/v1/me/recovery-codes`, `/v1/me/step-up/*`, `/v1/me/email/change`, `DELETE /v1/me` |
| Other device | `POST /v1/auth/device/start`, `status`, `redeem`, and `/v1/device/requests/{id}` with `approve` and `deny` |
| Operations | `GET /health/alive`, `GET /health/ready`, `GET /metrics` |

## Verifying tokens in your service

Your own services can check access tokens without calling this service on every request.

1. Fetch the public keys and cache them for a few minutes:

   ```sh
   curl -s "$AUTH/.well-known/jwks.json"
   ```

   The keys are EC P-256 keys with `"alg": "ES256"` and `"use": "sig"`. Pick the key whose `kid` matches the token header.

2. Check the token before you trust its claims:
   - the header `typ` is `at+jwt` (RFC 9068), so other JWTs signed with the same keys are not accepted;
   - `iss` equals `AIRLANCE_AUTH_JWT_ISSUER`, and `aud` equals `AIRLANCE_AUTH_JWT_AUDIENCE`;
   - `exp` is in the future.

3. Read the claims you need:
   - `sub`: the user ID;
   - `sid`: the session ID, which you can use to tell devices apart;
   - `amr`: the authentication methods used, and `auth_time`: when they were used.

Offline checks do not see revocation. A token stays valid until `exp`, which is 5 minutes by default. Where a revoked
session must stop at once, call this service (for example `GET /v1/native/me`) or shorten `AIRLANCE_AUTH_ACCESS_TTL`.

[examples/tokencheck](examples/tokencheck) is a complete verifier built on go-jose.

## Development

```sh
make help      # all targets
make check     # format, lint with import boundaries, vet, race tests, tidy check
make ci        # everything CI runs except integration and end-to-end tests
make test-int  # integration tests against PostgreSQL (make up first)
make test-e2e  # the built binary against PostgreSQL and Mailpit (make up first)
```

Generated code (sqlc and the OpenAPI server) is checked in; run `make generate` after changing a SQL
query or the OpenAPI file, and `make generate-check` to verify nothing is stale.

## Security

The threat model, the rules for tokens, tickets, quotas, retention and personal data.
Short version: no passwords, one-time proofs stored as hashes, a passkey required for every session,
step-up for sensitive operations, refresh rotation with reuse detection, and no email, IP or secrets in logs,
metrics or audit fields (the one exception is the client address inside a queued new-device mail).

### Database roles and scanning

In `deploy/compose.prod.yaml` the service connects as `airlance_auth_app`, which can read and write
rows in the `auth` schema and nothing else: no `DROP`, `ALTER`, `CREATE` or `TRUNCATE`. Only the
`migrate` container connects as the owner, `airlance_auth`. `deploy/postgres-init/10-app-role.sh`
creates the role when the data volume is new; `scripts/init_production.sh` makes one password per role.
If the database moves off this stack, keep the split and add `sslmode=verify-full` to both URLs.

CI runs `govulncheck`, `gosec` (inside golangci-lint, see `.golangci.yml` for the few justified
exclusions) and `gitleaks` over the whole git history (`make secrets` runs the same scan locally).

## Limitations

- The service speaks plain HTTP and expects a TLS-terminating proxy or ingress in front. Listening beyond the loopback requires `AIRLANCE_AUTH_TRUSTED_PROXIES`.
- Passkeys, the pairing flow and mobile secure storage have not been verified on real iOS and
  Android devices, and Safari with a real HTTPS domain is only partly verified.
- Production SMTP and a load review of the rate-limit values are still open.
- Device sign-in uses polling. There are no WebSocket or Connect transports yet.
- Backup and restore are local; the production procedure is not written yet.
