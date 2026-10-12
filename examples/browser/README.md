# Browser example

A framework-free page that shows the browser sign-in lifecycle: sign in with an emailed code and then a passkey, keep
the access token in memory, refresh through an HttpOnly cookie, and stay correct across tabs.

What it demonstrates, and what to check by hand with two tabs of the same browser:

- a session needs a passkey: the emailed code only buys a ticket, which registers a passkey (first
  sign-in, with recovery codes shown once) or proves one (later sign-ins), or is exchanged for a
  recovery code when the passkey is lost; a passkey alone also signs in, with no email at all;
- changing the email: a step-up for `change_email`, a code mailed to the new address, a second request
  that proves it; the old address gets a notice, the session stays, and the recognition of the
  account's clients ends;
- after sign-in and email change, browsers that support `signalCurrentUserDetails` receive the
  current email as the passkey label, using the account's unchanged 16-byte UUID user handle;
  unsupported providers can keep the old label, which does not change who the key authenticates;
  a passkey saved for a deleted account can still appear in the provider but no longer signs in;
- deleting the account: a step-up for `delete_account`, DELETE `/v1/me`, all sessions and keys
  removed, both cookies cleared and other tabs signed out;
- signing in on another device: "Sign in with another device" asks for a request and
  draws a QR locally, with a fallback link (the request id in the URL fragment, which no server sees) and a six-digit code.
  An explicit `?api=` setting is preserved in the link; other query parameters are discarded. The poll secret is an HttpOnly browser cookie.
  Scan the QR on the signed-in phone, type the code and press Approve (a fresh passkey proof for `approve_device`); the first
  tab then signs itself in with a session of its own. To see two devices, open the first one on another host name
  (`http://127.0.0.1:5173/?api=http://127.0.0.1:8080`, with that origin in `AIRLANCE_AUTH_BROWSER_ORIGINS`): cookies are per host.
  A Web Lock allows one active request across tabs of the page's origin. Cancel stops polling and ignores late start/status responses;
  the lock stays held until the outstanding response finishes, so a late cookie cannot overwrite a new request.
  Once redemption is sent, Cancel is disabled until the result arrives. Closing the tab releases its lock;
- the refresh token and the client binding are cookies the page cannot read; the access token
  lives in the tab's memory and is never written to storage or the URL;
- a refresh takes a Web Lock, so two tabs never present the same cookie at once (the server would
  treat that as a replay and end the session);
- the tab that waited for the lock first checks whether the other tab already refreshed;
- the result is broadcast, and a late response never replaces a newer access token;
- signing out in one tab signs out the other;
- a refusal ends the session locally, with no retry loop.

## Run

A passkey is bound to a domain, never to an IP address, so the page and the API use `localhost`
here (a browser treats it as a secure context and accepts Secure cookies on it).

```sh
make up                      # PostgreSQL and Mailpit
make migrate
export AIRLANCE_AUTH_BROWSER_ORIGINS=http://localhost:5173
export AIRLANCE_AUTH_WEBAUTHN_RP_ID=localhost
export AIRLANCE_AUTH_WEBAUTHN_ORIGINS=http://localhost:5173
# ...the variables of scripts/demo.sh (database, keyring, issuer, SMTP), then:
AIRLANCE_AUTH_HTTP_ADDR=127.0.0.1:8080 go run ./cmd/airlance-auth serve
python3 -m http.server 5173 --bind 127.0.0.1 --directory examples/browser
```

Open http://localhost:5173 in two tabs, request a code, read it in Mailpit
(http://127.0.0.1:8025), verify, and create a passkey when asked: the browser or the operating
system shows its own prompt. Copy the recovery codes. After that "Sign in with a passkey" works
without email. The page and the API are on different ports of one host, which is the same site, so
the default `SameSite=Strict` cookies are sent; a page on another site needs
`AIRLANCE_AUTH_COOKIE_SAMESITE=none` and its origin in `AIRLANCE_AUTH_BROWSER_ORIGINS`. Safari does not accept
Secure cookies over plain HTTP; use HTTPS there.

## Real devices over HTTPS

For Safari, iOS and Android the page needs a real HTTPS host. `make tunnel` (after `make up`) serves
the page and the API on one origin through [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/):
`scripts/devfront.py` listens on loopback, serves `index.html`, `app.js` and `qrcodegen.js`, and forwards `/v1/`,
`/health/` and `/.well-known/` to the API; `cloudflared` publishes it. The script sets the host as the
passkey relying party and as the issuer, trusts the forwarding of the loopback proxy only, and prints
the address to open on the phone. The codes still arrive in the local Mailpit
(http://127.0.0.1:8025): read them on the computer and type them on the phone.

- **Quick mode** (default) needs no account: a random `https://<words>.trycloudflare.com` host. The host,
  and with it every passkey made on it, is gone when the script stops.
- **Own domain:** in the Cloudflare Zero Trust dashboard create a tunnel (Networks, Tunnels), add a
  public hostname for it that points at `http://localhost:5173`, and run
  `AIRLANCE_AUTH_TUNNEL_HOST=auth.example.com CLOUDFLARED_TUNNEL_TOKEN=<token> make tunnel`. Passkeys then stay
  valid between runs. The token is read from the environment and never printed or stored. Without the token the script does not start a connector: it expects one for that
  tunnel to run already (the `cloudflared` system service, say) and only serves the origin.

The URL is public while the script runs, and the database behind it is the local throwaway one: stop it
with Ctrl+C when the check is done. `/metrics`, the Mailpit and every file but the page stay off it.

The page's scripts (`app.js` and `qrcodegen.js`) are served too; test files and documentation are not.

## Automated browser regressions

`make test-browser` runs the shipped scripts in Node's VM with controlled responses, timers and shared
locks. It checks cancellation, late responses, competing tabs, one redemption, retry after network failure,
QR payload and approval target capture. This also runs in `make ci`. Real-device passkey checks remain separate.

The QR encoder is [Project Nayuki v1.8.0](https://github.com/nayuki/QR-Code-generator/tree/v1.8.0), MIT;
the vendored script includes its license and runs locally.

Not checked here: Safari, iOS and Android.

## Real SMTP

Fill the SMTP settings in the project's ignored `.env` and run `make real-check`, then
`make real`. This uses the same HTTPS tunnel, with real delivery instead of Mailpit; codes
arrive in the real mailbox entered on the page. The launcher reads dotenv values literally,
never as shell commands. Its separate test keys live in `.secrets/real`. Local PostgreSQL
must already be running (`make up`); Mailpit is not used by this mode. For a stable domain,
put `AIRLANCE_AUTH_TUNNEL_HOST` and optionally `CLOUDFLARED_TUNNEL_TOKEN` in `.env`.
See [the root README](../../README.md#запуск) for settings and prerequisites.
