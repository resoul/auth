// Package bff is a backend-for-frontend that signs people in through the OpenID Provider (airlance-auth) and calls APIs for
// them: an example to copy, built on independent libraries (github.com/coreos/go-oidc for discovery and ID tokens,
// golang.org/x/oauth2 for the code exchange) rather than on anything of the provider.
//
// What it does, and what it keeps where:
//
//   - The client secret, the refresh token and every access token stay on the server, sealed in the session store (see
//     Vault). The browser gets one cookie, an opaque session identifier, HttpOnly and Secure (the __Host- prefix makes the
//     browser insist), and the store holds only its hash.
//   - A sign-in is a one-time transaction bound to the browser that began it (a cookie), with `state`, `nonce` and PKCE,
//     and the response is accepted only with the issuer's `iss`. The ID token is checked by go-oidc against the key set that
//     discovery named; the person is stored by (iss, sub), never by email.
//   - A refresh token rotates, so it is used by one request at a time (Store.WithSessionLock), a refusal of the grant
//     (`invalid_grant`) ends the session and answers 401 once, with no redirect that could loop, and a request that fails in
//     a way that does not say whether the provider acted is not repeated: repeating a rotated token would end the grant.
//   - The back-channel logout token is checked as the specification asks (issuer, audience, signature, type, event, sid, no
//     nonce, time) and handled once per jti, whatever the number of deliveries; the session of the sign-in it names ends.
//   - POST routes refuse requests that come from another site (Go's CrossOriginProtection), no code or token is ever logged
//     or kept in a URL the browser shows (the callback answers 303 to a local path), and the place to go after sign-in is
//     only ever a local path.
package bff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	loginTTL        = 10 * time.Minute
	defaultSession  = 8 * time.Hour
	accessSkew      = 30 * time.Second
	maxResponseSize = 1 << 20
	maxFormBytes    = 16 << 10
	backchannelType = "logout+jwt"
	backchannelKey  = "http://schemas.openid.net/event/backchannel-logout"
)

// Resource is an API the application calls for the person, through the proxy of the application.
type Resource struct {
	// Name is the path segment of the proxy: /api/{Name}/...
	Name string
	// URI is the value of the resource parameter the provider registered for the API.
	URI string
	// Scopes are the API's scopes asked at sign-in.
	Scopes []string
	// Upstream is where the proxy forwards the calls.
	Upstream *url.URL
}

// Config is what an application must know.
type Config struct {
	// Issuer is the exact iss of the provider, such as https://auth.example.com.
	Issuer       string
	ClientID     string
	ClientSecret string
	// BaseURL is the public origin of this application; the callback, the logout notice and the return address after
	// logout are under it.
	BaseURL string
	// Scopes are asked in addition to openid; email, for one.
	Scopes    []string
	Resources []Resource
	Store     Store
	Vault     *Vault
	// HTTPClient reaches the provider and the APIs. A client with a 10 second timeout if nil; every response is read with a
	// size limit.
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
	// SessionLifetime is how long a session lives; 8 hours if zero. The provider can end it sooner, by a logout notice.
	SessionLifetime time.Duration
	// MinKeyRefetch spaces the refetches of the key set that an unknown key id causes (30 seconds if zero), and KeyMaxAge is
	// how long a key set is trusted without a refetch (10 minutes if zero).
	MinKeyRefetch time.Duration
	KeyMaxAge     time.Duration
	// InsecureCookies lets the cookies go over plain http, for a development server on a loopback address. It is refused for
	// any other host.
	InsecureCookies bool
}

// App is the application. Create it with New; mount Handler.
type App struct {
	cfg     Config
	base    *url.URL
	origin  string
	client  *http.Client
	log     *slog.Logger
	store   Store
	vault   *Vault
	crossOr *http.CrossOriginProtection

	mu       sync.Mutex
	provider *providerState
}

// providerState is what discovery found, kept once it has been fetched.
type providerState struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
	revocation string
	issParam   bool
	keys       *keySet
}

// New checks the configuration. It does not contact the provider: the first request that needs it does, and tries again on
// the next one if it could not, so an application starts, and keeps serving signed-in people, while the provider is down.
func New(cfg Config) (*App, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || base.Path != "" && base.Path != "/" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("bff: BaseURL must be the origin of the application")
	}

	if base.Scheme != "https" && (base.Scheme != "http" || !loopback(base.Hostname())) {
		return nil, errors.New("bff: BaseURL must be https (http only for a loopback address)")
	}

	if cfg.InsecureCookies && base.Scheme != "http" {
		return nil, errors.New("bff: insecure cookies are for an http loopback address only")
	}

	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Store == nil || cfg.Vault == nil {
		return nil, errors.New("bff: an issuer, a client, a store and a vault are required")
	}

	for i, r := range cfg.Resources {
		if r.Name == "" || strings.ContainsAny(r.Name, "/?#") || r.URI == "" || r.Upstream == nil || len(r.Scopes) == 0 {
			return nil, errors.New("bff: a resource needs a name, a URI, scopes and an upstream")
		}

		for _, other := range cfg.Resources[:i] {
			if other.Name == r.Name || other.URI == r.URI {
				return nil, errors.New("bff: resources must differ")
			}
		}
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if cfg.SessionLifetime == 0 {
		cfg.SessionLifetime = defaultSession
	}

	if cfg.MinKeyRefetch == 0 {
		cfg.MinKeyRefetch = 30 * time.Second
	}

	if cfg.KeyMaxAge == 0 {
		cfg.KeyMaxAge = 10 * time.Minute
	}

	client := *cfg.HTTPClient
	client.Transport = &limitedTransport{next: cfg.HTTPClient.Transport, max: maxResponseSize}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Unsafe methods from another site are refused before they reach a handler, except the provider's notice: it is a server
	// to server call with no browser, and is authenticated by its signed token.
	crossOr := http.NewCrossOriginProtection()
	crossOr.AddInsecureBypassPattern("POST /auth/backchannel-logout")

	return &App{
		cfg: cfg, base: base, origin: strings.TrimSuffix(base.String(), "/"), client: &client, log: cfg.Logger, store: cfg.Store,
		vault: cfg.Vault, crossOr: crossOr,
	}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// limitedTransport caps what a response may carry, so a server that sends without end cannot fill the memory.
type limitedTransport struct {
	next http.RoundTripper
	max  int64
}

func (t *limitedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}

	resp, err := next.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	resp.Body = &cappedBody{ReadCloser: resp.Body, left: t.max}

	return resp, nil
}

type cappedBody struct {
	io.ReadCloser
	left int64
}

var errTooLarge = errors.New("bff: the response is too large")

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errTooLarge
	}

	if int64(len(p)) > b.left {
		p = p[:b.left]
	}

	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)

	return n, err
}

// ensure discovers the provider once. A failure is not kept: the next request tries again.
func (a *App) ensure(ctx context.Context) (*providerState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.provider != nil {
		return a.provider, nil
	}

	ctx = oidc.ClientContext(ctx, a.client)

	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("bff: discover the provider: %w", err)
	}

	var meta struct {
		JWKSURI    string `json:"jwks_uri"`
		EndSession string `json:"end_session_endpoint"`
		Revocation string `json:"revocation_endpoint"`
		IssParam   bool   `json:"authorization_response_iss_parameter_supported"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, fmt.Errorf("bff: read the discovery document: %w", err)
	}
	// The key set is taken from the one address the document names, and only if it is the issuer's own host.
	issuer, err := url.Parse(a.cfg.Issuer)
	if err != nil {
		return nil, err
	}

	jwks, err := url.Parse(meta.JWKSURI)
	if err != nil || jwks.Host != issuer.Host || jwks.Scheme != issuer.Scheme || jwks.User != nil || jwks.Fragment != "" {
		return nil, errors.New("bff: the key set is not on the issuer's host")
	}

	keys := &keySet{url: meta.JWKSURI, client: a.client, now: a.cfg.Now, maxAge: a.cfg.KeyMaxAge, minRefetch: a.cfg.MinKeyRefetch}
	verifier := oidc.NewVerifier(a.cfg.Issuer, keys, &oidc.Config{
		ClientID: a.cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256}, Now: a.cfg.Now,
	})
	// One list, each scope once: the provider refuses a repeated scope, and two APIs may share a name.
	scopes := []string{oidc.ScopeOpenID}

	for _, list := range append([][]string{a.cfg.Scopes}, resourceScopes(a.cfg.Resources)...) {
		for _, sc := range list {
			if !slices.Contains(scopes, sc) {
				scopes = append(scopes, sc)
			}
		}
	}

	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	a.provider = &providerState{
		oauth: oauth2.Config{
			ClientID: a.cfg.ClientID, ClientSecret: a.cfg.ClientSecret, Endpoint: endpoint,
			RedirectURL: a.origin + "/auth/callback", Scopes: scopes,
		},
		verifier: verifier, keys: keys, endSession: meta.EndSession, revocation: meta.Revocation, issParam: meta.IssParam,
	}

	return a.provider, nil
}

func resourceScopes(list []Resource) [][]string {
	out := make([][]string, 0, len(list))
	for _, r := range list {
		out = append(out, r.Scopes)
	}

	return out
}

// Handler serves the routes of the application.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("GET /api/me", a.me)
	mux.HandleFunc("/api/{name}/{rest...}", a.proxy)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("GET /logged-out", a.loggedOut)
	mux.HandleFunc("POST /auth/backchannel-logout", a.backchannel)

	return a.crossOr.Handler(noStore(mux))
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// Cookie names. The __Host- prefix makes a browser accept the cookie only if it is Secure, has Path=/ and no Domain.
func (a *App) cookieName(name string) string {
	if a.cfg.InsecureCookies {
		return name
	}

	return "__Host-" + name
}

func (a *App) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(name), Value: value, Path: "/", HttpOnly: true, Secure: !a.cfg.InsecureCookies, SameSite: http.SameSiteLaxMode,
		MaxAge: int(maxAge / time.Second),
	})
}

func (a *App) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(name), Value: "", Path: "/", HttpOnly: true, Secure: !a.cfg.InsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (a *App) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(a.cookieName(name))
	if err != nil {
		return ""
	}

	return c.Value
}

// secret returns 256 random bits as 43 characters, and their hash.
func secret() (value, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}

	value = base64.RawURLEncoding.EncodeToString(raw)

	return value, hashOf(value), nil
}

func hashOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// safeLocal returns raw if it is a path of this site and nothing else: it starts with a single slash and names no host, no
// scheme, no backslash and no control character. Anything else goes to the front page.
func safeLocal(raw string) string {
	if raw == "" || len(raw) > 512 || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}

	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}

	return raw
}

// login starts a sign-in: a transaction kept on the server, a cookie that ties it to this browser, and the redirect.
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	p, err := a.ensure(r.Context())
	if err != nil {
		a.unavailable(w, "discover", err)
		return
	}

	cookieValue, key, err := secret()
	if err != nil {
		a.fail(w, "random", err)
		return
	}

	state, _, err := secret()
	if err != nil {
		a.fail(w, "random", err)
		return
	}

	nonce, _, err := secret()
	if err != nil {
		a.fail(w, "random", err)
		return
	}

	verifier := oauth2.GenerateVerifier()

	tx := LoginTx{Key: key, State: state, Nonce: nonce, Verifier: verifier, ReturnTo: safeLocal(r.URL.Query().Get("return_to")), StartedAt: a.cfg.Now(), ExpiresAt: a.cfg.Now().Add(loginTTL)}
	if err := a.store.PutLogin(r.Context(), tx); err != nil {
		a.fail(w, "store", err)
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	target := p.oauth.AuthCodeURL(state, opts...)
	// The resource parameter is repeated, one for each API (RFC 8707), which a single option cannot express.
	for _, res := range a.cfg.Resources {
		target += "&resource=" + url.QueryEscape(res.URI)
	}

	a.setCookie(w, "bff_login", cookieValue, loginTTL)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// callback receives the browser back from the provider.
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	a.clearCookie(w, "bff_login")

	p, err := a.ensure(r.Context())
	if err != nil {
		a.unavailable(w, "discover", err)
		return
	}

	q := r.URL.Query()

	cookieValue := a.cookie(r, "bff_login")
	if cookieValue == "" {
		a.page(w, http.StatusBadRequest, "The sign-in did not start in this browser, or it expired.")
		return
	}
	// The transaction is spent whatever follows: a code is used once, and so is the page that was sent to ask for it.
	tx, ok, err := a.store.TakeLogin(r.Context(), hashOf(cookieValue), a.cfg.Now())
	if err != nil {
		a.fail(w, "store", err)
		return
	}

	if !ok || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(tx.State)) != 1 {
		a.page(w, http.StatusBadRequest, "The sign-in did not start in this browser, or it expired.")
		return
	}
	// RFC 9207: the response says who sent it, and only the provider this application trusts will do.
	if iss := q.Get("iss"); iss != "" && iss != a.cfg.Issuer || iss == "" && p.issParam {
		a.page(w, http.StatusBadRequest, "The sign-in answer came from a source this application does not trust.")
		return
	}

	if q.Get("error") != "" {
		// The provider's words are not shown: they come through the browser, so they are anyone's.
		a.log.Info("sign-in refused by the provider", "error", cleanCode(q.Get("error")))
		a.page(w, http.StatusForbidden, "The sign-in was not completed.")

		return
	}

	code := q.Get("code")
	if code == "" || len(code) > 512 {
		a.page(w, http.StatusBadRequest, "The sign-in answer is not valid.")
		return
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)

	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		a.log.Warn("code exchange failed", "error", errClass(err))
		a.page(w, http.StatusBadGateway, "The sign-in could not be completed. Try again.")

		return
	}

	rawID, _ := token.Extra("id_token").(string)
	if rawID == "" || token.RefreshToken == "" {
		a.page(w, http.StatusBadGateway, "The sign-in answer is not complete.")
		return
	}

	id, err := p.verifier.Verify(oidc.ClientContext(r.Context(), a.client), rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(tx.Nonce)) != 1 || id.Subject == "" || id.Issuer != a.cfg.Issuer {
		a.log.Warn("id token refused", "error", errClass(err))
		a.page(w, http.StatusBadGateway, "The sign-in answer is not valid.")

		return
	}

	var claims struct {
		SID string `json:"sid"`
	}
	if err := id.Claims(&claims); err != nil {
		a.page(w, http.StatusBadGateway, "The sign-in answer is not valid.")
		return
	}

	userID, err := a.store.UpsertUser(r.Context(), id.Issuer, id.Subject)
	if err != nil {
		a.fail(w, "store", err)
		return
	}

	cookie, key, err := secret()
	if err != nil {
		a.fail(w, "random", err)
		return
	}

	now := a.cfg.Now()

	refresh, err := a.vault.Seal(token.RefreshToken, key)
	if err != nil {
		a.fail(w, "seal", err)
		return
	}

	idSealed, err := a.vault.Seal(rawID, key)
	if err != nil {
		a.fail(w, "seal", err)
		return
	}

	err = a.store.CreateSession(r.Context(), Session{
		Key: key, UserID: userID, Issuer: id.Issuer, Subject: id.Subject, ProviderSession: claims.SID, IDTokenSealed: idSealed,
		RefreshSealed: refresh, Access: map[string]SealedAccess{}, CreatedAt: now, SignInStarted: tx.StartedAt, ExpiresAt: now.Add(a.cfg.SessionLifetime),
	})
	if errors.Is(err, ErrSessionEnded) {
		a.page(w, http.StatusForbidden, "This sign-in has already ended.")
		return
	}

	if err != nil {
		a.fail(w, "store", err)
		return
	}

	a.setCookie(w, "bff_session", cookie, a.cfg.SessionLifetime)
	// The code is in this request's address and nowhere after: the browser is sent on to a plain local path.
	http.Redirect(w, r, tx.ReturnTo, http.StatusSeeOther)
}

// session returns the live session of the request.
func (a *App) session(r *http.Request) (Session, bool) {
	cookie := a.cookie(r, "bff_session")
	if cookie == "" || len(cookie) > 128 {
		return Session{}, false
	}

	s, err := a.store.GetSession(r.Context(), hashOf(cookie))
	if err != nil {
		return Session{}, false
	}

	if !a.cfg.Now().Before(s.ExpiresAt) {
		_ = a.store.DeleteSession(r.Context(), s.Key)
		return Session{}, false
	}

	return s, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// loginRequired answers a call that has no session. It does not redirect: a page that runs in the browser decides what to do,
// and a redirect from here could send a browser round and round when the provider keeps refusing.
func (a *App) loginRequired(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login": "/login"})
}

// me tells the page who is signed in. It carries no token.
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r)
	if !ok {
		a.loginRequired(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user_id": s.UserID, "issuer": s.Issuer, "subject": s.Subject, "expires_at": s.ExpiresAt.UTC()})
}

// Errors of the refresh.
var (
	// ErrLoginRequired means the provider ended the grant: the person must sign in again.
	ErrLoginRequired = errors.New("bff: the grant is over")
	// ErrResourceRefused means the provider will not issue a token for the resource to this application.
	ErrResourceRefused = errors.New("bff: the provider refused the resource")
	// errAmbiguous is a refresh whose outcome is not known: the provider may have rotated the token.
	errAmbiguous = errors.New("bff: the refresh may have been made")
	// ErrProvider means the provider could not be reached or did not answer as expected. The session stays.
	ErrProvider = errors.New("bff: the provider is unavailable")
)

// accessToken returns an access token for the resource, refreshing it if the one held is nearly over. The refresh is made
// with the session held exclusively, so a second tab that needs a token at the same moment waits and then finds the first
// one's result instead of presenting a refresh token that has already been spent.
func (a *App) accessToken(ctx context.Context, s Session, res Resource) (string, error) {
	p, err := a.ensure(ctx)
	if err != nil {
		return "", ErrProvider
	}

	var token string

	ambiguous := false

	err = a.store.WithSessionLock(ctx, s.Key, func(held *Session) error {
		now := a.cfg.Now()
		// An earlier refresh began and never finished: the provider may have rotated the token, so the one held must not be
		// presented again. This comes before anything else, the cache included: the store clears its mark as this call
		// returns, and a token taken from the cache would hide the interruption from the next one.
		interrupted := held.RefreshInterrupted
		if interrupted {
			held.RefreshSealed = ""
		}

		if e, ok := held.Access[res.URI]; ok && now.Add(accessSkew).Before(e.ExpiresAt) {
			if t, err := a.vault.Open(e.Sealed, s.Key); err == nil {
				token = t
				return nil
			}
		}

		if interrupted {
			held.Access = map[string]SealedAccess{}
			ambiguous = true

			return nil
		}

		if held.RefreshSealed == "" {
			return ErrLoginRequired
		}

		refresh, err := a.vault.Open(held.RefreshSealed, s.Key)
		if err != nil {
			return ErrLoginRequired
		}
		// Recorded durably before the provider is asked, so that a crash after it rotates the token cannot lead to a replay.
		if held.BeginRefresh != nil {
			if err := held.BeginRefresh(ctx); err != nil {
				a.log.Warn("refresh not started", "error", errClass(err))
				return ErrProvider
			}
		}

		got, err := a.refresh(ctx, p, refresh, res.URI)
		if errors.Is(err, errAmbiguous) {
			// The provider may have rotated the token and the answer was lost: the one held is spent or about to be, and
			// presenting it again would be a replay that ends the grant. It is dropped now; the person signs in again.
			held.RefreshSealed, held.Access = "", map[string]SealedAccess{}
			ambiguous = true

			return nil
		}

		if err != nil {
			return err
		}
		// The provider has rotated the token by now: failing to keep the new one is as lost as a lost answer.
		sealedRefresh, err := a.vault.Seal(got.refreshToken, s.Key)
		if err == nil {
			var sealedAccess string
			if sealedAccess, err = a.vault.Seal(got.accessToken, s.Key); err == nil {
				held.RefreshSealed = sealedRefresh
				if held.Access == nil {
					held.Access = map[string]SealedAccess{}
				}

				held.Access[res.URI] = SealedAccess{Sealed: sealedAccess, ExpiresAt: now.Add(got.expiresIn)}
				token = got.accessToken

				return nil
			}
		}

		held.RefreshSealed, held.Access = "", map[string]SealedAccess{}
		ambiguous = true

		return nil
	})
	if err == nil && ambiguous {
		return "", ErrProvider
	}

	switch {
	case errors.Is(err, ErrLoginRequired):
		// The grant is over, here or at the provider: the session goes with it. The next call finds none.
		_ = a.store.DeleteSession(ctx, s.Key)
		return "", ErrLoginRequired
	case errors.Is(err, ErrNoSession):
		return "", ErrLoginRequired
	case err != nil:
		return "", err
	}

	return token, nil
}

type refreshed struct {
	accessToken  string
	refreshToken string
	expiresIn    time.Duration
}

// refresh presents the refresh token for the token of one resource. The answer is classified, never passed on: the
// provider's words are not the person's to read.
func (a *App) refresh(ctx context.Context, p *providerState, refreshToken, resource string) (refreshed, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "resource": {resource}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oauth.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return refreshed{}, ErrProvider
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))

	resp, err := a.client.Do(req)
	if err != nil {
		// Whether the provider acted is not known. The request is not repeated: if it did rotate the token, a repeat is a
		// replay and ends the grant. The caller tells the person to try again, and the next call finds out.
		a.log.Warn("refresh did not complete", "error", errClass(err))
		return refreshed{}, errAmbiguous
	}

	defer func() { _ = resp.Body.Close() }()

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	// A 5xx may come from a proxy that lost the answer after the provider rotated the token, so it proves nothing.
	if resp.StatusCode >= http.StatusInternalServerError {
		a.log.Warn("refresh answered with a server error", "status", resp.StatusCode)
		return refreshed{}, errAmbiguous
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil || json.Unmarshal(data, &body) != nil && resp.StatusCode == http.StatusOK {
		return refreshed{}, errAmbiguous
	}

	if resp.StatusCode == http.StatusOK {
		if body.AccessToken == "" || body.RefreshToken == "" || body.ExpiresIn <= 0 {
			return refreshed{}, errAmbiguous
		}

		return refreshed{accessToken: body.AccessToken, refreshToken: body.RefreshToken, expiresIn: time.Duration(body.ExpiresIn) * time.Second}, nil
	}

	switch body.Error {
	case "invalid_grant":
		return refreshed{}, ErrLoginRequired
	case "invalid_target", "invalid_scope":
		return refreshed{}, ErrResourceRefused
	}

	a.log.Warn("refresh refused", "status", resp.StatusCode, "error", cleanCode(body.Error))

	return refreshed{}, ErrProvider
}

// proxy calls an API for the person: the browser never sees the token, and the API never sees the cookie.
func (a *App) proxy(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r)
	if !ok {
		a.loginRequired(w)
		return
	}

	var res *Resource

	for i := range a.cfg.Resources {
		if a.cfg.Resources[i].Name == r.PathValue("name") {
			res = &a.cfg.Resources[i]
		}
	}

	if res == nil {
		http.NotFound(w, r)
		return
	}

	token, err := a.accessToken(r.Context(), s, *res)
	switch {
	case errors.Is(err, ErrLoginRequired):
		a.clearCookie(w, "bff_session")
		a.loginRequired(w)

		return
	case errors.Is(err, ErrResourceRefused):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource_refused"})
		return
	case err != nil:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "provider_unavailable"})
		return
	}

	rest := r.PathValue("rest")
	for _, seg := range strings.Split(rest, "/") {
		if seg == ".." || seg == "." || strings.ContainsAny(seg, "\\\x00") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
	}

	target := *res.Upstream
	target.Path = strings.TrimSuffix(target.Path, "/") + "/" + strings.TrimPrefix(r.PathValue("rest"), "/")
	target.RawQuery = r.URL.RawQuery

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), http.MaxBytesReader(w, r.Body, maxResponseSize))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}

	out.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.client.Do(out)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_unavailable"})
		return
	}

	defer func() { _ = resp.Body.Close() }()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// logout ends the session here, takes the grant back, and sends the browser to the provider to end the shared sign-in.
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	p, err := a.ensure(r.Context())
	if err != nil {
		a.unavailable(w, "discover", err)
		return
	}

	hint := ""

	if s, ok := a.session(r); ok {
		if refresh, err := a.vault.Open(s.RefreshSealed, s.Key); err == nil {
			a.revoke(r.Context(), p, refresh)
		}

		if t, err := a.vault.Open(s.IDTokenSealed, s.Key); err == nil {
			hint = t
		}

		_ = a.store.DeleteSession(r.Context(), s.Key)
	}

	a.clearCookie(w, "bff_session")

	if p.endSession == "" {
		http.Redirect(w, r, "/logged-out", http.StatusSeeOther)
		return
	}

	state, _, err := secret()
	if err != nil {
		a.fail(w, "random", err)
		return
	}

	a.setCookie(w, "bff_logout", state, loginTTL)

	q := url.Values{"client_id": {a.cfg.ClientID}, "post_logout_redirect_uri": {a.origin + "/logged-out"}, "state": {state}}
	if hint != "" {
		q.Set("id_token_hint", hint)
	}

	http.Redirect(w, r, p.endSession+"?"+q.Encode(), http.StatusSeeOther)
}

// revoke tells the provider this application does not want the grant any more. It is best effort: the session is gone
// either way.
func (a *App) revoke(ctx context.Context, p *providerState, refreshToken string) {
	if p.revocation == "" {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.revocation, strings.NewReader(url.Values{"token": {refreshToken}}.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))

	resp, err := a.client.Do(req)
	if err != nil {
		a.log.Warn("revocation did not complete", "error", errClass(err))
		return
	}

	_ = resp.Body.Close()
}

// loggedOut is where the provider sends the browser back. The state it carries must be the one this browser was given.
func (a *App) loggedOut(w http.ResponseWriter, r *http.Request) {
	want := a.cookie(r, "bff_logout")
	a.clearCookie(w, "bff_logout")

	got := r.URL.Query().Get("state")
	if got != "" || want != "" {
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			a.page(w, http.StatusBadRequest, "This sign-out was not started from this browser.")
			return
		}
	}

	a.page(w, http.StatusOK, "You are signed out.")
}

// backchannel receives the provider's notice that a sign-in ended (OpenID Connect Back-Channel Logout 1.0).
func (a *App) backchannel(w http.ResponseWriter, r *http.Request) {
	refuse := func() { writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"}) }

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if mt := strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]; strings.TrimSpace(mt) != "application/x-www-form-urlencoded" {
		refuse()
		return
	}

	if err := r.ParseForm(); err != nil || len(r.PostForm["logout_token"]) != 1 {
		refuse()
		return
	}

	p, err := a.ensure(r.Context())
	if err != nil {
		// Not "invalid": the provider delivers again.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}

	raw := r.PostForm.Get("logout_token")
	if !hasType(raw, backchannelType) {
		refuse()
		return
	}
	// Signature, issuer, audience (this client) and expiry are go-oidc's; the rest of what the specification asks is below.
	// go-oidc does not wrap what the key set says, so the question "could the key be had?" is asked first.
	_, err = p.keys.VerifySignature(r.Context(), raw)
	if errors.Is(err, ErrKeysUnavailable) {
		// Not a verdict on the token: the key may be one just published. The provider delivers again on a 503, not on a 400.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}

	tok, err := p.verifier.Verify(oidc.ClientContext(r.Context(), a.client), raw)
	if err != nil {
		a.log.Info("logout token refused", "error", errClass(err))
		refuse()

		return
	}

	var claims map[string]json.RawMessage
	if err := tok.Claims(&claims); err != nil {
		refuse()
		return
	}

	var (
		events   map[string]json.RawMessage
		sid, jti string
	)

	_ = json.Unmarshal(claims["events"], &events)
	_ = json.Unmarshal(claims["sid"], &sid)
	_ = json.Unmarshal(claims["jti"], &jti)
	// The notice is for this application alone.
	if len(tok.Audience) != 1 {
		refuse()
		return
	}

	_, hasEvent := events[backchannelKey]
	_, hasNonce := claims["nonce"]

	var iat float64

	_ = json.Unmarshal(claims["iat"], &iat)
	if !hasEvent || hasNonce || sid == "" || jti == "" || len(jti) > 256 || len(sid) > 256 || tok.Subject == "" || iat <= 0 ||
		time.Unix(int64(iat), 0).After(a.cfg.Now().Add(time.Minute)) {
		refuse()
		return
	}
	// One atomic step: the notice is remembered, the sign-in is marked ended and its sessions go, or none of it happens and the
	// provider's next delivery starts again. A repeat of a handled notice is answered as the first was.
	first, n, err := a.store.EndProviderSession(r.Context(), tok.Issuer, sid, jti, tok.Expiry)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}

	if first {
		a.log.Info("sign-in ended by the provider", "sessions", n)
	}

	w.WriteHeader(http.StatusOK)
}

// hasType reports whether the protected header of a compact JWT names the type.
func hasType(token, typ string) bool {
	seg, _, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return false
	}

	var h struct {
		Typ string `json:"typ"`
	}

	return json.Unmarshal(raw, &h) == nil && h.Typ == typ
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in</title></head>
<body><main><p>{{.}}</p><p><a href="/login">Sign in</a></p></main></body></html>
`))

// page shows a fixed message. The sign-in is never restarted from here: a person who is refused is told, and chooses.
func (a *App) page(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, message)
}

func (a *App) unavailable(w http.ResponseWriter, what string, err error) {
	a.log.Warn("the provider is unavailable", "step", what, "error", errClass(err))
	a.page(w, http.StatusServiceUnavailable, "Signing in is not possible right now. Try again in a moment.")
}

func (a *App) fail(w http.ResponseWriter, what string, err error) {
	a.log.Error("request failed", "step", what, "error", errClass(err))
	a.page(w, http.StatusInternalServerError, "Something went wrong.")
}

// errClass is what is logged of an error: never its text, which could carry an address with a code in it.
func errClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errTooLarge):
		return "too_large"
	}

	var oauthErr *oauth2.RetrieveError
	if errors.As(err, &oauthErr) {
		return "oauth_" + cleanCode(oauthErr.ErrorCode)
	}

	return "error"
}

// cleanCode keeps a short lower-case code and nothing else, so a value that came from the network cannot reach a log.
func cleanCode(s string) string {
	if len(s) > 40 {
		return "other"
	}

	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') {
			return "other"
		}
	}

	return s
}
