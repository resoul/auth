//go:build integration

package oidc_test

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/jwt"
	"airlance.org/auth/internal/adapter/postgres"
	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	doidc "airlance.org/auth/internal/domain/oidc"
	dsession "airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
)

const (
	issuer      = "https://auth.example.test"
	appCallback = "https://app.example.test/callback"
	appTwo      = "https://other.example.test/callback"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// env runs the provider's use cases against PostgreSQL with real signers, so the locks and the tokens are the real ones.
type env struct {
	t        *testing.T
	store    *postgres.Store
	clock    *testutil.FakeClock
	factory  *testutil.Factory
	device   *jwt.Signer
	oidcKeys *jwt.RSARing
	secrets  crypto.OIDC

	authorize  *appoidc.Authorize
	login      *appoidc.CompleteLogin
	token      *appoidc.Token
	userinfo   *appoidc.UserInfo
	clients    *appoidc.Clients
	logout     *appoidc.Logout
	revoke     *appoidc.Revoke
	resources  *appoidc.Resources
	introspect *appoidc.Introspect
	apps       *appoidc.Apps
	metrics    *recordedMetrics
	signer     *jwt.OIDCTokens
}

func newEnv(t *testing.T) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: testutil.PostgresStore(t), clock: factory.Clock, factory: factory}

	ecPEM := testutil.NewSigningKeyPEM(t)
	ec, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", ecPEM.Private)})
	must(t, err)
	e.device, err = jwt.NewSigner(ec, e.clock, "https://auth.example.test", "example", 5*time.Minute)
	must(t, err)
	deviceVerifier, err := jwt.NewVerifier(ec.PublicKeys(), e.clock, "https://auth.example.test", "example", 30*time.Second)
	must(t, err)

	rsaPEM := testutil.NewRSAKeyPEM(t)
	e.oidcKeys, err = jwt.LoadRSARing("oidc-a", map[string]string{"oidc-a": testutil.WriteFile(t, "oidc.pem", rsaPEM.Private)})
	must(t, err)
	tokens, err := jwt.NewOIDCTokens(e.oidcKeys, e.clock, issuer, 5*time.Minute, 5*time.Minute, 30*time.Second)
	must(t, err)

	e.metrics = &recordedMetrics{counts: map[string]int{}}
	deps := appoidc.Deps{
		UnitOfWork: e.store, Clock: e.clock, Secrets: e.secrets, IDs: factory.IDs, Signer: tokens, Verifier: tokens,
		Issuer: issuer, Policy: doidc.DefaultPolicy(), Metrics: e.metrics,
	}
	e.authorize, err = appoidc.NewAuthorize(deps)
	must(t, err)
	e.login, err = appoidc.NewCompleteLogin(deps, deviceVerifier)
	must(t, err)
	e.token, err = appoidc.NewToken(deps)
	must(t, err)
	e.userinfo, err = appoidc.NewUserInfo(deps)
	must(t, err)
	e.clients, err = appoidc.NewClients(deps)
	must(t, err)
	e.logout, err = appoidc.NewLogout(deps)
	must(t, err)
	e.revoke, err = appoidc.NewRevoke(deps)
	must(t, err)
	e.resources, err = appoidc.NewResources(appoidc.Resources{UnitOfWork: e.store, Clock: e.clock, Issuer: issuer, Metrics: e.metrics, Secrets: e.secrets, IDs: factory.IDs})
	must(t, err)
	e.introspect, err = appoidc.NewIntrospect(deps)
	must(t, err)
	e.apps, err = appoidc.NewApps(appoidc.Apps{UnitOfWork: e.store, Clock: e.clock, Metrics: e.metrics})
	must(t, err)
	e.signer = tokens
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(fn func(ctx context.Context, st port.Stores) error) {
	e.t.Helper()
	must(e.t, e.store.Do(context.Background(), fn))
}

// client is a registered application.
type client struct {
	id, secret, redirect string
}

func (e *env) register(id, redirect string, scopes ...string) client {
	e.t.Helper()
	got, err := e.clients.Register(context.Background(), appoidc.RegisterCommand{
		ID: id, Name: id, RedirectURIs: []string{redirect}, AllowedScopes: scopes,
	})
	must(e.t, err)
	return client{id: id, secret: got.Secret, redirect: redirect}
}

// person is a user who can sign in on this device: it makes the access token the sign-in page would hold.
type person struct {
	user *identity.User
}

func (e *env) newPerson() person {
	e.t.Helper()
	user := e.factory.User(testutil.UserSpec{})
	e.do(func(ctx context.Context, st port.Stores) error {
		_, _, err := st.Users.Ensure(ctx, user)
		return err
	})
	return person{user: user}
}

// signIn makes a device session and the access token of it, as the sign-in page holds after a passkey login.
func (e *env) signIn(p person) string {
	e.t.Helper()
	sess := e.factory.Session(testutil.SessionSpec{User: p.user, AMR: []string{"otp", "passkey"}})
	e.do(func(ctx context.Context, st port.Stores) error { return st.Sessions.Create(ctx, sess) })
	token, err := e.device.SignAccess(port.AccessClaims{UserID: p.user.ID(), SessionID: sess.ID(), AuthTime: e.clock.Now(), AMR: []string{"otp", "passkey"}})
	must(e.t, err)
	return token.Value
}

// flow is one run of the code flow of one application.
type flow struct {
	client   client
	state    string
	nonce    string
	verifier string
	// scope replaces the default "openid email"; resources are the resource parameters.
	scope     string
	resources []string
}

func (e *env) newFlow(c client) flow {
	e.t.Helper()
	verifier, _, err := e.secrets.NewOIDCSecret() // 43 characters of the unreserved set
	must(e.t, err)
	state, _, err := e.secrets.NewOIDCSecret()
	must(e.t, err)
	nonce, _, err := e.secrets.NewOIDCSecret()
	must(e.t, err)
	return flow{client: c, state: state, nonce: nonce, verifier: verifier}
}

func (f flow) command(sso string) appoidc.AuthorizeCommand {
	scope := f.scope
	if scope == "" {
		scope = "openid email"
	}
	return appoidc.AuthorizeCommand{
		ResponseType: "code", ClientID: f.client.id, RedirectURI: f.client.redirect, Scope: scope, State: f.state, Nonce: f.nonce,
		CodeChallenge: doidc.Challenge(f.verifier), CodeChallengeMethod: "S256", SSOSecret: sso, Resources: f.resources,
	}
}

func (e *env) authorizeWith(cmd appoidc.AuthorizeCommand) appoidc.AuthorizeResult {
	e.t.Helper()
	got, err := e.authorize.Execute(context.Background(), cmd)
	must(e.t, err)
	return got
}

// signedIn runs a flow through the sign-in page and returns the code and the new SSO cookie.
func (e *env) signedIn(f flow, p person) (code, sso string) {
	e.t.Helper()
	asked := e.authorizeWith(f.command(""))
	if asked.Kind != appoidc.AuthorizeLogin {
		e.t.Fatalf("authorize = %+v, want the sign-in page", asked)
	}
	done, err := e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{
		RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: e.signIn(p),
	})
	must(e.t, err)
	if done.Failure != nil || done.SSOSecret == "" {
		e.t.Fatalf("complete login = %+v", done)
	}
	return e.codeOf(f, done.Location), done.SSOSecret
}

// codeOf reads the code from the redirect back to the application and checks what must be there.
func (e *env) codeOf(f flow, location string) string {
	e.t.Helper()
	q := e.query(location, f.client.redirect)
	if q.Get("state") != f.state || q.Get("iss") != issuer || q.Get("code") == "" || q.Get("error") != "" {
		e.t.Fatalf("redirect %q does not carry a code, the state and the issuer", location)
	}
	return q.Get("code")
}

func (e *env) query(location, wantPrefix string) url.Values {
	e.t.Helper()
	if !strings.HasPrefix(location, wantPrefix+"?") {
		e.t.Fatalf("redirect %q does not go to %s", location, wantPrefix)
	}
	u, err := url.Parse(location)
	must(e.t, err)
	return u.Query()
}

func (e *env) exchange(f flow, code string) appoidc.TokenResult {
	e.t.Helper()
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: f.client.id, ClientSecret: f.client.secret, GrantType: "authorization_code", Code: code,
		RedirectURI: f.client.redirect, CodeVerifier: f.verifier,
	})
	must(e.t, err)
	return got
}

func (e *env) refresh(c client, refreshToken string) appoidc.TokenResult {
	e.t.Helper()
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: c.id, ClientSecret: c.secret, GrantType: "refresh_token", RefreshToken: refreshToken,
	})
	must(e.t, err)
	return got
}

// tokens runs a whole sign-in and returns the tokens of the application.
func (e *env) tokens(f flow, p person) (*appoidc.TokenResponse, string) {
	e.t.Helper()
	code, sso := e.signedIn(f, p)
	got := e.exchange(f, code)
	if got.Response == nil {
		e.t.Fatalf("exchange = %+v", got.Failure)
	}
	return got.Response, sso
}

// idClaims verifies an ID Token's signature against the published keys and returns its claims.
func (e *env) idClaims(token string) map[string]any {
	e.t.Helper()
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	must(e.t, err)
	var claims map[string]any
	must(e.t, parsed.Claims(e.oidcKeys.PublicKeys()["oidc-a"], &claims))
	return claims
}

// registerWithLogout registers an application that has a return address after logout and, if backchannel is not empty, an
// endpoint to be told when a sign-in ends.
func (e *env) registerWithLogout(id, redirect, postLogout, backchannel string) client {
	e.t.Helper()
	cmd := appoidc.RegisterCommand{ID: id, Name: id, RedirectURIs: []string{redirect}, BackchannelLogoutURI: backchannel}
	if postLogout != "" {
		cmd.PostLogoutRedirectURIs = []string{postLogout}
	}
	got, err := e.clients.Register(context.Background(), cmd)
	must(e.t, err)
	return client{id: id, secret: got.Secret, redirect: redirect}
}

// opSessionOf reads the shared sign-in of a cookie.
func (e *env) opSessionOf(sso string) *doidc.OPSession {
	e.t.Helper()
	hash, err := e.secrets.HashOIDCSecret(sso)
	must(e.t, err)
	var op *doidc.OPSession
	e.do(func(ctx context.Context, st port.Stores) error {
		var err error
		op, err = st.OPSessions.GetBySecret(ctx, hash)
		return err
	})
	return op
}

// appsessionByID reads a device session of the /v1 API by its id.
func appsessionByID(ctx context.Context, st port.Stores, id string) (*dsession.Session, error) {
	sid, err := dsession.ParseID(id)
	if err != nil {
		return nil, err
	}
	return st.Sessions.Get(ctx, sid)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recordedMetrics remembers what the use cases counted.
type recordedMetrics struct {
	mu     sync.Mutex
	counts map[string]int
}

func (m *recordedMetrics) ResourceToken(resource, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts["token:"+resource+":"+outcome]++
}

func (m *recordedMetrics) PermissionChange(change string, ended int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts["change:"+change]++
	m.counts["ended:"+change] += ended
}

func (m *recordedMetrics) Introspection(resource, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts["introspect:"+resource+":"+outcome]++
}

func (m *recordedMetrics) count(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[key]
}
