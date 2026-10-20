//go:build integration

package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

func TestSignInOnceAndEnterTwoApplications(t *testing.T) {
	e := newEnv(t)
	panels := e.register("panels-web", appCallback, "openid", "email")
	other := e.register("other-app", appTwo, "openid", "email")
	alice := e.newPerson()

	// The first application: the browser signs in once, with a passkey, and the code goes back.
	first := e.newFlow(panels)
	got, sso := e.tokens(first, alice)

	claims := e.idClaims(got.IDToken)
	if claims["iss"] != issuer || claims["sub"] != alice.user.ID().String() || claims["nonce"] != first.nonce {
		t.Errorf("id token claims = %v", claims)
	}

	if aud, _ := claims["aud"].(string); aud != "panels-web" {
		t.Errorf("aud = %v, want only the client", claims["aud"])
	}

	if claims["email"] != alice.user.Email().String() || claims["email_verified"] != true {
		t.Errorf("email claims = %v, %v", claims["email"], claims["email_verified"])
	}

	for _, name := range []string{"auth_time", "amr", "sid", "iat", "exp"} {
		if claims[name] == nil {
			t.Errorf("id token has no %s", name)
		}
	}

	if got.Scope != "openid email" || got.AccessToken == "" || got.RefreshToken == "" || got.ExpiresIn != 300 {
		t.Errorf("token response = %+v", got)
	}

	// UserInfo agrees with the ID token about who this is.
	info, err := e.userinfo.Execute(context.Background(), got.AccessToken)
	must(t, err)

	if info.Claims == nil || info.Claims.Subject != claims["sub"] || !info.Claims.HasEmail || info.Claims.Email != alice.user.Email().String() {
		t.Fatalf("userinfo = %+v", info)
	}

	// The second application: the cookie of the first sign-in is enough. No passkey, no sign-in page.
	second := e.newFlow(other)

	again := e.authorizeWith(second.command(sso))
	if again.Kind != appoidc.AuthorizeRedirect {
		t.Fatalf("authorize with the shared sign-in = %+v, want a code at once", again)
	}

	otherTokens := e.exchange(second, e.codeOf(second, again.Location))
	if otherTokens.Response == nil {
		t.Fatalf("exchange = %+v", otherTokens.Failure)
	}

	otherClaims := e.idClaims(otherTokens.Response.IDToken)
	if otherClaims["sub"] != claims["sub"] || otherClaims["sid"] != claims["sid"] || otherClaims["aud"] != "other-app" {
		t.Errorf("the second application sees %v, want the same user and sign-in under its own audience", otherClaims)
	}
	// The tokens are the application's own: the first one's access token is not the second one's.
	if otherTokens.Response.AccessToken == got.AccessToken || otherTokens.Response.RefreshToken == got.RefreshToken {
		t.Error("two applications were given the same token")
	}
}

func TestEveryRefusalOfAnAuthorizeRequest(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	f := e.newFlow(app)

	// The client or the redirect URI cannot be trusted: shown here, nobody is sent anywhere.
	page := map[string]func(c *appoidc.AuthorizeCommand){
		"an unknown client":        func(c *appoidc.AuthorizeCommand) { c.ClientID = "nobody" },
		"an unregistered redirect": func(c *appoidc.AuthorizeCommand) { c.RedirectURI = "https://evil.example.test/callback" },
		"a redirect with a suffix": func(c *appoidc.AuthorizeCommand) { c.RedirectURI = appCallback + "/" },
		"a redirect with a query":  func(c *appoidc.AuthorizeCommand) { c.RedirectURI = appCallback + "?x=1" },
		"no redirect":              func(c *appoidc.AuthorizeCommand) { c.RedirectURI = "" },
	}
	for name, mutate := range page {
		cmd := f.command("")
		mutate(&cmd)

		if got := e.authorizeWith(cmd); got.Kind != appoidc.AuthorizeFailure || got.Location != "" {
			t.Errorf("%s: %+v, want an error page and no redirect", name, got)
		}
	}

	// The redirect URI is trusted: the error goes back to the application, with its state and the issuer.
	back := map[string]struct {
		mutate func(c *appoidc.AuthorizeCommand)
		code   string
	}{
		"implicit flow":          {func(c *appoidc.AuthorizeCommand) { c.ResponseType = "token" }, appoidc.ErrUnsupportedResponseType},
		"no state":               {func(c *appoidc.AuthorizeCommand) { c.State = "" }, appoidc.ErrInvalidRequest},
		"no nonce":               {func(c *appoidc.AuthorizeCommand) { c.Nonce = "" }, appoidc.ErrInvalidRequest},
		"no PKCE":                {func(c *appoidc.AuthorizeCommand) { c.CodeChallenge, c.CodeChallengeMethod = "", "" }, appoidc.ErrInvalidRequest},
		"plain PKCE":             {func(c *appoidc.AuthorizeCommand) { c.CodeChallengeMethod = "plain" }, appoidc.ErrInvalidRequest},
		"a short challenge":      {func(c *appoidc.AuthorizeCommand) { c.CodeChallenge = "abc" }, appoidc.ErrInvalidRequest},
		"a repeated parameter":   {func(c *appoidc.AuthorizeCommand) { c.Repeated = true }, appoidc.ErrInvalidRequest},
		"no openid scope":        {func(c *appoidc.AuthorizeCommand) { c.Scope = "email" }, appoidc.ErrInvalidScope},
		"an unknown scope":       {func(c *appoidc.AuthorizeCommand) { c.Scope = "openid admin" }, appoidc.ErrInvalidScope},
		"offline access":         {func(c *appoidc.AuthorizeCommand) { c.Scope = "openid offline_access" }, appoidc.ErrInvalidScope},
		"a repeated scope":       {func(c *appoidc.AuthorizeCommand) { c.Scope = "openid openid" }, appoidc.ErrInvalidScope},
		"a bad max_age":          {func(c *appoidc.AuthorizeCommand) { c.MaxAge = "-1" }, appoidc.ErrInvalidRequest},
		"a bad prompt":           {func(c *appoidc.AuthorizeCommand) { c.Prompt = "sudo" }, appoidc.ErrInvalidRequest},
		"none with login":        {func(c *appoidc.AuthorizeCommand) { c.Prompt = "none login" }, appoidc.ErrInvalidRequest},
		"a repeated prompt":      {func(c *appoidc.AuthorizeCommand) { c.Prompt = "login login" }, appoidc.ErrInvalidRequest},
		"select_account":         {func(c *appoidc.AuthorizeCommand) { c.Prompt = "select_account" }, appoidc.ErrAccountSelection},
		"consent asked again":    {func(c *appoidc.AuthorizeCommand) { c.Prompt = "consent" }, appoidc.ErrConsentRequired},
		"none without a session": {func(c *appoidc.AuthorizeCommand) { c.Prompt = "none" }, appoidc.ErrLoginRequired},
	}
	for name, tc := range back {
		cmd := f.command("")
		tc.mutate(&cmd)

		got := e.authorizeWith(cmd)
		if got.Kind != appoidc.AuthorizeRedirect {
			t.Errorf("%s: %+v, want a redirect with an error", name, got)
			continue
		}

		q := e.query(got.Location, appCallback)
		if q.Get("error") != tc.code || q.Get("iss") != issuer || q.Get("code") != "" {
			t.Errorf("%s: redirect %q, want error %s and the issuer, and no code", name, got.Location, tc.code)
		}

		if cmd.State != "" && q.Get("state") != cmd.State {
			t.Errorf("%s: the state was not returned unchanged", name)
		}
	}

	// A scope the client was not registered for is refused even though the provider offers it.
	narrow := e.register("narrow-app", appTwo, "openid")
	nf := e.newFlow(narrow)

	got := e.authorizeWith(nf.command(""))
	if q := e.query(got.Location, appTwo); q.Get("error") != appoidc.ErrInvalidScope {
		t.Errorf("a scope the client may not ask for: %q", got.Location)
	}
}

func TestPromptsAndMaxAgeDecideWhetherTheSharedSignInIsEnough(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	_, sso := e.signedIn(e.newFlow(app), alice)

	// Later, with the cookie.
	e.clock.Advance(10 * time.Minute)

	ask := func(mutate func(c *appoidc.AuthorizeCommand)) appoidc.AuthorizeResult {
		f := e.newFlow(app)
		cmd := f.command(sso)
		mutate(&cmd)

		return e.authorizeWith(cmd)
	}
	if got := ask(func(*appoidc.AuthorizeCommand) {}); got.Kind != appoidc.AuthorizeRedirect || !strings.Contains(got.Location, "code=") {
		t.Errorf("plain request = %+v, want a code", got)
	}

	if got := ask(func(c *appoidc.AuthorizeCommand) { c.Prompt = "none" }); got.Kind != appoidc.AuthorizeRedirect || !strings.Contains(got.Location, "code=") {
		t.Errorf("prompt=none with a session = %+v, want a code and no screen", got)
	}

	if got := ask(func(c *appoidc.AuthorizeCommand) { c.Prompt = "login" }); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("prompt=login = %+v, want a fresh sign-in", got)
	}

	if got := ask(func(c *appoidc.AuthorizeCommand) { c.MaxAge = "0" }); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("max_age=0 = %+v, want a fresh sign-in", got)
	}

	if got := ask(func(c *appoidc.AuthorizeCommand) { c.MaxAge = "3600" }); got.Kind != appoidc.AuthorizeRedirect {
		t.Errorf("max_age above the age of the sign-in = %+v, want a code", got)
	}
	// The age of the authentication counts, not the time since the last use: 10 minutes ago is older than 5.
	if got := ask(func(c *appoidc.AuthorizeCommand) { c.MaxAge = "300" }); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("max_age=300 after 10 minutes = %+v, want a fresh sign-in", got)
	}
	// prompt=none must not show a screen even when one is needed.
	if got := ask(func(c *appoidc.AuthorizeCommand) { c.Prompt = "none"; c.MaxAge = "300" }); got.Kind != appoidc.AuthorizeRedirect ||
		!strings.Contains(got.Location, "error=login_required") {
		t.Errorf("prompt=none with a too old sign-in = %+v, want login_required", got)
	}
}

func TestTheSharedSignInEndsWhenItIsTooOldOrIdle(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	_, sso := e.signedIn(e.newFlow(app), alice)
	policy := doidc.DefaultPolicy()

	e.clock.Advance(policy.OPSessionIdle + time.Minute)

	if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("after the idle time = %+v, want a sign-in", got)
	}

	// Keep it in use through the idle time: it still ends at its absolute time.
	_, sso = e.signedIn(e.newFlow(app), alice)
	for elapsed := time.Duration(0); elapsed < policy.OPSessionAbsolute; elapsed += 12 * time.Hour {
		e.clock.Advance(12 * time.Hour)

		if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind == appoidc.AuthorizeLogin {
			if elapsed+12*time.Hour < policy.OPSessionAbsolute {
				t.Fatalf("the sign-in ended after %v, before its absolute time", elapsed+12*time.Hour)
			}

			return
		}
	}

	e.clock.Advance(time.Hour)

	if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("past the absolute time = %+v, want a sign-in however recently it was used", got)
	}
}

func TestACodeIsOneTimeAndTiedToItsClientRedirectAndVerifier(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	other := e.register("other-app", appTwo, "openid")
	alice := e.newPerson()

	t.Run("a wrong verifier spends the code", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		bad := f

		bad.verifier, _, _ = e.secrets.NewOIDCSecret()
		if got := e.exchange(bad, code); got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidGrant {
			t.Errorf("wrong verifier = %+v", got)
		}

		if got := e.exchange(f, code); got.Response != nil {
			t.Error("a code that was presented with a wrong verifier still worked")
		}
	})

	t.Run("no verifier, and a plain challenge used as a verifier", func(t *testing.T) {
		f := e.newFlow(app)

		code, _ := e.signedIn(f, alice)
		for name, verifier := range map[string]string{"empty": "", "the challenge itself": doidc.Challenge(f.verifier), "short": "abc"} {
			bad := f

			bad.verifier = verifier
			if got := e.exchange(bad, code); got.Response != nil {
				t.Errorf("%s: the exchange worked", name)
			}

			code, _ = e.signedIn(f, alice) // the previous one is spent
		}
	})

	t.Run("another redirect URI", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
			ClientID: app.id, ClientSecret: app.secret, GrantType: "authorization_code", Code: code,
			RedirectURI: appTwo, CodeVerifier: f.verifier,
		})
		must(t, err)

		if got.Response != nil || got.Failure.Code != appoidc.ErrInvalidGrant {
			t.Errorf("another redirect = %+v", got)
		}
	})

	t.Run("a code of another client changes nothing", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		stolen := f

		stolen.client = other
		if got := e.exchange(stolen, code); got.Response != nil {
			t.Fatal("another client exchanged a code that was not its own")
		}
		// The honest client still can: the attempt neither spent the code nor closed the grant.
		if got := e.exchange(f, code); got.Response == nil {
			t.Errorf("the owner can no longer exchange its code: %+v", got.Failure)
		}
	})

	t.Run("an expired code", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		e.clock.Advance(doidc.DefaultPolicy().CodeTTL + time.Second)

		if got := e.exchange(f, code); got.Response != nil {
			t.Error("an expired code was exchanged")
		}
	})

	t.Run("a made-up code", func(t *testing.T) {
		f := e.newFlow(app)

		fake, _, _ := e.secrets.NewOIDCSecret()
		if got := e.exchange(f, fake); got.Response != nil || got.Failure.Code != appoidc.ErrInvalidGrant {
			t.Errorf("made-up code = %+v", got)
		}

		if got := e.exchange(f, "not-a-secret"); got.Response != nil {
			t.Error("a malformed code was exchanged")
		}
	})
}

func TestClientAuthentication(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	f := e.newFlow(app)
	code, _ := e.signedIn(f, alice)

	for name, mutate := range map[string]func(c *client){
		"no secret":     func(c *client) { c.secret = "" },
		"a wrong one":   func(c *client) { c.secret, _, _ = e.secrets.NewOIDCSecret() },
		"a short one":   func(c *client) { c.secret = "abc" },
		"an unknown id": func(c *client) { c.id = "nobody" },
	} {
		bad := f
		mutate(&bad.client)

		if got := e.exchange(bad, code); got.Response != nil || got.Failure.Code != appoidc.ErrInvalidClient {
			t.Errorf("%s: %+v, want invalid_client", name, got)
		}
	}
	// None of that spent the code.
	if got := e.exchange(f, code); got.Response == nil {
		t.Errorf("the code was spent by requests that did not even authenticate: %+v", got.Failure)
	}

	// A disabled client cannot authenticate, and its tokens die with it.
	f2 := e.newFlow(app)
	tokens, _ := e.tokens(f2, alice)
	must(t, e.clients.SetActive(context.Background(), app.id, false))

	if got := e.refresh(app, tokens.RefreshToken); got.Response != nil || got.Failure.Code != appoidc.ErrInvalidClient {
		t.Errorf("disabled client refreshes = %+v", got)
	}

	if info, _ := e.userinfo.Execute(context.Background(), tokens.AccessToken); info.Claims != nil {
		t.Error("the access token of a disabled client still works")
	}

	if got := e.authorizeWith(e.newFlow(app).command("")); got.Kind != appoidc.AuthorizeFailure {
		t.Errorf("authorize for a disabled client = %+v", got)
	}

	must(t, e.clients.SetActive(context.Background(), app.id, true))

	if got := e.refresh(app, tokens.RefreshToken); got.Response != nil {
		t.Error("enabling the client again revived a grant that was revoked")
	}
}

func TestOnlyFirstPartyClientsCanBeRegistered(t *testing.T) {
	e := newEnv(t)
	for name, cmd := range map[string]appoidc.RegisterCommand{
		"http outside localhost": {ID: "app-one", Name: "x", RedirectURIs: []string{"http://app.example.test/cb"}},
		"a wildcard":             {ID: "app-one", Name: "x", RedirectURIs: []string{"https://*.example.test/cb"}},
		"a fragment":             {ID: "app-one", Name: "x", RedirectURIs: []string{"https://app.example.test/cb#x"}},
		"credentials":            {ID: "app-one", Name: "x", RedirectURIs: []string{"https://u:p@app.example.test/cb"}},
		"no redirect":            {ID: "app-one", Name: "x"},
		"a bad id":               {ID: "App One", Name: "x", RedirectURIs: []string{"https://app.example.test/cb"}},
		"no name":                {ID: "app-one", RedirectURIs: []string{"https://app.example.test/cb"}},
		"an unknown scope":       {ID: "app-one", Name: "x", RedirectURIs: []string{"https://app.example.test/cb"}, AllowedScopes: []string{"openid", "admin"}},
		"no openid":              {ID: "app-one", Name: "x", RedirectURIs: []string{"https://app.example.test/cb"}, AllowedScopes: []string{"email"}},
	} {
		if _, err := e.clients.Register(context.Background(), cmd); err == nil {
			t.Errorf("%s: the registration was accepted", name)
		}
	}

	if _, err := e.clients.Register(context.Background(), appoidc.RegisterCommand{ID: "dev-app", Name: "x", RedirectURIs: []string{"http://localhost:3000/cb"}}); err != nil {
		t.Errorf("a localhost development client: %v", err)
	}

	e.register("taken-id", appCallback, "openid")

	if _, err := e.clients.Register(context.Background(), appoidc.RegisterCommand{ID: "taken-id", Name: "x", RedirectURIs: []string{appCallback}}); err == nil {
		t.Error("a client ID was registered twice")
	}
}

func TestRotatingASecretKeepsTheOldOneForTheOverlapOnly(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	next, err := e.clients.RotateSecret(context.Background(), app.id, time.Hour)
	must(t, err)

	useSecret := func(secret string) bool {
		c := app
		c.secret = secret
		f := e.newFlow(c)
		code, _ := e.signedIn(f, alice)

		return e.exchange(f, code).Response != nil
	}
	if !useSecret(app.secret) || !useSecret(next) {
		t.Fatal("during the overlap both secrets should work")
	}

	e.clock.Advance(time.Hour + time.Minute)

	if useSecret(app.secret) {
		t.Error("the old secret works after the overlap")
	}

	if !useSecret(next) {
		t.Error("the new secret stopped working")
	}
	// A second rotation retires the leftovers of the first at once.
	third, err := e.clients.RotateSecret(context.Background(), app.id, time.Hour)
	must(t, err)

	if !useSecret(next) || !useSecret(third) {
		t.Error("the previous and the new secret should both work during the second overlap")
	}
}

func TestCompleteLoginRefusals(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice, mallory := e.newPerson(), e.newPerson()
	f := e.newFlow(app)

	begin := func() appoidc.AuthorizeResult {
		asked := e.authorizeWith(f.command(""))
		if asked.Kind != appoidc.AuthorizeLogin {
			t.Fatalf("authorize = %+v", asked)
		}

		return asked
	}
	complete := func(a appoidc.AuthorizeResult, mutate func(c *appoidc.CompleteLoginCommand)) appoidc.CompleteLoginResult {
		cmd := appoidc.CompleteLoginCommand{RequestSecret: a.RequestID, BindingSecret: a.BindingSecret, AccessToken: e.signIn(alice)}
		mutate(&cmd)
		got, err := e.login.Execute(context.Background(), cmd)
		must(t, err)

		return got
	}
	refused := func(name string, got appoidc.CompleteLoginResult) {
		t.Helper()

		if got.Failure == nil || got.SSOSecret != "" || got.Location != "" {
			t.Errorf("%s: %+v, want a refusal that opens nothing", name, got)
		}
	}

	a := begin()
	other, _, _ := e.secrets.NewOIDCSecret()

	refused("another browser", complete(a, func(c *appoidc.CompleteLoginCommand) { c.BindingSecret = other }))
	refused("no binding", complete(a, func(c *appoidc.CompleteLoginCommand) { c.BindingSecret = "" }))
	refused("another request id", complete(a, func(c *appoidc.CompleteLoginCommand) { c.RequestSecret = other }))
	refused("a forged token", complete(a, func(c *appoidc.CompleteLoginCommand) { c.AccessToken = "a.b.c" }))
	refused("no token", complete(a, func(c *appoidc.CompleteLoginCommand) { c.AccessToken = "" }))

	// A token of a session that was ended is not proof, even before the token expires.
	revoked := e.signIn(alice)
	e.do(func(ctx context.Context, st port.Stores) error {
		return st.Sessions.RevokeAllForUser(ctx, alice.user.ID(), e.clock.Now())
	})
	refused("a revoked session", complete(a, func(c *appoidc.CompleteLoginCommand) { c.AccessToken = revoked }))

	// The request survived all that and still works, once.
	if got := complete(a, func(c *appoidc.CompleteLoginCommand) {}); got.Failure != nil || got.SSOSecret == "" {
		t.Fatalf("the genuine completion = %+v", got)
	}

	refused("a second completion", complete(a, func(c *appoidc.CompleteLoginCommand) {}))

	// It expires.
	b := begin()

	e.clock.Advance(doidc.DefaultPolicy().RequestTTL + time.Second)
	refused("an expired request", complete(b, func(c *appoidc.CompleteLoginCommand) { c.AccessToken = e.signIn(mallory) }))

	// A blocked user is sent back with access_denied and gets no sign-in.
	c := begin()

	e.do(func(ctx context.Context, st port.Stores) error {
		u, err := st.Users.GetForUpdate(ctx, alice.user.ID())
		if err != nil {
			return err
		}

		if err := u.Block(e.clock.Now()); err != nil {
			return err
		}

		return st.Users.SetBlocked(ctx, u)
	})

	got := complete(c, func(c *appoidc.CompleteLoginCommand) {})
	if got.SSOSecret != "" || !strings.Contains(got.Location, "error=access_denied") {
		t.Errorf("a blocked user = %+v", got)
	}
}

func TestAFreshLoginIsRequiredWhenAsked(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	old := e.signIn(alice) // proved at t0

	e.clock.Advance(time.Minute)
	f := e.newFlow(app)
	cmd := f.command("")
	cmd.Prompt = "login"
	asked := e.authorizeWith(cmd)
	got, err := e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: old})
	must(t, err)

	if got.Failure == nil || got.Failure.Code != appoidc.ErrLoginRequired || got.SSOSecret != "" {
		t.Errorf("a proof from before the request, for prompt=login = %+v", got)
	}
	// The same request with a proof made after it is accepted.
	got, err = e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: e.signIn(alice)})
	must(t, err)

	if got.Failure != nil || got.SSOSecret == "" {
		t.Errorf("a fresh proof = %+v", got)
	}
}
