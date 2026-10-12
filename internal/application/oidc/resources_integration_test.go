//go:build integration

package oidc_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	doidc "airlance.org/auth/internal/domain/oidc"
)

const (
	platformURI = "https://api.example.test/platform"
	videoURI    = "https://video.example.test/"
	callURI     = "https://calls.example.test/"
)

// registerResource registers an API; the audience is the identifier unless the test says otherwise.
func (e *env) registerResource(id, uri string, scopes ...string) *doidc.Resource {
	e.t.Helper()
	res, err := e.resources.Register(context.Background(), appoidc.RegisterResourceCommand{ID: id, Name: id, URI: uri, Audience: id, Scopes: scopes})
	must(e.t, err)
	return res
}

func (e *env) allow(c client, resourceID string, scopes ...string) int {
	e.t.Helper()
	n, err := e.resources.Allow(context.Background(), c.id, resourceID, scopes)
	must(e.t, err)
	return n
}

// exchangeFor exchanges a code for the token of one resource.
func (e *env) exchangeFor(f flow, code, resource, scope string) appoidc.TokenResult {
	e.t.Helper()
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: f.client.id, ClientSecret: f.client.secret, GrantType: "authorization_code", Code: code,
		RedirectURI: f.client.redirect, CodeVerifier: f.verifier, Resource: resource, Scope: scope,
	})
	must(e.t, err)
	return got
}

func (e *env) refreshFor(c client, refreshToken, resource, scope string) appoidc.TokenResult {
	e.t.Helper()
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: c.id, ClientSecret: c.secret, GrantType: "refresh_token", RefreshToken: refreshToken, Resource: resource, Scope: scope,
	})
	must(e.t, err)
	return got
}

func wantFailure(t *testing.T, name string, got appoidc.TokenResult, code string) {
	t.Helper()
	if got.Response != nil || got.Failure == nil || got.Failure.Code != code {
		t.Errorf("%s: response %+v, failure %+v, want %s", name, got.Response, got.Failure, code)
	}
}

func (e *env) accessFor(token, audience string) (port.OIDCAccessClaims, error) {
	return e.signer.VerifyOIDCAccess(token, audience)
}

// resourceSetup is the usual world of these tests: a product API with two rights groups, a separate video API, and an
// application allowed some of each.
type resourceSetup struct {
	e     *env
	app   client
	alice person
}

func newResourceSetup(t *testing.T) resourceSetup {
	t.Helper()
	e := newEnv(t)
	e.registerResource("platform-api", platformURI, "messages:read", "messages:send", "video:read", "video:upload")
	e.registerResource("video-api", videoURI, "video:read", "video:upload")
	e.registerResource("calls-api", callURI, "calls:join")
	app := e.registerWithLogout("panels-web", appCallback, "", appBackchannel)
	e.allow(app, "platform-api", "messages:read", "messages:send")
	e.allow(app, "video-api", "video:read", "video:upload")
	return resourceSetup{e: e, app: app, alice: e.newPerson()}
}

func TestOneSignInTwoSeparateAPIsGetTwoSeparateTokens(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid email messages:send video:read", []string{platformURI, videoURI}

	// One sign-in, one code, one grant.
	code, sso := e.signedIn(f, s.alice)
	first := e.exchangeFor(f, code, platformURI, "")
	if first.Response == nil {
		t.Fatalf("exchange = %+v", first.Failure)
	}
	if first.Response.IDToken == "" || first.Response.Scope != "messages:send" {
		t.Errorf("the first token response = %+v, want an ID token and only the right of the first API", first.Response)
	}
	claims, err := e.accessFor(first.Response.AccessToken, "platform-api")
	if err != nil || claims.Subject != s.alice.user.ID() || claims.ClientID != "panels-web" || strings.Join(claims.Scope, " ") != "messages:send" {
		t.Fatalf("the platform token = %+v, %v", claims, err)
	}

	// The second API's token comes from the refresh token, with its own audience and its own rights.
	second := e.refreshFor(s.app, first.Response.RefreshToken, videoURI, "")
	if second.Response == nil {
		t.Fatalf("refresh = %+v", second.Failure)
	}
	videoClaims, err := e.accessFor(second.Response.AccessToken, "video-api")
	if err != nil || strings.Join(videoClaims.Scope, " ") != "video:read" || second.Response.Scope != "video:read" || videoClaims.GrantID != claims.GrantID {
		t.Fatalf("the video token = %+v, %v", videoClaims, err)
	}
	if second.Response.RefreshToken == first.Response.RefreshToken {
		t.Error("the refresh token was not rotated")
	}

	// A token is for one API: the other API refuses it, whoever the user is, however valid the signature.
	if _, err := e.accessFor(first.Response.AccessToken, "video-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("the platform token was accepted by the video API: %v", err)
	}
	if _, err := e.accessFor(second.Response.AccessToken, "platform-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("the video token was accepted by the platform API: %v", err)
	}
	// Nor does UserInfo take a token of an API as its own.
	for _, token := range []string{first.Response.AccessToken, second.Response.AccessToken} {
		if info, err := e.userinfo.Execute(context.Background(), token); err != nil || info.Claims != nil {
			t.Errorf("userinfo took the token of an API: %+v, %v", info, err)
		}
	}
	// Without a resource the answer is what it always was: a token for UserInfo with the protocol scopes.
	plain := e.refreshFor(s.app, second.Response.RefreshToken, "", "")
	if plain.Response == nil || plain.Response.Scope != "openid email" {
		t.Fatalf("refresh without a resource = %+v, %+v", plain.Response, plain.Failure)
	}
	if info, err := e.userinfo.Execute(context.Background(), plain.Response.AccessToken); err != nil || info.Claims == nil || info.Claims.Subject != s.alice.user.ID().String() {
		t.Errorf("userinfo = %+v, %v", info, err)
	}
	// The person stays signed in for everything else.
	if e.opSessionOf(sso) == nil {
		t.Error("the shared sign-in was lost")
	}
}

func TestOneSharedAPIKeepsOneAudienceAndEveryScopeApart(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	e.allow(s.app, "platform-api", "messages:read", "messages:send", "video:read", "video:upload")
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid messages:read messages:send video:read video:upload", []string{platformURI}
	code, _ := e.signedIn(f, s.alice)
	got := e.exchangeFor(f, code, platformURI, "")
	if got.Response == nil || got.Response.Scope != "messages:read messages:send video:read video:upload" {
		t.Fatalf("exchange = %+v, %+v", got.Response, got.Failure)
	}
	claims, err := e.accessFor(got.Response.AccessToken, "platform-api")
	if err != nil || len(claims.Scope) != 4 {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	// The scope claim is a list: each right is a whole element, so a longer scope is not a shorter one.
	have := func(scope string) bool {
		for _, s := range claims.Scope {
			if s == scope {
				return true
			}
		}
		return false
	}
	if !have("messages:send") || have("messages") || have("messages:send:any") || have("send") {
		t.Errorf("scope = %v", claims.Scope)
	}
	// A refresh may narrow what a token carries, never widen it.
	narrow := e.refreshFor(s.app, got.Response.RefreshToken, platformURI, "video:read")
	if narrow.Response == nil || narrow.Response.Scope != "video:read" {
		t.Fatalf("narrowing = %+v, %+v", narrow.Response, narrow.Failure)
	}
	wantFailure(t, "a scope the grant does not hold", e.refreshFor(s.app, narrow.Response.RefreshToken, platformURI, "calls:join"), appoidc.ErrInvalidScope)
}

func TestEveryRefusalOfAResourceRequest(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	// calls-api exists but this client was never allowed it; "dormant-api" is disabled.
	e.registerResource("dormant-api", "https://dormant.example.test/", "dormant:read")
	e.allow(s.app, "dormant-api", "dormant:read")
	if _, err := e.resources.SetActive(context.Background(), "dormant-api", false); err != nil {
		t.Fatal(err)
	}
	f := e.newFlow(s.app)

	back := map[string]struct {
		scope     string
		resources []string
		code      string
	}{
		"an unknown resource":                  {"openid messages:send", []string{"https://nobody.example.test/"}, appoidc.ErrInvalidTarget},
		"a disabled resource":                  {"openid dormant:read", []string{"https://dormant.example.test/"}, appoidc.ErrInvalidTarget},
		"a resource the client was not given":  {"openid calls:join", []string{callURI}, appoidc.ErrInvalidTarget},
		"a resource that is not a URI":         {"openid messages:send", []string{"platform-api"}, appoidc.ErrInvalidTarget},
		"a resource with a query":              {"openid messages:send", []string{platformURI + "?x=1"}, appoidc.ErrInvalidTarget},
		"the same resource twice":              {"openid messages:send", []string{platformURI, platformURI}, appoidc.ErrInvalidTarget},
		"a scope the client was not allowed":   {"openid video:read", []string{platformURI}, appoidc.ErrInvalidScope},
		"a scope of another resource":          {"openid messages:send video:upload", []string{platformURI, callURI}, appoidc.ErrInvalidTarget},
		"a scope no resource asked defines":    {"openid messages:send calls:join", []string{platformURI}, appoidc.ErrInvalidScope},
		"a right with no resource":             {"openid messages:send", nil, appoidc.ErrInvalidScope},
		"a resource with no right":             {"openid", []string{platformURI}, appoidc.ErrInvalidScope},
		"a resource with only protocol scopes": {"openid email", []string{platformURI}, appoidc.ErrInvalidScope},
		"a comma-separated list":               {"openid messages:read,messages:send", []string{platformURI}, appoidc.ErrInvalidScope},
		"another case":                         {"openid Messages:Send", []string{platformURI}, appoidc.ErrInvalidScope},
		"a longer scope":                       {"openid messages:send:any", []string{platformURI}, appoidc.ErrInvalidScope},
		"a repeated scope":                     {"openid messages:send messages:send", []string{platformURI}, appoidc.ErrInvalidScope},
	}
	for name, tc := range back {
		cmd := f.command("")
		cmd.Scope, cmd.Resources = tc.scope, tc.resources
		got := e.authorizeWith(cmd)
		if got.Kind != appoidc.AuthorizeRedirect {
			t.Errorf("%s: %+v, want a redirect with an error", name, got)
			continue
		}
		q := e.query(got.Location, appCallback)
		if q.Get("error") != tc.code || q.Get("code") != "" || q.Get("iss") != issuer {
			t.Errorf("%s: redirect %q, want error %s and no code", name, got.Location, tc.code)
		}
	}
	// None of them left a grant or a request behind.
	e.do(func(ctx context.Context, st port.Stores) error {
		apps, err := st.OIDCApps.LiveGrantsOfUser(ctx, s.alice.user.ID(), e.clock.Now())
		if err != nil || len(apps) != 0 {
			t.Errorf("grants = %v, %v", apps, err)
		}
		return nil
	})
}

func TestARefusalOnTheTokenEndpointNeverSpendsTheCode(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid messages:send video:read", []string{platformURI, videoURI}
	code, _ := e.signedIn(f, s.alice)

	wantFailure(t, "an unknown resource", e.exchangeFor(f, code, "https://nobody.example.test/", ""), appoidc.ErrInvalidTarget)
	wantFailure(t, "a malformed resource", e.exchangeFor(f, code, "platform-api", ""), appoidc.ErrInvalidTarget)
	wantFailure(t, "a resource that was not asked for", e.exchangeFor(f, code, callURI, ""), appoidc.ErrInvalidTarget)
	wantFailure(t, "a scope of another API", e.exchangeFor(f, code, platformURI, "video:read"), appoidc.ErrInvalidScope)
	wantFailure(t, "a protocol scope for an API", e.exchangeFor(f, code, platformURI, "openid"), appoidc.ErrInvalidScope)
	// The code is still good, for the right request.
	if got := e.exchangeFor(f, code, videoURI, ""); got.Response == nil || got.Response.Scope != "video:read" {
		t.Fatalf("the code did not survive the refusals: %+v, %+v", got.Response, got.Failure)
	}
}

func TestARefreshCannotWidenTheGrant(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid messages:send", []string{platformURI}
	got, _ := e.tokens(f, s.alice)

	// Another resource, more rights of the same one: both need a new authorization, even though the client may ask for them.
	wantFailure(t, "a resource that was not agreed", e.refreshFor(s.app, got.RefreshToken, videoURI, ""), appoidc.ErrInvalidTarget)
	wantFailure(t, "a right that was not agreed", e.refreshFor(s.app, got.RefreshToken, platformURI, "messages:read"), appoidc.ErrInvalidScope)
	wantFailure(t, "a protocol scope", e.refreshFor(s.app, got.RefreshToken, "", "openid messages:send"), appoidc.ErrInvalidScope)
	wantFailure(t, "an API scope without a resource", e.refreshFor(s.app, got.RefreshToken, "", "messages:send"), appoidc.ErrInvalidScope)
	// None of that used the refresh token up.
	if next := e.refreshFor(s.app, got.RefreshToken, platformURI, ""); next.Response == nil || next.Response.Scope != "messages:send" {
		t.Fatalf("the refresh token was spent by a refusal: %+v, %+v", next.Response, next.Failure)
	}
}

func TestAClientWithoutAResourceKeepsTheOldContract(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	got, _ := e.tokens(e.newFlow(app), alice)
	if got.Scope != "openid email" || got.IDToken == "" {
		t.Fatalf("response = %+v", got)
	}
	claims, err := e.accessFor(got.AccessToken, issuer+"/oauth2/userinfo")
	if err != nil || strings.Join(claims.Scope, " ") != "openid email" {
		t.Fatalf("access token = %+v, %v", claims, err)
	}
	// A resource asked at the token endpoint of a flow that never named one is refused.
	wantFailure(t, "a resource that was never agreed", e.refreshFor(app, got.RefreshToken, platformURI, ""), appoidc.ErrInvalidTarget)
}

func TestRegisteringAResourceRefusesCollisions(t *testing.T) {
	e := newEnv(t)
	e.registerResource("platform-api", platformURI, "messages:send")
	e.register("panels-web", appCallback, "openid", "email")
	ctx := context.Background()
	for name, cmd := range map[string]appoidc.RegisterResourceCommand{
		"the same id":                {ID: "platform-api", Name: "x", URI: "https://other.example.test/", Audience: "other-api", Scopes: []string{"a:b"}},
		"the same uri":               {ID: "other-api", Name: "x", URI: platformURI, Audience: "other-api", Scopes: []string{"a:b"}},
		"the same audience":          {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: "platform-api", Scopes: []string{"a:b"}},
		"a client id as audience":    {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: "panels-web", Scopes: []string{"a:b"}},
		"the issuer as audience":     {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: issuer, Scopes: []string{"a:b"}},
		"the userinfo as audience":   {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: issuer + "/oauth2/userinfo", Scopes: []string{"a:b"}},
		"a protocol scope":           {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: "other-api", Scopes: []string{"openid"}},
		"an audience with a space":   {ID: "other-api", Name: "x", URI: "https://other.example.test/", Audience: "other api", Scopes: []string{"a:b"}},
		"a resource uri with a hash": {ID: "other-api", Name: "x", URI: "https://other.example.test/#a", Audience: "other-api", Scopes: []string{"a:b"}},
	} {
		if _, err := e.resources.Register(ctx, cmd); err == nil {
			t.Errorf("%s was registered", name)
		}
	}
	// And a client cannot take the audience of a resource as its identifier.
	if _, err := e.clients.Register(ctx, appoidc.RegisterCommand{ID: "platform-api", Name: "x", RedirectURIs: []string{appCallback}}); err == nil {
		t.Error("a client took the audience of a resource")
	}
	// The catalog is only for scopes the resource defines.
	if _, err := e.resources.Allow(ctx, "panels-web", "platform-api", []string{"video:read"}); !errors.Is(err, doidc.ErrInvalidScope) {
		t.Errorf("allowing a scope the resource does not define: %v", err)
	}
	if _, err := e.resources.Allow(ctx, "nobody", "platform-api", []string{"messages:send"}); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("allowing an unknown client: %v", err)
	}
	if _, err := e.resources.Allow(ctx, "panels-web", "nothing-api", []string{"messages:send"}); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("allowing an unknown resource: %v", err)
	}
}

// grantOfBoth makes a grant holding both APIs and returns the refresh token and the flow.
func (s resourceSetup) grantOfBoth(p person) (flow, *appoidc.TokenResponse, string) {
	s.e.t.Helper()
	f := s.e.newFlow(s.app)
	f.scope, f.resources = "openid messages:send video:read", []string{platformURI, videoURI}
	code, sso := s.e.signedIn(f, p)
	got := s.e.exchangeFor(f, code, platformURI, "")
	if got.Response == nil {
		s.e.t.Fatalf("exchange = %+v", got.Failure)
	}
	return f, got.Response, sso
}

func TestTakingARightAwayEndsTheGrantsThatHoldIt(t *testing.T) {
	type change struct {
		apply func(e *env, app client) (ended int)
		// asking for the changed API afterwards: a disabled resource is refused as a target before the grant is looked at.
		forChanged string
	}
	cases := map[string]change{
		"the client's right is narrowed": {func(e *env, app client) int { return e.allow(app, "platform-api", "messages:read") }, appoidc.ErrInvalidGrant},
		"the client loses the resource": {func(e *env, app client) int {
			n, err := e.resources.Deny(context.Background(), app.id, "platform-api")
			must(e.t, err)
			return n
		}, appoidc.ErrInvalidGrant},
		"the resource is disabled": {func(e *env, app client) int {
			n, err := e.resources.SetActive(context.Background(), "platform-api", false)
			must(e.t, err)
			return n
		}, appoidc.ErrInvalidTarget},
		"the resource drops the scope": {func(e *env, app client) int {
			n, err := e.resources.SetScopes(context.Background(), "platform-api", []string{"messages:read", "video:read", "video:upload"})
			must(e.t, err)
			return n
		}, appoidc.ErrInvalidGrant},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := newResourceSetup(t)
			e := s.e
			bob := e.newPerson()
			_, held, sso := s.grantOfBoth(s.alice)
			_, other, _ := s.grantOfBoth(bob)
			// A grant that holds only the other API is not touched.
			vf := e.newFlow(s.app)
			vf.scope, vf.resources = "openid video:read", []string{videoURI}
			videoOnly, _ := e.tokens(vf, e.newPerson())
			e.queued() // drain

			if ended := change.apply(e, s.app); ended != 2 {
				t.Fatalf("%d grants ended, want the two that hold the resource", ended)
			}
			// Their refresh tokens are dead, for either API, and the clients were told.
			for _, token := range []string{held.RefreshToken, other.RefreshToken} {
				wantFailure(t, "a refresh after the change", e.refreshFor(s.app, token, videoURI, ""), appoidc.ErrInvalidGrant)
				wantFailure(t, "a refresh for the changed API", e.refreshFor(s.app, token, platformURI, ""), change.forChanged)
			}
			if n := e.queued()["panels-web"]; n != 2 {
				t.Errorf("%d logout notices queued, want one for each grant that ended", n)
			}
			// The other grant, and the shared sign-in, live on.
			if got := e.refreshFor(s.app, videoOnly.RefreshToken, videoURI, ""); got.Response == nil {
				t.Errorf("a grant that did not hold the resource was ended: %+v", got.Failure)
			}
			if e.opSessionOf(sso) == nil || !e.opSessionOf(sso).Active(e.clock.Now(), doidc.DefaultPolicy()) {
				t.Error("the shared sign-in was ended")
			}
		})
	}
}

func TestGivingARightNeverWidensAGrantThatExists(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid messages:send", []string{platformURI}
	got, sso := e.tokens(f, s.alice)

	// The right is given; the grant that exists is the same as before.
	if n := e.allow(s.app, "platform-api", "messages:read", "messages:send", "video:read"); n != 0 {
		t.Fatalf("widening ended %d grants", n)
	}
	wantFailure(t, "the new right on the old grant", e.refreshFor(s.app, got.RefreshToken, platformURI, "video:read"), appoidc.ErrInvalidScope)
	if still := e.refreshFor(s.app, got.RefreshToken, platformURI, ""); still.Response == nil || still.Response.Scope != "messages:send" {
		t.Fatalf("the old grant changed: %+v, %+v", still.Response, still.Failure)
	}

	// A new authorization that asks for the right gets a new grant, and the old one is replaced, not widened.
	again := e.newFlow(s.app)
	again.scope, again.resources = "openid messages:send video:read", []string{platformURI}
	res := e.authorizeWith(again.command(sso))
	if res.Kind != appoidc.AuthorizeRedirect {
		t.Fatalf("authorize = %+v", res)
	}
	fresh := e.exchangeFor(again, e.codeOf(again, res.Location), platformURI, "")
	if fresh.Response == nil || fresh.Response.Scope != "messages:send video:read" {
		t.Fatalf("the new grant = %+v, %+v", fresh.Response, fresh.Failure)
	}
	// A request the grant already covers uses it.
	narrower := e.newFlow(s.app)
	narrower.scope, narrower.resources = "openid video:read", []string{platformURI}
	res = e.authorizeWith(narrower.command(sso))
	cover := e.exchangeFor(narrower, e.codeOf(narrower, res.Location), platformURI, "")
	if cover.Response == nil || cover.Response.Scope != "video:read" {
		t.Fatalf("a narrower request = %+v, %+v", cover.Response, cover.Failure)
	}
	if got := e.refreshFor(s.app, fresh.Response.RefreshToken, platformURI, ""); got.Response == nil {
		t.Errorf("a covered request replaced the grant: %+v", got.Failure)
	}
}

func TestAReplayEndsTheGrantThatHoldsSeveralAPIs(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	_, first, _ := s.grantOfBoth(s.alice)
	second := e.refreshFor(s.app, first.RefreshToken, videoURI, "")
	if second.Response == nil {
		t.Fatalf("refresh = %+v", second.Failure)
	}
	// The first refresh token comes back, from a copy: the grant, with every API on it, ends.
	replay := e.refreshFor(s.app, first.RefreshToken, platformURI, "")
	wantFailure(t, "a replay", replay, appoidc.ErrInvalidGrant)
	if !replay.Replay {
		t.Error("the replay was not reported")
	}
	wantFailure(t, "the descendant of a replayed token", e.refreshFor(s.app, second.Response.RefreshToken, videoURI, ""), appoidc.ErrInvalidGrant)
	// Ending the resource's rights later, and enabling it again, brings nothing back.
	if _, err := e.resources.SetActive(context.Background(), "video-api", false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.resources.SetActive(context.Background(), "video-api", true); err != nil {
		t.Fatal(err)
	}
	wantFailure(t, "a revoked grant after the resource came back", e.refreshFor(s.app, second.Response.RefreshToken, videoURI, ""), appoidc.ErrInvalidGrant)
}

func TestAPersonTakesAnApplicationBack(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	other := e.registerWithLogout("other-app", appTwo, "", "https://other.example.test/backchannel")
	e.allow(other, "video-api", "video:read")
	bob := e.newPerson()
	ctx := context.Background()

	f, held, sso := s.grantOfBoth(s.alice)
	otherFlow := e.newFlow(other)
	otherFlow.scope, otherFlow.resources = "openid video:read", []string{videoURI}
	res := e.authorizeWith(otherFlow.command(sso))
	otherTokens := e.exchangeFor(otherFlow, e.codeOf(otherFlow, res.Location), videoURI, "")
	if otherTokens.Response == nil {
		t.Fatalf("the second application = %+v", otherTokens.Failure)
	}
	_, bobs, _ := s.grantOfBoth(bob)
	e.queued()

	listed, err := e.apps.List(ctx, s.alice.user.ID())
	must(t, err)
	if len(listed) != 2 || listed[0].ClientID != "other-app" || listed[1].ClientID != "panels-web" {
		t.Fatalf("the list = %+v, want the person's two applications by name", listed)
	}
	panels := listed[1]
	if len(panels.Resources) != 2 || panels.Resources[0].ID != "platform-api" || strings.Join(panels.Resources[0].Scopes, " ") != "messages:send" ||
		panels.Resources[1].ID != "video-api" || strings.Join(panels.Resources[1].Scopes, " ") != "video:read" || strings.Join(panels.Scopes, " ") != "openid" {
		t.Errorf("what the application holds = %+v", panels)
	}
	if panels.ExpiresAt.Before(panels.CreatedAt) || panels.LastUsedAt.IsZero() {
		t.Errorf("times = %+v", panels)
	}

	// A person cannot end a grant that is another's: the answer is the same as for one that does not exist.
	must(t, e.apps.RevokeGrant(ctx, bob.user.ID(), panels.ID))
	must(t, e.apps.RevokeGrant(ctx, bob.user.ID(), "not-an-id"))
	moved := e.refreshFor(s.app, held.RefreshToken, platformURI, "")
	if moved.Response == nil {
		t.Fatalf("another person ended the grant: %+v", moved.Failure)
	}
	e.queued() // the exchange above is not a notice, but be sure of a clean count

	// The owner ends one grant: that one only, its application is told, and the others carry on.
	must(t, e.apps.RevokeGrant(ctx, s.alice.user.ID(), panels.ID))
	wantFailure(t, "the revoked grant", e.refreshFor(s.app, moved.Response.RefreshToken, platformURI, ""), appoidc.ErrInvalidGrant)
	if got := e.refreshFor(other, otherTokens.Response.RefreshToken, videoURI, ""); got.Response == nil {
		t.Errorf("another application was ended: %+v", got.Failure)
	}
	bobsToken := bobs.RefreshToken
	if got := e.refreshFor(s.app, bobsToken, platformURI, ""); got.Response == nil {
		t.Errorf("another person's grant was ended: %+v", got.Failure)
	} else {
		bobsToken = got.Response.RefreshToken
	}
	if n := e.queued(); n["panels-web"] != 1 || n["other-app"] != 0 {
		t.Errorf("notices = %v, want one, for the application that was taken back", n)
	}
	if !e.opSessionOf(sso).Active(e.clock.Now(), doidc.DefaultPolicy()) {
		t.Error("taking an application back ended the person's sign-in")
	}
	// The sign-in is alive and the application is trusted: asking again gives a new grant, which is not a ban.
	again := e.newFlow(s.app)
	again.scope, again.resources = f.scope, f.resources
	if res := e.authorizeWith(again.command(sso)); res.Kind != appoidc.AuthorizeRedirect {
		t.Errorf("authorize = %+v", res)
	}

	// Taking back an application ends every grant of it, and no other.
	must(t, e.apps.RevokeClient(ctx, s.alice.user.ID(), "other-app"))
	wantFailure(t, "the application taken back", e.refreshFor(other, otherTokens.Response.RefreshToken, videoURI, ""), appoidc.ErrInvalidGrant)
	must(t, e.apps.RevokeClient(ctx, s.alice.user.ID(), "../x"))
	if got := e.refreshFor(s.app, bobsToken, videoURI, ""); got.Response == nil {
		t.Errorf("another person's grant was ended: %+v", got.Failure)
	}
	if left, err := e.apps.List(ctx, bob.user.ID()); err != nil || len(left) != 1 {
		t.Errorf("the other person's list = %+v, %v", left, err)
	}
}

// A token is being issued for a resource while its rights are taken away: whichever comes first, nothing is issued after the
// change has completed.
func TestIssuingWaitsForAChangeOfRights(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	_, held, _ := s.grantOfBoth(s.alice)

	started := make(chan struct{})
	release := make(chan struct{})
	changed := make(chan error, 1)
	go func() {
		// The administrator's transaction: it holds the resource exclusively, as the use case does, and takes its time.
		changed <- e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
			if _, err := st.OIDCResources.GetForUpdate(ctx, "platform-api"); err != nil {
				return err
			}
			close(started)
			<-release
			if err := st.OIDCResources.SetStatus(ctx, "platform-api", doidc.ResourceDisabled, e.clock.Now()); err != nil {
				return err
			}
			_, err := st.OIDCApps.RevokeOfResource(ctx, "platform-api", "", nil, e.clock.Now())
			return err
		})
	}()
	<-started

	var wg sync.WaitGroup
	done := make(chan appoidc.TokenResult, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		done <- e.refreshFor(s.app, held.RefreshToken, platformURI, "")
	}()
	select {
	case got := <-done:
		t.Fatalf("a token was issued while the rights were being changed: %+v, %+v", got.Response, got.Failure)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	must(t, <-changed)
	got := <-done
	wg.Wait()
	if got.Response != nil {
		t.Fatalf("a token was issued after the resource was disabled: %+v", got.Response)
	}
	if got.Failure == nil || (got.Failure.Code != appoidc.ErrInvalidTarget && got.Failure.Code != appoidc.ErrInvalidGrant) {
		t.Errorf("failure = %+v", got.Failure)
	}
}

// Many issuers and many changes at once finish, with no deadlock and no token that outlives a change that completed.
func TestIssuingAndChangingRightsTogetherDoNotDeadlock(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	const people = 6
	type holder struct {
		person person
		token  string
	}
	var holders []holder
	for range people {
		p := e.newPerson()
		_, got, _ := s.grantOfBoth(p)
		holders = append(holders, holder{p, got.RefreshToken})
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for _, h := range holders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := h.token
			for range 4 {
				got, err := e.token.Execute(ctx, appoidc.TokenCommand{ClientID: s.app.id, ClientSecret: s.app.secret, GrantType: "refresh_token", RefreshToken: token, Resource: platformURI})
				if err != nil {
					errs <- err
					return
				}
				if got.Response == nil {
					return // the grant was ended by one of the changes
				}
				token = got.Response.RefreshToken
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 4 {
			var err error
			if i%2 == 0 {
				_, err = e.resources.Allow(ctx, s.app.id, "platform-api", []string{"messages:read"})
			} else {
				_, err = e.resources.Allow(ctx, s.app.id, "platform-api", []string{"messages:read", "messages:send"})
			}
			if err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a request failed: %v", err)
	}
	// The first change took messages:send from the client, and every grant held it: once that has completed, no grant is live
	// whatever the interleaving of the refreshes with it.
	e.do(func(ctx context.Context, st port.Stores) error {
		for _, h := range holders {
			apps, err := st.OIDCApps.LiveGrantsOfUser(ctx, h.person.user.ID(), e.clock.Now())
			if err != nil {
				return err
			}
			if len(apps) != 0 {
				t.Errorf("a grant that held a withdrawn right is live: %+v", apps)
			}
		}
		return nil
	})
}

func TestWhatHappensToResourceTokensIsCounted(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	f := e.newFlow(s.app)
	f.scope, f.resources = "openid messages:send", []string{platformURI}
	code, _ := e.signedIn(f, s.alice)
	wantFailure(t, "a resource that is not registered", e.exchangeFor(f, code, "https://nobody.example.test/", ""), appoidc.ErrInvalidTarget)
	wantFailure(t, "a scope not held", e.exchangeFor(f, code, platformURI, "video:read"), appoidc.ErrInvalidScope)
	got := e.exchangeFor(f, code, platformURI, "")
	if got.Response == nil {
		t.Fatalf("exchange = %+v", got.Failure)
	}
	for key, want := range map[string]int{
		"token:unknown:invalid_target":     1,
		"token:platform-api:invalid_scope": 1,
		"token:platform-api:issued":        1,
		"change:client_allowed":            2,
		"change:resource_registered":       3,
		"change:grant_revoked_by_user":     0,
	} {
		if got := e.metrics.count(key); got != want {
			t.Errorf("%s = %d, want %d", key, got, want)
		}
	}
	if _, err := e.resources.Deny(context.Background(), s.app.id, "platform-api"); err != nil {
		t.Fatal(err)
	}
	if e.metrics.count("change:client_denied") != 1 || e.metrics.count("ended:client_denied") != 1 {
		t.Errorf("the denial and the grant it ended were not counted: %v", e.metrics.counts)
	}
	// A request that named no resource is not a resource event.
	before := len(e.metrics.counts)
	plain := e.newFlow(e.register("plain-app", appTwo, "openid", "email"))
	e.tokens(plain, s.alice)
	if len(e.metrics.counts) != before {
		t.Errorf("a token request without a resource was counted: %v", e.metrics.counts)
	}
}
