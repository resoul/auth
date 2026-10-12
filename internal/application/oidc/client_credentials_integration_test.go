//go:build integration

package oidc_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	doidc "airlance.org/auth/internal/domain/oidc"
)

// registerService registers a service identity.
func (e *env) registerService(id string) client {
	e.t.Helper()
	got, err := e.clients.Register(context.Background(), appoidc.RegisterCommand{ID: id, Name: id, Service: true})
	must(e.t, err)
	return client{id: id, secret: got.Secret}
}

// serviceToken asks the token endpoint for a service's token.
func (e *env) serviceToken(c client, resource, scope string) appoidc.TokenResult {
	e.t.Helper()
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: c.id, ClientSecret: c.secret, GrantType: "client_credentials", Resource: resource, Scope: scope,
	})
	must(e.t, err)
	return got
}

type serviceSetup struct {
	resourceSetup
	svc client
}

func newServiceSetup(t *testing.T) serviceSetup {
	t.Helper()
	s := newResourceSetup(t)
	svc := s.e.registerService("billing-worker")
	s.e.allow(svc, "platform-api", "messages:read", "messages:send")
	return serviceSetup{resourceSetup: s, svc: svc}
}

func TestAServiceGetsATokenForTheAPIItWasAllowedAndNothingElse(t *testing.T) {
	s := newServiceSetup(t)
	e := s.e

	got := e.serviceToken(s.svc, platformURI, "")
	if got.Response == nil {
		t.Fatalf("token = %+v", got.Failure)
	}
	r := got.Response
	if r.Scope != "messages:read messages:send" || r.RefreshToken != "" || r.IDToken != "" || r.ExpiresIn <= 0 || got.Resource != "platform-api" {
		t.Errorf("response = %+v", r)
	}
	claims, err := e.signer.VerifyServiceAccess(r.AccessToken, "platform-api")
	if err != nil || claims.ClientID != "billing-worker" || strings.Join(claims.Scope, " ") != "messages:read messages:send" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	// It is not a person's token: UserInfo and the user verifier refuse it, and no other API takes it.
	if _, err := e.accessFor(r.AccessToken, "platform-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("a user verifier took it: %v", err)
	}
	if info, err := e.userinfo.Execute(context.Background(), r.AccessToken); err != nil || info.Claims != nil {
		t.Errorf("userinfo took it: %+v %v", info, err)
	}
	if _, err := e.signer.VerifyServiceAccess(r.AccessToken, "video-api"); err == nil {
		t.Error("another API took it")
	}

	// A narrower scope is given; the scope may only narrow.
	narrow := e.serviceToken(s.svc, platformURI, "messages:read")
	if narrow.Response == nil || narrow.Response.Scope != "messages:read" {
		t.Errorf("narrowed = %+v %+v", narrow.Response, narrow.Failure)
	}
	if e.metrics.count("token:platform-api:issued") != 2 {
		t.Errorf("issued counted %d", e.metrics.count("token:platform-api:issued"))
	}
	if n := e.queued(); len(n) != 0 {
		t.Errorf("a service token queued notices: %v", n)
	}
}

func TestAServiceIsRefusedWhatItWasNotAllowed(t *testing.T) {
	s := newServiceSetup(t)
	e := s.e
	asService := func(name, resource, scope, code string) {
		t.Helper()
		got := e.serviceToken(s.svc, resource, scope)
		if got.Response != nil || got.Failure == nil || got.Failure.Code != code {
			t.Errorf("%s: %+v %+v, want %s", name, got.Response, got.Failure, code)
		}
	}
	asService("no resource", "", "", appoidc.ErrInvalidTarget)
	asService("an unknown resource", "https://nobody.example.test/", "", appoidc.ErrInvalidTarget)
	asService("a malformed resource", "platform-api", "", appoidc.ErrInvalidTarget)
	asService("a resource it was not allowed", videoURI, "", appoidc.ErrInvalidTarget)
	asService("a right it was not allowed", platformURI, "video:read", appoidc.ErrInvalidScope)
	asService("a right wider than allowed", platformURI, "messages:read messages:send video:read", appoidc.ErrInvalidScope)
	asService("a protocol scope", platformURI, "openid", appoidc.ErrInvalidScope)
	asService("a repeated scope", platformURI, "messages:read messages:read", appoidc.ErrInvalidScope)

	// Parameters of another grant make the request wrong, not ignored.
	got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: s.svc.id, ClientSecret: s.svc.secret, GrantType: "client_credentials", Resource: platformURI, Code: "x",
	})
	must(t, err)
	if got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidRequest {
		t.Errorf("a code with client_credentials: %+v", got.Failure)
	}

	// Only a service may use the grant, and a service may use no other.
	wantFailure(t, "an application using client_credentials", e.serviceToken(s.app, platformURI, ""), appoidc.ErrUnauthorizedClient)
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
			ClientID: s.svc.id, ClientSecret: s.svc.secret, GrantType: grant, Code: "c", RefreshToken: "r", RedirectURI: "https://a.example.test/cb", CodeVerifier: strings.Repeat("a", 43),
		})
		must(t, err)
		wantFailure(t, "a service using "+grant, got, appoidc.ErrUnauthorizedClient)
	}
	bad := s.svc
	bad.secret += "x"
	wantFailure(t, "the wrong secret", e.serviceToken(bad, platformURI, ""), appoidc.ErrInvalidClient)

	// A service signs nobody in: authorize treats it as a client that is not registered.
	f := e.newFlow(client{id: s.svc.id, secret: s.svc.secret, redirect: appCallback})
	res := e.authorizeWith(f.command(""))
	if res.Kind != appoidc.AuthorizeFailure {
		t.Errorf("authorize for a service = %+v", res)
	}
}

func TestAServiceIsRegisteredWithoutAnythingToSignInWith(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, cmd := range map[string]appoidc.RegisterCommand{
		"redirect addresses": {ID: "svc-one", Name: "x", Service: true, RedirectURIs: []string{appCallback}},
		"scopes":             {ID: "svc-one", Name: "x", Service: true, AllowedScopes: []string{"openid"}},
		"a back-channel URI": {ID: "svc-one", Name: "x", Service: true, BackchannelLogoutURI: appBackchannel},
	} {
		if _, err := e.clients.Register(ctx, cmd); !errors.Is(err, doidc.ErrInvalidClient) {
			t.Errorf("a service with %s: %v", name, err)
		}
	}
	svc := e.registerService("svc-one")
	if err := e.clients.SetLogout(ctx, svc.id, nil, appBackchannel); !errors.Is(err, doidc.ErrInvalidClient) {
		t.Errorf("logout settings on a service: %v", err)
	}
	// Its identifier is no resource's audience, and the other way round.
	e.registerResource("platform-api", platformURI, "messages:read")
	if _, err := e.clients.Register(ctx, appoidc.RegisterCommand{ID: "platform-api", Name: "x", Service: true}); !errors.Is(err, doidc.ErrInvalidClient) {
		t.Errorf("a service named like an audience: %v", err)
	}
	list, err := e.clients.List(ctx)
	must(t, err)
	if len(list) != 1 || !list[0].Service() {
		t.Errorf("list = %+v", list)
	}
}

func TestAServiceTokenIsEndedTheMomentItsRightsAre(t *testing.T) {
	cases := map[string]func(s serviceSetup){
		"its right is narrowed": func(s serviceSetup) { s.e.allow(s.svc, "platform-api", "messages:read") },
		"it loses the API": func(s serviceSetup) {
			_, err := s.e.resources.Deny(context.Background(), s.svc.id, "platform-api")
			must(s.e.t, err)
		},
		"the API drops the scope": func(s serviceSetup) {
			_, err := s.e.resources.SetScopes(context.Background(), "platform-api", []string{"messages:read", "video:read", "video:upload"})
			must(s.e.t, err)
		},
		"the service is disabled": func(s serviceSetup) { must(s.e.t, s.e.clients.SetActive(context.Background(), s.svc.id, false)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServiceSetup(t)
			e := s.e
			apiSecret := e.secretOf("platform-api")
			got := e.serviceToken(s.svc, platformURI, "")
			if got.Response == nil {
				t.Fatalf("token = %+v", got.Failure)
			}
			token := got.Response.AccessToken
			live := e.ask("platform-api", apiSecret, token)
			if live.Token == nil || live.Token.Subject != "billing-worker" || live.Token.ClientID != "billing-worker" || live.Token.Audience != "platform-api" ||
				strings.Join(live.Token.Scope, " ") != "messages:read messages:send" {
				t.Fatalf("before the change: %+v %+v", live.Token, live.Failure)
			}
			change(s)
			// The signature still verifies: only the issuer knows.
			if _, err := e.signer.VerifyServiceAccess(token, "platform-api"); err != nil {
				t.Fatalf("the token itself stopped verifying: %v", err)
			}
			wantInactive(t, name, e.ask("platform-api", apiSecret, token))
		})
	}
}

func TestAServiceTokenIsAnswerableOnlyToItsOwnAPIAndRightsAddedChangeNothing(t *testing.T) {
	s := newServiceSetup(t)
	e := s.e
	platform, video := e.secretOf("platform-api"), e.secretOf("video-api")
	token := e.serviceToken(s.svc, platformURI, "messages:send").Response.AccessToken

	wantInactive(t, "another API asking", e.ask("video-api", video, token))
	// Widening what the service may ask does not widen a token that exists.
	e.allow(s.svc, "platform-api", "messages:read", "messages:send")
	got := e.ask("platform-api", platform, token)
	if got.Token == nil || strings.Join(got.Token.Scope, " ") != "messages:send" {
		t.Errorf("after widening: %+v %+v", got.Token, got.Failure)
	}
	// Past its life it is inactive.
	e.clock.Advance(10 * time.Minute)
	wantInactive(t, "an expired token", e.ask("platform-api", platform, token))
}

func TestARotatedServiceSecretStopsAskingForTokensButTokensRunOut(t *testing.T) {
	s := newServiceSetup(t)
	e := s.e
	platform := e.secretOf("platform-api")
	old := s.svc.secret
	token := e.serviceToken(s.svc, platformURI, "").Response.AccessToken

	// With an overlap both secrets work, then the old one stops.
	fresh, err := e.clients.RotateSecret(context.Background(), s.svc.id, time.Minute)
	must(t, err)
	if e.serviceToken(client{id: s.svc.id, secret: old}, platformURI, "").Response == nil || e.serviceToken(client{id: s.svc.id, secret: fresh}, platformURI, "").Response == nil {
		t.Fatal("a secret did not work during the overlap")
	}
	e.clock.Advance(2 * time.Minute)
	wantFailure(t, "the old secret after the overlap", e.serviceToken(client{id: s.svc.id, secret: old}, platformURI, ""), appoidc.ErrInvalidClient)
	if e.serviceToken(client{id: s.svc.id, secret: fresh}, platformURI, "").Response == nil {
		t.Error("the new secret stopped working")
	}
	// A token already issued runs to its end (five minutes) unless the API asks; the API asks, and it is still the same client.
	if e.ask("platform-api", platform, token).Token == nil {
		t.Error("a rotation ended a token that was already issued")
	}
}
