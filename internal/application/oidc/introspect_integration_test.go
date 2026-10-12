//go:build integration

package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	appoidc "airlance.org/auth/internal/application/oidc"
)

// ask introspects a token as the API of a resource.
func (e *env) ask(resourceID, secret, token string) appoidc.IntrospectResult {
	e.t.Helper()
	got, err := e.introspect.Execute(context.Background(), appoidc.IntrospectCommand{ResourceID: resourceID, Secret: secret, Token: token})
	must(e.t, err)
	return got
}

func (e *env) secretOf(resourceID string) string {
	e.t.Helper()
	secret, err := e.resources.RotateSecret(context.Background(), resourceID, time.Hour)
	must(e.t, err)
	return secret
}

func wantInactive(t *testing.T, name string, got appoidc.IntrospectResult) {
	t.Helper()
	if got.Failure != nil || got.Token != nil {
		t.Errorf("%s: %+v, failure %+v, want inactive", name, got.Token, got.Failure)
	}
}

func TestAnAPILearnsAboutItsOwnTokensOnly(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	platform, video := e.secretOf("platform-api"), e.secretOf("video-api")
	_, first, _ := s.grantOfBoth(s.alice)
	second := e.refreshFor(s.app, first.RefreshToken, videoURI, "")
	if second.Response == nil {
		t.Fatalf("refresh = %+v", second.Failure)
	}
	plain := e.refreshFor(s.app, second.Response.RefreshToken, "", "")
	if plain.Response == nil {
		t.Fatalf("refresh = %+v", plain.Failure)
	}

	got := e.ask("platform-api", platform, first.AccessToken)
	if got.Failure != nil || got.Token == nil {
		t.Fatalf("a live token = %+v, failure %+v", got.Token, got.Failure)
	}
	claims, err := e.accessFor(first.AccessToken, "platform-api")
	must(t, err)
	if strings.Join(got.Token.Scope, " ") != "messages:send" || got.Token.ClientID != "panels-web" || got.Token.Subject != s.alice.user.ID().String() ||
		got.Token.Audience != "platform-api" || got.Token.JTI != claims.JTI || !got.Token.ExpiresAt.Equal(claims.ExpiresAt) {
		t.Errorf("what it was told = %+v, token %+v", got.Token, claims)
	}

	// Another API's token, UserInfo's token, a garbage string, and an ID token are all "not active" to this API.
	wantInactive(t, "the video token asked by the platform API", e.ask("platform-api", platform, second.Response.AccessToken))
	wantInactive(t, "the platform token asked by the video API", e.ask("video-api", video, first.AccessToken))
	wantInactive(t, "the UserInfo token", e.ask("platform-api", platform, plain.Response.AccessToken))
	wantInactive(t, "the ID token", e.ask("platform-api", platform, first.IDToken))
	wantInactive(t, "garbage", e.ask("platform-api", platform, "not.a.token"))
	wantInactive(t, "a refresh token", e.ask("platform-api", platform, first.RefreshToken))
	if n := e.metrics.count("introspect:platform-api:active"); n != 1 {
		t.Errorf("active answers counted = %d", n)
	}
}

func TestAnAPIThatCannotProveItselfLearnsNothing(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	platform := e.secretOf("platform-api")
	videoSecret := e.secretOf("video-api")
	_, first, _ := s.grantOfBoth(s.alice)

	for name, c := range map[string]struct{ id, secret string }{
		"the wrong secret":       {"platform-api", platform + "x"},
		"another API's secret":   {"platform-api", videoSecret},
		"an unknown resource":    {"nobody-api", platform},
		"no secret at all":       {"platform-api", ""},
		"a client's credentials": {"panels-web", s.app.secret},
	} {
		if got := e.ask(c.id, c.secret, first.AccessToken); got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidClient || got.Token != nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// A disabled API cannot ask either.
	if _, err := e.resources.SetActive(context.Background(), "platform-api", false); err != nil {
		t.Fatal(err)
	}
	if got := e.ask("platform-api", platform, first.AccessToken); got.Failure == nil {
		t.Errorf("a disabled API was answered: %+v", got)
	}
}

func TestIntrospectionSeesEveryWayAGrantEnds(t *testing.T) {
	cases := map[string]func(s resourceSetup, held *appoidc.TokenResponse){
		"the person takes the application back": func(s resourceSetup, _ *appoidc.TokenResponse) {
			list, err := s.e.apps.List(context.Background(), s.alice.user.ID())
			must(s.e.t, err)
			must(s.e.t, s.e.apps.RevokeGrant(context.Background(), s.alice.user.ID(), list[0].ID))
		},
		"the application's right is narrowed": func(s resourceSetup, _ *appoidc.TokenResponse) {
			s.e.allow(s.app, "platform-api", "messages:read")
		},
		"the application loses the API": func(s resourceSetup, _ *appoidc.TokenResponse) {
			_, err := s.e.resources.Deny(context.Background(), s.app.id, "platform-api")
			must(s.e.t, err)
		},
		"the API drops the scope": func(s resourceSetup, _ *appoidc.TokenResponse) {
			_, err := s.e.resources.SetScopes(context.Background(), "platform-api", []string{"messages:read", "video:read", "video:upload"})
			must(s.e.t, err)
		},
		"the application revokes the token": func(s resourceSetup, held *appoidc.TokenResponse) {
			got, err := s.e.revoke.Execute(context.Background(), appoidc.RevokeCommand{ClientID: s.app.id, ClientSecret: s.app.secret, Token: held.RefreshToken})
			must(s.e.t, err)
			if got.Failure != nil {
				s.e.t.Fatalf("revoke = %+v", got.Failure)
			}
		},
		"a replayed refresh token": func(s resourceSetup, held *appoidc.TokenResponse) {
			s.e.refreshFor(s.app, held.RefreshToken, platformURI, "")
			wantFailure(s.e.t, "the replay", s.e.refreshFor(s.app, held.RefreshToken, platformURI, ""), appoidc.ErrInvalidGrant)
		},
		"the application is disabled": func(s resourceSetup, _ *appoidc.TokenResponse) {
			must(s.e.t, s.e.clients.SetActive(context.Background(), s.app.id, false))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := newResourceSetup(t)
			e := s.e
			platform := e.secretOf("platform-api")
			_, held, _ := s.grantOfBoth(s.alice)
			if got := e.ask("platform-api", platform, held.AccessToken); got.Token == nil {
				t.Fatalf("not live before the change: %+v", got)
			}
			change(s, held)
			// The token's own expiry is minutes away: the signature still verifies, and the answer is already no.
			if _, err := e.accessFor(held.AccessToken, "platform-api"); err != nil {
				t.Fatalf("the token itself stopped verifying: %v", err)
			}
			wantInactive(t, name, e.ask("platform-api", platform, held.AccessToken))
		})
	}
}

func TestIntrospectionLeavesAnUnrelatedGrantAndALaterRightAlone(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	platform := e.secretOf("platform-api")
	bob := e.newPerson()
	_, held, _ := s.grantOfBoth(s.alice)
	_, bobs, _ := s.grantOfBoth(bob)

	// Widening what the application may ask changes no token that exists.
	e.allow(s.app, "platform-api", "messages:read", "messages:send", "video:read")
	if got := e.ask("platform-api", platform, held.AccessToken); got.Token == nil || strings.Join(got.Token.Scope, " ") != "messages:send" {
		t.Errorf("a right added changed a live token: %+v", got)
	}
	// Ending one person's grant ends only theirs.
	list, err := e.apps.List(context.Background(), s.alice.user.ID())
	must(t, err)
	must(t, e.apps.RevokeGrant(context.Background(), s.alice.user.ID(), list[0].ID))
	wantInactive(t, "the person who took the application back", e.ask("platform-api", platform, held.AccessToken))
	if got := e.ask("platform-api", platform, bobs.AccessToken); got.Token == nil {
		t.Errorf("another person's token was ended: %+v", got)
	}
}

func TestATokenIsInactiveWhenItHasExpiredAndSecretsRotateWithAnOverlap(t *testing.T) {
	s := newResourceSetup(t)
	e := s.e
	old := e.secretOf("platform-api")
	_, held, _ := s.grantOfBoth(s.alice)

	// A new secret: the old one still works for the overlap, then stops.
	fresh, err := e.resources.RotateSecret(context.Background(), "platform-api", time.Minute)
	must(t, err)
	if e.ask("platform-api", old, held.AccessToken).Token == nil || e.ask("platform-api", fresh, held.AccessToken).Token == nil {
		t.Fatal("a secret did not work during the overlap")
	}
	e.clock.Advance(2 * time.Minute)
	if got := e.ask("platform-api", old, held.AccessToken); got.Failure == nil {
		t.Errorf("the old secret worked after the overlap: %+v", got)
	}
	if e.ask("platform-api", fresh, held.AccessToken).Token == nil {
		t.Error("the new secret stopped working")
	}
	// Rotating with no overlap ends the earlier ones at once.
	last, err := e.resources.RotateSecret(context.Background(), "platform-api", 0)
	must(t, err)
	if got := e.ask("platform-api", fresh, held.AccessToken); got.Failure == nil {
		t.Errorf("a secret rotated away without an overlap still worked: %+v", got)
	}
	// Past the token's lifetime (and the provider's leeway) it is inactive.
	e.clock.Advance(10 * time.Minute)
	wantInactive(t, "an expired token", e.ask("platform-api", last, held.AccessToken))
	if _, err := e.resources.RotateSecret(context.Background(), "no-such-api", time.Minute); err == nil {
		t.Error("a secret was made for a resource that is not there")
	}
}
