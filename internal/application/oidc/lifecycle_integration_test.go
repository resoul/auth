//go:build integration

package oidc_test

import (
	"context"
	"sync"
	"testing"
	"time"

	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	doidc "airlance.org/auth/internal/domain/oidc"
)

func (e *env) userinfoOK(accessToken string) bool {
	e.t.Helper()
	got, err := e.userinfo.Execute(context.Background(), accessToken)
	must(e.t, err)
	return got.Claims != nil
}

func TestRefreshRotatesAndNarrowsButNeverWidens(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	first, _ := e.tokens(e.newFlow(app), alice)

	e.clock.Advance(time.Minute)
	next := e.refresh(app, first.RefreshToken)
	if next.Response == nil {
		t.Fatalf("refresh = %+v", next.Failure)
	}
	if next.Response.RefreshToken == "" || next.Response.RefreshToken == first.RefreshToken || next.Response.AccessToken == first.AccessToken {
		t.Error("a refresh did not rotate the tokens")
	}
	if next.Response.IDToken != "" {
		t.Error("a refresh issued an ID token, which would pass for a new sign-in")
	}
	if !e.userinfoOK(next.Response.AccessToken) {
		t.Error("the refreshed access token does not work")
	}
	// auth_time stays the time of the real sign-in: a refresh is not a sign-in.
	e.do(func(ctx context.Context, st port.Stores) error { return nil })

	// Narrower is allowed; wider is not.
	narrow, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
		ClientID: app.id, ClientSecret: app.secret, GrantType: "refresh_token", RefreshToken: next.Response.RefreshToken, Scope: "openid",
	})
	must(t, err)
	if narrow.Response == nil || narrow.Response.Scope != "openid" {
		t.Fatalf("narrower scope = %+v", narrow)
	}
	if info, _ := e.userinfo.Execute(context.Background(), narrow.Response.AccessToken); info.Claims == nil || info.Claims.HasEmail {
		t.Errorf("an access token without the email scope still reveals the email: %+v", info)
	}
	for name, scope := range map[string]string{"unknown": "openid admin", "offline": "openid offline_access", "malformed": "openid  email"} {
		got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
			ClientID: app.id, ClientSecret: app.secret, GrantType: "refresh_token", RefreshToken: narrow.Response.RefreshToken, Scope: scope,
		})
		must(t, err)
		if got.Response != nil || got.Failure.Code != appoidc.ErrInvalidScope {
			t.Errorf("%s scope = %+v", name, got)
		}
	}
	// The narrowed grant did not lose its scopes: the refused requests changed nothing, and the token still works.
	if got := e.refresh(app, narrow.Response.RefreshToken); got.Response == nil || got.Response.Scope != "openid email" {
		t.Errorf("refresh after refusals = %+v", got)
	}
}

func TestAReplayedRefreshTokenEndsTheWholeGrant(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	first, _ := e.tokens(e.newFlow(app), alice)

	second := e.refresh(app, first.RefreshToken)
	if second.Response == nil {
		t.Fatalf("refresh = %+v", second.Failure)
	}
	// The first token is presented again: someone holds a copy.
	if got := e.refresh(app, first.RefreshToken); got.Response != nil || got.Failure.Code != appoidc.ErrInvalidGrant {
		t.Fatalf("a replayed token = %+v", got)
	}
	// The newest token and the access tokens are dead too, and that was committed with the refusal.
	if got := e.refresh(app, second.Response.RefreshToken); got.Response != nil {
		t.Error("the successor of a replayed token still works")
	}
	if e.userinfoOK(first.AccessToken) || e.userinfoOK(second.Response.AccessToken) {
		t.Error("an access token of a revoked grant still works")
	}
	// The sign-in itself is not ended: only this application's grant.
}

func TestAReplayedCodeEndsItsGrantButOnlyForTheRealClient(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()

	t.Run("the same exchange twice", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		won := e.exchange(f, code)
		if won.Response == nil {
			t.Fatalf("exchange = %+v", won.Failure)
		}
		if got := e.exchange(f, code); got.Response != nil {
			t.Fatal("a code was exchanged twice")
		}
		if got := e.refresh(app, won.Response.RefreshToken); got.Response != nil {
			t.Error("the refresh token survived the replay of its code")
		}
		if e.userinfoOK(won.Response.AccessToken) {
			t.Error("the access token survived the replay of its code")
		}
	})

	t.Run("a replay that could not be the first exchange leaves the grant alone", func(t *testing.T) {
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)
		won := e.exchange(f, code)
		if won.Response == nil {
			t.Fatalf("exchange = %+v", won.Failure)
		}
		bad := f
		bad.verifier, _, _ = e.secrets.NewOIDCSecret()
		if got := e.exchange(bad, code); got.Response != nil {
			t.Fatal("a wrong verifier was accepted")
		}
		if got := e.refresh(app, won.Response.RefreshToken); got.Response == nil {
			t.Errorf("a replay with a wrong verifier closed the grant: %+v", got.Failure)
		}
	})
}

func TestTokensEndWhenTheSignInEnds(t *testing.T) {
	cases := map[string]func(e *env, p person){
		"signing out everywhere": func(e *env, p person) {
			e.do(func(ctx context.Context, st port.Stores) error {
				return appsession.RevokeEverything(ctx, st, p.user.ID(), e.clock.Now())
			})
		},
		"a block": func(e *env, p person) {
			e.do(func(ctx context.Context, st port.Stores) error {
				u, err := st.Users.GetForUpdate(ctx, p.user.ID())
				if err != nil {
					return err
				}
				if err := u.Block(e.clock.Now()); err != nil {
					return err
				}
				return st.Users.SetBlocked(ctx, u)
			})
		},
		"the idle time": func(e *env, p person) { e.clock.Advance(doidc.DefaultPolicy().OPSessionIdle + time.Minute) },
		"the absolute time": func(e *env, p person) {
			for range 8 {
				e.clock.Advance(24 * time.Hour)
				_ = e.refresh // keep nothing alive: the days just pass
			}
		},
	}
	for name, end := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			app := e.register("panels-web", appCallback, "openid", "email")
			alice := e.newPerson()
			tokens, sso := e.tokens(e.newFlow(app), alice)
			if !e.userinfoOK(tokens.AccessToken) {
				t.Fatal("setup: the access token does not work")
			}
			end(e, alice)

			if got := e.refresh(app, tokens.RefreshToken); got.Response != nil {
				t.Errorf("a refresh token still works after %s", name)
			}
			if name != "the idle time" && name != "the absolute time" && e.userinfoOK(tokens.AccessToken) {
				t.Errorf("an access token still works after %s", name)
			}
			if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind == appoidc.AuthorizeRedirect {
				t.Errorf("the shared sign-in still opens a code after %s", name)
			}
		})
	}
}

func TestAccessTokenRefusals(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	tokens, _ := e.tokens(e.newFlow(app), alice)

	for name, token := range map[string]string{
		"an ID token in place of an access token": tokens.IDToken,
		"a refresh token":                         tokens.RefreshToken,
		"garbage":                                 "a.b.c",
		"empty":                                   "",
		"a token with a tampered body":            tokens.AccessToken[:len(tokens.AccessToken)-4] + "AAAA",
		"the signature stripped":                  tokens.AccessToken[:len(tokens.AccessToken)-86],
		"the device token of the /v1 API":         e.signIn(alice),
	} {
		got, err := e.userinfo.Execute(context.Background(), token)
		must(t, err)
		if got.Claims != nil || got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidToken {
			t.Errorf("%s: %+v, want invalid_token", name, got)
		}
	}
	if !e.userinfoOK(tokens.AccessToken) {
		t.Fatal("the genuine token was refused")
	}
	e.clock.Advance(6 * time.Minute)
	if e.userinfoOK(tokens.AccessToken) {
		t.Error("an expired access token works")
	}
}

func TestOnlyOneOfTwoSimultaneousExchangesOfACodeSucceeds(t *testing.T) {
	for round := range 8 {
		e := newEnv(t)
		app := e.register("panels-web", appCallback, "openid", "email")
		alice := e.newPerson()
		f := e.newFlow(app)
		code, _ := e.signedIn(f, alice)

		var results [2]appoidc.TokenResult
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := e.token.Execute(context.Background(), appoidc.TokenCommand{
					ClientID: app.id, ClientSecret: app.secret, GrantType: "authorization_code", Code: code, RedirectURI: appCallback, CodeVerifier: f.verifier,
				})
				if err != nil {
					t.Errorf("round %d: %v", round, err)
				}
				results[i] = got
			}()
		}
		wg.Wait()
		wins := 0
		for _, r := range results {
			if r.Response != nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: %d exchanges of one code succeeded, want exactly 1", round, wins)
		}
		// The loser was a replay, so the winner's grant ended with it: strict, and committed.
		for _, r := range results {
			if r.Response != nil && e.refresh(app, r.Response.RefreshToken).Response != nil {
				t.Errorf("round %d: the grant of a raced code survived", round)
			}
		}
	}
}

func TestOnlyOneOfTwoSimultaneousRefreshesSucceeds(t *testing.T) {
	for round := range 8 {
		e := newEnv(t)
		app := e.register("panels-web", appCallback, "openid", "email")
		alice := e.newPerson()
		tokens, _ := e.tokens(e.newFlow(app), alice)

		var results [2]appoidc.TokenResult
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = e.refresh(app, tokens.RefreshToken)
			}()
		}
		wg.Wait()
		wins := 0
		for _, r := range results {
			if r.Response != nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: %d refreshes of one token succeeded, want exactly 1", round, wins)
		}
	}
}

func TestARefreshAndASignOutEverywhereDoNotLeaveATokenBehind(t *testing.T) {
	// The strict order of locks decides this: whichever of the two gets the user first, afterwards nothing works.
	for round := range 8 {
		e := newEnv(t)
		app := e.register("panels-web", appCallback, "openid", "email")
		alice := e.newPerson()
		tokens, _ := e.tokens(e.newFlow(app), alice)

		var refreshed appoidc.TokenResult
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); refreshed = e.refresh(app, tokens.RefreshToken) }()
		go func() {
			defer wg.Done()
			e.do(func(ctx context.Context, st port.Stores) error {
				return appsession.RevokeEverything(ctx, st, alice.user.ID(), e.clock.Now())
			})
		}()
		wg.Wait()
		if refreshed.Response != nil {
			if e.refresh(app, refreshed.Response.RefreshToken).Response != nil {
				t.Errorf("round %d: a refresh token issued while everything was being revoked still works", round)
			}
			if e.userinfoOK(refreshed.Response.AccessToken) {
				t.Errorf("round %d: an access token issued while everything was being revoked still works", round)
			}
		}
	}
}
