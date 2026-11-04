//go:build integration

package oidc_test

import (
	"context"
	"testing"
	"time"

	appoidc "go.airlance.org/auth/internal/application/oidc"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

const nativeCallback = "airlance://auth/callback"

func (e *env) registerNative(id string) client {
	e.t.Helper()
	got, err := e.clients.Register(context.Background(), appoidc.RegisterCommand{
		ID: id, Name: id, RedirectURIs: []string{nativeCallback}, AllowedScopes: []string{"openid", "email"}, Native: true,
	})
	must(e.t, err)

	if got.Secret != "" {
		e.t.Fatalf("a native client got a secret")
	}

	return client{id: id, redirect: nativeCallback}
}

func TestANativeClientSignsInWithoutASecret(t *testing.T) {
	e := newEnv(t)
	app := e.registerNative("airlance-ios")
	got, _ := e.tokens(e.newFlow(app), e.newPerson())

	if got.AccessToken == "" || got.RefreshToken == "" || got.IDToken == "" {
		t.Fatalf("token response = %+v", got)
	}

	next := e.refresh(app, got.RefreshToken)
	if next.Response == nil {
		t.Fatalf("refresh = %+v", next.Failure)
	}
}

func TestANativeClientIsRefusedASecretAndAConfidentialOneNeedsIt(t *testing.T) {
	e := newEnv(t)
	native := e.registerNative("airlance-ios")
	web := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()

	nativeFlow := e.newFlow(native)
	nativeCode, _ := e.signedIn(nativeFlow, alice)
	withSecret := nativeFlow
	withSecret.client.secret, _, _ = e.secrets.NewOIDCSecret()

	if got := e.exchange(withSecret, nativeCode); got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidClient {
		t.Errorf("native with a secret = %+v, want invalid_client", got)
	}

	webFlow := e.newFlow(web)
	webCode, _ := e.signedIn(webFlow, alice)
	webFlow.client.secret = ""

	if got := e.exchange(webFlow, webCode); got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidClient {
		t.Errorf("confidential without a secret = %+v, want invalid_client", got)
	}
}

func TestANativeCodeStillNeedsItsVerifier(t *testing.T) {
	e := newEnv(t)
	f := e.newFlow(e.registerNative("airlance-ios"))
	code, _ := e.signedIn(f, e.newPerson())
	bad := f
	bad.verifier = "wrong-verifier-wrong-verifier-wrong-verifier-wrong"

	if got := e.exchange(bad, code); got.Response != nil {
		t.Fatalf("a code without its verifier was exchanged: %+v", got)
	}
}

func TestANativeClientCanRetryARefreshWhoseAnswerWasLost(t *testing.T) {
	e := newEnv(t)
	app := e.registerNative("airlance-ios")
	got, _ := e.tokens(e.newFlow(app), e.newPerson())

	lost := e.refresh(app, got.RefreshToken)
	if lost.Response == nil {
		t.Fatalf("first refresh = %+v", lost.Failure)
	}

	e.clock.Advance(doidc.RefreshRetryWindow / 2)

	retry := e.refresh(app, got.RefreshToken)
	if retry.Response == nil || retry.Replay {
		t.Fatalf("retry = %+v", retry)
	}

	if retry.Response.RefreshToken == lost.Response.RefreshToken {
		t.Fatal("the retry returned the lost token")
	}

	if again := e.refresh(app, retry.Response.RefreshToken); again.Response == nil {
		t.Fatalf("refresh with the retried token = %+v", again.Failure)
	}
}

func TestASupersededTokenThatComesBackEndsTheGrant(t *testing.T) {
	e := newEnv(t)
	app := e.registerNative("airlance-ios")
	got, _ := e.tokens(e.newFlow(app), e.newPerson())
	lost := e.refresh(app, got.RefreshToken)
	retry := e.refresh(app, got.RefreshToken)

	if replay := e.refresh(app, lost.Response.RefreshToken); replay.Response != nil || !replay.Replay {
		t.Fatalf("the superseded token = %+v, want a replay", replay)
	}

	if after := e.refresh(app, retry.Response.RefreshToken); after.Response != nil {
		t.Fatalf("the grant survived a replay: %+v", after)
	}
}

func TestARetryEndsTheGrantOnceTheSuccessorWasUsedOrTheWindowPassed(t *testing.T) {
	for name, step := range map[string]func(*env, client, string){
		"successor used": func(e *env, app client, next string) { e.refresh(app, next) },
		"window passed":  func(e *env, _ client, _ string) { e.clock.Advance(doidc.RefreshRetryWindow + time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			app := e.registerNative("airlance-ios")
			got, _ := e.tokens(e.newFlow(app), e.newPerson())
			step(e, app, e.refresh(app, got.RefreshToken).Response.RefreshToken)

			if retry := e.refresh(app, got.RefreshToken); retry.Response != nil || !retry.Replay {
				t.Fatalf("retry = %+v, want a replay", retry)
			}
		})
	}
}

func TestAConfidentialClientHasNoRetry(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	got, _ := e.tokens(e.newFlow(app), e.newPerson())
	e.refresh(app, got.RefreshToken)

	if retry := e.refresh(app, got.RefreshToken); retry.Response != nil || !retry.Replay {
		t.Fatalf("retry = %+v, want a replay", retry)
	}
}
