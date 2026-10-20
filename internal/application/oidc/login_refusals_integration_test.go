//go:build integration

package oidc_test

import (
	"context"
	"testing"

	appoidc "go.airlance.org/auth/internal/application/oidc"
)

// An application that is switched off while the person signs in cannot receive the sign-in: the request is refused
// with the application-level error, and no session or code is made for it.
func TestAnApplicationSwitchedOffDuringTheSignInCannotComplete(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()

	asked := e.authorizeWith(e.newFlow(app).command(""))
	if asked.Kind != appoidc.AuthorizeLogin {
		t.Fatalf("authorize = %+v, want the sign-in page", asked)
	}

	must(t, e.clients.SetActive(context.Background(), app.id, false))
	got, err := e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{
		RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: e.signIn(alice),
	})
	must(t, err)

	if got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidRequest || got.SSOSecret != "" || got.Location != "" {
		t.Errorf("a switched-off application = %+v, want invalid_request and nothing opened", got)
	}
}
