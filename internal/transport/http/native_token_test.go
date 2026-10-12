package http_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeRefreshRotatesTheToken(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	e.clock.Advance(time.Hour)

	rec := e.refresh(signedIn.RefreshToken)
	res := decode[tokenResponse](t, rec, http.StatusOK)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the token response may be cached")
	}
	if res.RefreshToken == "" || res.RefreshToken == signedIn.RefreshToken || res.AccessToken == signedIn.AccessToken {
		t.Fatalf("refresh = %+v, want new tokens", res)
	}
	claims, err := e.verifier.VerifyAccess(res.AccessToken)
	if err != nil || claims.UserID.String() != signedIn.User.ID || !res.ExpiresAt.Equal(t0.Add(time.Hour+5*time.Minute)) {
		t.Errorf("claims = %+v (%v), expires_at = %v", claims, err, res.ExpiresAt)
	}
	// The new token rotates again.
	decode[tokenResponse](t, e.refresh(res.RefreshToken), http.StatusOK)
}

func TestNativeRefreshReplayIsRefusedAndRevokesTheSession(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	rotated := decode[tokenResponse](t, e.refresh(signedIn.RefreshToken), http.StatusOK)

	wantProblem(t, e.refresh(signedIn.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
	// Strict policy: the replay ended the session, so the newest token is dead as well.
	wantProblem(t, e.refresh(rotated.RefreshToken), http.StatusUnauthorized, "invalid_refresh")

	metrics := e.get("/metrics").Body.String()
	if !strings.Contains(metrics, "airlance_auth_refresh_reuse_total 1") {
		t.Errorf("the reuse is not counted:\n%s", metrics)
	}
}

func TestNativeRefreshRefusesUnknownAndMalformedTokens(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	for name, token := range map[string]string{
		"empty":     "",
		"malformed": "not-a-token",
		"unknown":   strings.Repeat("A", len(signedIn.RefreshToken)),
		"padded":    signedIn.RefreshToken + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, e.refresh(token), http.StatusUnauthorized, "invalid_refresh")
		})
	}
	wantProblem(t, e.postRaw(refreshPath, `{"refresh_token": `), http.StatusBadRequest, "invalid_request")
	// None of the refusals touched the real token.
	decode[tokenResponse](t, e.refresh(signedIn.RefreshToken), http.StatusOK)
}

func TestNativeRoutesIgnoreCookies(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	req := e.refreshRequest("")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: signedIn.RefreshToken})
	wantProblem(t, e.do(req), http.StatusUnauthorized, "invalid_refresh")
}

func (e *env) refreshRequest(token string) *http.Request {
	req, err := http.NewRequest(http.MethodPost, refreshPath, strings.NewReader(`{"refresh_token": "`+token+`"}`))
	if err != nil {
		e.t.Fatal(err)
	}
	return req
}
