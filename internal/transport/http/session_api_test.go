package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
	httpapi "airlance.org/auth/internal/transport/http"
)

type sessionBody struct {
	ID           string    `json:"id"`
	DeviceName   string    `json:"device_name"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	Current      bool      `json:"current"`
}

type meBody struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Session sessionBody `json:"session"`
}

type listBody struct {
	Sessions []sessionBody `json:"sessions"`
}

// protected is every operation that needs an access token, in both profiles.
var protected = []struct{ method, path string }{
	{http.MethodGet, "/v1/me"}, {http.MethodGet, "/v1/sessions"}, {http.MethodDelete, "/v1/sessions/00000000-0000-4000-8000-000000000001"}, {http.MethodPost, "/v1/signout"},
	{http.MethodGet, "/v1/native/me"}, {http.MethodGet, "/v1/native/sessions"}, {http.MethodDelete, "/v1/native/sessions/00000000-0000-4000-8000-000000000001"}, {http.MethodPost, "/v1/native/signout"},
}

func (e *env) call(method, path, token, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return e.do(req)
}

func (e *env) wantUnauthenticated(rec *httptest.ResponseRecorder) {
	e.t.Helper()
	wantProblem(e.t, rec, http.StatusUnauthorized, "unauthenticated")
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		e.t.Errorf("WWW-Authenticate = %q", got)
	}
}

func (e *env) recognized(email, bindingSecret string) bool {
	e.t.Helper()
	hash, err := crypto.Binding{}.HashBinding(bindingSecret)
	if err != nil {
		e.t.Fatal(err)
	}
	found := false
	err = e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Recognized.FindActive(ctx, mustEmail(e.t, email), hash, e.clock.Now())
		found = err == nil
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return found
}

func (e *env) sessionOf(token string) session.ID {
	e.t.Helper()
	claims, err := e.verifier.VerifyAccess(token)
	if err != nil {
		e.t.Fatal(err)
	}
	return claims.SessionID
}

func (e *env) revoked(id session.ID) bool {
	e.t.Helper()
	s, ok := e.store.Session(id)
	return ok && !s.RevokedAt().IsZero()
}

func TestMeReturnsTheUserAndTheCurrentSessionInBothProfiles(t *testing.T) {
	e := newEnv(t)
	started := e.start("Alice@Example.test", "")
	step := e.verifyStep(started.FlowID, started.ClientBinding)
	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	rec := e.registerWith(auth, step.Ticket, started.ClientBinding, map[string]any{"device_name": "Alice's phone"})
	signedIn := decode[tokenResponse](t, rec, http.StatusOK)

	for _, path := range []string{"/v1/me", "/v1/native/me"} {
		rec := e.call(http.MethodGet, path, signedIn.AccessToken, "")
		me := decode[meBody](t, rec, http.StatusOK)
		if me.User.ID != signedIn.User.ID || me.User.Email != "alice@example.test" ||
			me.Session.ID != e.sessionOf(signedIn.AccessToken).String() || !me.Session.Current || me.Session.DeviceName != "Alice's phone" {
			t.Errorf("%s = %+v", path, me)
		}
		if !me.Session.CreatedAt.Equal(t0) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: created %v, Cache-Control %q", path, me.Session.CreatedAt, rec.Header().Get("Cache-Control"))
		}
	}
}

func TestEveryProtectedRouteRefusesAnythingButAValidBearerTokenOfALiveSession(t *testing.T) {
	e := newEnv(t)
	old, _ := e.signIn("alice@example.test")
	expired := old.AccessToken // signed an hour ago with a five minute life
	e.clock.Advance(time.Hour)
	// A token that is valid now: each case below is refused for its form alone.
	signedIn, _ := e.signIn("alice@example.test")
	good := signedIn.AccessToken
	goodSession := e.sessionOf(good)

	for _, op := range protected {
		for name, mod := range map[string]func(*http.Request){
			"no header":     func(r *http.Request) {},
			"empty bearer":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
			"bare token":    func(r *http.Request) { r.Header.Set("Authorization", good) },
			"other scheme":  func(r *http.Request) { r.Header.Set("Authorization", "Basic "+good) },
			"garbage":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer not.a.token") },
			"expired token": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+expired) },
			"two headers": func(r *http.Request) {
				r.Header.Add("Authorization", "Bearer "+good)
				r.Header.Add("Authorization", "Bearer "+good)
			},
			"token with space": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+good+" extra") },
			"huge token":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 5000)) },
			"token in a query": func(r *http.Request) { r.URL.RawQuery = "access_token=" + good },
			"token in a cookie": func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "access_token", Value: good})
				r.AddCookie(&http.Cookie{Name: httpapi.RefreshCookieName, Value: good})
			},
			"refresh token as a bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+signedIn.RefreshToken) },
		} {
			t.Run(op.method+" "+op.path+" "+name, func(t *testing.T) {
				req := httptest.NewRequest(op.method, op.path, strings.NewReader(`{"scope": "all"}`))
				req.Header.Set("Content-Type", "application/json")
				mod(req)
				e.wantUnauthenticated(e.do(req))
			})
		}
	}
	if e.revoked(goodSession) {
		t.Error("a refused request revoked a session")
	}
}

func TestARevokedSessionStopsWorkingAtOnceDespiteAValidToken(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	decode[meBody](t, e.call(http.MethodGet, "/v1/native/me", signedIn.AccessToken, ""), http.StatusOK)

	if rec := e.call(http.MethodPost, "/v1/native/signout", signedIn.AccessToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
	}
	// The token is signed and unexpired, but its session is over.
	for _, op := range protected[4:7] {
		e.wantUnauthenticated(e.call(op.method, op.path, signedIn.AccessToken, ""))
	}
	wantProblem(t, e.refresh(signedIn.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
}

func TestListShowsOnlyTheCallersActiveSessionsWithoutSecrets(t *testing.T) {
	e := newEnv(t)
	laptop, _ := e.signIn("alice@example.test")
	laptopID := e.sessionOf(laptop.AccessToken).String()
	e.clock.Advance(time.Hour)
	phone, _ := e.signIn("alice@example.test")
	phoneID := e.sessionOf(phone.AccessToken).String()
	e.signIn("bob@example.test")
	e.clock.Advance(time.Hour)
	tablet, _ := e.signIn("alice@example.test")
	if rec := e.call(http.MethodPost, "/v1/native/signout", tablet.AccessToken, ""); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	// The phone's old access token has expired; its refresh gives a fresh one and counts as activity.
	phone = decode[tokenResponse](t, e.refresh(phone.RefreshToken), http.StatusOK)

	for _, path := range []string{"/v1/sessions", "/v1/native/sessions"} {
		rec := e.call(http.MethodGet, path, phone.AccessToken, "")
		list := decode[listBody](t, rec, http.StatusOK)
		if len(list.Sessions) != 2 || list.Sessions[0].ID != phoneID || list.Sessions[1].ID != laptopID {
			t.Fatalf("%s = %+v, want the phone then the laptop", path, list.Sessions)
		}
		if !list.Sessions[0].Current || list.Sessions[1].Current {
			t.Errorf("%s: current flags = %v, %v", path, list.Sessions[0].Current, list.Sessions[1].Current)
		}
		raw := strings.ToLower(rec.Body.String())
		for _, leak := range []string{"hash", "binding", "refresh", "secret", "token", "alice@example.test"} {
			if strings.Contains(raw, leak) {
				t.Errorf("%s leaks %q: %s", path, leak, rec.Body)
			}
		}
	}
}

func TestRevokingAnotherSessionEndsItAndKeepsTheCaller(t *testing.T) {
	e := newEnv(t)
	laptop, _ := e.signIn("alice@example.test")
	phone, _ := e.signIn("alice@example.test")
	phoneID := e.sessionOf(phone.AccessToken).String()

	for _, path := range []string{"/v1/sessions/", "/v1/native/sessions/"} {
		if rec := e.call(http.MethodDelete, path+phoneID, laptop.AccessToken, ""); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("DELETE %s = %d %q", path, rec.Code, rec.Body)
		}
	}
	if !e.revoked(e.sessionOf(phone.AccessToken)) {
		t.Fatal("the session was not revoked")
	}
	e.wantUnauthenticated(e.call(http.MethodGet, "/v1/native/me", phone.AccessToken, ""))
	wantProblem(t, e.refresh(phone.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
	decode[meBody](t, e.call(http.MethodGet, "/v1/native/me", laptop.AccessToken, ""), http.StatusOK)
	decode[tokenResponse](t, e.refresh(laptop.RefreshToken), http.StatusOK)
}

func TestRevokingAForeignOrMissingSessionLooksLikeSuccessAndChangesNothing(t *testing.T) {
	e := newEnv(t)
	alice, _ := e.signIn("alice@example.test")
	mallory, _ := e.signIn("mallory@example.test")
	aliceID := e.sessionOf(alice.AccessToken).String()

	answers := map[string]int{}
	for name, id := range map[string]string{
		"someone else's session": aliceID,
		"unknown session":        "00000000-0000-4000-8000-0000000000ff",
		"malformed id":           "nope",
	} {
		rec := e.call(http.MethodDelete, "/v1/native/sessions/"+id, mallory.AccessToken, "")
		answers[name] = rec.Code
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Body)
		}
	}
	if e.revoked(e.sessionOf(alice.AccessToken)) || e.revoked(e.sessionOf(mallory.AccessToken)) {
		t.Error("a foreign revoke ended a session")
	}
	decode[tokenResponse](t, e.refresh(alice.RefreshToken), http.StatusOK)
}

func TestSignOutOfTheCurrentSessionKeepsTheDeviceRecognized(t *testing.T) {
	e := newEnv(t)
	laptop, laptopBinding := e.signIn("alice@example.test")
	phone, _ := e.signIn("alice@example.test")

	// An empty body means scope current without forgetting.
	if rec := e.call(http.MethodPost, "/v1/native/signout", laptop.AccessToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
	}
	if !e.revoked(e.sessionOf(laptop.AccessToken)) || e.revoked(e.sessionOf(phone.AccessToken)) {
		t.Error("the wrong sessions are revoked")
	}
	if !e.recognized("alice@example.test", laptopBinding) {
		t.Error("an ordinary sign-out forgot the device")
	}
	wantProblem(t, e.refresh(laptop.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
	decode[tokenResponse](t, e.refresh(phone.RefreshToken), http.StatusOK)
}

func TestSignOutWithForgetClientForgetsThisDeviceOnly(t *testing.T) {
	e := newEnv(t)
	laptop, laptopBinding := e.signIn("alice@example.test")
	_, phoneBinding := e.signIn("alice@example.test")

	rec := e.call(http.MethodPost, "/v1/native/signout", laptop.AccessToken, `{"scope": "current", "forget_client": true}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
	}
	if e.recognized("alice@example.test", laptopBinding) || !e.recognized("alice@example.test", phoneBinding) {
		t.Error("forget_client did not forget exactly this device")
	}
}

func TestSignOutEverywhereEndsEverySessionAndForgetsEveryDevice(t *testing.T) {
	e := newEnv(t)
	laptop, laptopBinding := e.signIn("alice@example.test")
	phone, phoneBinding := e.signIn("alice@example.test")
	bob, bobBinding := e.signIn("bob@example.test")

	if rec := e.call(http.MethodPost, "/v1/signout", laptop.AccessToken, `{"scope": "all"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
	}
	for name, tok := range map[string]tokenResponse{"laptop": laptop, "phone": phone} {
		if !e.revoked(e.sessionOf(tok.AccessToken)) {
			t.Errorf("the %s session survived", name)
		}
		wantProblem(t, e.refresh(tok.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
	}
	if e.recognized("alice@example.test", laptopBinding) || e.recognized("alice@example.test", phoneBinding) {
		t.Error("a device stayed recognized")
	}
	if e.revoked(e.sessionOf(bob.AccessToken)) || !e.recognized("bob@example.test", bobBinding) {
		t.Error("another user was affected")
	}
}

func TestSignOutRefusesAnUnknownScope(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	for _, body := range []string{`{"scope": "everything"}`, `{"scope": 1}`, `{"forget_client": "yes"}`, `[`} {
		wantProblem(t, e.call(http.MethodPost, "/v1/native/signout", signedIn.AccessToken, body), http.StatusBadRequest, "invalid_request")
	}
	if e.revoked(e.sessionOf(signedIn.AccessToken)) {
		t.Error("a malformed sign-out ended the session")
	}
}

func TestBrowserSignOutClearsTheCookies(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		body        string
		clearBinder bool
	}{
		"current":            {`{}`, false},
		"no body":            {``, false},
		"current and forget": {`{"forget_client": true}`, true},
		"everywhere":         {`{"scope": "all"}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBrowser(e)
			access := b.signIn(strings.ReplaceAll(name, " ", "-") + "@example.test")
			req := b.request(http.MethodPost, "/v1/signout", tc.body)
			req.Header.Set("Authorization", "Bearer "+access.AccessToken)
			rec := b.send(req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("sign out = %d %s", rec.Code, rec.Body)
			}
			cookies := setCookies(rec)
			refresh := cookies[httpapi.RefreshCookieName]
			if refresh == nil || refresh.MaxAge >= 0 || refresh.Value != "" || refresh.Path != "/v1/token" || !refresh.Secure || !refresh.HttpOnly {
				t.Errorf("the refresh cookie was not cleared: %+v", refresh)
			}
			binding := cookies[httpapi.BindingCookieName]
			if tc.clearBinder != (binding != nil) || (binding != nil && (binding.MaxAge >= 0 || binding.Path != "/v1/auth")) {
				t.Errorf("binding cookie = %+v, want cleared = %v", binding, tc.clearBinder)
			}
			// The cookie is gone, and the refresh it carried is dead.
			wantProblem(t, b.postRaw(browserRefresh, ""), http.StatusUnauthorized, "invalid_refresh")
		})
	}
}

func TestRevokingOwnSessionInTheBrowserClearsTheRefreshCookie(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	access := b.signIn("alice@example.test")
	req := b.request(http.MethodDelete, "/v1/sessions/"+e.sessionOf(access.AccessToken).String(), "")
	req.Header.Set("Authorization", "Bearer "+access.AccessToken)
	rec := b.send(req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if ck := setCookies(rec)[httpapi.RefreshCookieName]; ck == nil || ck.MaxAge >= 0 {
		t.Errorf("the refresh cookie was not cleared: %+v", ck)
	}
}

func TestStateChangingSessionRoutesRejectForeignPages(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	for _, op := range []struct{ method, path string }{
		{http.MethodPost, "/v1/signout"}, {http.MethodDelete, "/v1/sessions/00000000-0000-4000-8000-000000000001"},
		{http.MethodPost, "/v1/native/signout"}, {http.MethodDelete, "/v1/native/sessions/00000000-0000-4000-8000-000000000001"},
	} {
		req := httptest.NewRequest(op.method, op.path, nil)
		req.Header.Set("Authorization", "Bearer "+signedIn.AccessToken)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		wantProblem(t, e.do(req), http.StatusForbidden, "permission_denied")
	}
	if e.revoked(e.sessionOf(signedIn.AccessToken)) {
		t.Error("a foreign page ended the session")
	}
}

func TestPreflightAllowsDeleteAndAuthorizationForTrustedOrigins(t *testing.T) {
	e := newEnvWithOrigins(t, appOrigin)
	rec := e.preflight("/v1/sessions/00000000-0000-4000-8000-000000000001", appOrigin)
	h := rec.Header()
	if rec.Code != http.StatusNoContent || !strings.Contains(h.Get("Access-Control-Allow-Methods"), "DELETE") || !strings.Contains(h.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("preflight = %d %v", rec.Code, h)
	}
}

func TestSessionRoutesLeaveNoTokensInTheLogs(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	e.call(http.MethodGet, "/v1/native/me", signedIn.AccessToken, "")
	e.call(http.MethodGet, "/v1/native/me", "forged."+signedIn.AccessToken, "")
	e.call(http.MethodPost, "/v1/native/signout", signedIn.AccessToken, "")
	logs := e.logs.String()
	for _, secret := range []string{signedIn.AccessToken, signedIn.RefreshToken, "Bearer"} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs contain a secret: %s", secret[:min(len(secret), 12)])
		}
	}
}

func TestATechnicalFailureOfASessionRouteIsTemporarilyUnavailable(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")
	e.faults.wrap = func(s port.Stores) port.Stores { s.Sessions = failingSessions{s.Sessions}; return s }
	rec := e.call(http.MethodGet, "/v1/native/me", signedIn.AccessToken, "")
	wantProblem(t, rec, http.StatusServiceUnavailable, "temporarily_unavailable")
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("the response leaks the failure: %s", rec.Body)
	}
	e.faults.wrap = nil
	decode[meBody](t, e.call(http.MethodGet, "/v1/native/me", signedIn.AccessToken, ""), http.StatusOK)
}

type failingSessions struct{ port.SessionRepository }

func (failingSessions) Get(context.Context, session.ID) (*session.Session, error) {
	return nil, errBoom
}
