package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
	httpapi "airlance.org/auth/internal/transport/http"
)

const (
	browserStart   = "/v1/auth/email/start"
	browserVerify  = "/v1/auth/email/verify"
	browserResend  = "/v1/auth/email/resend"
	browserRefresh = "/v1/token/refresh"
	nativeResend   = "/v1/native/auth/email/resend"

	browserRegisterOptions = "/v1/auth/passkey/register/options"
	browserRegisterVerify  = "/v1/auth/passkey/register/verify"
	browserLoginOptions    = "/v1/auth/passkey/login/options"
	browserLoginVerify     = "/v1/auth/passkey/login/verify"
	browserRecoveryVerify  = "/v1/auth/recovery/verify"
)

// browser is a page of one origin with a cookie jar that obeys Path, Max-Age and Secure
// like a real one: a cookie is sent only to a path under its own.
type browser struct {
	e       *env
	cookies map[string]*http.Cookie
}

func newBrowser(e *env) *browser { return &browser{e: e, cookies: map[string]*http.Cookie{}} }

func (b *browser) request(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.Host)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, ck := range b.cookies {
		if strings.HasPrefix(path, ck.Path) {
			req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
	}
	return req
}

func (b *browser) send(req *http.Request) *httptest.ResponseRecorder {
	b.e.t.Helper()
	rec := b.e.do(req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(b.cookies, ck.Name)
		} else {
			b.cookies[ck.Name] = ck
		}
	}
	return rec
}

func (b *browser) post(path string, body any) *httptest.ResponseRecorder {
	b.e.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return b.send(b.request(http.MethodPost, path, string(data)))
}

func (b *browser) postRaw(path, body string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	return b.send(b.request(http.MethodPost, path, body))
}

type flowResponse struct {
	FlowID      string    `json:"flow_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	ResendAfter time.Time `json:"resend_after"`
}

type accessResponse struct {
	User *struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (b *browser) start(email string) flowResponse {
	b.e.t.Helper()
	return decode[flowResponse](b.e.t, b.post(browserStart, map[string]string{"email": email}), http.StatusAccepted)
}

// verifyStep proves the code of the flow and returns the next step the browser is told about.
func (b *browser) verifyStep(f flowResponse) nextStepResponse {
	b.e.t.Helper()
	return decode[nextStepResponse](b.e.t, b.post(browserVerify, map[string]string{"flow_id": f.FlowID, "code": b.e.code(f.FlowID)}), http.StatusOK)
}

// register runs the registration of a passkey with the ticket; the binding is the cookie.
func (b *browser) register(auth *testutil.SoftAuthenticator, ticket string, extra map[string]any) *httptest.ResponseRecorder {
	b.e.t.Helper()
	begun := decode[ceremonyResponse](b.e.t, b.post(browserRegisterOptions, map[string]string{"ticket": ticket}), http.StatusOK)
	body := map[string]any{"ticket": ticket, "challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Register(begun.Options))}
	for k, v := range extra {
		body[k] = v
	}
	return b.post(browserRegisterVerify, body)
}

// assert runs the passkey login; ticket may be empty.
func (b *browser) assert(auth *testutil.SoftAuthenticator, ticket string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	begun := decode[ceremonyResponse](b.e.t, b.post(browserLoginOptions, nil), http.StatusOK)
	body := map[string]any{"challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Assert(begun.Options))}
	if ticket != "" {
		body["ticket"] = ticket
	}
	return b.post(browserLoginVerify, body)
}

// signIn runs the whole browser sign-in: the email code, then a passkey. A user seen before
// proves the passkey they registered; a new one registers one.
func (b *browser) signIn(email string) accessResponse {
	b.e.t.Helper()
	step := b.verifyStep(b.start(email))
	if auth, ok := b.e.auths[email]; ok {
		return decode[accessResponse](b.e.t, b.assert(auth, step.Ticket), http.StatusOK)
	}
	auth := testutil.NewSoftAuthenticator(b.e.t, rpID, rpOrigin)
	b.e.auths[email] = auth
	return decode[accessResponse](b.e.t, b.register(auth, step.Ticket, nil), http.StatusOK)
}

func setCookies(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, ck := range rec.Result().Cookies() {
		out[ck.Name] = ck
	}
	return out
}

func TestBrowserStartSetsTheBindingCookieAndNeverPutsItInTheBody(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	rec := b.post(browserStart, map[string]string{"email": "alice@example.test"})
	res := decode[map[string]any](t, rec, http.StatusAccepted)

	if _, leaked := res["client_binding"]; leaked || len(res) != 3 {
		t.Errorf("body = %v, want flow_id, expires_at and resend_after only", res)
	}
	ck := setCookies(rec)[httpapi.BindingCookieName]
	if ck == nil || ck.Value == "" {
		t.Fatalf("no binding cookie: %v", rec.Header()["Set-Cookie"])
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/v1/auth" || ck.Domain != "" {
		t.Errorf("binding cookie = %+v, want HttpOnly, Secure, Strict, Path /v1/auth and no Domain", ck)
	}
	if want := int(identity.RecognitionTTL / time.Second); ck.MaxAge != want {
		t.Errorf("binding cookie Max-Age = %d, want %d", ck.MaxAge, want)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response may be cached")
	}

	// The next start of this browser reuses its binding and issues no new one.
	again := b.post(browserStart, map[string]string{"email": "alice@example.test"})
	decode[flowResponse](t, again, http.StatusAccepted)
	if len(again.Result().Cookies()) != 0 {
		t.Errorf("a browser with a binding got another: %v", again.Header()["Set-Cookie"])
	}
}

func TestBrowserVerifyOpensNoSessionAndSetsNoCookie(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	f := b.start("alice@example.test")
	rec := b.post(browserVerify, map[string]string{"flow_id": f.FlowID, "code": e.code(f.FlowID)})
	res := decode[map[string]any](t, rec, http.StatusOK)
	if len(res) != 3 || res["next"] != "enroll_passkey" || res["ticket"] == "" || res["expires_at"] == nil {
		t.Errorf("body = %v, want next, ticket and expires_at only", res)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("verify set cookies: %v", rec.Header()["Set-Cookie"])
	}
	if e.store.SessionCount() != 0 {
		t.Error("verify opened a session")
	}
}

func TestBrowserRegistrationSetsTheRefreshCookieAndKeepsItOutOfTheBody(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	step := b.verifyStep(b.start("alice@example.test"))
	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	rec := b.register(auth, step.Ticket, map[string]any{"device_name": "Alice's laptop", "name": "Laptop"})
	res := decode[accessResponse](t, rec, http.StatusOK)
	var codes struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &codes); err != nil || len(codes.RecoveryCodes) != 10 {
		t.Errorf("recovery codes = %v, %v", codes.RecoveryCodes, err)
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "refresh") || strings.Contains(raw, step.Ticket) {
		t.Errorf("the browser body mentions a refresh token: %s", raw)
	}
	claims, err := e.verifier.VerifyAccess(res.AccessToken)
	if err != nil || res.User == nil || claims.UserID.String() != res.User.ID || res.User.Email != "alice@example.test" {
		t.Errorf("claims = %+v (%v), user = %+v", claims, err, res.User)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}

	cookies := setCookies(rec)
	refresh := cookies[httpapi.RefreshCookieName]
	if refresh == nil || refresh.Value == "" {
		t.Fatalf("no refresh cookie: %v", rec.Header()["Set-Cookie"])
	}
	if !refresh.HttpOnly || !refresh.Secure || refresh.SameSite != http.SameSiteStrictMode || refresh.Path != "/v1/token" || refresh.Domain != "" {
		t.Errorf("refresh cookie = %+v, want HttpOnly, Secure, Strict, Path /v1/token and no Domain", refresh)
	}
	if want := t0.Add(30 * 24 * time.Hour); !refresh.Expires.Equal(want) {
		t.Errorf("refresh cookie expires %v, want %v: the token's own expiry", refresh.Expires, want)
	}
	if bind := cookies[httpapi.BindingCookieName]; bind == nil || bind.Value != b.cookies[httpapi.BindingCookieName].Value || bind.MaxAge <= 0 {
		t.Errorf("the binding cookie was not renewed with its own value: %+v", bind)
	}
	sess, ok := e.store.Session(claims.SessionID)
	if !ok || sess.DeviceName() != "Alice's laptop" {
		t.Errorf("session = %v, %v", sess, ok)
	}
}

func TestBrowserRefreshRotatesTheCookie(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	signedIn := b.signIn("alice@example.test")
	first := b.cookies[httpapi.RefreshCookieName].Value
	e.clock.Advance(time.Hour)

	rec := b.postRaw(browserRefresh, "")
	res := decode[accessResponse](t, rec, http.StatusOK)
	if res.AccessToken == "" || res.AccessToken == signedIn.AccessToken || res.User != nil || strings.Contains(rec.Body.String(), "refresh") {
		t.Errorf("refresh body = %s", rec.Body)
	}
	if !res.ExpiresAt.Equal(t0.Add(time.Hour + 5*time.Minute)) {
		t.Errorf("expires_at = %v", res.ExpiresAt)
	}
	next := setCookies(rec)[httpapi.RefreshCookieName]
	if next == nil || next.Value == "" || next.Value == first || !next.HttpOnly || !next.Secure || next.Path != "/v1/token" {
		t.Errorf("rotated cookie = %+v", next)
	}
	// The new cookie keeps working; the old value does not.
	decode[accessResponse](t, b.postRaw(browserRefresh, ""), http.StatusOK)
}

func TestBrowserRefreshReplayRevokesTheSessionAndClearsTheCookie(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	b.signIn("alice@example.test")
	stolen := b.cookies[httpapi.RefreshCookieName].Value
	decode[accessResponse](t, b.postRaw(browserRefresh, ""), http.StatusOK)

	// Another party replays the old cookie.
	thief := newBrowser(e)
	thief.cookies[httpapi.RefreshCookieName] = &http.Cookie{Name: httpapi.RefreshCookieName, Value: stolen, Path: "/v1/token"}
	rec := thief.postRaw(browserRefresh, "")
	wantProblem(t, rec, http.StatusUnauthorized, "invalid_refresh")
	if ck := setCookies(rec)[httpapi.RefreshCookieName]; ck == nil || ck.MaxAge >= 0 || ck.Value != "" {
		t.Errorf("a refused refresh did not clear the cookie: %+v", ck)
	}
	// The victim's newest cookie died with the session.
	wantProblem(t, b.postRaw(browserRefresh, ""), http.StatusUnauthorized, "invalid_refresh")
	if !strings.Contains(e.get("/metrics").Body.String(), "airlance_auth_refresh_reuse_total 1") {
		t.Error("the reuse is not counted")
	}
}

func TestBrowserRefreshWithoutACookieIsRefused(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test") // a native sign-in
	b := newBrowser(e)

	wantProblem(t, b.postRaw(browserRefresh, ""), http.StatusUnauthorized, "invalid_refresh")
	// A refresh token in the body is not read by the browser route.
	wantProblem(t, b.post(browserRefresh, map[string]string{"refresh_token": signedIn.RefreshToken}), http.StatusUnauthorized, "invalid_refresh")
	// The native session survived both.
	decode[tokenResponse](t, e.refresh(signedIn.RefreshToken), http.StatusOK)
}

func TestCookiesAreSentOnlyToTheirOwnPaths(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	b.signIn("alice@example.test")

	for _, tc := range []struct {
		cookie, path string
		sent         bool
	}{
		{httpapi.RefreshCookieName, browserRefresh, true},
		{httpapi.RefreshCookieName, browserStart, false},
		{httpapi.RefreshCookieName, browserVerify, false},
		{httpapi.RefreshCookieName, "/v1/native/token/refresh", false},
		{httpapi.RefreshCookieName, "/.well-known/jwks.json", false},
		{httpapi.BindingCookieName, browserStart, true},
		{httpapi.BindingCookieName, browserVerify, true},
		{httpapi.BindingCookieName, browserResend, true},
		{httpapi.BindingCookieName, browserRefresh, false},
		{httpapi.BindingCookieName, "/v1/native/auth/email/start", false},
	} {
		sent := false
		for _, c := range b.request(http.MethodPost, tc.path, "").Cookies() {
			sent = sent || c.Name == tc.cookie
		}
		if sent != tc.sent {
			t.Errorf("cookie %s to %s: sent = %v, want %v", tc.cookie, tc.path, sent, tc.sent)
		}
	}
}

func TestBrowserVerifyNeedsTheBindingOfTheStart(t *testing.T) {
	e := newEnv(t)
	owner, other := newBrowser(e), newBrowser(e)
	f := owner.start("alice@example.test")
	other.start("bob@example.test")
	code := e.code(f.FlowID)
	body := map[string]string{"flow_id": f.FlowID, "code": code}

	// No cookie, a cookie of another browser and a malformed cookie all give the same answer.
	nobody := newBrowser(e)
	wantProblem(t, nobody.post(browserVerify, body), http.StatusBadRequest, "invalid_code")
	wantProblem(t, other.post(browserVerify, body), http.StatusBadRequest, "invalid_code")
	forged := newBrowser(e)
	forged.cookies[httpapi.BindingCookieName] = &http.Cookie{Name: httpapi.BindingCookieName, Value: "x", Path: "/v1/auth/email"}
	wantProblem(t, forged.post(browserVerify, body), http.StatusBadRequest, "invalid_code")
	if e.store.SessionCount() != 0 {
		t.Fatal("a refused verify created a session")
	}

	// A binding smuggled into the body is not read by the browser route.
	smuggled := newBrowser(e)
	wantProblem(t, smuggled.post(browserVerify, map[string]string{
		"flow_id": f.FlowID, "code": code, "client_binding": owner.cookies[httpapi.BindingCookieName].Value,
	}), http.StatusBadRequest, "invalid_code")

	decode[accessResponse](t, owner.post(browserVerify, body), http.StatusOK)
}

func TestBrowserStartReplacesAMalformedBindingCookieAndIgnoresABodyBinding(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	b.cookies[httpapi.BindingCookieName] = &http.Cookie{Name: httpapi.BindingCookieName, Value: "short", Path: "/v1/auth/email"}
	rec := b.post(browserStart, map[string]string{"email": "alice@example.test"})
	decode[flowResponse](t, rec, http.StatusAccepted)
	if ck := setCookies(rec)[httpapi.BindingCookieName]; ck == nil || ck.Value == "short" || len(ck.Value) != 43 {
		t.Errorf("the malformed binding was not replaced: %+v", ck)
	}

	// A binding in the body does not become this browser's binding.
	fresh := newBrowser(e)
	rec = fresh.post(browserStart, map[string]string{"email": "bob@example.test", "client_binding": strings.Repeat("A", 43)})
	decode[flowResponse](t, rec, http.StatusAccepted)
	if ck := setCookies(rec)[httpapi.BindingCookieName]; ck == nil || ck.Value == strings.Repeat("A", 43) {
		t.Errorf("a binding from the body was adopted: %+v", ck)
	}
}

func TestBrowserStartRefusesMalformedInputAndSetsNoCookie(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	rec := b.post(browserStart, map[string]string{"email": "not-an-email"})
	wantProblem(t, rec, http.StatusBadRequest, "invalid_request")
	wantProblem(t, b.postRaw(browserStart, `{"email": `), http.StatusBadRequest, "invalid_request")
	if len(rec.Result().Cookies()) != 0 || e.store.FlowCount() != 0 {
		t.Error("a refused start set a cookie or stored a flow")
	}
}

func TestBrowserResend(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	f := b.start("alice@example.test")
	oldCode := e.code(f.FlowID)

	// Inside the pause.
	wantProblem(t, b.post(browserResend, map[string]string{"flow_id": f.FlowID}), http.StatusTooManyRequests, "rate_limited")

	e.clock.Advance(time.Minute)
	rec := b.post(browserResend, map[string]string{"flow_id": f.FlowID})
	res := decode[flowResponse](t, rec, http.StatusAccepted)
	if res.FlowID != f.FlowID || !res.ExpiresAt.Equal(f.ExpiresAt) || !res.ResendAfter.After(e.clock.Now()) {
		t.Errorf("resend = %+v, started %+v", res, f)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("resend set cookies: %v", rec.Header()["Set-Cookie"])
	}
	if jobs := e.store.OutboxJobs(); len(jobs) != 2 || jobs[1].Generation != 2 {
		t.Errorf("outbox = %+v", jobs)
	}
	if e.code(f.FlowID) == oldCode {
		t.Error("the code did not change")
	}

	// Without the binding, with another browser's binding and for an unknown flow: one answer.
	e.clock.Advance(time.Minute)
	stranger := newBrowser(e)
	stranger.start("bob@example.test")
	wantProblem(t, newBrowser(e).post(browserResend, map[string]string{"flow_id": f.FlowID}), http.StatusBadRequest, "invalid_code")
	wantProblem(t, stranger.post(browserResend, map[string]string{"flow_id": f.FlowID}), http.StatusBadRequest, "invalid_code")
	wantProblem(t, b.post(browserResend, map[string]string{"flow_id": "AAECAwQFBgcICQoLDA0ODw"}), http.StatusBadRequest, "invalid_code")
}

func TestNativeResend(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	e.clock.Advance(time.Minute)

	rec := e.post(nativeResend, map[string]string{"flow_id": started.FlowID, "client_binding": started.ClientBinding})
	res := decode[flowResponse](t, rec, http.StatusAccepted)
	if res.FlowID != started.FlowID || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("resend = %+v, headers %v", res, rec.Header())
	}
	e.clock.Advance(time.Minute)
	other := e.start("bob@example.test", "")
	wantProblem(t, e.post(nativeResend, map[string]string{"flow_id": started.FlowID, "client_binding": other.ClientBinding}), http.StatusBadRequest, "invalid_code")
	wantProblem(t, e.post(nativeResend, map[string]string{"flow_id": started.FlowID, "client_binding": "x"}), http.StatusBadRequest, "invalid_code")

	// The native route reads no cookie: a binding cookie is not a binding.
	req := httptest.NewRequest(http.MethodPost, nativeResend, strings.NewReader(`{"flow_id": "`+started.FlowID+`", "client_binding": ""}`))
	req.AddCookie(&http.Cookie{Name: httpapi.BindingCookieName, Value: started.ClientBinding})
	wantProblem(t, e.do(req), http.StatusBadRequest, "invalid_code")
}

func TestBrowserProfileLeavesNativeSecretsInJSONAlone(t *testing.T) {
	e := newEnv(t)
	rec := e.post(startPath, map[string]string{"email": "alice@example.test"})
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("a native route set cookies: %v", rec.Header()["Set-Cookie"])
	}
	signedIn, _ := e.signIn("alice@example.test")
	if len(e.refresh(signedIn.RefreshToken).Result().Cookies()) != 0 {
		t.Error("native refresh set a cookie")
	}
}
