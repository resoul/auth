package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

type optionsBody struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		Selection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

func TestNativePasskeyLifecycle(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")

	step := e.verifyStep(started.FlowID, started.ClientBinding)
	if step.Next != "enroll_passkey" {
		t.Fatalf("next = %q", step.Next)
	}

	// The options require user verification.
	begun := decode[ceremonyResponse](t, e.post(nativeRegisterOptions, map[string]string{"ticket": step.Ticket, "client_binding": started.ClientBinding}), http.StatusOK)

	var opts optionsBody
	if err := json.Unmarshal(begun.Options, &opts); err != nil {
		t.Fatal(err)
	}

	if opts.PublicKey.RP.ID != rpID || opts.PublicKey.Selection.ResidentKey != "required" || opts.PublicKey.Selection.UserVerification != "required" {
		t.Errorf("options = %+v", opts.PublicKey)
	}

	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	rec := e.post(nativeRegisterVerify, map[string]any{
		"ticket": step.Ticket, "client_binding": started.ClientBinding, "challenge_id": begun.ChallengeID,
		"credential": json.RawMessage(auth.Register(begun.Options)), "name": "Phone", "device_name": "Alice's phone",
	})

	registered := decode[registerResponse](t, rec, http.StatusOK)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response may be cached")
	}

	if registered.RefreshToken == "" || len(registered.RecoveryCodes) != 10 || registered.User.Email != "alice@example.test" {
		t.Errorf("registered = %+v", registered)
	}

	claims, err := e.verifier.VerifyAccess(registered.AccessToken)
	if err != nil || strings.Join(claims.AMR, ",") != "otp,passkey" {
		t.Errorf("claims = %+v, %v", claims, err)
	}

	// The same passkey signs in alone, from a client that has no binding yet.
	e.clock.Advance(time.Hour)

	login := decode[loginResponse](t, e.assert(auth, "", ""), http.StatusOK)
	if login.RefreshToken == "" || login.ClientBinding == "" || login.User.ID != registered.User.ID {
		t.Errorf("login = %+v", login)
	}

	claims, err = e.verifier.VerifyAccess(login.AccessToken)
	if err != nil || strings.Join(claims.AMR, ",") != "passkey" {
		t.Errorf("claims = %+v, %v", claims, err)
	}
	// A client that has a binding keeps it: none is issued.
	again := decode[loginResponse](t, e.assert(auth, "", login.ClientBinding), http.StatusOK)
	if again.ClientBinding != "" {
		t.Errorf("a client with a binding was given another: %q", again.ClientBinding)
	}

	// And the email code leads to the second factor, which the same passkey completes.
	second := e.start("alice@example.test", "")

	next := e.verifyStep(second.FlowID, second.ClientBinding)
	if next.Next != "second_factor" {
		t.Fatalf("next = %q", next.Next)
	}

	done := decode[loginResponse](t, e.assert(auth, next.Ticket, second.ClientBinding), http.StatusOK)

	claims, err = e.verifier.VerifyAccess(done.AccessToken)
	if err != nil || strings.Join(claims.AMR, ",") != "otp,passkey" {
		t.Errorf("claims = %+v, %v", claims, err)
	}

	if e.store.SessionCount() != 4 {
		t.Errorf("%d sessions, want 4", e.store.SessionCount())
	}
}

type loginResponse struct {
	tokenResponse
	ClientBinding string `json:"client_binding"`
}

// Every refusal of a proof is the same invalid_proof: the client never learns which part was wrong.
func TestPasskeyRefusalsLookAlike(t *testing.T) {
	e := newEnv(t)
	alice := e.start("alice@example.test", "")
	step := e.verifyStep(alice.FlowID, alice.ClientBinding)
	other := e.start("bob@example.test", "")
	aliceAuth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	begun := decode[ceremonyResponse](t, e.post(nativeRegisterOptions, map[string]string{"ticket": step.Ticket, "client_binding": alice.ClientBinding}), http.StatusOK)
	credential := json.RawMessage(aliceAuth.Register(begun.Options))
	unknown := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

	finish := func(ticket, binding, challenge string, cred json.RawMessage) *httptest.ResponseRecorder {
		return e.post(nativeRegisterVerify, map[string]any{"ticket": ticket, "client_binding": binding, "challenge_id": challenge, "credential": cred})
	}
	cases := map[string]*httptest.ResponseRecorder{
		"unknown ticket":      finish(unknown, alice.ClientBinding, begun.ChallengeID, credential),
		"malformed ticket":    finish("x", alice.ClientBinding, begun.ChallengeID, credential),
		"another binding":     finish(step.Ticket, other.ClientBinding, begun.ChallengeID, credential),
		"malformed binding":   finish(step.Ticket, "x", begun.ChallengeID, credential),
		"unknown challenge":   finish(step.Ticket, alice.ClientBinding, "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", credential),
		"malformed challenge": finish(step.Ticket, alice.ClientBinding, "x", credential),
		"empty credential":    finish(step.Ticket, alice.ClientBinding, begun.ChallengeID, json.RawMessage(`{}`)),
		"wrong origin": func() *httptest.ResponseRecorder {
			evil := testutil.NewSoftAuthenticator(t, rpID, "https://evil.test")
			b := decode[ceremonyResponse](t, e.post(nativeRegisterOptions, map[string]string{"ticket": step.Ticket, "client_binding": alice.ClientBinding}), http.StatusOK)

			return finish(step.Ticket, alice.ClientBinding, b.ChallengeID, json.RawMessage(evil.Register(b.Options)))
		}(),
		"unknown options ticket": e.post(nativeRegisterOptions, map[string]string{"ticket": unknown, "client_binding": alice.ClientBinding}),
		"recovery unknown ticket": e.post(nativeRecoveryVerify, map[string]string{
			"ticket": unknown, "client_binding": alice.ClientBinding, "code": "AAAA-AAAA-AAAA-AAAA",
		}),
		"login unknown challenge": e.post(nativeLoginVerify, map[string]any{
			"challenge_id": "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", "credential": credential,
		}),
		"login malformed ticket": e.post(nativeLoginVerify, map[string]any{
			"challenge_id": begun.ChallengeID, "credential": credential, "ticket": "x", "client_binding": alice.ClientBinding,
		}),
	}

	var first problem

	for name, rec := range cases {
		wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")

		p := decode[problem](t, rec, http.StatusBadRequest)
		if first.Code == "" {
			first = p
		}

		if strings.Count(rec.Body.String(), `"`) != strings.Count(cases["unknown ticket"].Body.String(), `"`) {
			t.Errorf("%s: the refusal body has another shape: %s", name, rec.Body)
		}
	}

	if e.store.SessionCount() != 0 {
		t.Error("a refused proof opened a session")
	}
	// Nothing above spent the ticket: the right proof still works.
	good := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	decode[registerResponse](t, e.register(good, step.Ticket, alice.ClientBinding), http.StatusOK)
}

func TestMalformedPasskeyRequestsAreInvalidRequests(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{nativeRegisterOptions, nativeRegisterVerify, nativeLoginVerify, nativeRecoveryVerify} {
		wantProblem(t, e.postRaw(path, "{"), http.StatusBadRequest, "invalid_request")
		wantProblem(t, e.postRaw(path, `{"ticket": 5}`), http.StatusBadRequest, "invalid_request")
	}
}

func TestPasskeyNamesAreValidated(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	step := e.verifyStep(started.FlowID, started.ClientBinding)

	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	for name, extra := range map[string]map[string]any{
		"long device name":     {"device_name": strings.Repeat("x", 65)},
		"long passkey name":    {"name": strings.Repeat("x", 65)},
		"control in the label": {"name": "a\nb"},
	} {
		wantProblem(t, e.registerWith(auth, step.Ticket, started.ClientBinding, extra), http.StatusBadRequest, "invalid_request")

		_ = name
	}
	// A refused label spent nothing.
	decode[registerResponse](t, e.registerWith(auth, step.Ticket, started.ClientBinding, map[string]any{"name": "Phone"}), http.StatusOK)
}

func TestNativeRecoveryEndsWithAWorkingPasskey(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	step := e.verifyStep(started.FlowID, started.ClientBinding)
	old := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	registered := decode[registerResponse](t, e.register(old, step.Ticket, started.ClientBinding), http.StatusOK)
	e.auths["alice@example.test"] = old

	// The device is lost: the email code asks for the second factor, and a recovery code answers.
	lost := e.start("alice@example.test", "")

	second := e.verifyStep(lost.FlowID, lost.ClientBinding)
	if second.Next != "second_factor" {
		t.Fatalf("next = %q", second.Next)
	}

	rec := e.post(nativeRecoveryVerify, map[string]string{"ticket": second.Ticket, "client_binding": lost.ClientBinding, "code": strings.ToLower(registered.RecoveryCodes[0])})

	enroll := decode[nextStepResponse](t, rec, http.StatusOK)
	if enroll.Next != "enroll_passkey" || enroll.Ticket == "" || enroll.Ticket == second.Ticket {
		t.Fatalf("recovery step = %+v", enroll)
	}

	fresh := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	recovered := decode[registerResponse](t, e.register(fresh, enroll.Ticket, lost.ClientBinding), http.StatusOK)

	claims, err := e.verifier.VerifyAccess(recovered.AccessToken)
	if err != nil || strings.Join(claims.AMR, ",") != "otp,recovery_code,passkey" {
		t.Errorf("claims = %+v, %v", claims, err)
	}
	// The code is spent, and the session of the lost device is gone.
	again := e.start("alice@example.test", "")
	third := e.verifyStep(again.FlowID, again.ClientBinding)
	wantProblem(t, e.post(nativeRecoveryVerify, map[string]string{"ticket": third.Ticket, "client_binding": again.ClientBinding, "code": registered.RecoveryCodes[0]}),
		http.StatusBadRequest, "invalid_proof")
	wantProblem(t, e.call(http.MethodGet, "/v1/native/me", registered.AccessToken, ""), http.StatusUnauthorized, "unauthenticated")
	decode[meBody](t, e.call(http.MethodGet, "/v1/native/me", recovered.AccessToken, ""), http.StatusOK)
}

func TestBrowserPasskeyLifecycle(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	f := b.start("alice@example.test")
	step := b.verifyStep(f)
	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	rec := b.register(auth, step.Ticket, nil)

	registered := decode[accessResponse](t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "refresh") || registered.AccessToken == "" {
		t.Errorf("body = %s", rec.Body)
	}

	refresh := b.cookies[httpapi.RefreshCookieName]
	if refresh == nil || !refresh.HttpOnly || !refresh.Secure {
		t.Fatalf("no safe refresh cookie: %+v", refresh)
	}

	// The passkey alone signs in again; the binding cookie of this browser is reused.
	binding := b.cookies[httpapi.BindingCookieName].Value

	e.clock.Advance(time.Hour)

	login := b.assert(auth, "")
	decode[accessResponse](t, login, http.StatusOK)

	if strings.Contains(login.Body.String(), "refresh") {
		t.Errorf("login body = %s", login.Body)
	}

	if got := b.cookies[httpapi.BindingCookieName].Value; got != binding {
		t.Error("a browser with a binding was given another")
	}

	if b.cookies[httpapi.RefreshCookieName].Value == refresh.Value {
		t.Error("a new session shares the refresh cookie of the old one")
	}

	// A browser with no cookies at all gets a binding and a refresh cookie from a passkey sign-in.
	fresh := newBrowser(e)
	decode[accessResponse](t, fresh.assert(auth, ""), http.StatusOK)

	if fresh.cookies[httpapi.BindingCookieName] == nil || fresh.cookies[httpapi.RefreshCookieName] == nil {
		t.Errorf("cookies = %v", fresh.cookies)
	}
}

func TestBrowserSecondFactorNeedsTheBindingCookieOfTheEmailProof(t *testing.T) {
	e := newEnv(t)
	owner := newBrowser(e)
	owner.signIn("alice@example.test")

	auth := e.auths["alice@example.test"]

	// Another browser proves the mailbox; its ticket is bound to its own binding cookie.
	thief := newBrowser(e)

	step := thief.verifyStep(thief.start("alice@example.test"))
	if step.Next != "second_factor" {
		t.Fatalf("next = %q", step.Next)
	}
	// Presented from a browser that does not hold that cookie, the ticket is useless.
	stranger := newBrowser(e)
	stranger.cookies[httpapi.BindingCookieName] = owner.cookies[httpapi.BindingCookieName]
	wantProblem(t, stranger.assert(auth, step.Ticket), http.StatusBadRequest, "invalid_proof")

	empty := newBrowser(e)
	wantProblem(t, empty.assert(auth, step.Ticket), http.StatusBadRequest, "invalid_proof")
	// The browser that proved the mailbox can finish.
	decode[accessResponse](t, thief.assert(auth, step.Ticket), http.StatusOK)
}

func TestBrowserRecovery(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	step := b.verifyStep(b.start("alice@example.test"))
	registered := b.register(testutil.NewSoftAuthenticator(t, rpID, rpOrigin), step.Ticket, nil)

	var codes struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &codes); err != nil || len(codes.RecoveryCodes) != 10 {
		t.Fatalf("codes = %v, %v", codes.RecoveryCodes, err)
	}

	lost := newBrowser(e)
	second := lost.verifyStep(lost.start("alice@example.test"))

	next := decode[nextStepResponse](t, lost.post(browserRecoveryVerify, map[string]string{"ticket": second.Ticket, "code": codes.RecoveryCodes[3]}), http.StatusOK)
	if next.Next != "enroll_passkey" {
		t.Fatalf("next = %q", next.Next)
	}

	if len(lost.cookies) != 1 {
		t.Errorf("recovery must set no session cookie: %v", lost.cookies)
	}

	fresh := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	decode[accessResponse](t, lost.register(fresh, next.Ticket, nil), http.StatusOK)

	if lost.cookies[httpapi.RefreshCookieName] == nil {
		t.Error("no refresh cookie after recovery")
	}
	// A wrong code is the same invalid_proof, whatever it looked like.
	again := newBrowser(e)
	third := again.verifyStep(again.start("alice@example.test"))
	wantProblem(t, again.post(browserRecoveryVerify, map[string]string{"ticket": third.Ticket, "code": "AAAA-AAAA-AAAA-AAAA"}), http.StatusBadRequest, "invalid_proof")
}

func TestPasskeyRoutesRefuseForeignPagesWithoutSideEffects(t *testing.T) {
	e := newEnvWithOrigins(t)
	b := newBrowser(e)
	step := b.verifyStep(b.start("alice@example.test"))
	req := httptest.NewRequest(http.MethodPost, browserRegisterOptions, strings.NewReader(`{"ticket":"`+step.Ticket+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	for _, ck := range b.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}

	rec := e.do(req)
	wantProblem(t, rec, http.StatusForbidden, "permission_denied")

	if len(rec.Result().Cookies()) != 0 {
		t.Error("a refused request set a cookie")
	}
}

func TestBindingCookieTravelsToEveryBrowserSignInRoute(t *testing.T) {
	e := newEnv(t)
	b := newBrowser(e)
	b.start("alice@example.test")

	for _, path := range []string{browserStart, browserVerify, browserResend, browserRegisterOptions, browserRegisterVerify, browserLoginVerify, browserRecoveryVerify} {
		if !strings.HasPrefix(path, b.cookies[httpapi.BindingCookieName].Path) {
			t.Errorf("the binding cookie (path %s) does not reach %s", b.cookies[httpapi.BindingCookieName].Path, path)
		}
	}

	for _, path := range []string{browserRefresh, "/v1/me", "/v1/sessions", "/v1/signout"} {
		if strings.HasPrefix(path, b.cookies[httpapi.BindingCookieName].Path) {
			t.Errorf("the binding cookie reaches %s, which has no use for it", path)
		}
	}
}

func TestStartingCeremoniesOverTheBudgetIsRateLimitedInBothProfiles(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.PasskeyIP: {{Limit: 2, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{nativeLoginOptions, browserLoginOptions} {
		e := newEnv(t, memory.WithQuota(profile)) // one budget per route, so each profile is checked alone
		b := newBrowser(e)

		post := func() *httptest.ResponseRecorder {
			if path == browserLoginOptions {
				return b.post(path, nil)
			}

			return e.post(path, nil)
		}
		for range 2 {
			decode[ceremonyResponse](t, post(), http.StatusOK)
		}

		rec := post()
		wantProblem(t, rec, http.StatusTooManyRequests, "rate_limited")

		if strings.Contains(rec.Body.String(), "challenge") {
			t.Errorf("%s: a refused start hands out a challenge: %s", path, rec.Body)
		}
	}

	// The registration of one ticket is limited too.
	profile, err = quota.NewProfile(map[quota.Scope][]quota.Window{quota.PasskeyRef: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	e := newEnv(t, memory.WithQuota(profile))
	started := e.start("alice@example.test", "")
	step := e.verifyStep(started.FlowID, started.ClientBinding)
	body := map[string]string{"ticket": step.Ticket, "client_binding": started.ClientBinding}
	decode[ceremonyResponse](t, e.post(nativeRegisterOptions, body), http.StatusOK)
	wantProblem(t, e.post(nativeRegisterOptions, body), http.StatusTooManyRequests, "rate_limited")
}
