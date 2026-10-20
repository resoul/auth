package admin_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/testutil"
	adminhttp "go.airlance.org/auth/internal/transport/http/admin"
)

const api = "/admin/api/v1"

func TestSignInOverHTTPSetsAHardenedCookieAndShowsTheSession(t *testing.T) {
	e := newEnv(t)
	key := e.enrolled("Ops@Example.test")

	res := e.login(key)
	if res.status != http.StatusOK {
		t.Fatalf("login/finish = %d %s", res.status, res.body)
	}

	var body struct {
		Operator  struct{ ID, Email string } `json:"operator"`
		CSRFToken string                     `json:"csrf_token"`
		ExpiresAt time.Time                  `json:"expires_at"`
	}
	res.json(t, &body)

	if body.Operator.Email != "ops@example.test" || len(body.CSRFToken) != 64 || !body.ExpiresAt.After(t0) {
		t.Errorf("body = %+v", body)
	}

	var set *http.Cookie

	for _, c := range (&http.Response{Header: res.header}).Cookies() {
		if c.Name == adminhttp.CookieName {
			set = c
		}
	}

	if set == nil {
		t.Fatal("no session cookie")
	}

	if !set.HttpOnly || set.SameSite != http.SameSiteStrictMode || set.Path != "/admin" || set.MaxAge != int(operator.MaxAge/time.Second) || set.Value == "" {
		t.Errorf("cookie = %+v", set)
	}

	if set.Secure {
		t.Error("a plain-http (localhost) origin got a Secure cookie that the browser would drop")
	}

	if strings.Contains(string(res.body), set.Value) {
		t.Error("the session secret is in the response body, where scripts can read it")
	}

	e.csrf = body.CSRFToken

	session := e.get(api + "/session")
	if session.status != http.StatusOK {
		t.Fatalf("session = %d %s", session.status, session.body)
	}

	var again struct {
		CSRFToken string `json:"csrf_token"`
	}
	session.json(t, &again)

	if again.CSRFToken != body.CSRFToken {
		t.Error("the session endpoint hands out another CSRF token than sign-in did")
	}
}

func TestCookieIsSecureOnAnHTTPSOrigin(t *testing.T) {
	e := newEnvScheme(t, "https")

	res := e.login(e.enrolled("ops@example.test"))
	if res.status != http.StatusOK {
		t.Fatalf("login/finish = %d %s", res.status, res.body)
	}

	for _, c := range (&http.Response{Header: res.header}).Cookies() {
		if c.Name == adminhttp.CookieName {
			if !c.Secure {
				t.Error("the session cookie of an https origin is not Secure")
			}

			return
		}
	}

	t.Fatal("no session cookie")
}

func TestNewRefusesMissingPiecesAndBadOrigins(t *testing.T) {
	if h, err := adminhttp.New(adminhttp.Deps{}); err == nil || h != nil {
		t.Error("New accepted no dependencies")
	}

	e := newEnv(t)
	d := e.deps

	d.Origins = nil
	if _, err := adminhttp.New(d); err == nil {
		t.Error("New accepted no origin")
	}

	for _, bad := range []string{"localhost:8080", "http://localhost:8080/path", "https://u:p@example.test", "https://example.test?x=1", "not a url", "*"} {
		d.Origins = []string{bad}
		if _, err := adminhttp.New(d); err == nil {
			t.Errorf("New accepted the origin %q", bad)
		}
	}
}

func TestEverythingButSignInNeedsASession(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/session"}, {"POST", "/logout"}, {"GET", "/users"}, {"GET", "/users/00000000-0000-4000-8000-000000000001"},
		{"POST", "/users/00000000-0000-4000-8000-000000000001/block"}, {"POST", "/users/00000000-0000-4000-8000-000000000001/unblock"},
		{"POST", "/users/00000000-0000-4000-8000-000000000001/revoke-sessions"}, {"POST", "/users/00000000-0000-4000-8000-000000000001/delete"},
		{"GET", "/invitations"}, {"POST", "/invitations"}, {"POST", "/invitations/revoke"}, {"GET", "/audit"},
	} {
		res := e.send(request{method: tc.method, path: api + tc.path, body: map[string]string{}})
		if res.status != http.StatusUnauthorized || res.errorCode() != "unauthenticated" {
			t.Errorf("%s %s = %d %s", tc.method, tc.path, res.status, res.body)
		}
	}
}

func TestACookieThatIsNotASessionIsRefusedAndCleared(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	e.client.Jar.SetCookies(mustURL(t, e.server.URL+"/admin/"), []*http.Cookie{{Name: adminhttp.CookieName, Value: "garbage", Path: "/admin"}})

	res := e.get(api + "/users")
	if res.status != http.StatusUnauthorized {
		t.Fatalf("status = %d", res.status)
	}

	cleared := false

	for _, c := range (&http.Response{Header: res.header}).Cookies() {
		if c.Name == adminhttp.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}

	if !cleared {
		t.Error("a refused session cookie was not cleared")
	}
}

func TestChangesNeedTheOriginAndTheCSRFToken(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	target := e.user("target@example.test")
	path := api + "/users/" + target.ID().String() + "/block"

	cases := map[string]struct {
		header map[string]*string
		status int
		code   string
	}{
		"no origin":          {map[string]*string{"Origin": nil}, 403, "bad_origin"},
		"another origin":     {map[string]*string{"Origin": str("https://evil.example")}, 403, "bad_origin"},
		"origin with a path": {map[string]*string{"Origin": str(e.origin + "/")}, 403, "bad_origin"},
		"no csrf token":      {map[string]*string{"X-CSRF-Token": nil}, 403, "bad_csrf"},
		"wrong csrf token":   {map[string]*string{"X-CSRF-Token": str(strings.Repeat("0", 64))}, 403, "bad_csrf"},
		"short csrf token":   {map[string]*string{"X-CSRF-Token": str("x")}, 403, "bad_csrf"},
	}
	for name, tc := range cases {
		// The helper adds the token unless the case removes it.
		h := tc.header
		if _, ok := h["X-CSRF-Token"]; !ok {
			h["X-CSRF-Token"] = str(e.csrf)
		}

		res := e.send(request{method: "POST", path: path, header: h})
		if res.status != tc.status || res.errorCode() != tc.code {
			t.Errorf("%s: %d %s", name, res.status, res.body)
		}
	}
	// None of the refused requests blocked anyone.
	if got := e.get(api + "/users/" + target.ID().String()); !strings.Contains(string(got.body), `"blocked_at":null`) {
		t.Errorf("a refused request blocked the user: %s", got.body)
	}

	if res := e.post("/admin/api/v1/users/"+target.ID().String()+"/block", nil); res.status != http.StatusNoContent {
		t.Errorf("the same request done properly = %d %s", res.status, res.body)
	}
}

func TestSignInEndpointsNeedTheOriginToo(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/enroll/begin", "/enroll/finish", "/login/begin", "/login/finish"} {
		res := e.send(request{method: "POST", path: api + path, body: map[string]string{}, header: map[string]*string{"Origin": str("https://evil.example")}})
		if res.status != http.StatusForbidden || res.errorCode() != "bad_origin" {
			t.Errorf("%s = %d %s", path, res.status, res.body)
		}
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")

	if res := e.post(api+"/logout", nil); res.status != http.StatusNoContent {
		t.Fatalf("logout = %d %s", res.status, res.body)
	}

	if res := e.get(api + "/session"); res.status != http.StatusUnauthorized {
		t.Errorf("the session survived logout: %d", res.status)
	}
}

func TestAnIdleSessionEnds(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	e.clock.Advance(operator.IdleTimeout)

	if res := e.get(api + "/session"); res.status != http.StatusUnauthorized {
		t.Errorf("an idle session still works: %d", res.status)
	}
}

func TestEveryRefusalOfASignInLooksTheSame(t *testing.T) {
	e := newEnv(t)
	member := e.enrolled("ops@example.test")
	off := e.enrolled("off@example.test")
	cloned := e.enrolled("cloned@example.test")
	_, err := e.operators.SetDisabled(t.Context(), "off@example.test", true)
	must(t, err)

	cloned.SignCount = 10
	if res := e.login(cloned); res.status != http.StatusOK {
		t.Fatalf("a first sign-in of the key to be cloned: %d %s", res.status, res.body)
	}

	cloned.SignCount = 3 // the counter goes back
	stranger := testutil.NewSoftAuthenticator(t, rpID, e.origin)
	stranger.UserHandle = []byte("0123456789abcdef")

	refusals := map[string]reply{
		"unknown challenge": e.post(api+"/login/finish", map[string]any{"challenge_id": "0199c0de-0000-7000-8000-000000000001", "response": map[string]string{}}),
		"malformed id":      e.post(api+"/login/finish", map[string]any{"challenge_id": "nope", "response": map[string]string{}}),
		"unknown key":       e.login(stranger),
		"disabled operator": e.login(off),
		"copied key":        e.login(cloned),
	}
	strip := func(r reply) string {
		s := string(r.body)
		if i := strings.Index(s, `"request_id"`); i >= 0 {
			s = s[:i]
		}

		return s
	}

	want := strip(refusals["unknown key"])
	for name, r := range refusals {
		if r.status != http.StatusUnauthorized || r.errorCode() != "refused" || strip(r) != want {
			t.Errorf("%s: %d %s (want the body %s)", name, r.status, r.body, want)
		}
	}
	// The operator sees why, in the metrics only.
	reasons := map[string]bool{}
	for _, d := range e.metrics.denied {
		reasons[d] = true
	}

	for _, d := range []string{"admin_login_finish/bad_challenge", "admin_login_finish/ceremony_failed", "admin_login_finish/operator_disabled", "admin_login_finish/clone_suspected"} {
		if !reasons[d] {
			t.Errorf("denial %q was not reported; got %v", d, e.metrics.denied)
		}
	}
	// And the member still signs in: nothing above locked anything.
	if res := e.login(member); res.status != http.StatusOK {
		t.Errorf("a good sign-in after the refusals = %d", res.status)
	}
}

func TestEnrollmentRefusalsLookTheSameAndTheCodeIsNeverEchoed(t *testing.T) {
	e := newEnv(t)
	for _, code := range []string{"", "short", strings.Repeat("A", 43)} {
		res := e.post(api+"/enroll/begin", map[string]string{"code": code})
		if res.status != http.StatusUnauthorized || res.errorCode() != "refused" || strings.Contains(string(res.body), code+"\"") && code != "" {
			t.Errorf("code %q: %d %s", code, res.status, res.body)
		}
	}
}

func TestMalformedRequestsAreRefusedBeforeAnyWork(t *testing.T) {
	e := newEnv(t)

	cases := map[string]struct {
		request
		status int
		code   string
	}{
		"not json":           {request{method: "POST", path: api + "/enroll/begin", raw: "{nope"}, 400, "invalid_request"},
		"unknown field":      {request{method: "POST", path: api + "/enroll/begin", raw: `{"code":"x","extra":1}`}, 400, "invalid_request"},
		"two values":         {request{method: "POST", path: api + "/enroll/begin", raw: `{"code":"x"}{"code":"y"}`}, 400, "invalid_request"},
		"wrong content type": {request{method: "POST", path: api + "/enroll/begin", raw: `{"code":"x"}`, header: map[string]*string{"Content-Type": str("text/plain")}}, 415, "unsupported_media_type"},
		"no content type":    {request{method: "POST", path: api + "/enroll/begin", raw: `{"code":"x"}`, header: map[string]*string{"Content-Type": nil}}, 415, "unsupported_media_type"},
		"too large":          {request{method: "POST", path: api + "/enroll/begin", raw: `{"code":"` + strings.Repeat("a", 70<<10) + `"}`}, 413, "too_large"},
		"unknown route":      {request{method: "GET", path: api + "/nothing"}, 404, "not_found"},
		"outside the api":    {request{method: "GET", path: "/"}, 404, "not_found"},
		"wrong method":       {request{method: "GET", path: api + "/login/begin"}, 404, "not_found"},
	}
	for name, tc := range cases {
		res := e.send(tc.request)
		if res.status != tc.status || res.errorCode() != tc.code {
			t.Errorf("%s: %d %s", name, res.status, res.body)
		}
	}
}

func TestResponsesAreNeverCachedOrFramedAndCarryARequestID(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")

	for _, path := range []string{api + "/session", api + "/users", api + "/nothing"} {
		res := e.get(path)

		h := res.header
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			h.Get("X-Request-Id") == "" || h.Get("Content-Type") != "application/json" {
			t.Errorf("%s headers = %v", path, h)
		}
	}
}

func TestRequestsAreCountedByTheirRoutePattern(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	target := e.user("target@example.test")
	e.get(api + "/users/" + target.ID().String())

	found := false

	for _, r := range e.metrics.routes {
		if strings.Contains(r, target.ID().String()) {
			t.Errorf("a route label holds an identifier: %q", r)
		}

		if r == "GET /admin/api/v1/users/{id}" {
			found = true
		}
	}

	if !found {
		t.Errorf("routes = %v", e.metrics.routes)
	}
}

func TestThePageIsServedBelowAdminAndNeverShadowsTheAPI(t *testing.T) {
	e := newEnv(t)
	d := e.deps
	d.UI = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("the page")) })
	handler, err := adminhttp.New(d)
	must(t, err)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	get := func(path string) (int, string, http.Header) {
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(srv.URL + path)
		must(t, err)

		defer func() { _ = resp.Body.Close() }()

		b, err := io.ReadAll(resp.Body)
		must(t, err)

		return resp.StatusCode, string(b), resp.Header
	}
	if status, body, h := get("/admin/"); status != 200 || body != "the page" || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("/admin/ = %d %q %v", status, body, h)
	}
	// An unknown API path is the API's JSON 404, not the page, and the API still answers.
	if status, body, h := get(api + "/nothing"); status != 404 || !strings.Contains(body, `"not_found"`) || h.Get("Cache-Control") != "no-store" {
		t.Errorf("unknown api path = %d %q", status, body)
	}

	if status, _, _ := get(api + "/session"); status != http.StatusUnauthorized {
		t.Errorf("the API behind the page = %d", status)
	}

	if status, _, h := get("/admin"); status != http.StatusMovedPermanently || h.Get("Location") != "/admin/" {
		t.Errorf("/admin = %d, Location %q", status, h.Get("Location"))
	}

	if status, body, _ := get("/admin/other"); status != 404 || !strings.Contains(body, `"not_found"`) {
		t.Errorf("/admin/other = %d %q", status, body)
	}
	// Without a page there is nothing below /admin/.
	if r := e.get("/admin/"); r.status != http.StatusNotFound {
		t.Errorf("/admin/ without a page = %d", r.status)
	}
}
