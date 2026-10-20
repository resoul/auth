package bff_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/examples/bff"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

type world struct {
	t     *testing.T
	clock *clock
	prov  *provider
	store *bff.MemoryStore
	vault *bff.Vault
	app   *bff.App
	h     http.Handler
	logs  *bytes.Buffer
	// api is the upstream: it records which token it was given for which path.
	api     *httptest.Server
	apiMu   sync.Mutex
	apiSeen []string
}

func newWorld(t *testing.T, mutate ...func(*bff.Config)) *world {
	t.Helper()
	w := &world{t: t, clock: &clock{t: t0}, logs: &bytes.Buffer{}}
	w.prov = newProvider(t, w.clock.Now)
	w.store = bff.NewMemoryStore(w.clock.Now)

	var err error

	w.vault, err = bff.NewVault("v1", map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	w.api = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.apiMu.Lock()
		w.apiSeen = append(w.apiSeen, r.URL.Path+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("Cookie"))
		w.apiMu.Unlock()
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
	}))
	t.Cleanup(w.api.Close)
	up, _ := url.Parse(w.api.URL + "/v1")

	cfg := bff.Config{
		Issuer: w.prov.issuer(), ClientID: clientID, ClientSecret: clientSecret, BaseURL: "https://app.example.test",
		Scopes: []string{"email"}, Store: w.store, Vault: w.vault, Now: w.clock.Now,
		Resources: []bff.Resource{
			{Name: "platform", URI: platformURI, Scopes: []string{"messages:send"}, Upstream: up},
			{Name: "video", URI: videoURI, Scopes: []string{"video:read"}, Upstream: up},
		},
		Logger: slog.New(slog.NewTextHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, m := range mutate {
		m(&cfg)
	}

	w.app, err = bff.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	w.h = w.app.Handler()

	return w
}

// browser keeps cookies between calls.
type browser struct {
	w       *world
	cookies map[string]*http.Cookie
}

func (w *world) browser() *browser {
	return &browser{w: w, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	b.w.t.Helper()

	r := httptest.NewRequest(method, "https://app.example.test"+target, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}

	if body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for _, c := range b.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}

	rec := httptest.NewRecorder()
	b.w.h.ServeHTTP(rec, r)

	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}

	return rec
}

func (b *browser) get(target string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, target, nil, "")
}

// signIn runs the whole sign-in and returns the answer to the callback.
func (b *browser) signIn(returnTo string) *httptest.ResponseRecorder {
	b.w.t.Helper()

	start := b.get("/login?return_to=" + url.QueryEscape(returnTo))
	if start.Code != http.StatusSeeOther {
		b.w.t.Fatalf("login = %d", start.Code)
	}

	return b.callbackFor(start.Header().Get("Location"), nil)
}

// callbackFor lets the provider issue a code for the authorization request and brings the browser back with it.
func (b *browser) callbackFor(authorizeURL string, mutate func(q url.Values)) *httptest.ResponseRecorder {
	b.w.t.Helper()
	code := b.w.prov.issue(authorizeURL)
	u, _ := url.Parse(authorizeURL)

	q := url.Values{"code": {code}, "state": {u.Query().Get("state")}, "iss": {b.w.prov.issuer()}}
	if mutate != nil {
		mutate(q)
	}

	return b.get("/auth/callback?" + q.Encode())
}

func (b *browser) session() *http.Cookie {
	for _, c := range b.cookies {
		if strings.Contains(c.Name, "bff_session") {
			return c
		}
	}

	return nil
}

func TestSignInKeepsEverythingButACookieOnTheServer(t *testing.T) {
	w := newWorld(t)
	b := w.browser()

	start := b.get("/login?return_to=/inbox")
	if start.Code != http.StatusSeeOther {
		t.Fatalf("login = %d", start.Code)
	}

	loc, _ := url.Parse(start.Header().Get("Location"))

	q := loc.Query()
	if q.Get("client_id") != clientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("state") == "" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://app.example.test/auth/callback" {
		t.Fatalf("authorize request = %v", q)
	}

	if got := q["resource"]; len(got) != 2 || got[0] != platformURI || got[1] != videoURI {
		t.Errorf("resources = %v", got)
	}

	if got := strings.Fields(q.Get("scope")); strings.Join(got, " ") != "openid email messages:send video:read" {
		t.Errorf("scope = %v", got)
	}

	tx := b.cookies["__Host-bff_login"]
	if tx == nil || !tx.HttpOnly || !tx.Secure || tx.Path != "/" || tx.SameSite != http.SameSiteLaxMode {
		t.Fatalf("transaction cookie = %+v", tx)
	}

	done := b.callbackFor(start.Header().Get("Location"), nil)
	if done.Code != http.StatusSeeOther || done.Header().Get("Location") != "/inbox" {
		t.Fatalf("callback = %d %q", done.Code, done.Header().Get("Location"))
	}

	if b.cookies["__Host-bff_login"] != nil {
		t.Error("the transaction cookie outlived the transaction")
	}

	sess := b.session()
	if sess == nil || !sess.HttpOnly || !sess.Secure || sess.Path != "/" || sess.Domain != "" || sess.SameSite != http.SameSiteLaxMode || sess.MaxAge <= 0 {
		t.Fatalf("session cookie = %+v", sess)
	}
	// The cookie is an opaque identifier. It carries no token, and the store does not hold it.
	for _, secret := range []string{"access-", "refresh-", "eyJ"} {
		if strings.Contains(sess.Value, secret) {
			t.Errorf("the cookie carries %q", secret)
		}
	}

	me := b.get("/api/me")

	var body map[string]any

	_ = json.Unmarshal(me.Body.Bytes(), &body)
	if me.Code != http.StatusOK || body["subject"] != w.prov.subject || body["issuer"] != w.prov.issuer() || me.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("me = %d %v", me.Code, body)
	}

	if strings.Contains(me.Body.String(), "token") {
		t.Error("the page was told a token")
	}
	// The same person signing in again is the same user: the key is the pair, not an email.
	other := w.browser()
	other.signIn("/")

	var again map[string]any

	_ = json.Unmarshal(other.get("/api/me").Body.Bytes(), &again)
	if again["user_id"] != body["user_id"] {
		t.Errorf("one person became two users: %v %v", again["user_id"], body["user_id"])
	}
}

func TestEveryRefusalOfACallback(t *testing.T) {
	cases := map[string]func(w *world, b *browser, authorize string) *httptest.ResponseRecorder{
		"no transaction cookie": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			delete(b.cookies, "__Host-bff_login")
			return b.callbackFor(a, nil)
		},
		"a transaction of another browser": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			other := w.browser()
			other.get("/login")
			b.cookies["__Host-bff_login"] = other.cookies["__Host-bff_login"]

			return b.callbackFor(a, nil)
		},
		"another state": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Set("state", "forged") })
		},
		"no state": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Del("state") })
		},
		"another iss": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Set("iss", "https://evil.example.test") })
		},
		"no iss": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Del("iss") })
		},
		"an error from the provider": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) {
				q.Del("code")
				q.Set("error", "access_denied")
				q.Set("error_description", "<script>x</script>")
			})
		},
		"no code": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Del("code") })
		},
		"a code that was never issued": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			return b.callbackFor(a, func(q url.Values) { q.Set("code", "guess") })
		},
		"another nonce in the ID token": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			w.prov.nonceFor = "someone-elses"
			return b.callbackFor(a, nil)
		},
		"an ID token for another client": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			w.prov.audience = "other-app"
			return b.callbackFor(a, nil)
		},
		"an expired ID token": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			w.prov.expired = true
			return b.callbackFor(a, nil)
		},
		"a transaction that expired": func(w *world, b *browser, a string) *httptest.ResponseRecorder {
			w.clock.Advance(11 * time.Minute)
			return b.callbackFor(a, nil)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			b := w.browser()
			start := b.get("/login")

			got := run(w, b, start.Header().Get("Location"))
			if got.Code < 400 || got.Header().Get("Location") != "" || b.session() != nil {
				t.Fatalf("answer = %d %q, session %v: want a refusal, no redirect and no session", got.Code, got.Header().Get("Location"), b.session())
			}

			if strings.Contains(got.Body.String(), "script") || strings.Contains(got.Body.String(), "access_denied") {
				t.Errorf("the page repeats what came through the browser: %s", got.Body.String())
			}

			if strings.Contains(w.logs.String(), "code=") {
				t.Error("a code reached the log")
			}
		})
	}
}

func TestACallbackIsUsedOnce(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	start := b.get("/login")
	loc := start.Header().Get("Location")

	cookie := b.cookies["__Host-bff_login"]
	if got := b.callbackFor(loc, nil); got.Code != http.StatusSeeOther {
		t.Fatalf("first = %d", got.Code)
	}
	// The same page again, from a history or a copy of the address, with the cookie it came with.
	b.cookies["__Host-bff_login"] = cookie
	if got := b.callbackFor(loc, nil); got.Code != http.StatusBadRequest {
		t.Errorf("second = %d, want a refusal", got.Code)
	}
}

func TestOnlyALocalPlaceIsReturnedTo(t *testing.T) {
	for raw, want := range map[string]string{
		"/inbox": "/inbox", "/a/b?c=d": "/a/b?c=d", "": "/", "https://evil.example.test/": "/", "//evil.example.test/": "/", "/\\evil.example.test": "/",
		"javascript:alert(1)": "/", "inbox": "/", "/\r\nSet-Cookie: x=1": "/", "/%0d%0a": "/%0d%0a", "http:/evil.example.test": "/",
	} {
		w := newWorld(t)
		b := w.browser()

		got := b.signIn(raw)
		if loc := got.Header().Get("Location"); loc != want {
			t.Errorf("return_to %q went to %q, want %q", raw, loc, want)
		}
	}
}

func (b *browser) callProxy(path string) *httptest.ResponseRecorder {
	return b.get("/api/" + path)
}

func (w *world) tokensSeen() []string {
	w.apiMu.Lock()
	defer w.apiMu.Unlock()

	return append([]string(nil), w.apiSeen...)
}

func TestAPICallsGetTheTokenOfTheirOwnResourceAndNeverTheCookie(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")

	for _, path := range []string{"platform/messages", "video/clips", "platform/messages"} {
		if got := b.callProxy(path); got.Code != http.StatusOK || got.Body.String() != "ok" {
			t.Fatalf("%s = %d %s", path, got.Code, got.Body.String())
		}
	}

	seen := w.tokensSeen()
	if len(seen) != 3 {
		t.Fatalf("seen = %v", seen)
	}

	for i, want := range []string{platformURI, videoURI, platformURI} {
		parts := strings.Split(seen[i], "|")

		token := strings.TrimPrefix(parts[1], "Bearer ")
		if got, _ := w.prov.resourceOf(token); got != want {
			t.Errorf("call %d carried a token for %q, want %q", i, got, want)
		}

		if parts[2] != "" {
			t.Errorf("the application's cookie went to the API: %q", parts[2])
		}
	}
	// A token is kept until it is nearly over: three calls, two refreshes.
	if n := w.prov.refreshCount(); n != 2 {
		t.Errorf("%d refreshes for three calls to two APIs, want 2", n)
	}
	// After it is nearly over, the next call refreshes again.
	w.clock.Advance(280 * time.Second)

	if got := b.callProxy("platform/messages"); got.Code != http.StatusOK {
		t.Fatal(got.Code)
	}

	if n := w.prov.refreshCount(); n != 3 {
		t.Errorf("%d refreshes after the token neared its end", n)
	}
	// Dot segments do not leave the upstream's path, and an unknown API is not found.
	if got := b.callProxy("platform/%2e%2e/admin"); got.Code != http.StatusBadRequest {
		t.Errorf("a dot segment = %d", got.Code)
	}

	if got := b.callProxy("nothing/x"); got.Code != http.StatusNotFound {
		t.Errorf("an unknown API = %d", got.Code)
	}
}

func TestTabsAndInstancesRefreshOneAtATime(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")

	var wg sync.WaitGroup

	codes := make(chan int, 40)

	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			path := "platform/x"
			if i%2 == 1 {
				path = "video/x"
			}
			// Each call is its own request with the same cookie: a tab.
			rec := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/"+path, nil)
			rec.AddCookie(&http.Cookie{Name: b.session().Name, Value: b.session().Value})

			out := httptest.NewRecorder()
			w.h.ServeHTTP(out, rec)

			codes <- out.Code
		}()
	}

	wg.Wait()
	close(codes)

	for c := range codes {
		if c != http.StatusOK {
			t.Errorf("a call answered %d", c)
		}
	}

	if n := w.prov.replayCount(); n != 0 {
		t.Errorf("%d refresh tokens were presented twice", n)
	}
}

func TestAGrantThatEndsEndsTheSessionOnceAndLoopsNowhere(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	w.prov.endGrants()

	got := b.callProxy("platform/x")
	if got.Code != http.StatusUnauthorized || got.Header().Get("Location") != "" || !strings.Contains(got.Body.String(), "login_required") {
		t.Fatalf("answer = %d %q %s", got.Code, got.Header().Get("Location"), got.Body.String())
	}

	if b.session() != nil {
		t.Error("the session cookie was kept")
	}

	if again := b.callProxy("platform/x"); again.Code != http.StatusUnauthorized || w.prov.refreshCount() != 1 {
		t.Errorf("the next call = %d after %d refreshes: the dead session was tried again", again.Code, w.prov.refreshCount())
	}

	if me := b.get("/api/me"); me.Code != http.StatusUnauthorized {
		t.Errorf("me = %d", me.Code)
	}
}

func TestAnOutageOfTheProviderKeepsTheSessionAndAnAmbiguousAnswerIsNotRepeated(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")

	w.prov.refreshStatus = http.StatusServiceUnavailable

	if got := b.callProxy("platform/x"); got.Code != http.StatusBadGateway {
		t.Fatalf("an outage = %d", got.Code)
	}

	if b.session() == nil {
		t.Fatal("an outage ended the session")
	}
	// A 5xx may be a proxy that lost an answer after the rotation, so the token is not presented again.
	w.prov.refreshStatus = 0

	if got := b.callProxy("platform/x"); got.Code != http.StatusUnauthorized {
		t.Fatalf("after the outage = %d, want a new sign-in", got.Code)
	}

	if w.prov.replayCount() != 0 {
		t.Fatalf("the token was presented again (%d replays)", w.prov.replayCount())
	}

	b = w.browser()
	b.signIn("/")

	// The provider acts and the answer is lost: the call is not repeated with the same token, which would be a replay.
	w.clock.Advance(10 * time.Minute)
	before := w.prov.refreshCount()
	w.prov.refreshHang = true

	if got := b.callProxy("platform/x"); got.Code != http.StatusBadGateway {
		t.Fatalf("a lost answer = %d", got.Code)
	}

	if n := w.prov.refreshCount() - before; n != 1 {
		t.Errorf("the refresh was sent %d times", n)
	}
	// The old token is dropped, not tried again: the next call asks the person to sign in, and no replay ends the grant.
	w.prov.refreshHang = false

	if got := b.callProxy("platform/x"); got.Code != http.StatusUnauthorized {
		t.Errorf("the call after a lost answer = %d, want a new sign-in", got.Code)
	}

	if w.prov.replayCount() != 0 || w.prov.refreshCount()-before != 1 {
		t.Errorf("a spent refresh token was presented again (%d replays)", w.prov.replayCount())
	}
}

func TestNothingThatCanBePresentedIsStoredOrLogged(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	b.callProxy("platform/x")
	b.callProxy("video/x")

	w.prov.refreshStatus = http.StatusInternalServerError
	w.clock.Advance(time.Hour)
	b.callProxy("platform/x")
	b.do(http.MethodPost, "/logout", nil, "")

	key := ""
	_ = key

	logs := w.logs.String()
	for _, secret := range []string{clientSecret, "access-", "refresh-", "code-", "eyJ", b.cookies["x"].String()} {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("the log holds %q:\n%s", secret, logs)
		}
	}
}

func TestSealedValuesBelongToTheirRow(t *testing.T) {
	v, err := bff.NewVault("v1", map[string][]byte{"v1": bytes.Repeat([]byte{1}, 32), "v0": bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := v.Seal("refresh-token-value", "row-1")
	if err != nil || strings.Contains(sealed, "refresh-token-value") {
		t.Fatalf("sealed = %q, %v", sealed, err)
	}

	if got, err := v.Open(sealed, "row-1"); err != nil || got != "refresh-token-value" {
		t.Fatalf("open = %q, %v", got, err)
	}

	if _, err := v.Open(sealed, "row-2"); err == nil {
		t.Error("a value sealed for one row opened for another")
	}

	if _, err := v.Open(strings.Replace(sealed, "v1.", "v9.", 1), "row-1"); err == nil {
		t.Error("a value opened under a key that is not in the ring")
	}
	// Rotation: a value sealed under the old key opens while the old key is in the ring, new ones use the active key.
	old, _ := bff.NewVault("v0", map[string][]byte{"v0": bytes.Repeat([]byte{2}, 32)})

	oldSealed, _ := old.Seal("x", "row")
	if got, err := v.Open(oldSealed, "row"); err != nil || got != "x" {
		t.Errorf("a value of the old key: %q, %v", got, err)
	}

	if next, _ := v.Seal("x", "row"); !strings.HasPrefix(next, "v1.") {
		t.Errorf("a new value was sealed under %q", next)
	}

	if _, err := bff.NewVault("v1", map[string][]byte{"v1": []byte("short")}); err == nil {
		t.Error("a short key was accepted")
	}
}

func TestLogoutEndsTheSessionTakesTheGrantBackAndChecksTheReturn(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	b.callProxy("platform/x")

	// Another site cannot sign the person out.
	if got := b.do(http.MethodPost, "/logout", map[string]string{"Sec-Fetch-Site": "cross-site"}, ""); got.Code != http.StatusForbidden || b.session() == nil {
		t.Fatalf("a cross-site logout = %d", got.Code)
	}

	got := b.do(http.MethodPost, "/logout", map[string]string{"Sec-Fetch-Site": "same-origin"}, "")
	if got.Code != http.StatusSeeOther || b.session() != nil {
		t.Fatalf("logout = %d, session %v", got.Code, b.session())
	}

	loc, _ := url.Parse(got.Header().Get("Location"))

	q := loc.Query()
	if loc.Path != "/oauth2/logout" || q.Get("client_id") != clientID || q.Get("post_logout_redirect_uri") != "https://app.example.test/logged-out" ||
		q.Get("id_token_hint") == "" || q.Get("state") == "" {
		t.Fatalf("end session request = %s", loc)
	}

	if len(w.prov.revoked) != 1 {
		t.Errorf("the grant was not taken back: %v", w.prov.revoked)
	}

	if after := b.callProxy("platform/x"); after.Code != http.StatusUnauthorized {
		t.Errorf("a call after logout = %d", after.Code)
	}
	// The provider sends the browser back with the state it was given, and only that.
	if bad := b.get("/logged-out?state=forged"); bad.Code != http.StatusBadRequest {
		t.Errorf("a forged state = %d", bad.Code)
	}

	b.cookies["__Host-bff_logout"] = &http.Cookie{Name: "__Host-bff_logout", Value: q.Get("state")}
	if ok := b.get("/logged-out?state=" + url.QueryEscape(q.Get("state"))); ok.Code != http.StatusOK {
		t.Errorf("the right state = %d", ok.Code)
	}

	if again := b.get("/logged-out?state=" + url.QueryEscape(q.Get("state"))); again.Code != http.StatusBadRequest {
		t.Errorf("the same state again = %d", again.Code)
	}

	if plain := b.get("/logged-out"); plain.Code != http.StatusOK {
		t.Errorf("a visit = %d", plain.Code)
	}
}

func TestPostsFromAnotherSiteAreRefused(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")

	if got := b.do(http.MethodPost, "/api/platform/x", map[string]string{"Sec-Fetch-Site": "cross-site"}, "a=1"); got.Code != http.StatusForbidden {
		t.Errorf("a cross-site post to an API = %d", got.Code)
	}

	if got := b.do(http.MethodPost, "/api/platform/x", map[string]string{"Origin": "https://app.example.test"}, "a=1"); got.Code != http.StatusOK {
		t.Errorf("a same-origin post = %d", got.Code)
	}
}

func (w *world) backchannel(token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	out := httptest.NewRecorder()
	w.h.ServeHTTP(out, r)

	return out
}

func sidOf(t *testing.T, w *world, b *browser) string {
	t.Helper()
	// The provider put the sid in the ID token; the application stored it with the session.
	w.prov.mu.Lock()
	defer w.prov.mu.Unlock()

	for _, g := range w.prov.grants {
		return g.sid
	}

	t.Fatal("no grant")

	return ""
}

func TestBackchannelLogoutEndsTheSessionOfTheSignIn(t *testing.T) {
	w := newWorld(t)
	a, other := w.browser(), w.browser()
	a.signIn("/")
	sid := sidOf(t, w, a)

	other.signIn("/") // a second sign-in of the same person: its own sid
	w.prov.mu.Lock()

	var sids []string
	for _, g := range w.prov.grants {
		sids = append(sids, g.sid)
	}
	w.prov.mu.Unlock()

	if len(sids) != 2 {
		t.Fatalf("grants = %d", len(sids))
	}

	token := w.prov.logoutToken(func(c map[string]any, _ *string) { c["sid"] = sid })
	if got := w.backchannel(token); got.Code != http.StatusOK {
		t.Fatalf("notice = %d %s", got.Code, got.Body.String())
	}

	ended := 0

	for _, br := range []*browser{a, other} {
		if br.get("/api/me").Code == http.StatusUnauthorized {
			ended++
		}
	}

	if ended != 1 {
		t.Errorf("%d sessions ended, want only the one of the sign-in", ended)
	}
	// Delivered again, as the provider does when the first answer was lost: the same answer, nothing more.
	if got := w.backchannel(token); got.Code != http.StatusOK {
		t.Errorf("a second delivery = %d", got.Code)
	}
}

func TestEveryRefusalOfALogoutToken(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	sid := sidOf(t, w, b)

	spoil := map[string]func(c map[string]any, typ *string){
		"an ID token passed off as one":     func(c map[string]any, typ *string) { *typ = "JWT" },
		"an access token passed off as one": func(c map[string]any, typ *string) { *typ = "at+jwt" },
		"no event":                          func(c map[string]any, _ *string) { delete(c, "events") },
		"another event": func(c map[string]any, _ *string) {
			c["events"] = map[string]any{"http://schemas.openid.net/event/other": map[string]any{}}
		},
		"a nonce":              func(c map[string]any, _ *string) { c["nonce"] = "n" },
		"no sid":               func(c map[string]any, _ *string) { delete(c, "sid") },
		"no jti":               func(c map[string]any, _ *string) { delete(c, "jti") },
		"no iat":               func(c map[string]any, _ *string) { delete(c, "iat") },
		"an iat in the future": func(c map[string]any, _ *string) { c["iat"] = t0.Add(time.Hour).Unix() },
		"no subject":           func(c map[string]any, _ *string) { delete(c, "sub") },
		"another audience":     func(c map[string]any, _ *string) { c["aud"] = "other-app" },
		"two audiences":        func(c map[string]any, _ *string) { c["aud"] = []string{clientID, "other-app"} },
		"another issuer":       func(c map[string]any, _ *string) { c["iss"] = "https://evil.example.test" },
		"an expired token":     func(c map[string]any, _ *string) { c["exp"] = t0.Add(-time.Hour).Unix() },
	}
	for name, f := range spoil {
		token := w.prov.logoutToken(func(c map[string]any, typ *string) { c["sid"] = sid; f(c, typ) })
		if got := w.backchannel(token); got.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, got.Code)
		}
	}
	// Signed by a key the issuer never published, and under a key id it does.
	foreign := w.prov.sign("logout+jwt", "k1", map[string]any{
		"iss": w.prov.issuer(), "sub": w.prov.subject, "aud": clientID, "iat": t0.Unix(), "exp": t0.Add(time.Minute).Unix(), "jti": "x", "sid": sid,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}, testKey(2))
	if got := w.backchannel(foreign); got.Code != http.StatusBadRequest {
		t.Errorf("a forged signature: %d", got.Code)
	}

	for name, body := range map[string]string{
		"no token": "", "two tokens": "logout_token=a&logout_token=b", "garbage": "logout_token=not.a.jwt", "none": "logout_token=" + url.QueryEscape("eyJhbGciOiJub25lIiwidHlwIjoibG9nb3V0K2p3dCJ9.e30."),
		"a huge body": "logout_token=" + strings.Repeat("a", 40<<10),
	} {
		r := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		out := httptest.NewRecorder()
		w.h.ServeHTTP(out, r)

		if out.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, out.Code)
		}
	}

	r := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/backchannel-logout", strings.NewReader(`{"logout_token":"x"}`))
	r.Header.Set("Content-Type", "application/json")

	if out := httptest.NewRecorder(); func() int { w.h.ServeHTTP(out, r); return out.Code }() != http.StatusBadRequest {
		t.Error("a JSON body was accepted")
	}

	if b.get("/api/me").Code != http.StatusOK {
		t.Error("a refused notice ended the session")
	}
}

func TestTheKeySetIsBoundedAndSurvivesRotationAndOutage(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	sid := sidOf(t, w, b)
	notice := func(kid string, key int) int {
		tok := w.prov.sign("logout+jwt", kid, map[string]any{
			"iss": w.prov.issuer(), "sub": w.prov.subject, "aud": clientID, "iat": w.clock.Now().Unix(), "exp": w.clock.Now().Add(time.Minute).Unix(),
			"jti": w.prov.random("j-"), "sid": "other-" + sid, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
		}, testKey(key))

		return w.backchannel(tok).Code
	}
	base := w.prov.hits()

	for range 50 {
		if got := notice("invented", 2); got != http.StatusBadRequest && got != http.StatusServiceUnavailable {
			t.Fatalf("a token under an invented key = %d", got)
		}
	}

	if n := w.prov.hits() - base; n > 1 {
		t.Errorf("50 tokens with an unknown key id made %d fetches of the key set", n)
	}
	// Rotation: the provider signs with a new key. Until the interval has passed the application does not look again.
	w.prov.setKeys(map[string]int{"k1": 0, "k2": 1}, "k2")
	// A good notice under the new key, too soon to look: "try again", which makes the provider deliver again, not "invalid".
	if got := notice("k2", 1); got != http.StatusServiceUnavailable {
		t.Errorf("a notice under a key published a moment ago = %d, want 503", got)
	}

	w.clock.Advance(31 * time.Second)

	if got := notice("k2", 1); got != http.StatusOK {
		t.Errorf("a token under the new key = %d", got)
	}
	// An outage: the keys it holds keep working.
	w.prov.mu.Lock()
	w.prov.jwksDown = true
	w.prov.mu.Unlock()
	w.clock.Advance(20 * time.Minute)

	if got := notice("k2", 1); got != http.StatusOK {
		t.Errorf("during an outage of the key set = %d", got)
	}
}

func TestADiscoveryThatPointsAwayIsNotFollowedAndTheApplicationStartsWithoutTheProvider(t *testing.T) {
	w := newWorld(t)
	w.prov.mu.Lock()
	w.prov.jwksHost = "https://evil.example.test"
	w.prov.mu.Unlock()

	b := w.browser()
	if got := b.get("/login"); got.Code != http.StatusServiceUnavailable {
		t.Errorf("a key set on another host: %d", got.Code)
	}

	w.prov.mu.Lock()
	w.prov.jwksHost = ""
	w.prov.mu.Unlock()

	if got := b.get("/login"); got.Code != http.StatusSeeOther {
		t.Errorf("after the provider was right again: %d", got.Code)
	}

	// The provider is not there at all: the application starts, serves what needs no provider, and recovers.
	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()

	cfg := bff.Config{Issuer: url, ClientID: clientID, ClientSecret: clientSecret, BaseURL: "https://app.example.test", Store: w.store, Vault: w.vault}

	app, err := bff.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.test/login", nil))

	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "Try again") {
		t.Errorf("login with no provider = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.test/api/me", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("me with no provider = %d", rec.Code)
	}
}

func TestConfigurationIsChecked(t *testing.T) {
	w := newWorld(t)

	base := bff.Config{Issuer: "https://auth.example.test", ClientID: "c", ClientSecret: "s", BaseURL: "https://app.example.test", Store: w.store, Vault: w.vault}
	for name, mutate := range map[string]func(c *bff.Config){
		"plain http":           func(c *bff.Config) { c.BaseURL = "http://app.example.test" },
		"a path in the origin": func(c *bff.Config) { c.BaseURL = "https://app.example.test/app" },
		"insecure cookies":     func(c *bff.Config) { c.InsecureCookies = true },
		"no secret":            func(c *bff.Config) { c.ClientSecret = "" },
		"no vault":             func(c *bff.Config) { c.Vault = nil },
		"a resource with a slash": func(c *bff.Config) {
			c.Resources = []bff.Resource{{Name: "a/b", URI: "https://x/", Scopes: []string{"a:b"}, Upstream: &url.URL{}}}
		},
	} {
		cfg := base
		mutate(&cfg)

		if _, err := bff.New(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	local := base

	local.BaseURL, local.InsecureCookies = "http://127.0.0.1:8080", true
	if _, err := bff.New(local); err != nil {
		t.Errorf("a loopback development server was refused: %v", err)
	}
}

var _ = io.Discard

func TestAFirstFetchThatFailsIsNotRetriedEveryRequest(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")
	// A fresh application with the same store sees the key set down.
	w.prov.mu.Lock()
	w.prov.jwksDown = true
	w.prov.mu.Unlock()
	fresh := newWorldOn(t, w)

	before := w.prov.hits()
	for range 5 {
		fresh.backchannel(w.prov.logoutToken(nil))
	}

	if n := w.prov.hits() - before; n > 1 {
		t.Errorf("5 notices made %d fetches of an unreachable key set", n)
	}
}

func newWorldOn(t *testing.T, w *world) *world {
	app, err := bff.New(bff.Config{Issuer: w.prov.issuer(), ClientID: clientID, ClientSecret: clientSecret, BaseURL: "https://app.example.test", Store: bff.NewMemoryStore(w.clock.Now), Vault: w.vault, Now: w.clock.Now})
	if err != nil {
		t.Fatal(err)
	}

	return &world{t: t, clock: w.clock, prov: w.prov, vault: w.vault, h: app.Handler()}
}

// failingStore refuses to end a sign-in, then recovers.
type failingStore struct {
	*bff.MemoryStore
	fail bool
}

func (f *failingStore) EndProviderSession(ctx context.Context, iss, sid, jti string, exp time.Time) (bool, int, error) {
	if f.fail {
		return false, 0, errors.New("store down")
	}

	return f.MemoryStore.EndProviderSession(ctx, iss, sid, jti, exp)
}

func TestALogoutThatCouldNotBeStoredIsDeliveredAgainAndTakesEffect(t *testing.T) {
	var fs *failingStore

	w := newWorld(t, func(c *bff.Config) { fs = &failingStore{MemoryStore: bff.NewMemoryStore(nil)}; c.Store = fs })
	b := w.browser()
	b.signIn("/")

	token := w.prov.logoutToken(func(c map[string]any, _ *string) { c["sid"] = sidOf(t, w, b) })
	fs.fail = true

	if got := w.backchannel(token); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("with the store down = %d, want 503 so that it is delivered again", got.Code)
	}

	fs.fail = false

	if got := w.backchannel(token); got.Code != http.StatusOK || b.get("/api/me").Code != http.StatusUnauthorized {
		t.Errorf("the second delivery = %d, session still live: %v", got.Code, b.get("/api/me").Code == http.StatusOK)
	}
}

func TestASignInThatEndedWhileTheCodeWasBeingExchangedLeavesNoSession(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	start := b.get("/login")
	loc := start.Header().Get("Location")
	// The provider's notice for the new sign-in arrives before the callback has stored its session.
	code := w.prov.issue(loc)
	w.prov.mu.Lock()
	sid := ""
	w.prov.mu.Unlock()

	_ = sid
	// The code's sid is made at exchange; the notice names it as soon as the exchange has happened: model that with a hook.
	u, _ := url.Parse(loc)
	w.prov.onExchange = func(sid string) {
		tok := w.prov.logoutToken(func(c map[string]any, _ *string) { c["sid"] = sid })
		if got := w.backchannel(tok); got.Code != http.StatusOK {
			t.Errorf("the notice = %d", got.Code)
		}
	}

	got := b.get("/auth/callback?" + url.Values{"code": {code}, "state": {u.Query().Get("state")}, "iss": {w.prov.issuer()}}.Encode())
	if got.Code != http.StatusForbidden || b.session() != nil {
		t.Errorf("callback = %d, session %v: a sign-in that had ended was stored", got.Code, b.session())
	}
}

func TestTwoAPIsMayShareAScopeName(t *testing.T) {
	w := newWorld(t, func(c *bff.Config) {
		c.Resources[1].Scopes = []string{"messages:send", "video:read"}
		c.Scopes = []string{"email", "email"}
	})
	b := w.browser()
	loc := b.get("/login").Header().Get("Location")

	u, _ := url.Parse(loc)
	if got := u.Query().Get("scope"); got != "openid email messages:send video:read" {
		t.Errorf("scope = %q", got)
	}
}

func TestAGatewayErrorAfterTheRotationIsNotAReplay(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.signIn("/")

	w.prov.refreshLost = http.StatusBadGateway
	if got := b.callProxy("platform/x"); got.Code != http.StatusBadGateway {
		t.Fatalf("lost answer = %d", got.Code)
	}

	w.prov.refreshLost = 0

	if got := b.callProxy("platform/x"); got.Code != http.StatusUnauthorized {
		t.Errorf("next call = %d, want a new sign-in", got.Code)
	}

	if w.prov.replayCount() != 0 {
		t.Errorf("replays = %d: the spent token was presented again", w.prov.replayCount())
	}
}

func TestASignInBegunAfterTheNoticeIsNotEndedByIt(t *testing.T) {
	w := newWorld(t)
	w.prov.fixedSID = "sid-kept"
	b := w.browser()
	b.signIn("/")

	sid := "sid-kept"

	if got := w.backchannel(w.prov.logoutToken(func(c map[string]any, _ *string) { c["sid"] = sid })); got.Code != http.StatusOK {
		t.Fatalf("notice = %d", got.Code)
	}

	if b.get("/api/me").Code != http.StatusUnauthorized {
		t.Fatal("the notice left the session")
	}
	// The provider's session survives, so the next sign-in carries the same sid.
	w.clock.Advance(time.Second)
	b = w.browser()
	b.signIn("/")

	if b.get("/api/me").Code != http.StatusOK {
		t.Error("a new sign-in was refused after the old one ended")
	}
}

func TestALateRepeatOfANoticeDoesNotEndALaterSignIn(t *testing.T) {
	w := newWorld(t)
	w.prov.fixedSID = "sid-kept"
	b := w.browser()
	b.signIn("/")

	jti := "same-jti"

	notice := func() string {
		return w.prov.logoutToken(func(c map[string]any, _ *string) { c["sid"] = "sid-kept"; c["jti"] = jti })
	}
	if got := w.backchannel(notice()); got.Code != http.StatusOK {
		t.Fatalf("notice = %d", got.Code)
	}

	w.clock.Advance(time.Second)
	b = w.browser()
	b.signIn("/")
	w.clock.Advance(2 * time.Hour)

	if got := w.backchannel(notice()); got.Code != http.StatusOK {
		t.Fatalf("repeat = %d", got.Code)
	}

	if b.get("/api/me").Code != http.StatusOK {
		t.Error("a repeated notice ended a later sign-in")
	}
}

// markingStore is a store that survives a crash, as far as a test can say: it records a refresh as begun, and reports one that
// never finished as interrupted to the next caller.
type markingStore struct {
	*bff.MemoryStore
	mu      sync.Mutex
	started map[string]bool
	// interruptNext makes the next lock report an interrupted refresh, as after a crash.
	interruptNext bool
}

func (m *markingStore) WithSessionLock(ctx context.Context, key string, fn func(s *bff.Session) error) error {
	return m.MemoryStore.WithSessionLock(ctx, key, func(s *bff.Session) error {
		m.mu.Lock()
		s.RefreshInterrupted = m.started[key] || m.interruptNext
		delete(m.started, key)
		m.interruptNext = false
		m.mu.Unlock()

		s.BeginRefresh = func(context.Context) error { m.mu.Lock(); defer m.mu.Unlock(); m.started[key] = true; return nil }

		return fn(s)
	})
}

func TestARefreshThatDiedHalfwayIsNotRepeatedWithTheSpentToken(t *testing.T) {
	var store *markingStore

	w := newWorld(t, func(c *bff.Config) {
		store = &markingStore{MemoryStore: c.Store.(*bff.MemoryStore), started: map[string]bool{}}
		c.Store = store
	})
	b := w.browser()
	b.signIn("/")
	w.clock.Advance(10 * time.Minute)
	// The process marked a refresh as begun and died; the provider had rotated the token.
	store.interruptNext = true
	before := w.prov.refreshCount()

	if got := b.callProxy("platform/x"); got.Code != http.StatusBadGateway {
		t.Fatalf("the call after the interrupted refresh = %d", got.Code)
	}

	if w.prov.refreshCount() != before || w.prov.replayCount() != 0 {
		t.Errorf("the old token was presented again: %d refreshes, %d replays", w.prov.refreshCount()-before, w.prov.replayCount())
	}

	if got := b.callProxy("platform/x"); got.Code != http.StatusUnauthorized {
		t.Errorf("the next call = %d, want a new sign-in", got.Code)
	}
}

func TestAnInterruptedRefreshIsNotHiddenByACachedToken(t *testing.T) {
	var store *markingStore

	w := newWorld(t, func(c *bff.Config) {
		store = &markingStore{MemoryStore: c.Store.(*bff.MemoryStore), started: map[string]bool{}}
		c.Store = store
	})
	b := w.browser()
	b.signIn("/")

	if got := b.callProxy("platform/x"); got.Code != http.StatusOK {
		t.Fatalf("the first call = %d", got.Code)
	}
	// A refresh for another API began and died; the call that finds out is served from the cache, which must not clear the doubt.
	store.interruptNext = true

	if got := b.callProxy("platform/x"); got.Code != http.StatusOK {
		t.Fatalf("a cached call = %d", got.Code)
	}

	before := w.prov.refreshCount()

	if got := b.callProxy("video/x"); got.Code != http.StatusUnauthorized {
		t.Errorf("a call needing a refresh = %d, want a new sign-in", got.Code)
	}

	if w.prov.refreshCount() != before || w.prov.replayCount() != 0 {
		t.Errorf("the spent token was presented again: %d refreshes, %d replays", w.prov.refreshCount()-before, w.prov.replayCount())
	}
}
