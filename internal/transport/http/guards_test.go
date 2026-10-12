package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpapi "airlance.org/auth/internal/transport/http"
)

const appOrigin = "https://app.example.test"

func newEnvWithOrigins(t *testing.T, origins ...string) *env {
	t.Helper()
	return newEnvWith(t, func(d *httpapi.Deps) { d.BrowserOrigins = origins })
}

// from sends a browser-like POST with the given fetch metadata headers.
func (e *env) from(path, origin, fetchSite string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"email": "alice@example.test"}`))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	return e.do(req)
}

// Check own and foreign origins,
// neither protective header, CORS and the separation of profiles.
func TestStateChangingRequestsMustComeFromAnAllowedOrigin(t *testing.T) {
	for _, path := range []string{browserStart, startPath} {
		for _, tc := range []struct {
			name              string
			origin, fetchSite string
			want              int
		}{
			{"same origin", "http://example.com", "same-origin", http.StatusAccepted},
			{"same origin by Origin alone", "http://example.com", "", http.StatusAccepted},
			{"direct request: fetch site none", "", "none", http.StatusAccepted},
			{"neither header (not a browser page)", "", "", http.StatusAccepted},
			{"cross-site page", "https://evil.example", "cross-site", http.StatusForbidden},
			{"same-site sibling", "https://evil.example.com", "same-site", http.StatusForbidden},
			{"foreign Origin and no fetch site", "https://evil.example", "", http.StatusForbidden},
			{"foreign Origin dressed as same-origin", "https://evil.example", "same-origin", http.StatusAccepted},
			{"null origin", "null", "cross-site", http.StatusForbidden},
			{"trusted origin", appOrigin, "cross-site", http.StatusAccepted},
			{"trusted origin by Origin alone", appOrigin, "", http.StatusAccepted},
			{"look-alike of the trusted origin", "https://app.example.test.evil.example", "cross-site", http.StatusForbidden},
			{"trusted host with another scheme", "http://app.example.test", "cross-site", http.StatusForbidden},
			{"trusted host with another port", "https://app.example.test:8443", "cross-site", http.StatusForbidden},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				e := newEnvWithOrigins(t, appOrigin)
				rec := e.from(path, tc.origin, tc.fetchSite)
				if tc.want == http.StatusForbidden {
					wantProblem(t, rec, tc.want, "permission_denied")
					if e.store.FlowCount() != 0 || len(e.store.OutboxJobs()) != 0 || len(rec.Result().Cookies()) != 0 {
						t.Error("a refused request wrote a flow, a mail or a cookie")
					}
					return
				}
				if rec.Code != tc.want {
					t.Errorf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body)
				}
			})
		}
	}
}

func TestEveryStateChangingRouteIsProtected(t *testing.T) {
	e := newEnvWithOrigins(t)
	for _, path := range []string{
		startPath, verifyPath, refreshPath, nativeResend, browserStart, browserVerify, browserResend, browserRefresh,
		nativeRegisterOptions, nativeRegisterVerify, nativeLoginOptions, nativeLoginVerify, nativeRecoveryVerify,
		browserRegisterOptions, browserRegisterVerify, browserLoginOptions, browserLoginVerify, browserRecoveryVerify,
	} {
		rec := e.from(path, "https://evil.example", "cross-site")
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s from a foreign page = %d, want 403", path, rec.Code)
		}
	}
	if e.metrics == nil || strings.Contains(e.get("/metrics").Body.String(), "airlance_auth_refresh_reuse_total 1") {
		t.Error("a refused request reached the use case")
	}
}

func TestSafeRequestsAreNotBlockedByTheOriginCheck(t *testing.T) {
	e := newEnvWithOrigins(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := e.do(req); rec.Code != http.StatusOK {
		t.Errorf("GET jwks from a foreign page = %d", rec.Code)
	}
}

func (e *env) preflight(path, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	return e.do(req)
}

func TestCORSAnswersOnlyTheConfiguredOriginsOnBrowserRoutes(t *testing.T) {
	e := newEnvWithOrigins(t, appOrigin)

	rec := e.preflight(browserStart, appOrigin)
	h := rec.Header()
	if rec.Code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != appOrigin ||
		h.Get("Access-Control-Allow-Credentials") != "true" || !strings.Contains(h.Get("Access-Control-Allow-Methods"), "POST") ||
		!strings.Contains(h.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("trusted preflight = %d %v", rec.Code, h)
	}
	if !strings.Contains(strings.Join(h.Values("Vary"), ","), "Origin") {
		t.Errorf("Vary = %v: caches would mix origins", h.Values("Vary"))
	}

	for _, origin := range []string{"https://evil.example", "null", "https://app.example.test.evil.example", "http://app.example.test"} {
		rec := e.preflight(browserStart, origin)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("preflight from %q allowed origin %q", origin, got)
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") != "" || rec.Header().Get("Access-Control-Allow-Methods") != "" {
			t.Errorf("preflight from %q granted something: %v", origin, rec.Header())
		}
	}
}

func TestCORSHeadersAccompanyTheActualResponseOfATrustedOrigin(t *testing.T) {
	e := newEnvWithOrigins(t, appOrigin)
	rec := e.from(browserStart, appOrigin, "cross-site")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != appOrigin || h.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("headers = %v", h)
	}
	// Never a wildcard together with credentials.
	if h.Get("Access-Control-Allow-Origin") == "*" {
		t.Error("wildcard origin with credentials")
	}

	// A refused foreign page learns nothing it could read.
	rec = e.from(browserStart, "https://evil.example", "cross-site")
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("a foreign origin got CORS headers: %v", rec.Header())
	}
}

func TestNativeRoutesAreNotOpenedToBrowsers(t *testing.T) {
	e := newEnvWithOrigins(t, appOrigin)
	if rec := e.preflight(startPath, appOrigin); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("native preflight = %d %v, want 405 without CORS headers", rec.Code, rec.Header())
	}
	rec := e.from(startPath, appOrigin, "cross-site")
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("a native response carries CORS headers: %v", rec.Header())
	}
}

func TestSameSiteAttributeFollowsTheConfiguration(t *testing.T) {
	for name, tc := range map[string]struct {
		mode http.SameSite
		want http.SameSite
	}{
		"default is strict": {0, http.SameSiteStrictMode},
		"lax":               {http.SameSiteLaxMode, http.SameSiteLaxMode},
		"none":              {http.SameSiteNoneMode, http.SameSiteNoneMode},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnvWith(t, func(d *httpapi.Deps) {
				d.CookieSameSite = tc.mode
				d.BrowserOrigins = []string{appOrigin}
			})
			rec := e.from(browserStart, appOrigin, "cross-site")
			ck := setCookies(rec)[httpapi.BindingCookieName]
			if ck == nil || ck.SameSite != tc.want || !ck.Secure || !ck.HttpOnly {
				t.Errorf("cookie = %+v, want SameSite %v, Secure, HttpOnly", ck, tc.want)
			}
		})
	}
}

func TestTheHandlerRefusesUnsafeCookieAndOriginSettings(t *testing.T) {
	for name, configure := range map[string]func(*httpapi.Deps){
		"SameSite=None without a trusted origin": func(d *httpapi.Deps) { d.CookieSameSite = http.SameSiteNoneMode },
		"a wildcard origin":                      func(d *httpapi.Deps) { d.BrowserOrigins = []string{"*"} },
		"an origin with a path":                  func(d *httpapi.Deps) { d.BrowserOrigins = []string{"https://app.example.test/login"} },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildEnv(t, configure); err == nil {
				t.Error("the handler was assembled")
			}
		})
	}
	if _, err := buildEnv(t, func(d *httpapi.Deps) {
		d.CookieSameSite = http.SameSiteNoneMode
		d.BrowserOrigins = []string{appOrigin}
	}); err != nil {
		t.Errorf("SameSite=None with a trusted origin: %v", err)
	}
}
