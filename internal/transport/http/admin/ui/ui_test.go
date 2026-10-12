package ui_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"airlance.org/auth/internal/transport/http/admin/ui"
)

func site() fstest.MapFS {
	return fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>Admin</title>")},
		"assets/index-abc.js":  {Data: []byte("console.log(1)")},
		"assets/index-abc.css": {Data: []byte("body{}")},
		"secret.txt":           {Data: []byte("not served")},
		"assets":               {Mode: 0o755 | 1<<31},
	}
}

func get(h http.Handler, path string) *http.Response {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Result()
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestThePageAndItsAssetsAreServedWithTheirOwnCaching(t *testing.T) {
	h := ui.NewHandler(site())
	page := get(h, "/admin/")
	if page.StatusCode != 200 || !strings.Contains(body(t, page), "<title>Admin</title>") || page.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("index = %d, cache %q", page.StatusCode, page.Header.Get("Cache-Control"))
	}
	if get(h, "/admin/index.html").StatusCode != 200 {
		t.Error("/admin/index.html is not served")
	}
	asset := get(h, "/admin/assets/index-abc.js")
	if asset.StatusCode != 200 || !strings.Contains(asset.Header.Get("Cache-Control"), "immutable") || !strings.Contains(asset.Header.Get("Content-Type"), "javascript") {
		t.Errorf("asset = %d, cache %q, type %q", asset.StatusCode, asset.Header.Get("Cache-Control"), asset.Header.Get("Content-Type"))
	}
	if css := get(h, "/admin/assets/index-abc.css"); !strings.Contains(css.Header.Get("Content-Type"), "css") {
		t.Errorf("css type = %q", css.Header.Get("Content-Type"))
	}
}

func TestEveryResponseCarriesAPolicyThatAllowsOnlyItsOwnFiles(t *testing.T) {
	h := ui.NewHandler(site())
	for _, path := range []string{"/admin/", "/admin/assets/index-abc.js", "/admin/nothing"} {
		csp := get(h, path).Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: policy %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: the policy allows inline code: %q", path, csp)
		}
	}
}

func TestOnlyThePageAndItsAssetsAreReachable(t *testing.T) {
	h := ui.NewHandler(site())
	for _, path := range []string{
		"/admin/secret.txt", "/admin/assets/", "/admin/assets", "/admin/assets/missing.js", "/admin/other/index.html",
		"/admin/assets/../secret.txt", "/admin/assets/%2e%2e/secret.txt", "/admin/assets//index-abc.js", "/admin/./index.html",
	} {
		if r := get(h, path); r.StatusCode != 404 {
			t.Errorf("%s = %d, want 404", path, r.StatusCode)
		}
	}
}

func TestAMissingBuildSaysSoAndNothingElseBreaks(t *testing.T) {
	h := ui.NewHandler(fstest.MapFS{})
	page := get(h, "/admin/")
	if page.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body(t, page), "not built") || page.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("an unbuilt page = %d, cache %q", page.StatusCode, page.Header.Get("Cache-Control"))
	}
	if r := get(h, "/admin/assets/index-abc.js"); r.StatusCode != 404 {
		t.Errorf("an asset of an unbuilt page = %d", r.StatusCode)
	}
}

func TestTheEmbeddedHandlerNeverPanics(t *testing.T) {
	h := ui.Handler()
	r := get(h, "/admin/")
	// Built or not, the answer is a page or the explanation.
	if want := map[bool]int{true: 200, false: 503}[ui.Built()]; r.StatusCode != want {
		t.Errorf("status = %d, want %d (built: %v)", r.StatusCode, want, ui.Built())
	}
}
