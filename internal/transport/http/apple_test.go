package http_test

import (
	"net/http"
	"testing"

	httpapi "go.airlance.org/auth/internal/transport/http"
)

func TestAppleAppSiteAssociationNamesTheApps(t *testing.T) {
	e := newEnvWith(t, func(d *httpapi.Deps) { d.AppleAppIDs = []string{"ABCDE12345.com.example.app"} })

	rec := e.get("/.well-known/apple-app-site-association")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, Content-Type = %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	want := `{"webcredentials":{"apps":["ABCDE12345.com.example.app"]}}`
	if rec.Body.String() != want {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestAppleAppSiteAssociationIsAbsentWithoutApps(t *testing.T) {
	rec := newEnv(t).get("/.well-known/apple-app-site-association")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d", rec.Code)
	}
}
