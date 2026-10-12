//go:build integration

package bootstrap_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/bootstrap"
)

// secretOf reads the secret out of what `oidc resource rotate-secret` printed.
func secretOf(t *testing.T, printed string) string {
	t.Helper()
	for _, line := range strings.Split(printed, "\n") {
		if v, ok := strings.CutPrefix(line, "secret:"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no secret in %q", printed)
	return ""
}

func TestAPIIntrospectionOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	secret := o.register(t, "panels-web", panelsReturn)
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "platform-api", Name: "Platform", URI: platformResource,
		Audience: "platform-api", Scopes: []string{"messages:read", "messages:send"}})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "platform-api", ClientID: "panels-web", Scopes: []string{"messages:read", "messages:send"}})
	apiSecret := secretOf(t, o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRotate, ID: "platform-api", Overlap: time.Hour}))

	// The discovery document says where to ask, and how to authenticate.
	resp, err := http.Get(o.base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if doc["introspection_endpoint"] != oidcIssuer+"/oauth2/introspect" {
		t.Errorf("introspection_endpoint = %v", doc["introspection_endpoint"])
	}

	panels := newApp(t, "panels-web", secret, panelsReturn)
	panels.extra = url.Values{"scope": {"openid messages:send"}, "resource": {platformResource}}
	b := newBrowser(t, o.base)
	code := o.signIn(t, b, panels, "alice@example.test")
	aliceAccess := o.lastAccess
	_, tokens := panels.token(t, o.base, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {panels.redirect}, "code_verifier": {panels.verifier}, "resource": {platformResource},
	}, true)
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatalf("tokens = %v", tokens)
	}

	ask := func(user, pass, token, contentType string) (int, map[string]any, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", contentType)
		if user != "" {
			req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		return r.StatusCode, body, r.Header
	}
	form := "application/x-www-form-urlencoded"

	status, body, h := ask("platform-api", apiSecret, access, form)
	if status != http.StatusOK || body["active"] != true || body["scope"] != "messages:send" || body["aud"] != "platform-api" || body["client_id"] != "panels-web" ||
		body["iss"] != oidcIssuer || body["token_type"] != "Bearer" || body["sub"] == nil || body["jti"] == nil || body["exp"] == nil || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("a live token = %d %v", status, body)
	}
	if status, body, _ := ask("platform-api", apiSecret, "not.a.token", form); status != http.StatusOK || len(body) != 1 || body["active"] != false {
		t.Errorf("garbage = %d %v, want only {active:false}", status, body)
	}
	if status, _, h := ask("platform-api", "wrong", access, form); status != http.StatusUnauthorized || h.Get("WWW-Authenticate") == "" {
		t.Errorf("wrong secret = %d", status)
	}
	if status, _, _ := ask("", "", access, form); status != http.StatusUnauthorized {
		t.Errorf("no credentials = %d", status)
	}
	if status, _, _ := ask("panels-web", secret, access, form); status != http.StatusUnauthorized {
		t.Errorf("a client's credentials = %d", status)
	}
	if status, _, _ := ask("platform-api", apiSecret, access, "application/json"); status != http.StatusBadRequest {
		t.Errorf("a JSON body = %d", status)
	}
	if r, err := http.Get(o.base + "/oauth2/introspect?token=" + url.QueryEscape(access)); err != nil || r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET = %v, %v", r, err)
	}

	// The person takes the application back: the token still verifies offline, and the API is told it is over.
	page := b.page()
	_, listBody := page.call(http.MethodGet, "/v1/me/apps", "", aliceAccess)
	var list struct {
		Apps []struct {
			GrantID string `json:"grant_id"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(listBody), &list); err != nil || len(list.Apps) != 1 {
		t.Fatalf("list = %s, %v", listBody, err)
	}
	if r, body := page.call(http.MethodDelete, "/v1/me/apps/grants/"+list.Apps[0].GrantID, "", aliceAccess); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, body)
	}
	if status, body, _ := ask("platform-api", apiSecret, access, form); status != http.StatusOK || body["active"] != false {
		t.Errorf("after the person took the application back = %d %v", status, body)
	}
}
