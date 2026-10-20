//go:build integration

package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/bootstrap"
)

const (
	platformResource = "https://api.example.test/platform"
	videoResource    = "https://video.example.test/api"
)

// operate runs a command of the operator against the service's database and returns what it printed.
func (o *oidcService) operate(t *testing.T, req bootstrap.OIDCResourceRequest) string {
	t.Helper()

	var out bytes.Buffer
	if err := bootstrap.OIDCResource(context.Background(), o.cfg, req, &out); err != nil {
		t.Fatalf("oidc resource %s %s: %v", req.Action, req.ID, err)
	}

	return out.String()
}

// header reads the protected header of a compact JWT without checking it.
func header(t *testing.T, token string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}

	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}

	return h
}

func (a *app) refresh(t *testing.T, base, refreshToken, resource string) (*http.Response, map[string]any) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if resource != "" {
		form.Set("resource", resource)
	}

	return a.token(t, base, form, true)
}

func TestAPIResourcesOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	secret := o.register(t, "panels-web", panelsReturn)

	// The operator registers two APIs and decides what the application may ask of each.
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "platform-api", Name: "Platform", URI: platformResource,
		Audience: "platform-api", Scopes: []string{"messages:read", "messages:send", "video:read"}})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "video-api", Name: "Video", URI: videoResource,
		Audience: "video-api", Scopes: []string{"video:read", "video:upload"}})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "platform-api", ClientID: "panels-web", Scopes: []string{"messages:read", "messages:send"}})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "video-api", ClientID: "panels-web", Scopes: []string{"video:read"}})

	if list := o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceList}); !strings.Contains(list, "client panels-web may ask: messages:read messages:send") ||
		!strings.Contains(list, "audience: video-api") {
		t.Errorf("list = %q", list)
	}

	panels := newApp(t, "panels-web", secret, panelsReturn)
	panels.extra = url.Values{"scope": {"openid messages:send video:read"}, "resource": {platformResource, videoResource}}
	b := newBrowser(t, o.base)
	code := o.signIn(t, b, panels, "alice@example.test")
	aliceAccess := o.lastAccess

	// The token endpoint is asked for one API at a time; the audience is that API's, not the application's.
	resp, first := panels.token(t, o.base, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {panels.redirect}, "code_verifier": {panels.verifier}, "resource": {platformResource},
	}, true)
	if resp.StatusCode != http.StatusOK || first["scope"] != "messages:send" || first["id_token"] == nil || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token = %d %v", resp.StatusCode, first)
	}

	access := first["access_token"].(string)
	if h := header(t, access); h["typ"] != "at+jwt" || h["alg"] != "RS256" || h["kid"] != "oidc-a" || len(h) != 3 {
		t.Errorf("header = %v, want exactly alg, kid and the at+jwt type", h)
	}

	claims := verifiedIDToken(t, o.base, access) // the same published key set verifies it
	if claims["aud"] != "platform-api" || claims["scope"] != "messages:send" || claims["client_id"] != "panels-web" || claims["iss"] != oidcIssuer || claims["jti"] == nil || claims["sub"] == "" {
		t.Errorf("access token claims = %v", claims)
	}

	resp, second := panels.refresh(t, o.base, first["refresh_token"].(string), videoResource)
	if resp.StatusCode != http.StatusOK || second["scope"] != "video:read" {
		t.Fatalf("refresh for the second API = %d %v", resp.StatusCode, second)
	}

	if c := verifiedIDToken(t, o.base, second["access_token"].(string)); c["aud"] != "video-api" || c["scope"] != "video:read" || c["sub"] != claims["sub"] {
		t.Errorf("second access token claims = %v", c)
	}

	refreshToken := second["refresh_token"].(string)

	// What is refused, and with which code.
	for name, tc := range map[string]struct {
		resource string
		code     string
	}{
		"an unknown resource":    {"https://nobody.example.test/", "invalid_target"},
		"a malformed resource":   {"platform-api", "invalid_target"},
		"a resource with a hash": {platformResource + "#x", "invalid_target"},
	} {
		resp, body := panels.refresh(t, o.base, refreshToken, tc.resource)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != tc.code {
			t.Errorf("%s: %d %v", name, resp.StatusCode, body)
		}
	}

	resp, body := panels.token(t, o.base, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "resource": {platformResource, videoResource},
	}, true)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("two resources at the token endpoint: %d %v", resp.StatusCode, body)
	}

	resp, body = panels.token(t, o.base, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "resource": {platformResource}, "scope": {"video:upload"},
	}, true)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("a right the grant does not hold: %d %v", resp.StatusCode, body)
	}
	// None of those spent the refresh token. Without a resource the token is the one for UserInfo, as before.
	resp, plain := panels.refresh(t, o.base, refreshToken, "")
	if resp.StatusCode != http.StatusOK || plain["scope"] != "openid" {
		t.Fatalf("refresh without a resource = %d %v", resp.StatusCode, plain)
	}

	userinfo := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = r.Body.Close()

		return r.StatusCode
	}
	if got := userinfo(plain["access_token"].(string)); got != http.StatusOK {
		t.Errorf("userinfo with its own token = %d", got)
	}

	if got := userinfo(access); got != http.StatusUnauthorized {
		t.Errorf("userinfo took the token of an API: %d", got)
	}

	refreshToken = plain["refresh_token"].(string)

	// The person sees what they connected, and takes it back.
	page := b.page()

	resp2, listBody := page.call(http.MethodGet, "/v1/me/apps", "", aliceAccess)
	if resp2.StatusCode != http.StatusOK || resp2.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("list = %d %s", resp2.StatusCode, listBody)
	}

	var list struct {
		Apps []struct {
			GrantID   string   `json:"grant_id"`
			ClientID  string   `json:"client_id"`
			Name      string   `json:"name"`
			Scopes    []string `json:"scopes"`
			Resources []struct {
				ID     string   `json:"id"`
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			} `json:"resources"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(listBody), &list); err != nil || len(list.Apps) != 1 {
		t.Fatalf("list = %s, %v", listBody, err)
	}

	app := list.Apps[0]
	if app.ClientID != "panels-web" || len(app.Resources) != 2 || app.Resources[0].ID != "platform-api" || app.Resources[1].Scopes[0] != "video:read" {
		t.Errorf("the connected application = %+v", app)
	}

	for _, secret := range []string{refreshToken, access, code} {
		if strings.Contains(listBody, secret) {
			t.Errorf("the list shows a token")
		}
	}

	if r, _ := page.call(http.MethodGet, "/v1/me/apps", "", ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("list without a token = %d", r.StatusCode)
	}
	// Another person's grant is not found, and the answer is the one for a grant that does not exist.
	other := newBrowser(t, o.base)
	otherApp := newApp(t, "panels-web", secret, panelsReturn)
	otherApp.extra = panels.extra
	otherCode := o.signIn(t, other, otherApp, "bob@example.test")
	bobAccess := o.lastAccess
	_, bobs := otherApp.token(t, o.base, url.Values{
		"grant_type": {"authorization_code"}, "code": {otherCode}, "redirect_uri": {otherApp.redirect}, "code_verifier": {otherApp.verifier}, "resource": {videoResource},
	}, true)

	bobRefresh, _ := bobs["refresh_token"].(string)
	if bobRefresh == "" {
		t.Fatalf("bob's tokens = %v", bobs)
	}

	for name, id := range map[string]string{"alice's grant": app.GrantID, "a grant that does not exist": "00000000-0000-7000-8000-00000000ffff", "no id at all": "x"} {
		if r, body := other.page().call(http.MethodDelete, "/v1/me/apps/grants/"+id, "", bobAccess); r.StatusCode != http.StatusNoContent {
			t.Errorf("%s: %d %s", name, r.StatusCode, body)
		}
	}

	if r, body := other.page().call(http.MethodDelete, "/v1/me/apps/clients/panels-web", "", "bad-token"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("a revoke with a bad token = %d %s", r.StatusCode, body)
	}

	if resp, body := panels.refresh(t, o.base, refreshToken, platformResource); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice's grant was ended by bob: %d %v", resp.StatusCode, body)
	} else {
		refreshToken = body["refresh_token"].(string)
	}

	// Alice takes her grant back: hers only. Bob's carries on, and so does her sign-in with the provider.
	if r, body := page.call(http.MethodDelete, "/v1/me/apps/grants/"+app.GrantID, "", aliceAccess); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, body)
	}

	if resp, body := panels.refresh(t, o.base, refreshToken, platformResource); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("a refresh after the grant was taken back: %d %v", resp.StatusCode, body)
	}

	if resp, body := otherApp.refresh(t, o.base, bobRefresh, videoResource); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's grant was ended: %d %v", resp.StatusCode, body)
	} else {
		bobRefresh = body["refresh_token"].(string)
	}

	if r, body := page.call(http.MethodGet, "/v1/me/apps", "", aliceAccess); r.StatusCode != http.StatusOK || strings.Contains(body, "panels-web") {
		t.Errorf("the list after taking back = %d %s", r.StatusCode, body)
	}

	if n := countWhere(t, o.service, "oidc_op_sessions", "revoked_at IS NULL"); n != 2 {
		t.Errorf("%d live sign-ins, want both people's", n)
	}
	// The whole application at once.
	if r, body := other.page().call(http.MethodDelete, "/v1/me/apps/clients/panels-web", "", bobAccess); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke application = %d %s", r.StatusCode, body)
	}

	if resp, body := otherApp.refresh(t, o.base, bobRefresh, videoResource); resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("a refresh after the application was taken back: %d %v", resp.StatusCode, body)
	}
}
