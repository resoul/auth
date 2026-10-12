//go:build integration

package bootstrap_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"airlance.org/auth/internal/testutil"
)

// page is a browser page of the API's own origin with a hand-made cookie jar: the real
// jar would not send Secure cookies over the plain loopback HTTP the test uses.
type page struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
}

func (p *page) post(path, body string) (*http.Response, string) {
	p.t.Helper()
	req, err := http.NewRequest(http.MethodPost, p.base+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, ck := range p.cookies {
		if strings.HasPrefix(path, ck.Path) {
			req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.t.Fatal(err)
	}
	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(p.cookies, ck.Name)
		} else {
			p.cookies[ck.Name] = ck
		}
	}
	return resp, string(data)
}

func TestBrowserSignInRefreshAndReplayOnTheRealService(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	cfg, base := s.apiConfig(addrOf(smtp))
	stop := s.start(cfg)
	defer stop()
	waitReady(t, base)
	p := &page{t: t, base: base, cookies: map[string]*http.Cookie{}}

	resp, body := p.post("/v1/auth/email/start", `{"email": "alice@example.test"}`)
	if resp.StatusCode != http.StatusAccepted || strings.Contains(body, "client_binding") || p.cookies["__Secure-px_binding"] == nil {
		t.Fatalf("start = %d %s, cookies %v", resp.StatusCode, body, resp.Header["Set-Cookie"])
	}
	flowID := jsonField(t, body, "flow_id")
	waitUntil(t, "the mail", func() bool { return len(smtp.Messages()) == 1 })
	m := mailedCode.FindStringSubmatch(smtp.Messages()[0].Data)
	if m == nil {
		t.Fatal("the mail carries no code")
	}

	resp, body = p.post("/v1/auth/email/verify", `{"flow_id": "`+flowID+`", "code": "`+m[1]+m[2]+`"}`)
	if resp.StatusCode != http.StatusOK || jsonField(t, body, "next") != "enroll_passkey" || p.cookies["__Secure-px_refresh"] != nil {
		t.Fatalf("verify = %d %s, cookies %v", resp.StatusCode, body, resp.Header["Set-Cookie"])
	}
	if n := count(t, s, "sessions"); n != 0 {
		t.Fatalf("%d sessions after verify: a proven email is not a session", n)
	}
	resp, body = p.registerPasskey(t, newAuthenticator(t), jsonField(t, body, "ticket"))
	refresh := p.cookies["__Secure-px_refresh"]
	if resp.StatusCode != http.StatusOK || refresh == nil || strings.Contains(body, refresh.Value) || !refresh.HttpOnly || !refresh.Secure {
		t.Fatalf("register = %d %s, refresh cookie %+v", resp.StatusCode, body, refresh)
	}
	if n := count(t, s, "sessions"); n != 1 {
		t.Errorf("%d sessions after the registration", n)
	}
	old := refresh.Value

	resp, body = p.post("/v1/token/refresh", "")
	if resp.StatusCode != http.StatusOK || jsonField(t, body, "access_token") == "" || p.cookies["__Secure-px_refresh"].Value == old {
		t.Fatalf("refresh = %d %s", resp.StatusCode, body)
	}

	// The old cookie value replayed by someone else revokes the session.
	thief := &page{t: t, base: base, cookies: map[string]*http.Cookie{
		"__Secure-px_refresh": {Name: "__Secure-px_refresh", Value: old, Path: "/v1/token"},
	}}
	if resp, _ := thief.post("/v1/token/refresh", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay = %d, want 401", resp.StatusCode)
	}
	if resp, _ := p.post("/v1/token/refresh", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the victim's cookie survived the revocation: %d", resp.StatusCode)
	}

	// A foreign page is refused before anything is written.
	req, err := http.NewRequest(http.MethodPost, base+"/v1/auth/email/start", strings.NewReader(`{"email": "bob@example.test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden || count(t, s, "auth_flows") != 1 {
		t.Errorf("foreign page: status %d, %d flows", resp2.StatusCode, count(t, s, "auth_flows"))
	}
}

func jsonField(t *testing.T, body, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not JSON: %s", body)
	}
	v, _ := m[field].(string)
	return v
}

func (p *page) call(method, path, body, token string) (*http.Response, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, p.base+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		p.t.Fatal(err)
	}
	return resp, string(data)
}

// signIn runs the browser sign-in of a new device and returns its access token: the email
// code, then the passkey of auth, registered on the first sign-in and proven on the next.
func (p *page) signIn(t *testing.T, smtp *testutil.FakeSMTP, email string, auth *testutil.SoftAuthenticator) string {
	t.Helper()
	before := len(smtp.Messages())
	resp, body := p.post("/v1/auth/email/start", `{"email": "`+email+`"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start = %d %s", resp.StatusCode, body)
	}
	flowID := jsonField(t, body, "flow_id")
	waitUntil(t, "the mail", func() bool { return len(smtp.Messages()) > before })
	m := mailedCode.FindStringSubmatch(smtp.Messages()[before].Data)
	if m == nil {
		t.Fatal("the mail carries no code")
	}
	resp, body = p.post("/v1/auth/email/verify", `{"flow_id": "`+flowID+`", "code": "`+m[1]+m[2]+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify = %d %s", resp.StatusCode, body)
	}
	ticket := jsonField(t, body, "ticket")
	if jsonField(t, body, "next") == "second_factor" {
		resp, body = p.assertPasskey(t, auth, ticket)
	} else {
		resp, body = p.registerPasskey(t, auth, ticket)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey = %d %s", resp.StatusCode, body)
	}
	return jsonField(t, body, "access_token")
}

func TestSessionAPIOnTheRealService(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	cfg, base := s.apiConfig(addrOf(smtp))
	stop := s.start(cfg)
	defer stop()
	waitReady(t, base)

	laptop := &page{t: t, base: base, cookies: map[string]*http.Cookie{}}
	phone := &page{t: t, base: base, cookies: map[string]*http.Cookie{}}
	auth := newAuthenticator(t)
	laptopToken := laptop.signIn(t, smtp, "alice@example.test", auth)
	phoneToken := phone.signIn(t, smtp, "alice@example.test", auth) // the same passkey, synced to the phone

	resp, body := laptop.call(http.MethodGet, "/v1/me", "", laptopToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me = %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"email":"alice@example.test"`) || !strings.Contains(body, `"current":true`) {
		t.Errorf("me = %s", body)
	}
	resp, body = laptop.call(http.MethodGet, "/v1/sessions", "", laptopToken)
	if resp.StatusCode != http.StatusOK || strings.Count(body, `"id"`) != 2 || strings.Count(body, `"current":true`) != 1 {
		t.Fatalf("sessions = %d %s", resp.StatusCode, body)
	}
	if resp, _ := laptop.call(http.MethodGet, "/v1/me", "", ""); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("me without a token = %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// An ordinary sign-out ends the laptop's session at once but keeps the device recognized.
	if resp, body := laptop.call(http.MethodPost, "/v1/signout", `{}`, laptopToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("sign out = %d %s", resp.StatusCode, body)
	}
	if resp, _ := laptop.call(http.MethodGet, "/v1/me", "", laptopToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the signed-out token works: %d", resp.StatusCode)
	}
	if resp, _ := phone.call(http.MethodGet, "/v1/me", "", phoneToken); resp.StatusCode != http.StatusOK {
		t.Errorf("the other device was signed out: %d", resp.StatusCode)
	}
	if n := countWhere(t, s, "recognized_clients", "revoked_at IS NULL"); n != 2 {
		t.Errorf("%d active recognition records, want 2: an ordinary sign-out keeps the device recognized", n)
	}

	// Signing out everywhere ends every session and forgets every device.
	if resp, body := phone.call(http.MethodPost, "/v1/signout", `{"scope": "all"}`, phoneToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("sign out everywhere = %d %s", resp.StatusCode, body)
	}
	if n := countWhere(t, s, "sessions", "revoked_at IS NULL"); n != 0 {
		t.Errorf("%d sessions still active", n)
	}
	if n := countWhere(t, s, "recognized_clients", "revoked_at IS NULL"); n != 0 {
		t.Errorf("%d recognition records still active", n)
	}
	if n := countWhere(t, s, "refresh_tokens", "revoked_at IS NULL"); n != 0 {
		t.Errorf("%d refresh tokens still live", n)
	}
	if n := countWhere(t, s, "audit_events", "event = 'sessions.revoked_all'"); n != 1 {
		t.Errorf("%d revoked-all audit events", n)
	}
}

func countWhere(t *testing.T, s *service, table, where string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table + ` WHERE ` + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
