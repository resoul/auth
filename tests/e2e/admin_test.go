//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/testutil"
)

// The relying party of the admin page of the e2e service: it differs from the users'.
const (
	adminRPID     = "admin.e2e.test"
	adminOrigin   = "https://admin.e2e.test"
	adminAPI      = "/admin/api/v1"
	enrollmentRE  = `\n\s{4}([A-Za-z0-9_-]{43})\n`
	operatorEmail = "ops@e2e.example.test"
)

// adminStack is the service with the admin listener on.
func adminStack(t *testing.T, extra ...string) (*stack, string) {
	t.Helper()
	addr := freeAddr(t)
	env := append([]string{
		"AIRLANCE_AUTH_ADMIN_ADDR=" + addr, "AIRLANCE_AUTH_ADMIN_RP_ID=" + adminRPID, "AIRLANCE_AUTH_ADMIN_ORIGINS=" + adminOrigin,
	}, extra...)

	return newStack(t, env...), addr
}

func operatorCmd(t *testing.T, s *stack, args ...string) (string, error) {
	t.Helper()

	cmd := exec.Command(binary, append([]string{"operator"}, args...)...)
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()

	return string(out), err
}

// adminPage is a browser tab of the admin page: it sends the page's origin and, once signed in, the CSRF token.
type adminPage struct {
	*client
	csrf string
}

func newAdminPage(s *stack, addr string) *adminPage {
	return &adminPage{client: &client{t: s.t, base: "http://" + addr, cookies: map[string]*http.Cookie{}}}
}

func (p *adminPage) call(method, path string, body any) reply {
	p.t.Helper()

	headers := map[string]string{"Origin": adminOrigin}
	if p.csrf != "" {
		headers["X-CSRF-Token"] = p.csrf
	}

	return p.do(method, adminAPI+path, body, headers)
}

// enroll registers a key with the code the command printed.
func (p *adminPage) enroll(code string) *testutil.SoftAuthenticator {
	p.t.Helper()
	key := testutil.NewSoftAuthenticator(p.t, adminRPID, adminOrigin)
	begun := p.call(http.MethodPost, "/enroll/begin", map[string]string{"code": code})
	want(p.t, begun, http.StatusOK, "")

	done := p.call(http.MethodPost, "/enroll/finish", map[string]any{
		"challenge_id": begun.str("challenge_id"), "response": json.RawMessage(key.Register(begun.options())), "name": "e2e key",
	})
	if done.Status != http.StatusNoContent {
		p.t.Fatalf("enroll/finish = %d %s", done.Status, done.Raw)
	}

	return key
}

// login signs in with the key and remembers the CSRF token.
func (p *adminPage) login(key *testutil.SoftAuthenticator) reply {
	p.t.Helper()
	begun := p.call(http.MethodPost, "/login/begin", nil)
	want(p.t, begun, http.StatusOK, "")

	res := p.call(http.MethodPost, "/login/finish", map[string]any{
		"challenge_id": begun.str("challenge_id"), "response": json.RawMessage(key.Assert(begun.options())),
	})
	if res.Status == http.StatusOK {
		p.csrf = res.str("csrf_token")
	}

	return res
}

func (p *adminPage) sessionSecret() string {
	if c := p.cookies["px_admin"]; c != nil {
		return c.Value
	}

	return ""
}

// operator creates an operator with the command, enrolls a key and signs in.
func signInOperator(t *testing.T, s *stack, addr string) (*adminPage, *testutil.SoftAuthenticator) {
	t.Helper()

	out, err := operatorCmd(t, s, "create", operatorEmail)
	if err != nil {
		t.Fatalf("operator create: %v\n%s", err, out)
	}

	m := regexp.MustCompile(enrollmentRE).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no enrollment code in the output:\n%s", out)
	}

	s.secret(m[1])
	page := newAdminPage(s, addr)

	key := page.enroll(m[1])
	if res := page.login(key); res.Status != http.StatusOK {
		t.Fatalf("login = %d %s", res.Status, res.Raw)
	}

	s.secret(page.sessionSecret(), page.csrf)

	return page, key
}

func TestAnOperatorEnrollsASecurityKeySignsInAndTheAdminAPIStaysOffThePublicPort(t *testing.T) {
	s, addr := adminStack(t)
	page, _ := signInOperator(t, s, addr)

	session := page.call(http.MethodGet, "/session", nil)
	want(t, session, http.StatusOK, "")

	if op, _ := session.Body["operator"].(map[string]any); op["email"] != operatorEmail {
		t.Errorf("session = %s", session.Raw)
	}

	cookie := page.cookies["px_admin"]
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || !cookie.Secure || cookie.Path != "/admin" {
		t.Errorf("session cookie = %+v", cookie)
	}

	// The public listener knows nothing of the admin API, and the admin listener nothing of the public one.
	public := newClient(s)
	if r := public.do(http.MethodGet, adminAPI+"/session", nil, nil); r.Status != http.StatusNotFound {
		t.Errorf("the public port answers the admin API: %d %s", r.Status, r.Raw)
	}

	if r := page.do(http.MethodGet, "/v1/native/me", nil, nil); r.Status == http.StatusOK {
		t.Errorf("the admin port answers the public API: %d", r.Status)
	}

	// The admin listener serves the page (or says it was not built) and never confuses an unknown API path with it.
	pageReply := page.do(http.MethodGet, "/admin/", nil, nil)
	if pageReply.Status != http.StatusOK && pageReply.Status != http.StatusServiceUnavailable {
		t.Errorf("/admin/ = %d", pageReply.Status)
	}

	if pageReply.Status == http.StatusOK && !strings.Contains(pageReply.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("the page has no policy: %v", pageReply.Header)
	}

	if r := page.do(http.MethodGet, adminAPI+"/nothing", nil, nil); r.Status != http.StatusNotFound || r.str("error") != "not_found" {
		t.Errorf("an unknown API path = %d %s", r.Status, r.Raw)
	}

	// An operator's key is no user's key, and a user's passkey is no operator's.
	if out, err := operatorCmd(t, s, "list"); err != nil || !strings.Contains(out, operatorEmail) || !strings.Contains(out, "1 keys") {
		t.Errorf("operator list: %v\n%s", err, out)
	}

	user := uniqueEmail(t, "member")
	nativeSignIn(t, s, newClient(s), user, "")

	stranger := newAdminPage(s, addr)
	if res := stranger.login(s.auths[user]); res.Status != http.StatusUnauthorized || res.str("error") != "refused" {
		t.Errorf("a user's passkey signed in on the admin page: %d %s", res.Status, res.Raw)
	}

	if r := page.call(http.MethodPost, "/logout", nil); r.Status != http.StatusNoContent {
		t.Fatalf("logout = %d %s", r.Status, r.Raw)
	}

	if r := page.call(http.MethodGet, "/session", nil); r.Status != http.StatusUnauthorized {
		t.Errorf("the session survived logout: %d", r.Status)
	}

	if body := scrapeMetrics(t, s); !strings.Contains(body, `airlance_auth_http_requests_total{route="POST /admin/api/v1/login/finish",status_class="2xx"} 1`) {
		t.Errorf("the scrape lacks the admin sign-in:\n%s", body)
	}

	s.checkLogs()
}

func TestBlockingAUserEndsTheirSessionsAndStopsTheirMail(t *testing.T) {
	s, addr := adminStack(t)
	page, _ := signInOperator(t, s, addr)
	c := newClient(s)
	victim, bystander := uniqueEmail(t, "victim"), uniqueEmail(t, "bystander")
	me := nativeSignIn(t, s, c, victim, "")
	other := nativeSignIn(t, s, newClient(s), bystander, "")
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusOK, "")

	// The operator finds the user by the start of the address and sees the card.
	list := page.call(http.MethodGet, "/users?query="+victim[:8], nil)
	want(t, list, http.StatusOK, "")

	users, _ := list.Body["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("search = %s", list.Raw)
	}

	id, _ := users[0].(map[string]any)["id"].(string)
	card := page.call(http.MethodGet, "/users/"+id, nil)
	want(t, card, http.StatusOK, "")

	if sessions, _ := card.Body["sessions"].([]any); len(sessions) != 1 {
		t.Errorf("card = %s", card.Raw)
	}

	if keys, _ := card.Body["passkeys"].([]any); len(keys) != 1 || card.Body["recovery_codes_left"] != float64(10) {
		t.Errorf("card = %s", card.Raw)
	}

	for _, secret := range []string{"public_key", "credential_id", me.refresh, me.access} {
		if strings.Contains(card.Raw, secret) {
			t.Errorf("the card holds %q", secret)
		}
	}

	if r := page.call(http.MethodPost, "/users/"+id+"/block", nil); r.Status != http.StatusNoContent {
		t.Fatalf("block = %d %s", r.Status, r.Raw)
	}

	// Everything they had open is closed at once; a bystander is untouched.
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusUnauthorized, "unauthenticated")
	want(t, c.native(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": me.refresh}, ""), http.StatusUnauthorized, "invalid_refresh")
	want(t, newClient(s).native(http.MethodGet, "/v1/native/me", nil, other.access), http.StatusOK, "")

	// No new code is mailed, yet the answer is an ordinary start, so a client cannot tell who is blocked.
	before := len(mailIDs(t, victim))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": victim}, "")
	want(t, started, http.StatusAccepted, "")

	if started.str("flow_id") == "" || started.str("client_binding") == "" {
		t.Errorf("the answer to a blocked address is not an ordinary start: %s", started.Raw)
	}

	time.Sleep(3 * time.Second) // the worker polls every second

	if n := len(mailIDs(t, victim)); n != before {
		t.Errorf("a blocked address got %d new mails", n-before)
	}

	s.secret(started.str("client_binding"))

	// Even a code mailed earlier cannot open a session: the passkey step refuses.
	begun := c.native(http.MethodPost, "/v1/native/auth/passkey/login/options", nil, "")
	want(t, begun, http.StatusOK, "")

	refused := c.native(http.MethodPost, "/v1/native/auth/passkey/login/verify", map[string]any{
		"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(s.auths[victim].Assert(begun.options())), "device_name": "e2e",
	}, "")
	if refused.Status == http.StatusOK || refused.str("access_token") != "" {
		t.Errorf("a blocked user signed in with their key: %d %s", refused.Status, refused.Raw)
	}

	if n := s.count("sessions", "user_id = '"+id+"' AND revoked_at IS NULL"); n != 0 {
		t.Errorf("%d live sessions of a blocked user", n)
	}

	// The refusals are in the operator's metrics and the act is in the audit log, naming who did it.
	if body := scrapeMetrics(t, s); !strings.Contains(body, `airlance_auth_denied_total{operation="start",reason="blocked"} 1`) ||
		!strings.Contains(body, `reason="blocked"`) {
		t.Errorf("the scrape lacks the blocked refusals:\n%s", body)
	}

	audit := page.call(http.MethodGet, "/audit?type=admin.action&user_id="+id, nil)
	want(t, audit, http.StatusOK, "")

	entries, _ := audit.Body["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("audit = %s", audit.Raw)
	}

	entry, _ := entries[0].(map[string]any)
	if fields, _ := entry["fields"].(map[string]any); fields["operation"] != "block" || entry["operator_id"] == "" {
		t.Errorf("entry = %v", entry)
	}

	// Unblocked, the same user signs in again; the old sessions stay closed.
	if r := page.call(http.MethodPost, "/users/"+id+"/unblock", nil); r.Status != http.StatusNoContent {
		t.Fatalf("unblock = %d %s", r.Status, r.Raw)
	}

	again := nativeSignIn(t, s, newClient(s), victim, "")
	if again.userID != id || again.access == me.access {
		t.Errorf("after unblock: %+v", again)
	}

	want(t, c.native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusUnauthorized, "unauthenticated")
	s.checkLogs()
}

func TestDeletingAUserNeedsAFreshSignInAndTheAddress(t *testing.T) {
	s, addr := adminStack(t)
	page, key := signInOperator(t, s, addr)
	victim := uniqueEmail(t, "gone")
	me := nativeSignIn(t, s, newClient(s), victim, "")
	path := "/users/" + me.userID

	want(t, page.call(http.MethodPost, path+"/delete", map[string]string{"confirm_email": "wrong@e2e.example.test"}), http.StatusConflict, "")

	if r := page.call(http.MethodPost, path+"/delete", map[string]string{"confirm_email": "wrong@e2e.example.test"}); r.str("error") != "confirm_mismatch" {
		t.Errorf("a wrong address: %s", r.Raw)
	}

	if n := s.count("users", "id = '"+me.userID+"'"); n != 1 {
		t.Fatal("a refused delete removed the user")
	}

	if r := page.call(http.MethodPost, path+"/delete", map[string]string{"confirm_email": strings.ToUpper(victim)}); r.Status != http.StatusNoContent {
		t.Fatalf("delete = %d %s", r.Status, r.Raw)
	}

	if n := s.count("users", "id = '"+me.userID+"'"); n != 0 {
		t.Error("the user is still there")
	}

	want(t, newClient(s).native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusUnauthorized, "unauthenticated")

	// The act stays in the log, with who did it and without whom.
	audit := page.call(http.MethodGet, "/audit?type=admin.action", nil)

	entries, _ := audit.Body["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("audit = %s", audit.Raw)
	}

	if entry := entries[0].(map[string]any); entry["user_id"] != nil || entry["operator_id"] == "" {
		t.Errorf("entry = %v", entry)
	}

	// Old sign-ins cannot delete: back-date the session in the database, as time would.
	other := uniqueEmail(t, "late")

	late := nativeSignIn(t, s, newClient(s), other, "")
	if _, err := s.db.Exec(`UPDATE operator_sessions SET created_at = created_at - interval '11 minutes'`); err != nil {
		t.Fatal(err)
	}

	r := page.call(http.MethodPost, "/users/"+late.userID+"/delete", map[string]string{"confirm_email": other})
	want(t, r, http.StatusForbidden, "")

	if r.str("error") != "reauth_required" {
		t.Errorf("an old sign-in: %s", r.Raw)
	}

	if res := page.login(key); res.Status != http.StatusOK {
		t.Fatalf("sign in again = %d %s", res.Status, res.Raw)
	}

	if r := page.call(http.MethodPost, "/users/"+late.userID+"/delete", map[string]string{"confirm_email": other}); r.Status != http.StatusNoContent {
		t.Errorf("delete after a fresh sign-in = %d %s", r.Status, r.Raw)
	}

	s.checkLogs()
}

func TestInvitationsFromTheAdminPageReachTheGuest(t *testing.T) {
	const loginPage = "https://app.example.test/login"

	s, addr := adminStack(t, "AIRLANCE_AUTH_REGISTRATION=invite", "AIRLANCE_AUTH_INVITATION_URL="+loginPage)
	page, _ := signInOperator(t, s, addr)
	guest := uniqueEmail(t, "guest")

	res := page.call(http.MethodPost, "/invitations", map[string]any{"email": guest, "ttl_hours": 24})
	want(t, res, http.StatusCreated, "")
	waitForMail(t, guest, 1)

	var mail struct{ Text string }
	getJSON(t, mailpitURL+"/api/v1/message/"+mailIDs(t, guest)[0], &mail)

	if !strings.Contains(mail.Text, loginPage) || codeInMail.MatchString(mail.Text) {
		t.Errorf("the invitation mail = %q", mail.Text)
	}

	list := page.call(http.MethodGet, "/invitations", nil)
	want(t, list, http.StatusOK, "")

	if invs, _ := list.Body["invitations"].([]any); len(invs) != 1 {
		t.Errorf("list = %s", list.Raw)
	}

	// The guest registers, which spends the invitation; inviting a member is a conflict.
	nativeSignIn(t, s, newClient(s), guest, "")

	if r := page.call(http.MethodPost, "/invitations", map[string]any{"email": guest}); r.Status != http.StatusConflict || r.str("error") != "already_registered" {
		t.Errorf("inviting a member = %d %s", r.Status, r.Raw)
	}

	if r := page.call(http.MethodPost, "/invitations/revoke", map[string]string{"email": guest}); r.Status != http.StatusNotFound {
		t.Errorf("revoking a spent invitation = %d %s", r.Status, r.Raw)
	}

	s.checkLogs()
}

func TestDisablingAnOperatorClosesTheirSessionAtOnceAndEnrollmentBringsThemBack(t *testing.T) {
	s, addr := adminStack(t)
	page, key := signInOperator(t, s, addr)

	if out, err := operatorCmd(t, s, "create", operatorEmail); err == nil || !strings.Contains(out, "already an operator") {
		t.Errorf("a second create: %v\n%s", err, out)
	}

	if out, err := operatorCmd(t, s, "disable", operatorEmail); err != nil || !strings.Contains(out, "disabled") {
		t.Fatalf("disable: %v\n%s", err, out)
	}

	if r := page.call(http.MethodGet, "/session", nil); r.Status != http.StatusUnauthorized {
		t.Errorf("a disabled operator's session still works: %d", r.Status)
	}

	if res := page.login(key); res.Status != http.StatusUnauthorized {
		t.Errorf("a disabled operator signed in: %d", res.Status)
	}

	if out, err := operatorCmd(t, s, "enroll", operatorEmail); err == nil {
		t.Errorf("a code was issued to a disabled operator: %s", out)
	}

	if out, err := operatorCmd(t, s, "enable", operatorEmail); err != nil || !strings.Contains(out, "enabled") {
		t.Fatalf("enable: %v\n%s", err, out)
	}

	// Every key lost: only the server brings the operator back, with a new code and a new key.
	out, err := operatorCmd(t, s, "enroll", operatorEmail)
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, out)
	}

	m := regexp.MustCompile(enrollmentRE).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no code:\n%s", out)
	}

	s.secret(m[1])

	fresh := page.enroll(m[1])
	if res := page.login(fresh); res.Status != http.StatusOK {
		t.Errorf("sign in with the new key = %d %s", res.Status, res.Raw)
	}

	if res := page.login(key); res.Status != http.StatusOK {
		t.Errorf("the old key stopped working: %d", res.Status)
	}

	if out, err := operatorCmd(t, s, "enroll", "nobody@e2e.example.test"); err == nil || !strings.Contains(out, "no operator") {
		t.Errorf("enrolling an unknown operator: %v\n%s", err, out)
	}
	// The command line leaves its own trail.
	// create, disable, enable and enroll: a refused command leaves nothing.
	if n := s.count("audit_events", "event = 'operator.changed'"); n != 4 {
		t.Errorf("%d operator.changed events, want 4", n)
	}

	s.checkLogs()
}

func TestTheAdminListenerIsOffUnlessConfigured(t *testing.T) {
	s := newStack(t) // no admin settings
	if out, err := operatorCmd(t, s, "list"); err != nil || !strings.Contains(out, "admin API is off") {
		t.Errorf("operator list without the admin API: %v\n%s", err, out)
	}

	cmd := exec.Command(binary, "serve")

	cmd.Env = append(s.env, "AIRLANCE_AUTH_ADMIN_RP_ID=admin.e2e.test")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "AIRLANCE_AUTH_ADMIN_ADDR") {
		t.Errorf("a half-written admin configuration was accepted: %v\n%s", err, out)
	}
}
