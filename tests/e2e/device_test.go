//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// stepUpFor runs the passkey proof of the native phone for one operation and returns the token.
func stepUpFor(t *testing.T, s *stack, c *client, me nativeSession, email, operation string) string {
	t.Helper()
	key := s.auths[email]
	headers := map[string]string{"Authorization": "Bearer " + me.access}
	begun := c.do(http.MethodPost, "/v1/native/me/step-up/options", map[string]string{"operation": operation}, headers)
	want(t, begun, http.StatusOK, "")
	done := c.do(http.MethodPost, "/v1/native/me/step-up/verify", map[string]any{
		"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(key.Assert(begun.options())),
	}, headers)
	want(t, done, http.StatusOK, "")
	s.secret(done.str("step_up_token"))
	return done.str("step_up_token")
}

func TestAPageSignsInWithTheApprovalOfAPhoneOnTheRealService(t *testing.T) {
	s := newStack(t)
	phoneClient := newClient(s)
	email := uniqueEmail(t, "owner")
	phone := nativeSignIn(t, s, phoneClient, email, "")
	page := newClient(s) // a browser tab with no session

	started := page.browser(http.MethodPost, "/v1/auth/device/start", map[string]string{"device_name": "Office laptop"}, "")
	want(t, started, http.StatusOK, "")
	id, code := started.str("request_id"), started.str("pairing_code")
	if id == "" || len(code) != 6 || started.str("poll_secret") != "" || started.str("client_binding") != "" {
		t.Fatalf("start = %s", started.Raw)
	}
	for _, name := range []string{"__Secure-px_device", "__Secure-px_binding"} {
		if page.cookies[name] == nil {
			t.Fatalf("no %s cookie after start", name)
		}
		s.secret(page.cookies[name].Value)
	}
	status := func(c *client) string {
		r := c.browser(http.MethodPost, "/v1/auth/device/status", map[string]string{"request_id": id}, "")
		if r.Status != http.StatusOK {
			return "refused"
		}
		return r.str("state")
	}
	if got := status(page); got != "pending" {
		t.Fatalf("state = %s", got)
	}
	// Another browser holding only the identifier, as a scanner of the QR code does, is refused.
	if got := status(newClient(s)); got != "refused" {
		t.Errorf("the QR code alone read the status: %s", got)
	}

	// The phone looks, types a wrong code, then the right one with a fresh proof.
	phoneAuth := map[string]string{"Authorization": "Bearer " + phone.access}
	view := phoneClient.do(http.MethodGet, "/v1/native/device/requests/"+id, nil, phoneAuth)
	want(t, view, http.StatusOK, "")
	if view.str("device_name") != "Office laptop" || strings.Contains(view.Raw, code) {
		t.Errorf("view = %s", view.Raw)
	}
	approve := func(typed, proof string) reply {
		headers := map[string]string{"Authorization": "Bearer " + phone.access}
		if proof != "" {
			headers["X-Step-Up"] = proof
		}
		return phoneClient.do(http.MethodPost, "/v1/native/device/requests/"+id+"/approve", map[string]string{"pairing_code": typed}, headers)
	}
	want(t, approve(code, ""), http.StatusForbidden, "step_up_required")
	proof := stepUpFor(t, s, phoneClient, phone, email, "approve_device")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	want(t, approve(wrong, proof), http.StatusBadRequest, "invalid_proof")
	if r := approve(code, proof); r.Status != http.StatusNoContent {
		t.Fatalf("approve = %d %s", r.Status, r.Raw)
	}
	if got := status(page); got != "approved" {
		t.Fatalf("state = %s", got)
	}

	redeemed := page.browser(http.MethodPost, "/v1/auth/device/redeem", map[string]string{"request_id": id}, "")
	want(t, redeemed, http.StatusOK, "")
	access := redeemed.str("access_token")
	s.secret(access)
	if access == "" || redeemed.str("refresh_token") != "" || page.cookies["__Secure-px_refresh"] == nil || page.cookies["__Secure-px_device"] != nil {
		t.Fatalf("redeem = %s, cookies %v", redeemed.Raw, page.cookies)
	}
	s.secret(page.cookies["__Secure-px_refresh"].Value)
	want(t, page.browser(http.MethodGet, "/v1/me", nil, access), http.StatusOK, "")
	// The page refreshes on its own and the phone is not involved any more.
	want(t, page.browser(http.MethodPost, "/v1/token/refresh", nil, ""), http.StatusOK, "")
	want(t, phoneClient.do(http.MethodGet, "/v1/native/me", nil, phoneAuth), http.StatusOK, "")
	want(t, page.browser(http.MethodPost, "/v1/auth/device/redeem", map[string]string{"request_id": id}, ""), http.StatusBadRequest, "invalid_proof")

	// The owner is told about the new device, once, with its label and the address it came from; the first sign-in
	// of the account, the phone's, told nothing. Nothing in the notice opens anything.
	notice := waitForNotices(t, email, 1)
	for _, fragment := range []string{"Office laptop", "If it was not you"} {
		if !strings.Contains(notice, fragment) {
			t.Errorf("the notice lacks %q: %q", fragment, notice)
		}
	}
	if !strings.Contains(notice, "Address: 127.0.0.1") && !strings.Contains(notice, "Address: ::1") {
		t.Errorf("the notice names no loopback address: %q", notice)
	}
	if strings.Contains(notice, code) || strings.Contains(notice, id) {
		t.Errorf("the notice carries the pairing code or the request: %q", notice)
	}
	if n := len(noticeIDs(t, email)); n != 1 {
		t.Errorf("%d notices", n)
	}

	// Two sessions of one user, the audit says how the second opened, and the approval is kept for a year.
	if n := s.count("sessions", "revoked_at IS NULL"); n != 2 {
		t.Errorf("%d live sessions, want 2", n)
	}
	if n := s.count("audit_events", "event = 'device.approved'"); n != 1 {
		t.Errorf("%d device.approved events", n)
	}
	if n := s.count("audit_events", "event = 'login.succeeded' AND fields ->> 'method' = 'qr'"); n != 1 {
		t.Errorf("%d qr logins", n)
	}
	if n := s.count("device_requests", "state = 'redeemed'"); n != 1 {
		t.Errorf("%d redeemed requests", n)
	}
	body := scrapeMetrics(t, s)
	for _, series := range []string{`operation="device_status",reason="bad_secret"`, `operation="device_approve",reason="wrong_code"`, `operation="device_redeem"`} {
		if !strings.Contains(body, series) {
			t.Errorf("the scrape lacks %s", series)
		}
	}
	s.checkLogs()
}

func TestANativeAppSignsInTheSameWayAndAPhoneCanRefuse(t *testing.T) {
	s := newStack(t)
	phoneClient := newClient(s)
	email := uniqueEmail(t, "owner")
	phone := nativeSignIn(t, s, phoneClient, email, "")
	phoneAuth := map[string]string{"Authorization": "Bearer " + phone.access}
	tv := newClient(s)

	start := func() (id, code, secret, binding string) {
		r := tv.native(http.MethodPost, "/v1/native/auth/device/start", map[string]string{"device_name": "Living room TV"}, "")
		want(t, r, http.StatusOK, "")
		s.secret(r.str("poll_secret"), r.str("client_binding"))
		return r.str("request_id"), r.str("pairing_code"), r.str("poll_secret"), r.str("client_binding")
	}
	call := func(step, id, secret, binding string) reply {
		return tv.native(http.MethodPost, "/v1/native/auth/device/"+step, map[string]string{"request_id": id, "poll_secret": secret, "client_binding": binding}, "")
	}

	id, code, secret, binding := start()
	if secret == "" || binding == "" {
		t.Fatal("the native response lacks its secrets")
	}
	r := call("status", id, secret, binding)
	want(t, r, http.StatusOK, "")
	if r.str("state") != "pending" {
		t.Fatalf("state = %s", r.Raw)
	}
	want(t, call("status", id, secret, "wrong-binding"), http.StatusBadRequest, "invalid_proof")

	// Approve, then redeem with the secret and the binding.
	proof := stepUpFor(t, s, phoneClient, phone, email, "approve_device")
	headers := map[string]string{"Authorization": "Bearer " + phone.access, "X-Step-Up": proof}
	if r := phoneClient.do(http.MethodPost, "/v1/native/device/requests/"+id+"/approve", map[string]string{"pairing_code": code}, headers); r.Status != http.StatusNoContent {
		t.Fatalf("approve = %d %s", r.Status, r.Raw)
	}
	want(t, call("redeem", id, "x", binding), http.StatusBadRequest, "invalid_proof")
	signed := call("redeem", id, secret, binding)
	want(t, signed, http.StatusOK, "")
	s.secret(signed.str("access_token"), signed.str("refresh_token"))
	want(t, tv.native(http.MethodGet, "/v1/native/me", nil, signed.str("access_token")), http.StatusOK, "")
	want(t, tv.native(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": signed.str("refresh_token")}, ""), http.StatusOK, "")

	// A request the phone refuses stays refused; so does one whose code was guessed three times.
	id2, code2, secret2, binding2 := start()
	if r := phoneClient.do(http.MethodPost, "/v1/native/device/requests/"+id2+"/deny", nil, phoneAuth); r.Status != http.StatusNoContent {
		t.Fatalf("deny = %d %s", r.Status, r.Raw)
	}
	if r := call("status", id2, secret2, binding2); r.str("state") != "denied" {
		t.Errorf("state = %s", r.Raw)
	}
	id3, code3, secret3, binding3 := start()
	proof3 := stepUpFor(t, s, phoneClient, phone, email, "approve_device")
	guess := func(c string) reply {
		return phoneClient.do(http.MethodPost, "/v1/native/device/requests/"+id3+"/approve", map[string]string{"pairing_code": c},
			map[string]string{"Authorization": "Bearer " + phone.access, "X-Step-Up": proof3})
	}
	bad := "000000"
	if code3 == bad {
		bad = "111111"
	}
	for i := 0; i < 3; i++ {
		want(t, guess(bad), http.StatusBadRequest, "invalid_proof")
	}
	want(t, guess(code3), http.StatusNotFound, "not_found")
	if r := call("status", id3, secret3, binding3); r.str("state") != "denied" {
		t.Errorf("state = %s", r.Raw)
	}
	_ = code2
	s.checkLogs()
}

func TestABlockedUserOrAnEndedPhoneSessionCannotBeRedeemed(t *testing.T) {
	s := newStack(t)
	for _, tc := range []struct {
		name   string
		break_ func(userID string)
	}{
		{"the user is blocked after the approval", func(userID string) {
			if _, err := s.db.Exec(`UPDATE users SET blocked_at = now() WHERE id = $1`, userID); err != nil {
				t.Fatal(err)
			}
		}},
		{"the phone's sessions are revoked after the approval", func(userID string) {
			if _, err := s.db.Exec(`UPDATE sessions SET revoked_at = now() WHERE user_id = $1`, userID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phoneClient := newClient(s)
			email := uniqueEmail(t, "owner")
			phone := nativeSignIn(t, s, phoneClient, email, "")
			tv := newClient(s)
			r := tv.native(http.MethodPost, "/v1/native/auth/device/start", map[string]string{}, "")
			want(t, r, http.StatusOK, "")
			id, code, secret, binding := r.str("request_id"), r.str("pairing_code"), r.str("poll_secret"), r.str("client_binding")
			s.secret(secret, binding)
			proof := stepUpFor(t, s, phoneClient, phone, email, "approve_device")
			ok := phoneClient.do(http.MethodPost, "/v1/native/device/requests/"+id+"/approve", map[string]string{"pairing_code": code},
				map[string]string{"Authorization": "Bearer " + phone.access, "X-Step-Up": proof})
			if ok.Status != http.StatusNoContent {
				t.Fatalf("approve = %d %s", ok.Status, ok.Raw)
			}
			tc.break_(phone.userID)
			before := s.count("sessions", "user_id = '"+phone.userID+"' AND revoked_at IS NULL")
			want(t, tv.native(http.MethodPost, "/v1/native/auth/device/redeem", map[string]string{"request_id": id, "poll_secret": secret, "client_binding": binding}, ""), http.StatusBadRequest, "invalid_proof")
			if n := s.count("sessions", "user_id = '"+phone.userID+"' AND revoked_at IS NULL"); n != before {
				t.Errorf("%d live sessions of the user, %d before: a refused redemption opened one", n, before)
			}
		})
	}
	s.checkLogs()
}

func TestAnExpiredRequestAndTheStartQuotaOnTheRealService(t *testing.T) {
	s := newStack(t)
	tv := newClient(s)
	r := tv.native(http.MethodPost, "/v1/native/auth/device/start", map[string]string{}, "")
	want(t, r, http.StatusOK, "")
	id, secret, binding := r.str("request_id"), r.str("poll_secret"), r.str("client_binding")
	s.secret(secret, binding)
	if _, err := s.db.Exec(`UPDATE device_requests SET created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes'`); err != nil {
		t.Fatal(err)
	}
	st := tv.native(http.MethodPost, "/v1/native/auth/device/status", map[string]string{"request_id": id, "poll_secret": secret, "client_binding": binding}, "")
	want(t, st, http.StatusOK, "")
	if st.str("state") != "expired" {
		t.Errorf("state = %s", st.Raw)
	}
	want(t, tv.native(http.MethodPost, "/v1/native/auth/device/redeem", map[string]string{"request_id": id, "poll_secret": secret, "client_binding": binding}, ""), http.StatusBadRequest, "invalid_proof")

	// Thirty starts an hour per address.
	var limited bool
	for i := 0; i < 40 && !limited; i++ {
		limited = tv.native(http.MethodPost, "/v1/native/auth/device/start", map[string]string{}, "").Status == http.StatusTooManyRequests
	}
	if !limited {
		t.Error("forty starts from one address were all accepted")
	}
	time.Sleep(0)
	s.checkLogs()
}
