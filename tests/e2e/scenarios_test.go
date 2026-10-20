//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/examples/tokencheck"
	"go.airlance.org/auth/internal/testutil"
)

type nativeSession struct {
	access, refresh, binding, userID string
}

func nativeSignIn(t *testing.T, s *stack, c *client, email, binding string) nativeSession {
	t.Helper()
	before := len(mailIDs(t, email))

	body := map[string]string{"email": email}
	if binding != "" {
		body["client_binding"] = binding
	}

	started := c.native(http.MethodPost, "/v1/native/auth/email/start", body, "")
	want(t, started, http.StatusAccepted, "")

	if binding == "" {
		binding = started.str("client_binding")
	}

	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before), "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")

	return nativePasskeyStep(t, s, c, email, binding, verified)
}

func nativePasskeyStep(t *testing.T, s *stack, c *client, email, binding string, verified reply) nativeSession {
	t.Helper()

	ticket := verified.str("ticket")
	s.secret(ticket, binding)

	var signedIn reply

	switch verified.str("next") {
	case "enroll_passkey":
		auth := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
		s.auths[email] = auth
		begun := c.native(http.MethodPost, "/v1/native/auth/passkey/register/options", map[string]string{"ticket": ticket, "client_binding": binding}, "")
		want(t, begun, http.StatusOK, "")

		signedIn = c.native(http.MethodPost, "/v1/native/auth/passkey/register/verify", map[string]any{
			"ticket": ticket, "client_binding": binding, "challenge_id": begun.str("challenge_id"),
			"credential": json.RawMessage(auth.Register(begun.options())), "device_name": "e2e",
		}, "")
		for _, code := range signedIn.list("recovery_codes") {
			s.secret(code)
		}
	case "second_factor":
		auth, ok := s.auths[email]
		if !ok {
			t.Fatalf("%s has a passkey the test never registered", email)
		}

		begun := c.native(http.MethodPost, "/v1/native/auth/passkey/login/options", nil, "")
		want(t, begun, http.StatusOK, "")
		signedIn = c.native(http.MethodPost, "/v1/native/auth/passkey/login/verify", map[string]any{
			"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(auth.Assert(begun.options())),
			"ticket": ticket, "client_binding": binding, "device_name": "e2e",
		}, "")
	default:
		t.Fatalf("verify answered %s", verified.Raw)
	}

	want(t, signedIn, http.StatusOK, "")
	user, _ := signedIn.Body["user"].(map[string]any)
	got := nativeSession{
		access: signedIn.str("access_token"), refresh: signedIn.str("refresh_token"), binding: binding, userID: fmt.Sprint(user["id"]),
	}
	s.secret(got.access, got.refresh)

	return got
}

func browserSignIn(t *testing.T, s *stack, c *client, email string) string {
	t.Helper()
	before := len(mailIDs(t, email))
	started := c.browser(http.MethodPost, "/v1/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	verified := c.browser(http.MethodPost, "/v1/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before),
	}, "")
	want(t, verified, http.StatusOK, "")
	ticket := verified.str("ticket")
	s.secret(ticket)

	var signedIn reply

	switch verified.str("next") {
	case "enroll_passkey":
		auth := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
		s.auths[email] = auth
		begun := c.browser(http.MethodPost, "/v1/auth/passkey/register/options", map[string]string{"ticket": ticket}, "")
		want(t, begun, http.StatusOK, "")
		signedIn = c.browser(http.MethodPost, "/v1/auth/passkey/register/verify", map[string]any{
			"ticket": ticket, "challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(auth.Register(begun.options())),
		}, "")
	case "second_factor":
		auth := s.auths[email]
		if auth == nil {
			t.Fatalf("%s has a passkey the test never registered", email)
		}

		begun := c.browser(http.MethodPost, "/v1/auth/passkey/login/options", nil, "")
		want(t, begun, http.StatusOK, "")
		signedIn = c.browser(http.MethodPost, "/v1/auth/passkey/login/verify", map[string]any{
			"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(auth.Assert(begun.options())), "ticket": ticket,
		}, "")
	default:
		t.Fatalf("verify answered %s", verified.Raw)
	}

	want(t, signedIn, http.StatusOK, "")

	for _, ck := range c.cookies {
		s.secret(ck.Value)
	}

	s.secret(signedIn.str("access_token"))

	return signedIn.str("access_token")
}

func TestNativeLifecycleThroughRealMail(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "native")
	me := nativeSignIn(t, s, c, email, "")

	profile := c.native(http.MethodGet, "/v1/native/me", nil, me.access)
	want(t, profile, http.StatusOK, "")

	if user, _ := profile.Body["user"].(map[string]any); user["email"] != email || user["id"] != me.userID {
		t.Errorf("me = %s", profile.Raw)
	}

	rotated := c.native(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": me.refresh}, "")
	want(t, rotated, http.StatusOK, "")
	s.secret(rotated.str("access_token"), rotated.str("refresh_token"))

	want(t, c.native(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": me.refresh}, ""), http.StatusUnauthorized, "invalid_refresh")
	want(t, c.native(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": rotated.str("refresh_token")}, ""), http.StatusUnauthorized, "invalid_refresh")
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, rotated.str("access_token")), http.StatusUnauthorized, "unauthenticated")

	again := nativeSignIn(t, s, c, email, me.binding)
	if n := s.count("auth_flows", "quota_class = 'recognized'"); n != 1 {
		t.Errorf("%d recognized flows, want the second sign-in's", n)
	}

	want(t, c.native(http.MethodPost, "/v1/native/signout", map[string]any{"scope": "all"}, again.access), http.StatusNoContent, "")

	if n := s.count("sessions", "revoked_at IS NULL"); n != 0 {
		t.Errorf("%d sessions still active after signing out everywhere", n)
	}

	s.checkLogs()
}

func TestBrowserLifecycleAndTheTwoTabProtocol(t *testing.T) {
	s := newStack(t)
	tabA := newClient(s)
	email := uniqueEmail(t, "browser")
	access := browserSignIn(t, s, tabA, email)

	tabB := &client{t: t, base: s.base, cookies: tabA.cookies}
	want(t, tabB.browser(http.MethodGet, "/v1/me", nil, access), http.StatusOK, "")

	first := tabA.browser(http.MethodPost, "/v1/token/refresh", nil, "")
	want(t, first, http.StatusOK, "")

	second := tabB.browser(http.MethodPost, "/v1/token/refresh", nil, "")
	want(t, second, http.StatusOK, "")
	s.secret(first.str("access_token"), second.str("access_token"))
	want(t, tabA.browser(http.MethodGet, "/v1/me", nil, second.str("access_token")), http.StatusOK, "")

	cookie := tabA.cookies["__Secure-px_refresh"].Value

	var wg sync.WaitGroup

	statuses := make([]int, 2)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()

			racer := &client{t: t, base: s.base, cookies: map[string]*http.Cookie{
				"__Secure-px_refresh": {Name: "__Secure-px_refresh", Value: cookie, Path: "/v1/token"},
			}}
			statuses[i] = racer.browser(http.MethodPost, "/v1/token/refresh", nil, "").Status
		}()
	}

	wg.Wait()

	wins := 0

	for _, st := range statuses {
		if st == http.StatusOK {
			wins++
		}
	}

	if wins != 1 {
		t.Errorf("statuses %v: want exactly one winner of two simultaneous refreshes", statuses)
	}

	want(t, tabA.browser(http.MethodPost, "/v1/token/refresh", nil, ""), http.StatusUnauthorized, "invalid_refresh")

	access = browserSignIn(t, s, tabA, email)

	want(t, tabA.browser(http.MethodPost, "/v1/signout", map[string]any{}, access), http.StatusNoContent, "")

	if _, ok := tabA.cookies["__Secure-px_refresh"]; ok {
		t.Error("the refresh cookie survived the sign-out")
	}

	want(t, tabB.browser(http.MethodPost, "/v1/token/refresh", nil, ""), http.StatusUnauthorized, "invalid_refresh")
	s.checkLogs()
}

func TestForeignPagesAreRefusedAndTrustedOriginsAreServed(t *testing.T) {
	s := newStack(t, "AIRLANCE_AUTH_BROWSER_ORIGINS=https://app.example.test")
	c := newClient(s)
	body := map[string]string{"email": uniqueEmail(t, "origin")}

	foreign := c.do(http.MethodPost, "/v1/auth/email/start", body, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	want(t, foreign, http.StatusForbidden, "permission_denied")

	if foreign.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("a foreign page got CORS headers")
	}

	trusted := c.do(http.MethodPost, "/v1/auth/email/start", body, map[string]string{"Origin": "https://app.example.test", "Sec-Fetch-Site": "cross-site"})
	want(t, trusted, http.StatusAccepted, "")

	if trusted.Header.Get("Access-Control-Allow-Origin") != "https://app.example.test" || trusted.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("CORS headers = %v", trusted.Header)
	}

	if n := s.count("auth_flows", "true"); n != 1 {
		t.Errorf("%d flows, want only the trusted page's", n)
	}
}

func TestTheOwnerSignsInWhileAnAttackerBurnsTheBudget(t *testing.T) {
	s := newStack(t, "AIRLANCE_AUTH_TRUSTED_PROXIES=127.0.0.1/32")
	c := newClient(s)
	email := uniqueEmail(t, "owner")
	owner := nativeSignIn(t, s, c, email, "")

	limited := 0

	for i := 0; i < 14; i++ {
		r := c.do(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email},
			map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1)})
		if r.Status == http.StatusTooManyRequests {
			limited++
		}
	}

	if limited == 0 {
		t.Fatal("the attacker was never limited")
	}

	stranger := c.do(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, map[string]string{"X-Forwarded-For": "203.0.113.200"})
	want(t, stranger, http.StatusTooManyRequests, "rate_limited")

	deadline := time.Now().Add(20 * time.Second)
	for s.count("outbox", "status = 'queued'") != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the mail queue did not drain")
		}

		time.Sleep(50 * time.Millisecond)
	}

	again := nativeSignIn(t, s, c, email, owner.binding)
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, again.access), http.StatusOK, "")
	s.checkLogs()
}

func TestAFlowAndItsMailSurviveARestartAndStopIsClean(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "restart")
	before := len(mailIDs(t, email))

	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")

	s.restart()

	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before), "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")

	s.restart()
	me := nativePasskeyStep(t, s, c, email, binding, verified)

	s.restart()
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusOK, "")
	s.checkLogs()
}

func TestAProductServiceTrustsTokensThroughTheJWKS(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	me := nativeSignIn(t, s, c, uniqueEmail(t, "service"), "")

	verifier, err := tokencheck.New(tokencheck.Config{Issuer: s.base, Audience: "e2e", JWKSURL: s.base + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.Verify(context.Background(), me.access)
	if err != nil || claims.Subject != me.userID {
		t.Fatalf("claims = %+v, %v", claims, err)
	}

	other, err := tokencheck.New(tokencheck.Config{Issuer: s.base, Audience: "another-product", JWKSURL: s.base + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := other.Verify(context.Background(), me.access); !errors.Is(err, tokencheck.ErrInvalidToken) {
		t.Errorf("a service of another audience accepted the token: %v", err)
	}

	if _, err := verifier.Verify(context.Background(), me.refresh); !errors.Is(err, tokencheck.ErrInvalidToken) {
		t.Errorf("a refresh token passed as an access token: %v", err)
	}

	want(t, c.native(http.MethodPost, "/v1/native/signout", nil, me.access), http.StatusNoContent, "")

	if _, err := verifier.Verify(context.Background(), me.access); err != nil {
		t.Errorf("the JWT of a signed-out session stopped verifying early: %v", err)
	}

	want(t, c.native(http.MethodGet, "/v1/native/me", nil, me.access), http.StatusUnauthorized, "unauthenticated")
}

func TestAMailboxAloneNeverOpensASession(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "mailbox")
	owner := nativeSignIn(t, s, c, email, "")
	sessions := s.count("sessions", "true")

	before := len(mailIDs(t, email))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")
	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before), "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")

	if verified.str("next") != "second_factor" || verified.str("access_token") != "" || verified.str("refresh_token") != "" {
		t.Fatalf("verify = %s", verified.Raw)
	}

	ticket := verified.str("ticket")
	s.secret(ticket, binding)

	want(t, c.native(http.MethodPost, "/v1/native/auth/passkey/register/options", map[string]string{"ticket": ticket, "client_binding": binding}, ""),
		http.StatusBadRequest, "invalid_proof")

	attacker := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
	attacker.UserHandle = []byte("0123456789abcdef")
	begun := c.native(http.MethodPost, "/v1/native/auth/passkey/login/options", nil, "")
	want(t, c.native(http.MethodPost, "/v1/native/auth/passkey/login/verify", map[string]any{
		"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(attacker.Assert(begun.options())),
		"ticket": ticket, "client_binding": binding,
	}, ""), http.StatusBadRequest, "invalid_proof")

	want(t, c.native(http.MethodPost, "/v1/native/auth/recovery/verify", map[string]string{"ticket": ticket, "client_binding": binding, "code": "AAAA-AAAA-AAAA-AAAA"}, ""),
		http.StatusBadRequest, "invalid_proof")

	if n := s.count("sessions", "true"); n != sessions {
		t.Errorf("%d new sessions without a passkey", n-sessions)
	}

	want(t, c.native(http.MethodGet, "/v1/native/me", nil, owner.access), http.StatusOK, "")
	s.checkLogs()
}

func TestRecoveryCodeReplacesALostPasskeyAndClosesOldSessions(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "recovery")

	before := len(mailIDs(t, email))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")
	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before), "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")
	ticket := verified.str("ticket")
	auth := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
	s.auths[email] = auth
	begun := c.native(http.MethodPost, "/v1/native/auth/passkey/register/options", map[string]string{"ticket": ticket, "client_binding": binding}, "")
	registered := c.native(http.MethodPost, "/v1/native/auth/passkey/register/verify", map[string]any{
		"ticket": ticket, "client_binding": binding, "challenge_id": begun.str("challenge_id"),
		"credential": json.RawMessage(auth.Register(begun.options())),
	}, "")
	want(t, registered, http.StatusOK, "")

	codes := registered.list("recovery_codes")
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes", len(codes))
	}

	for _, code := range codes {
		s.secret(code)
	}

	s.secret(ticket, binding, registered.str("access_token"), registered.str("refresh_token"))
	lostDevice := registered.str("access_token")

	before = len(mailIDs(t, email))
	again := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, again, http.StatusAccepted, "")
	newBinding := again.str("client_binding")
	second := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": again.str("flow_id"), "code": code(t, email, before), "client_binding": newBinding,
	}, "")
	want(t, second, http.StatusOK, "")

	if second.str("next") != "second_factor" {
		t.Fatalf("next = %s", second.str("next"))
	}

	redeemed := c.native(http.MethodPost, "/v1/native/auth/recovery/verify", map[string]string{
		"ticket": second.str("ticket"), "client_binding": newBinding, "code": codes[0],
	}, "")
	want(t, redeemed, http.StatusOK, "")

	if redeemed.str("next") != "enroll_passkey" || redeemed.str("access_token") != "" {
		t.Fatalf("recovery = %s", redeemed.Raw)
	}

	s.secret(second.str("ticket"), redeemed.str("ticket"), newBinding)

	want(t, c.native(http.MethodGet, "/v1/native/me", nil, lostDevice), http.StatusOK, "")
	fresh := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
	begun = c.native(http.MethodPost, "/v1/native/auth/passkey/register/options", map[string]string{"ticket": redeemed.str("ticket"), "client_binding": newBinding}, "")
	want(t, begun, http.StatusOK, "")
	recovered := c.native(http.MethodPost, "/v1/native/auth/passkey/register/verify", map[string]any{
		"ticket": redeemed.str("ticket"), "client_binding": newBinding, "challenge_id": begun.str("challenge_id"),
		"credential": json.RawMessage(fresh.Register(begun.options())),
	}, "")
	want(t, recovered, http.StatusOK, "")
	s.secret(recovered.str("access_token"), recovered.str("refresh_token"))

	for _, code := range recovered.list("recovery_codes") {
		s.secret(code)
	}

	want(t, c.native(http.MethodGet, "/v1/native/me", nil, lostDevice), http.StatusUnauthorized, "unauthenticated")
	want(t, c.native(http.MethodGet, "/v1/native/me", nil, recovered.str("access_token")), http.StatusOK, "")

	if n := s.count("sessions", "revoked_at IS NULL"); n != 1 {
		t.Errorf("%d live sessions after the recovery, want one", n)
	}

	if n := s.count("recovery_codes", "used_at IS NOT NULL"); n != 0 {
		t.Errorf("%d used codes: the recovery issues a whole fresh set", n)
	}

	s.checkLogs()
}

func TestManagingPasskeysNeedsAFreshProofOnTheRealService(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "manage")
	me := nativeSignIn(t, s, c, email, "")
	first := s.auths[email]
	auth := func(method, path string, body any, stepUp string) reply {
		headers := map[string]string{"Authorization": "Bearer " + me.access}
		if stepUp != "" {
			headers["X-Step-Up"] = stepUp
		}

		return c.do(method, "/v1/native/me"+path, body, headers)
	}
	stepUp := func(key *testutil.SoftAuthenticator, operation string) string {
		t.Helper()

		begun := auth(http.MethodPost, "/step-up/options", map[string]string{"operation": operation}, "")
		want(t, begun, http.StatusOK, "")
		done := auth(http.MethodPost, "/step-up/verify", map[string]any{
			"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(key.Assert(begun.options())),
		}, "")
		want(t, done, http.StatusOK, "")
		s.secret(done.str("step_up_token"))

		return done.str("step_up_token")
	}

	want(t, auth(http.MethodPost, "/passkeys/options", nil, ""), http.StatusForbidden, "step_up_required")
	want(t, auth(http.MethodPost, "/recovery-codes", nil, ""), http.StatusForbidden, "step_up_required")

	token := stepUp(first, "add_passkey")
	second := testutil.NewSoftAuthenticator(t, e2eRPID, e2eRPOrigin)
	begun := auth(http.MethodPost, "/passkeys/options", nil, token)
	want(t, begun, http.StatusOK, "")
	added := auth(http.MethodPost, "/passkeys", map[string]any{
		"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(second.Register(begun.options())), "name": "Second",
	}, token)
	want(t, added, http.StatusCreated, "")
	want(t, auth(http.MethodPost, "/passkeys/options", nil, token), http.StatusForbidden, "step_up_required")

	listed := auth(http.MethodGet, "/passkeys", nil, "")
	want(t, listed, http.StatusOK, "")

	keys, _ := listed.Body["passkeys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("passkeys = %s", listed.Raw)
	}

	firstID := fmt.Sprint(keys[0].(map[string]any)["id"])
	secondID := added.str("id")

	if r := auth(http.MethodDelete, "/passkeys/"+firstID, nil, stepUp(second, "delete_passkey")); r.Status != http.StatusNoContent {
		t.Fatalf("delete = %d %s", r.Status, r.Raw)
	}

	want(t, auth(http.MethodDelete, "/passkeys/"+secondID, nil, stepUp(second, "delete_passkey")), http.StatusConflict, "last_passkey")

	before := len(mailIDs(t, email))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")
	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": code(t, email, before), "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")

	asserting := c.native(http.MethodPost, "/v1/native/auth/passkey/login/options", nil, "")
	want(t, c.native(http.MethodPost, "/v1/native/auth/passkey/login/verify", map[string]any{
		"challenge_id": asserting.str("challenge_id"), "credential": json.RawMessage(first.Assert(asserting.options())),
		"ticket": verified.str("ticket"), "client_binding": binding,
	}, ""), http.StatusBadRequest, "invalid_proof")
	s.secret(verified.str("ticket"), binding)

	codes := auth(http.MethodPost, "/recovery-codes", nil, stepUp(second, "regenerate_recovery_codes"))
	want(t, codes, http.StatusOK, "")

	if n := len(codes.list("recovery_codes")); n != 10 {
		t.Errorf("%d codes", n)
	}

	for _, code := range codes.list("recovery_codes") {
		s.secret(code)
	}

	s.checkLogs()
}

func subjectsTo(t *testing.T, email string) []string {
	t.Helper()

	var subjects []string

	for _, id := range mailIDs(t, email) {
		var msg struct{ Subject string }
		getJSON(t, mailpitURL+"/api/v1/message/"+id, &msg)
		subjects = append(subjects, msg.Subject)
	}

	return subjects
}

func waitForMail(t *testing.T, email string, n int) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for len(mailIDs(t, email)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s has %d mails, want %d", email, len(mailIDs(t, email)), n)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func TestChangingTheEmailMovesTheAccountAndTellsTheOldAddress(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	oldEmail, newEmail := uniqueEmail(t, "before"), uniqueEmail(t, "after")
	me := nativeSignIn(t, s, c, oldEmail, "")
	key := s.auths[oldEmail]
	auth := func(method, path string, body any, stepUp string) reply {
		headers := map[string]string{"Authorization": "Bearer " + me.access}
		if stepUp != "" {
			headers["X-Step-Up"] = stepUp
		}

		return c.do(method, "/v1/native/me"+path, body, headers)
	}
	stepUp := func() string {
		t.Helper()

		begun := auth(http.MethodPost, "/step-up/options", map[string]string{"operation": "change_email"}, "")
		want(t, begun, http.StatusOK, "")
		done := auth(http.MethodPost, "/step-up/verify", map[string]any{
			"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(key.Assert(begun.options())),
		}, "")
		want(t, done, http.StatusOK, "")
		s.secret(done.str("step_up_token"))

		return done.str("step_up_token")
	}

	want(t, auth(http.MethodPost, "/email/change", map[string]string{"email": newEmail}, ""), http.StatusForbidden, "step_up_required")

	if len(mailIDs(t, newEmail)) != 0 {
		t.Fatal("a refused request sent a mail to the new address")
	}

	token := stepUp()
	started := auth(http.MethodPost, "/email/change", map[string]string{"email": newEmail}, token)
	want(t, started, http.StatusAccepted, "")

	flowID := started.str("flow_id")

	got := code(t, newEmail, 0)
	if subjects := subjectsTo(t, newEmail); len(subjects) != 1 || subjects[0] != "Confirm your new email address" {
		t.Errorf("mails to the new address = %q", subjects)
	}

	want(t, auth(http.MethodPost, "/email/change", map[string]string{"email": uniqueEmail(t, "again")}, token), http.StatusForbidden, "step_up_required")

	if before := len(mailIDs(t, oldEmail)); before != 1 { // the sign-in code only: nothing is announced yet
		t.Errorf("the old address has %d mails before the change", before)
	}

	wrong := "00000000"
	if got == wrong {
		wrong = "11111111"
	}

	want(t, auth(http.MethodPost, "/email/change/confirm", map[string]string{"flow_id": flowID, "code": wrong}, ""), http.StatusBadRequest, "invalid_code")
	done := auth(http.MethodPost, "/email/change/confirm", map[string]string{"flow_id": flowID, "code": got}, "")
	want(t, done, http.StatusOK, "")

	if done.str("email") != newEmail {
		t.Errorf("email = %q", done.str("email"))
	}

	want(t, auth(http.MethodPost, "/email/change/confirm", map[string]string{"flow_id": flowID, "code": got}, ""), http.StatusBadRequest, "invalid_code")

	waitForMail(t, oldEmail, 2)

	subjects := subjectsTo(t, oldEmail)
	if subjects[0] != "The email address of your account changed" {
		t.Fatalf("mails to the old address = %q", subjects)
	}

	var notice struct{ Text string }
	getJSON(t, mailpitURL+"/api/v1/message/"+mailIDs(t, oldEmail)[0], &notice)

	if codeInMail.MatchString(notice.Text) || strings.Contains(notice.Text, newEmail) || strings.Contains(notice.Text, "e2e.example.test") {
		t.Errorf("the notice carries a code or an address: %q", notice.Text)
	}

	profile := auth(http.MethodGet, "", nil, "")
	want(t, profile, http.StatusOK, "")

	if user, _ := profile.Body["user"].(map[string]any); user["email"] != newEmail {
		t.Errorf("profile = %s", profile.Raw)
	}

	if n := s.count("users", "email = '"+oldEmail+"'"); n != 0 {
		t.Errorf("%d accounts keep the old address", n)
	}

	if n := s.count("users", "email = '"+newEmail+"'"); n != 1 {
		t.Errorf("%d accounts have the new address", n)
	}

	s.auths[newEmail] = key

	again := nativeSignIn(t, s, c, newEmail, "")
	if again.userID != me.userID {
		t.Errorf("the new address opened user %s, want %s", again.userID, me.userID)
	}

	strangerBefore := len(mailIDs(t, oldEmail))
	started2 := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": oldEmail}, "")
	want(t, started2, http.StatusAccepted, "")
	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started2.str("flow_id"), "code": code(t, oldEmail, strangerBefore), "client_binding": started2.str("client_binding"),
	}, "")
	want(t, verified, http.StatusOK, "")

	if verified.str("next") != "enroll_passkey" {
		t.Errorf("the old address was told %q, want enroll_passkey", verified.str("next"))
	}

	s.secret(verified.str("ticket"), started2.str("client_binding"), got)
	s.checkLogs()
}

func TestDeletingAccountStopsEverySessionAndAllowsANewIdentity(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "delete")
	me := nativeSignIn(t, s, c, email, "")
	other := nativeSignIn(t, s, c, email, "")
	key := s.auths[email]
	headers := map[string]string{"Authorization": "Bearer " + me.access}
	want(t, c.do(http.MethodDelete, "/v1/native/me", nil, headers), http.StatusForbidden, "step_up_required")
	begun := c.do(http.MethodPost, "/v1/native/me/step-up/options", map[string]string{"operation": "delete_account"}, headers)
	want(t, begun, http.StatusOK, "")
	proof := c.do(http.MethodPost, "/v1/native/me/step-up/verify", map[string]any{"challenge_id": begun.str("challenge_id"), "credential": json.RawMessage(key.Assert(begun.options()))}, headers)
	want(t, proof, http.StatusOK, "")
	s.secret(proof.str("step_up_token"))
	headers["X-Step-Up"] = proof.str("step_up_token")
	want(t, c.do(http.MethodDelete, "/v1/native/me", nil, headers), http.StatusNoContent, "")

	for _, sess := range []nativeSession{me, other} {
		want(t, c.do(http.MethodGet, "/v1/native/me", nil, map[string]string{"Authorization": "Bearer " + sess.access}), http.StatusUnauthorized, "unauthenticated")
		want(t, c.do(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": sess.refresh}, nil), http.StatusUnauthorized, "invalid_refresh")
	}

	want(t, c.do(http.MethodDelete, "/v1/native/me", nil, headers), http.StatusUnauthorized, "unauthenticated")

	again := nativeSignIn(t, s, c, email, "")
	if again.userID == me.userID {
		t.Error("new registration reused deleted identity")
	}

	s.checkLogs()
}

func rotate(t *testing.T, s *stack, args ...string) (string, error) {
	t.Helper()

	parsed, err := url.Parse(s.dsn)
	if err != nil {
		t.Fatal(err)
	}

	full := append([]string{"../../scripts/rotate_keys.py", "--keyring", filepath.Join(s.dir, "keyring.json"), "--schema", parsed.Query().Get("search_path")}, args...)
	cmd := exec.Command("python3", full...)

	if _, err := exec.LookPath("psql"); err == nil {
		direct := *parsed
		direct.RawQuery = url.Values{"sslmode": parsed.Query()["sslmode"]}.Encode()
		cmd.Env = append(os.Environ(), "AIRLANCE_AUTH_PSQL_URL="+direct.String())
	}

	out, err := cmd.CombinedOutput()

	return string(out), err
}

func keyIDs(t *testing.T, s *stack) []string {
	t.Helper()

	var set struct {
		Keys []struct{ Kid string } `json:"keys"`
	}
	getJSON(t, s.base+"/.well-known/jwks.json", &set)

	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}

	sort.Strings(kids)

	return kids
}

func tokenKid(t *testing.T, token string) string {
	t.Helper()

	header, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct{ Kid string }
	if err := json.Unmarshal(header, &parsed); err != nil {
		t.Fatal(err)
	}

	return parsed.Kid
}

func TestRotatingKeysKeepsEveryLoginAndTokenValid(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "rotate")
	old := nativeSignIn(t, s, c, email, "")
	oldKid := tokenKid(t, old.access)
	me := func(token string) reply { return c.native(http.MethodGet, "/v1/native/me", nil, token) }
	want(t, me(old.access), http.StatusOK, "")

	before := len(mailIDs(t, email))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")
	pending := code(t, email, before)

	for _, purpose := range []string{"otp", "jwt"} {
		if out, err := rotate(t, s, "add", purpose); err != nil {
			t.Fatalf("add %s: %v\n%s", purpose, err, out)
		}
	}

	s.restart()

	kids := keyIDs(t, s)
	if len(kids) != 2 || !slices.Contains(kids, oldKid) {
		t.Fatalf("key set after add = %v, want the old kid %s and a new one", kids, oldKid)
	}

	if tokenKid(t, nativeSignIn(t, s, c, email, "").access) != oldKid {
		t.Error("a key that is only published already signs")
	}

	newJWT := ""

	for _, kid := range kids {
		if kid != oldKid {
			newJWT = kid
		}
	}

	if out, err := rotate(t, s, "activate", "jwt", newJWT); err == nil || !strings.Contains(out, "wait") {
		t.Fatalf("activate before the cache wait: %v\n%s", err, out)
	}

	if out, err := rotate(t, s, "activate", "jwt", newJWT, "--cache-wait", "0s"); err != nil {
		t.Fatalf("activate jwt: %v\n%s", err, out)
	}

	otpKids, _ := rotate(t, s, "status")

	newOTP := regexp.MustCompile(`otp-\d{8}\S*`).FindString(otpKids)
	if out, err := rotate(t, s, "activate", "otp", newOTP); err != nil {
		t.Fatalf("activate otp: %v\n%s", err, out)
	}

	s.restart()

	want(t, me(old.access), http.StatusOK, "")

	fresh := nativeSignIn(t, s, c, email, "")
	if got := tokenKid(t, fresh.access); got != newJWT {
		t.Errorf("a new token is signed with %q, want %q", got, newJWT)
	}

	verified := c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": pending, "client_binding": binding,
	}, "")
	want(t, verified, http.StatusOK, "")

	if verified.str("next") != "second_factor" {
		t.Fatalf("the half done sign-in was told %q", verified.str("next"))
	}

	if out, err := rotate(t, s, "retire", "otp", "otp-a"); err != nil {
		t.Fatalf("retire otp: %v\n%s", err, out)
	}

	if out, err := rotate(t, s, "retire", "jwt", oldKid, "--access-ttl", "5m"); err == nil || !strings.Contains(out, "can still be valid") {
		t.Fatalf("retire jwt at once: %v\n%s", err, out)
	}

	s.restart()
	want(t, me(old.access), http.StatusOK, "")
	nativeSignIn(t, s, c, email, "")

	if out, err := rotate(t, s, "retire", "jwt", oldKid, "--compromised"); err != nil {
		t.Fatalf("retire compromised: %v\n%s", err, out)
	}

	s.restart()

	if kids := keyIDs(t, s); len(kids) != 1 || kids[0] != newJWT {
		t.Errorf("key set after the compromise = %v, want only %s", kids, newJWT)
	}

	want(t, me(old.access), http.StatusUnauthorized, "unauthenticated")
	want(t, me(fresh.access), http.StatusOK, "")
	s.checkLogs()
}

func scrapeMetrics(t *testing.T, s *stack) string {
	t.Helper()

	resp, err := http.Get(s.base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape = %d, %v", resp.StatusCode, err)
	}

	return string(body)
}

func TestMetricsShowFailingSignInWithoutRevealingWhoFailed(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	email := uniqueEmail(t, "metrics")
	nativeSignIn(t, s, c, email, "")

	before := len(mailIDs(t, email))
	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": email}, "")
	want(t, started, http.StatusAccepted, "")
	binding := started.str("client_binding")
	right := code(t, email, before)

	wrong := "00000000"
	if right == wrong {
		wrong = "11111111"
	}

	want(t, c.native(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": started.str("flow_id"), "code": wrong, "client_binding": binding}, ""), http.StatusBadRequest, "invalid_code")
	s.secret(binding)

	body := scrapeMetrics(t, s)
	for _, series := range []string{
		`airlance_auth_http_requests_total{route="POST /v1/native/auth/email/start",status_class="2xx"}`,
		`airlance_auth_http_requests_total{route="POST /v1/native/auth/email/verify",status_class="4xx"} 1`,
		`airlance_auth_denied_total{operation="verify",reason="wrong_code"} 1`,
		`airlance_auth_http_request_seconds_count{route="POST /v1/native/auth/email/verify"}`,
		`airlance_auth_mail_queue_stats_up 1`,
	} {
		if !strings.Contains(body, series) {
			t.Errorf("the scrape lacks %s", series)
		}
	}

	for _, secret := range []string{email, strings.Split(email, "@")[0], binding, started.str("flow_id"), "127.0.0.1", "e2e.example.test"} {
		if strings.Contains(body, secret) {
			t.Errorf("the scrape contains %q", secret)
		}
	}

	for _, labels := range regexp.MustCompile(`\{[^}]*\}`).FindAllString(body, -1) {
		if strings.Contains(labels, right) || strings.Contains(labels, wrong) {
			t.Errorf("a label carries a code: %s", labels)
		}
	}

	if strings.Contains(body, `route="GET /metrics"`) {
		t.Error("the scrape counts itself")
	}
}

func invite(t *testing.T, s *stack, args ...string) (string, error) {
	t.Helper()

	cmd := exec.Command(binary, append([]string{"invite"}, args...)...)
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()

	return string(out), err
}

func TestClosedRegistrationLetsOnlyTheInvitedIn(t *testing.T) {
	const loginPage = "https://app.example.test/login"

	s := newStack(t, "AIRLANCE_AUTH_REGISTRATION=invite", "AIRLANCE_AUTH_INVITATION_URL="+loginPage)
	c := newClient(s)
	guest, stranger := uniqueEmail(t, "guest"), uniqueEmail(t, "stranger")

	started := c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": stranger}, "")
	want(t, started, http.StatusAccepted, "")

	if started.str("flow_id") == "" || started.str("client_binding") == "" {
		t.Fatalf("the answer to a stranger is not an ordinary start: %s", started.Raw)
	}

	time.Sleep(3 * time.Second)

	if n := len(mailIDs(t, stranger)); n != 0 {
		t.Fatalf("a stranger got %d mails", n)
	}

	s.secret(started.str("client_binding"))

	if out, err := invite(t, s, "create", guest); err != nil || !strings.Contains(out, "invited "+guest) {
		t.Fatalf("invite create: %v\n%s", err, out)
	}

	if out, err := invite(t, s, "list"); err != nil || !strings.Contains(out, guest) || !strings.Contains(out, "active") {
		t.Fatalf("invite list: %v\n%s", err, out)
	}

	waitForMail(t, guest, 1)

	if subjects := subjectsTo(t, guest); len(subjects) != 1 || subjects[0] != "You have been invited" {
		t.Fatalf("mails to the guest = %q", subjects)
	}

	var invitation struct{ Text string }
	getJSON(t, mailpitURL+"/api/v1/message/"+mailIDs(t, guest)[0], &invitation)

	if !strings.Contains(invitation.Text, loginPage) || !strings.Contains(invitation.Text, "valid until") || codeInMail.MatchString(invitation.Text) {
		t.Errorf("the invitation mail = %q", invitation.Text)
	}

	me := nativeSignIn(t, s, c, guest, "")
	if me.access == "" {
		t.Fatal("the guest got no session")
	}

	if out, err := invite(t, s, "list"); err != nil || !strings.Contains(out, "no invitations") {
		t.Errorf("the invitation survived the registration: %v\n%s", err, out)
	}

	nativeSignIn(t, s, c, guest, "")

	late := uniqueEmail(t, "late")
	if out, err := invite(t, s, "create", late, "--no-mail"); err != nil || !strings.Contains(out, "no email was queued") {
		t.Fatalf("invite create: %v\n%s", err, out)
	}

	if out, err := invite(t, s, "revoke", late); err != nil || !strings.Contains(out, "revoked") {
		t.Fatalf("invite revoke: %v\n%s", err, out)
	}

	want(t, c.native(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": late}, ""), http.StatusAccepted, "")
	time.Sleep(3 * time.Second)

	if n := len(mailIDs(t, late)); n != 0 {
		t.Errorf("a withdrawn invitation still got %d mails", n)
	}

	if body := scrapeMetrics(t, s); !strings.Contains(body, `airlance_auth_denied_total{operation="start",reason="not_invited"} 2`) {
		t.Errorf("the scrape lacks two not_invited refusals:\n%s", body)
	}

	if s.count("users", "email = '"+stranger+"'") != 0 || s.count("users", "email = '"+late+"'") != 0 {
		t.Error("an account exists for an address that was never invited")
	}

	s.checkLogs()
}

func TestTheInviteCommandSaysWhenTheModeMakesItPointlessAndRefusesRegisteredAddresses(t *testing.T) {
	s := newStack(t)
	c := newClient(s)
	member := uniqueEmail(t, "member")
	nativeSignIn(t, s, c, member, "")

	out, err := invite(t, s, "create", uniqueEmail(t, "guest"))
	if err != nil || !strings.Contains(out, "have no effect") {
		t.Errorf("create in the open mode: %v\n%s", err, out)
	}

	out, err = invite(t, s, "create", member)
	if err != nil || !strings.Contains(out, "already has an account") {
		t.Errorf("create for a member: %v\n%s", err, out)
	}

	if out, err := invite(t, s, "create", "not an address"); err == nil {
		t.Errorf("a bad address was accepted: %s", out)
	}

	if out, err := invite(t, s, "create", uniqueEmail(t, "x"), "--ttl", "1m"); err == nil {
		t.Errorf("a one-minute invitation was accepted: %s", out)
	}
}
