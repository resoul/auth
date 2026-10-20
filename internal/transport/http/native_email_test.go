package http_test

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

func TestNativeStartIssuesAFlowAndABindingToANewClient(t *testing.T) {
	e := newEnv(t)
	rec := e.post(startPath, map[string]string{"email": " Alice@Example.test "})
	res := decode[startResponse](t, rec, http.StatusAccepted)

	if res.FlowID == "" || res.ClientBinding == "" {
		t.Fatalf("response = %+v, want a flow and a new binding", res)
	}

	if !res.ExpiresAt.Equal(t0.Add(10*time.Minute)) || !res.ResendAfter.Equal(t0.Add(time.Minute)) {
		t.Errorf("expires_at = %v, resend_after = %v", res.ExpiresAt, res.ResendAfter)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q: the response carries a client secret", got)
	}

	if jobs := e.store.OutboxJobs(); len(jobs) != 1 || jobs[0].FlowID.String() != res.FlowID {
		t.Errorf("outbox = %+v, want one job of the flow", jobs)
	}
}

func TestNativeStartWithAKnownBindingIssuesNoNewOne(t *testing.T) {
	e := newEnv(t)
	first := e.start("alice@example.test", "")

	again := e.start("alice@example.test", first.ClientBinding)
	if again.ClientBinding != "" || again.FlowID == first.FlowID {
		t.Errorf("second start = %+v, want a new flow and no new binding", again)
	}
}

func TestNativeStartLooksTheSameForNewAndExistingEmails(t *testing.T) {
	e := newEnv(t)
	e.signIn("alice@example.test")

	fields := func(email string) []string {
		rec := e.post(startPath, map[string]string{"email": email})
		body := decode[map[string]any](t, rec, http.StatusAccepted)

		return slices.Sorted(maps.Keys(body))
	}

	existing, unknown := fields("alice@example.test"), fields("bob@example.test")
	if !slices.Equal(existing, unknown) {
		t.Errorf("existing email gives %v, new email gives %v", existing, unknown)
	}

	if slices.Contains(existing, "user_id") || slices.Contains(existing, "is_existing_user") {
		t.Errorf("start reveals the account: %v", existing)
	}
}

func TestNativeStartRefusesMalformedInputAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	for name, body := range map[string]string{
		"invalid email":   `{"email": "not-an-email"}`,
		"missing email":   `{}`,
		"bad binding":     `{"email": "alice@example.test", "client_binding": "short"}`,
		"not json":        `email=alice@example.test`,
		"wrong type":      `{"email": 42}`,
		"empty body":      ``,
		"oversized body":  `{"email": "alice@example.test", "pad": "` + strings.Repeat("x", 20<<10) + `"}`,
		"truncated json":  `{"email": "alice@example.test"`,
		"array, not dict": `["alice@example.test"]`,
	} {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, e.postRaw(startPath, body), http.StatusBadRequest, "invalid_request")
		})
	}

	if e.store.FlowCount() != 0 || len(e.store.OutboxJobs()) != 0 {
		t.Error("a refused start wrote a flow or a mail")
	}
}

func TestNativeStartOverQuotaIsRateLimited(t *testing.T) {
	e := newEnv(t, memory.WithLimits(1, memory.Unlimited))
	e.start("alice@example.test", "")
	wantProblem(t, e.post(startPath, map[string]string{"email": "alice@example.test"}), http.StatusTooManyRequests, "rate_limited")
}

func TestNativeVerifyIssuesATicketAndNoSession(t *testing.T) {
	e := newEnv(t)
	started := e.start("Alice@Example.test", "")
	rec := e.post(verifyPath, map[string]string{"flow_id": started.FlowID, "code": e.code(started.FlowID), "client_binding": started.ClientBinding})
	body := decode[map[string]any](t, rec, http.StatusOK)

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response may be cached")
	}

	if len(body) != 3 || body["next"] != "enroll_passkey" || body["ticket"] == "" || body["expires_at"] == nil {
		t.Errorf("body = %v, want next, ticket and expires_at only", body)
	}

	if _, ok := e.store.User(mustEmail(t, "alice@example.test")); !ok {
		t.Error("the user of a proven email was not created")
	}

	if e.store.SessionCount() != 0 || e.store.TokenCount() != 0 {
		t.Error("verify opened a session: that needs a passkey")
	}
}

func TestNativeVerifyOfAUserWithAPasskeyAsksForTheSecondFactor(t *testing.T) {
	e := newEnv(t)
	e.signIn("alice@example.test")
	started := e.start("alice@example.test", "")

	step := decode[nextStepResponse](t, e.verify(started.FlowID, e.code(started.FlowID), started.ClientBinding), http.StatusOK)
	if step.Next != "second_factor" || step.Ticket == "" {
		t.Errorf("step = %+v", step)
	}

	if e.store.SessionCount() != 1 {
		t.Errorf("%d sessions: a second factor ticket must not be a session", e.store.SessionCount())
	}
}

func TestNativeVerifyRefusalsLookAlike(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	other := e.start("bob@example.test", "")
	code := e.code(started.FlowID)

	wrong := "00000000"
	if code == wrong {
		wrong = "11111111"
	}

	for name, body := range map[string]map[string]string{
		"wrong code":        {"flow_id": started.FlowID, "code": wrong, "client_binding": started.ClientBinding},
		"code with a space": {"flow_id": started.FlowID, "code": code[:4] + " " + code[4:], "client_binding": started.ClientBinding},
		"unknown flow":      {"flow_id": "AAECAwQFBgcICQoLDA0ODw", "code": code, "client_binding": started.ClientBinding},
		"malformed flow":    {"flow_id": "../../etc", "code": code, "client_binding": started.ClientBinding},
		"other binding":     {"flow_id": started.FlowID, "code": code, "client_binding": other.ClientBinding},
		"malformed binding": {"flow_id": started.FlowID, "code": code, "client_binding": "x"},
		"nothing":           {},
	} {
		t.Run(name, func(t *testing.T) {
			wantProblem(t, e.post(verifyPath, body), http.StatusBadRequest, "invalid_code")
		})
	}

	if e.store.SessionCount() != 0 {
		t.Error("a refused verify created a session")
	}
}

func TestNativeVerifyWorksOncePerFlow(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	code := e.code(started.FlowID)
	decode[nextStepResponse](t, e.verify(started.FlowID, code, started.ClientBinding), http.StatusOK)
	wantProblem(t, e.verify(started.FlowID, code, started.ClientBinding), http.StatusBadRequest, "invalid_code")

	if e.store.TicketCount() != 1 {
		t.Errorf("%d tickets, want one", e.store.TicketCount())
	}
}

func TestNativeVerifyOverQuotaIsRateLimited(t *testing.T) {
	e := newEnv(t, memory.WithLimits(memory.Unlimited, 0))
	started := e.start("alice@example.test", "")
	wantProblem(t, e.verify(started.FlowID, e.code(started.FlowID), started.ClientBinding), http.StatusTooManyRequests, "rate_limited")
}

func TestTechnicalFailureIsTemporarilyUnavailableAndLoggedOnce(t *testing.T) {
	e := newEnv(t)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }
	rec := e.post(startPath, map[string]string{"email": "alice@example.test"})

	wantProblem(t, rec, http.StatusServiceUnavailable, "temporarily_unavailable")

	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("the response leaks the internal error: %s", rec.Body)
	}

	if e.store.FlowCount() != 0 {
		t.Error("the flow survived the failed enqueue")
	}

	logs := e.logs.String()
	if strings.Count(logs, `"msg":"request failed"`) != 1 || !strings.Contains(logs, rec.Header().Get("X-Request-Id")) || !strings.Contains(logs, "boom") {
		t.Errorf("want one error line with the request id and the cause:\n%s", logs)
	}
}

func mustEmail(t *testing.T, s string) identity.Email {
	t.Helper()

	email, err := identity.ParseEmail(s)
	if err != nil {
		t.Fatal(err)
	}

	return email
}
