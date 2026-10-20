package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

type changeStarted struct {
	FlowID    string    `json:"flow_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type changeDone struct {
	Email string `json:"email"`
}

func (m manage) startChange(token, email string) *httptest.ResponseRecorder {
	m.e.t.Helper()
	return m.json(http.MethodPost, "/email/change", token, map[string]string{"email": email})
}

func (m manage) confirmChange(flowID, code string) *httptest.ResponseRecorder {
	m.e.t.Helper()
	return m.json(http.MethodPost, "/email/change/confirm", "", map[string]string{"flow_id": flowID, "code": code})
}

// begin asks for a code at the address with a fresh step-up and returns the flow.
func (m manage) beginChange(email string) changeStarted {
	m.e.t.Helper()
	token := m.stepUp(m.auth, "change_email")

	return decode[changeStarted](m.e.t, m.startChange(token, email), http.StatusAccepted)
}

func TestChangingTheEmailInBothProfiles(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := build(t, e, name+"-old@example.test")

			// Without a step-up for this operation nothing starts, and nothing is sent.
			jobsBefore := len(e.store.OutboxJobs())

			wantProblem(t, m.startChange("", name+"-new@example.test"), http.StatusForbidden, "step_up_required")
			wrongOp := m.stepUp(m.auth, "add_passkey")
			wantProblem(t, m.startChange(wrongOp, name+"-new@example.test"), http.StatusForbidden, "step_up_required")

			if len(e.store.OutboxJobs()) != jobsBefore {
				t.Fatalf("a refused start queued a mail: %d jobs, was %d", len(e.store.OutboxJobs()), jobsBefore)
			}

			started := m.beginChange(" " + strings.ToUpper(name) + "-New@Example.test ")
			if started.FlowID == "" || started.ExpiresAt.IsZero() {
				t.Fatalf("started = %+v", started)
			}
			// The step-up bought exactly one start.
			wantProblem(t, m.startChange(m.stepUp(m.auth, "change_email")+"x", name+"-other@example.test"), http.StatusForbidden, "step_up_required")

			wantProblem(t, m.confirmChange(started.FlowID, "00000000"), http.StatusBadRequest, "invalid_code")
			code := e.code(started.FlowID)

			done := decode[changeDone](t, m.confirmChange(started.FlowID, code), http.StatusOK)
			if done.Email != name+"-new@example.test" {
				t.Errorf("email = %q", done.Email)
			}

			wantProblem(t, m.confirmChange(started.FlowID, code), http.StatusBadRequest, "invalid_code")

			// The session survives and shows the new address.
			me := decode[struct {
				User struct {
					Email string `json:"email"`
				} `json:"user"`
			}](t, m.call(http.MethodGet, "", "", ""), http.StatusOK)
			if me.User.Email != name+"-new@example.test" {
				t.Errorf("/me email = %q", me.User.Email)
			}

			// The old address is told, once, and the mail names no address of the new one.
			var notices []port.MailJob

			for _, job := range e.store.OutboxJobs() {
				if job.Kind == port.JobEmailChanged {
					notices = append(notices, job)
				}
			}

			if len(notices) != 1 || notices[0].Recipient.String() != name+"-old@example.test" {
				t.Fatalf("notices = %+v", notices)
			}

			// Signing in by email now goes through the new address, and the old one is a stranger.
			started2 := e.start(name+"-new@example.test", "")
			if step := e.verifyStep(started2.FlowID, started2.ClientBinding); step.Next != "second_factor" {
				t.Errorf("the new address was told %q, want second_factor: it owns the account's keys", step.Next)
			}

			started3 := e.start(name+"-old@example.test", "")
			if step := e.verifyStep(started3.FlowID, started3.ClientBinding); step.Next != "enroll_passkey" {
				t.Errorf("the old address was told %q, want enroll_passkey: it is a new account now", step.Next)
			}
		})
	}
}

func TestEmailChangeRefusals(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	nativeManage(t, e, "taken@example.test")

	// The address the account already has asks for no change.
	token := m.stepUp(m.auth, "change_email")
	wantProblem(t, m.startChange(token, " ALICE@example.test"), http.StatusBadRequest, "invalid_request")
	wantProblem(t, m.startChange(token, "not an address"), http.StatusBadRequest, "invalid_request")
	wantProblem(t, m.json(http.MethodPost, "/email/change", token, map[string]any{"email": 5}), http.StatusBadRequest, "invalid_request")
	// Neither used the token up.
	started := decode[changeStarted](t, m.startChange(token, "fresh@example.test"), http.StatusAccepted)

	// A wrong code spends attempts; a flow that is not this account's or not a change flow is unknown.
	wantProblem(t, m.confirmChange(started.FlowID, "00000000"), http.StatusBadRequest, "invalid_code")
	wantProblem(t, m.confirmChange("AAAAAAAAAAAAAAAAAAAAAA", "30999009"), http.StatusBadRequest, "invalid_code")
	wantProblem(t, m.confirmChange("not a flow", "30999009"), http.StatusBadRequest, "invalid_code")

	loginFlow := e.start("alice@example.test", "")
	wantProblem(t, m.confirmChange(loginFlow.FlowID, e.code(loginFlow.FlowID)), http.StatusBadRequest, "invalid_code")
	bob := nativeManage(t, e, "bob@example.test")
	wantProblem(t, bob.confirmChange(started.FlowID, e.code(started.FlowID)), http.StatusBadRequest, "invalid_code")
	wantProblem(t, m.json(http.MethodPost, "/email/change/confirm", "", map[string]any{"flow_id": 1}), http.StatusBadRequest, "invalid_request")

	// The address another account has is an ordinary start: the answer does not say who is registered.
	taken := decode[changeStarted](t, m.startChange(m.stepUp(m.auth, "change_email"), "taken@example.test"), http.StatusAccepted)
	if taken.FlowID == "" {
		t.Fatal("no flow for an address that has an account")
	}
	// Only the proof of the mailbox shows it: a conflict, with the account untouched.
	wantProblem(t, m.confirmChange(taken.FlowID, e.code(taken.FlowID)), http.StatusConflict, "email_taken")

	if _, ok := e.store.User(mustEmail(t, "alice@example.test")); !ok {
		t.Error("the account moved to an address another account has")
	}
}

func TestEmailChangeRoutesRefuseWhoIsNotSignedIn(t *testing.T) {
	e := newEnv(t)

	for _, base := range []string{"/v1/native/me", "/v1/me"} {
		for _, path := range []string{"/email/change", "/email/change/confirm"} {
			for _, token := range []string{"", "x.y.z"} {
				req := httptest.NewRequest(http.MethodPost, base+path, strings.NewReader(`{"email":"a@example.test","flow_id":"x","code":"30999009"}`))
				req.Header.Set("Content-Type", "application/json")

				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}

				if base == "/v1/me" {
					req.Header.Set("Sec-Fetch-Site", "same-origin")
				}

				e.wantUnauthenticated(e.do(req))
			}
		}
	}
}

func TestBrowserEmailChangeRefusesAForeignOrigin(t *testing.T) {
	e := newEnv(t)
	m := browserManage(t, e, "alice@example.test")
	token := m.stepUp(m.auth, "change_email")
	flowsBefore := e.store.FlowCount()

	for _, path := range []string{"/email/change", "/email/change/confirm"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/me"+path, strings.NewReader(`{"email":"b@example.test","flow_id":"x","code":"30999009"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+m.token)
		req.Header.Set("X-Step-Up", token)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		wantProblem(t, e.do(req), http.StatusForbidden, "permission_denied")
	}

	if e.store.FlowCount() != flowsBefore {
		t.Errorf("flows = %d after refused foreign calls, was %d", e.store.FlowCount(), flowsBefore)
	}
}

func TestEmailChangeIsBoundedByTheQuotaOfTheNewAddress(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownSendEmail: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	e := newEnv(t, memory.WithQuota(profile))
	m := nativeManage(t, e, "alice@example.test")

	// The budget of an address is shared by every use of it.
	decode[changeStarted](t, m.startChange(m.stepUp(m.auth, "change_email"), "victim@example.test"), http.StatusAccepted)
	token := m.stepUp(m.auth, "change_email")
	rec := m.startChange(token, "victim@example.test")
	wantProblem(t, rec, http.StatusTooManyRequests, "rate_limited")
	// The refused start kept the token, and another address has its own budget.
	decode[changeStarted](t, m.startChange(token, "other@example.test"), http.StatusAccepted)
}

func TestEmailChangeFailureLeavesTheAccountAndTheTokenAlone(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	token := m.stepUp(m.auth, "change_email")
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }

	rec := m.startChange(token, "next@example.test")
	wantProblem(t, rec, http.StatusServiceUnavailable, "temporarily_unavailable")

	e.faults.wrap = nil

	decode[changeStarted](t, m.startChange(token, "next@example.test"), http.StatusAccepted)
}

// otherDevice signs the same user in again, as a second device, and returns its tokens.
func otherDevice(t *testing.T, e *env, email string) tokenResponse {
	t.Helper()

	signed, _ := e.signIn(email)

	return signed
}

func (e *env) meStatus(token string) int {
	req := httptest.NewRequest(http.MethodGet, "/v1/native/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return e.do(req).Code
}

func TestChangingTheEmailEndsTheOtherDevicesButNotThisOne(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	phone := otherDevice(t, e, "alice@example.test")

	bob := otherDevice(t, e, "bob@example.test")
	if e.meStatus(phone.AccessToken) != http.StatusOK {
		t.Fatal("the second device is not signed in")
	}

	started := m.beginChange("new@example.test")
	decode[changeDone](t, m.confirmChange(started.FlowID, e.code(started.FlowID)), http.StatusOK)

	if got := e.meStatus(m.token); got != http.StatusOK {
		t.Errorf("the device that changed the address = %d, want 200", got)
	}

	if got := e.meStatus(phone.AccessToken); got != http.StatusUnauthorized {
		t.Errorf("the other device = %d, want 401", got)
	}

	wantProblem(t, e.refresh(phone.RefreshToken), http.StatusUnauthorized, "invalid_refresh")

	if got := e.meStatus(bob.AccessToken); got != http.StatusOK {
		t.Errorf("another user's device = %d, want 200", got)
	}
}

func TestDeletingAPasskeyEndsTheOtherDevicesButNotThisOne(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	second := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	decode[passkeyBody](t, m.addKey(m.stepUp(m.auth, "add_passkey"), second, "second"), http.StatusCreated)
	phone := otherDevice(t, e, "alice@example.test")
	victim := m.keys()[1].ID

	if rec := m.call(http.MethodDelete, "/passkeys/"+victim, m.stepUp(m.auth, "delete_passkey"), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}

	if got := e.meStatus(m.token); got != http.StatusOK {
		t.Errorf("the device that deleted the key = %d, want 200", got)
	}

	if got := e.meStatus(phone.AccessToken); got != http.StatusUnauthorized {
		t.Errorf("the other device = %d, want 401", got)
	}

	wantProblem(t, e.refresh(phone.RefreshToken), http.StatusUnauthorized, "invalid_refresh")
}
