package http_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/quota"
)

// emailChangeNotices counts the notices to the old address that were queued.
func (e *env) emailChangeNotices() int {
	e.t.Helper()

	n := 0

	for _, job := range e.store.OutboxJobs() {
		if job.Kind == port.JobEmailChanged {
			n++
		}
	}

	return n
}

// A change belongs to the session that asked for it. When that session ends before the code is proved, the change is
// over: the code is right and the flow is alive, but nothing moves.
func TestAChangeIsLostWhenTheSessionThatAskedForItEnds(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			kept := nativeManage(t, e, name+"-old@example.test")
			doomed := build(t, e, name+"-old@example.test")
			started := doomed.beginChange(name + "-new@example.test")
			code := e.code(started.FlowID)

			if rec := e.call(http.MethodDelete, "/v1/native/sessions/"+e.sessionOf(doomed.token).String(), kept.token, ""); rec.Code != http.StatusNoContent {
				t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
			}

			e.wantUnauthenticated(doomed.confirmChange(started.FlowID, code))

			if _, ok := e.store.User(mustEmail(t, name+"-old@example.test")); !ok {
				t.Error("the account moved although the session that asked for the change had ended")
			}

			if n := e.emailChangeNotices(); n != 0 {
				t.Errorf("%d notices queued for a change that did not happen", n)
			}
			// The session that is alive sees the old address still.
			if rec := kept.call(http.MethodGet, "", "", ""); rec.Code != http.StatusOK {
				t.Errorf("the other session = %d", rec.Code)
			}
		})
	}
}

// Every wrong code uses an attempt, and after the last one even the right code is refused.
func TestWrongCodesExhaustAChangeEvenForTheRightCode(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	started := m.beginChange("fresh@example.test")
	code := e.code(started.FlowID)

	wrong := "00000000"
	if code == wrong {
		wrong = "11111111"
	}

	for range authflow.DefaultPolicy().MaxAttempts {
		wantProblem(t, m.confirmChange(started.FlowID, wrong), http.StatusBadRequest, "invalid_code")
	}

	wantProblem(t, m.confirmChange(started.FlowID, code), http.StatusBadRequest, "invalid_code")

	if _, ok := e.store.User(mustEmail(t, "alice@example.test")); !ok {
		t.Error("the account moved after the attempts ran out")
	}

	if n := e.emailChangeNotices(); n != 0 {
		t.Errorf("%d notices queued", n)
	}
}

func TestAnExpiredChangeCannotBeConfirmed(t *testing.T) {
	e := newEnv(t)
	signed, _ := e.signIn("alice@example.test")
	m := manage{e: e, base: "/v1/native/me", token: signed.AccessToken, auth: e.auths["alice@example.test"]}
	started := m.beginChange("late@example.test")
	code := e.code(started.FlowID)

	// The flow outlives the access token, so the session is refreshed first: the refusal must come from the flow.
	e.clock.Advance(authflow.DefaultPolicy().TTL + time.Second)
	m.token = decode[tokenResponse](t, e.refresh(signed.RefreshToken), http.StatusOK).AccessToken
	wantProblem(t, m.confirmChange(started.FlowID, code), http.StatusBadRequest, "invalid_code")

	if _, ok := e.store.User(mustEmail(t, "alice@example.test")); !ok {
		t.Error("an expired change moved the account")
	}
}

// Two changes to one address may both be asked for, since the account does not have it yet. Only the first proof
// moves the account; the second is refused and queues no second notice.
func TestTwoChangesToOneAddressMoveTheAccountOnce(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	first := m.beginChange("shared@example.test")
	second := m.beginChange("shared@example.test")

	done := decode[changeDone](t, m.confirmChange(first.FlowID, e.code(first.FlowID)), http.StatusOK)
	if done.Email != "shared@example.test" {
		t.Errorf("email = %q", done.Email)
	}

	wantProblem(t, m.confirmChange(second.FlowID, e.code(second.FlowID)), http.StatusBadRequest, "invalid_code")

	if n := e.emailChangeNotices(); n != 1 {
		t.Errorf("%d notices, want exactly one to the old address", n)
	}

	if _, ok := e.store.User(mustEmail(t, "shared@example.test")); !ok {
		t.Error("the account is not on the shared address")
	}
}

// Each refusal of the change answers the same in both profiles.
func TestEmailChangeRefusalsAreTheSameInBothProfiles(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := build(t, e, name+"-old@example.test")
			nativeManage(t, e, name+"-taken@example.test")

			wantProblem(t, m.startChange("", name+"-new@example.test"), http.StatusForbidden, "step_up_required")
			wantProblem(t, m.startChange(m.stepUp(m.auth, "change_email"), "not an address"), http.StatusBadRequest, "invalid_request")
			wantProblem(t, m.startChange(m.stepUp(m.auth, "change_email"), " "+strings.ToUpper(name)+"-OLD@example.test"), http.StatusBadRequest, "invalid_request")
			wantProblem(t, m.confirmChange("AAAAAAAAAAAAAAAAAAAAAA", "30999009"), http.StatusBadRequest, "invalid_code")

			started := m.beginChange(name + "-new@example.test")
			code := e.code(started.FlowID)

			wrong := "00000000"
			if code == wrong {
				wrong = "11111111"
			}

			wantProblem(t, m.confirmChange(started.FlowID, wrong), http.StatusBadRequest, "invalid_code")

			// An address that has an account only shows at the proof of its mailbox, and then as a conflict.
			taken := m.beginChange(name + "-taken@example.test")
			wantProblem(t, m.confirmChange(taken.FlowID, e.code(taken.FlowID)), http.StatusConflict, "email_taken")

			if _, ok := e.store.User(mustEmail(t, name+"-old@example.test")); !ok {
				t.Error("a refused change moved the account")
			}

			if n := e.emailChangeNotices(); n != 0 {
				t.Errorf("%d notices queued by refused changes", n)
			}
		})
	}
}

// The proof of the mailbox has its own budget: once it is spent, a further code is refused without being compared.
func TestEmailConfirmationIsBoundedByItsVerifyBudget(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownVerifyEmail: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, memory.WithQuota(profile))
			m := build(t, e, name+"@example.test")
			started := m.beginChange(name + "-new@example.test")

			wantProblem(t, m.confirmChange(started.FlowID, "00000000"), http.StatusBadRequest, "invalid_code")
			wantProblem(t, m.confirmChange(started.FlowID, e.code(started.FlowID)), http.StatusTooManyRequests, "rate_limited")

			if _, ok := e.store.User(mustEmail(t, name+"@example.test")); !ok {
				t.Error("the account moved although the budget was spent")
			}
		})
	}
}
