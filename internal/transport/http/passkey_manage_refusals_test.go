package http_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"airlance.org/auth/internal/testutil"
)

// neverIssuedChallenge is a well-formed challenge id that no ceremony of the tests ever created.
const neverIssuedChallenge = "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"

// A session that was ended keeps its token for up to five minutes, and the token still verifies. Every passkey route
// must refuse it, while the sessions that are alive keep working.
func TestARevokedSessionCannotManageItsPasskeysOnAnyRoute(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			kept := nativeManage(t, e, name+"@example.test")
			doomed := build(t, e, name+"@example.test")
			keyID := kept.keys()[0].ID
			deleteTicket := doomed.stepUp(doomed.auth, "delete_passkey")
			addTicket := doomed.stepUp(doomed.auth, "add_passkey")
			codesTicket := doomed.stepUp(doomed.auth, "regenerate_recovery_codes")

			// The other session ends it.
			if rec := e.call(http.MethodDelete, "/v1/native/sessions/"+e.sessionOf(doomed.token).String(), kept.token, ""); rec.Code != http.StatusNoContent {
				t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
			}

			// Every route with the tickets it would need, so that only the session is what refuses.
			routes := []struct{ method, path, stepUp, body string }{
				{http.MethodGet, "/passkeys", "", ""},
				{http.MethodPost, "/passkeys/options", addTicket, ""},
				{http.MethodPost, "/passkeys", addTicket, `{"challenge_id":"` + neverIssuedChallenge + `","credential":{}}`},
				{http.MethodPatch, "/passkeys/" + keyID, "", `{"name":"mine"}`},
				{http.MethodDelete, "/passkeys/" + keyID, deleteTicket, ""},
				{http.MethodPost, "/recovery-codes", codesTicket, ""},
				{http.MethodPost, "/step-up/options", "", `{"operation":"delete_passkey"}`},
			}
			for _, r := range routes {
				e.wantUnauthenticated(doomed.call(r.method, r.path, r.stepUp, r.body))
			}

			// Nothing changed, and the session that is alive still sees both keys.
			if n := len(kept.keys()); n != 1 {
				t.Errorf("%d keys, want 1", n)
			}
		})
	}
}

// Finishing an addition needs the step-up token, a challenge of this ceremony, a valid name, and it works once.
func TestFinishingAPasskeyAdditionRefusesEachMissingPart(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	addTicket := m.stepUp(m.auth, "add_passkey")
	begun := decode[ceremonyResponse](t, m.json(http.MethodPost, "/passkeys/options", addTicket, nil), http.StatusOK)
	credential := json.RawMessage(testutil.NewSoftAuthenticator(t, rpID, rpOrigin).Register(begun.Options))
	body := func(challenge string, name string) map[string]any {
		data := map[string]any{"challenge_id": challenge, "credential": credential}
		if name != "" {
			data["name"] = name
		}
		return data
	}

	wantProblem(t, m.json(http.MethodPost, "/passkeys", "", body(begun.ChallengeID, "")), http.StatusForbidden, "step_up_required")
	wantProblem(t, m.json(http.MethodPost, "/passkeys", addTicket, body(begun.ChallengeID, strings.Repeat("x", 65))), http.StatusBadRequest, "invalid_request")
	wantProblem(t, m.json(http.MethodPost, "/passkeys", addTicket, body(neverIssuedChallenge, "")), http.StatusBadRequest, "invalid_proof")
	if n := len(m.keys()); n != 1 {
		t.Fatalf("%d keys after refusals, want 1", n)
	}

	// The refusals spent nothing: the right request works, and its replay does not.
	added := decode[passkeyBody](t, m.json(http.MethodPost, "/passkeys", addTicket, body(begun.ChallengeID, "Phone")), http.StatusCreated)
	if added.Name != "Phone" {
		t.Errorf("added = %+v", added)
	}
	wantProblem(t, m.json(http.MethodPost, "/passkeys", addTicket, body(begun.ChallengeID, "Again")), http.StatusForbidden, "step_up_required")
	if n := len(m.keys()); n != 2 {
		t.Errorf("%d keys, want 2", n)
	}
}

// The browser profile is the native one behind the page's headers, so each refusal must answer the same in both.
func TestPasskeyRefusalsAreTheSameInBothProfiles(t *testing.T) {
	const missing = "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := build(t, e, name+"@example.test")
			keyID := m.keys()[0].ID

			wantProblem(t, m.json(http.MethodPost, "/passkeys/options", "", nil), http.StatusForbidden, "step_up_required")
			wantProblem(t, m.json(http.MethodPost, "/passkeys/options", m.stepUp(m.auth, "delete_passkey"), nil), http.StatusForbidden, "step_up_required")
			wantProblem(t, m.json(http.MethodPatch, "/passkeys/"+keyID, "", map[string]string{"name": " "}), http.StatusBadRequest, "invalid_request")
			wantProblem(t, m.json(http.MethodPatch, "/passkeys/"+missing, "", map[string]string{"name": "x"}), http.StatusNotFound, "not_found")
			wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+keyID, "", ""), http.StatusForbidden, "step_up_required")
			wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+missing, m.stepUp(m.auth, "delete_passkey"), ""), http.StatusNotFound, "not_found")
			wantProblem(t, m.json(http.MethodPost, "/recovery-codes", "", nil), http.StatusForbidden, "step_up_required")
			wantProblem(t, m.json(http.MethodPost, "/step-up/options", "", map[string]string{"operation": "login"}), http.StatusBadRequest, "invalid_proof")
			wantProblem(t, m.call(http.MethodPost, "/step-up/options", "", `{"operation": 5}`), http.StatusBadRequest, "invalid_request")
			wantProblem(t, m.call(http.MethodPost, "/passkeys", "", `{`), http.StatusBadRequest, "invalid_request")

			if n := len(m.keys()); n != 1 {
				t.Errorf("%d keys after refusals, want 1", n)
			}
		})
	}
}
