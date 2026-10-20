package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/testutil"
)

type passkeyBody struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	BackupEligible bool       `json:"backup_eligible"`
	BackedUp       bool       `json:"backed_up"`
	Transports     []string   `json:"transports"`
}

type stepUpBody struct {
	Token     string    `json:"step_up_token"`
	Operation string    `json:"operation"`
	ExpiresAt time.Time `json:"expires_at"`
}

// manage is a signed-in caller of the passkey routes of one profile.
type manage struct {
	e     *env
	base  string
	token string
	auth  *testutil.SoftAuthenticator
	// browser sends the Origin and Sec-Fetch-Site headers of a page of the API's own origin.
	browser bool
}

func (m manage) call(method, path, stepUp, body string) *httptest.ResponseRecorder {
	m.e.t.Helper()

	req := httptest.NewRequest(method, m.base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", "Bearer "+m.token)

	if stepUp != "" {
		req.Header.Set("X-Step-Up", stepUp)
	}

	if m.browser {
		req.Header.Set("Origin", "http://"+req.Host)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}

	return m.e.do(req)
}

func (m manage) json(method, path, stepUp string, body any) *httptest.ResponseRecorder {
	m.e.t.Helper()

	data := ""

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			m.e.t.Fatal(err)
		}

		data = string(raw)
	}

	return m.call(method, path, stepUp, data)
}

// stepUp runs the whole proof for the operation with the authenticator.
func (m manage) stepUp(auth *testutil.SoftAuthenticator, operation string) string {
	m.e.t.Helper()
	begun := decode[ceremonyResponse](m.e.t, m.json(http.MethodPost, "/step-up/options", "", map[string]string{"operation": operation}), http.StatusOK)

	got := decode[stepUpBody](m.e.t, m.json(http.MethodPost, "/step-up/verify", "", map[string]any{
		"challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Assert(begun.Options)),
	}), http.StatusOK)
	if got.Token == "" || got.Operation != operation {
		m.e.t.Fatalf("step-up = %+v", got)
	}

	return got.Token
}

func (m manage) addKey(token string, auth *testutil.SoftAuthenticator, name string) *httptest.ResponseRecorder {
	m.e.t.Helper()

	rec := m.json(http.MethodPost, "/passkeys/options", token, nil)
	if rec.Code != http.StatusOK {
		return rec
	}

	begun := decode[ceremonyResponse](m.e.t, rec, http.StatusOK)

	body := map[string]any{"challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Register(begun.Options))}
	if name != "" {
		body["name"] = name
	}

	return m.json(http.MethodPost, "/passkeys", token, body)
}

func (m manage) keys() []passkeyBody {
	m.e.t.Helper()

	return decode[struct {
		Passkeys []passkeyBody `json:"passkeys"`
	}](m.e.t, m.call(http.MethodGet, "/passkeys", "", ""), http.StatusOK).Passkeys
}

func nativeManage(t *testing.T, e *env, email string) manage {
	t.Helper()

	signed, _ := e.signIn(email)

	return manage{e: e, base: "/v1/native/me", token: signed.AccessToken, auth: e.auths[email]}
}

func browserManage(t *testing.T, e *env, email string) manage {
	t.Helper()

	b := newBrowser(e)
	signed := b.signIn(email)

	return manage{e: e, base: "/v1/me", token: signed.AccessToken, auth: e.auths[email], browser: true}
}

func TestManagingPasskeysInBothProfiles(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := build(t, e, name+"@example.test")

			keys := m.keys()
			if len(keys) != 1 || keys[0].Name != "Passkey" || keys[0].ID == "" || keys[0].LastUsedAt != nil || keys[0].Transports == nil {
				t.Fatalf("keys = %+v", keys)
			}

			// Adding a key needs a step-up; with one it works once.
			second := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
			wantProblem(t, m.addKey("", second, "Phone"), http.StatusForbidden, "step_up_required")
			token := m.stepUp(m.auth, "add_passkey")

			added := decode[passkeyBody](t, m.addKey(token, second, "Phone"), http.StatusCreated)
			if added.Name != "Phone" || added.ID == "" {
				t.Errorf("added = %+v", added)
			}

			wantProblem(t, m.addKey(token, testutil.NewSoftAuthenticator(t, rpID, rpOrigin), "again"), http.StatusForbidden, "step_up_required")

			if keys = m.keys(); len(keys) != 2 || keys[0].LastUsedAt == nil {
				t.Fatalf("keys = %+v: the key that proved the step-up shows its use", keys)
			}

			// Renaming needs none.
			renamed := decode[passkeyBody](t, m.json(http.MethodPatch, "/passkeys/"+added.ID, "", map[string]string{"name": "Work phone"}), http.StatusOK)
			if renamed.Name != "Work phone" || renamed.ID != added.ID {
				t.Errorf("renamed = %+v", renamed)
			}

			// Deleting needs one for that operation; the first key goes, the last one stays.
			wrongOp := m.stepUp(second, "regenerate_recovery_codes")
			wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+keys[0].ID, wrongOp, ""), http.StatusForbidden, "step_up_required")

			del := m.stepUp(second, "delete_passkey")
			if rec := m.call(http.MethodDelete, "/passkeys/"+keys[0].ID, del, ""); rec.Code != http.StatusNoContent {
				t.Fatalf("delete = %d %s", rec.Code, rec.Body)
			}

			wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+added.ID, m.stepUp(second, "delete_passkey"), ""), http.StatusConflict, "last_passkey")
			wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+keys[0].ID, m.stepUp(second, "delete_passkey"), ""), http.StatusNotFound, "not_found")

			if left := m.keys(); len(left) != 1 || left[0].ID != added.ID {
				t.Errorf("keys left = %+v", left)
			}

			// New recovery codes need one too.
			wantProblem(t, m.json(http.MethodPost, "/recovery-codes", "", nil), http.StatusForbidden, "step_up_required")

			codes := decode[struct {
				Codes []string `json:"recovery_codes"`
			}](t, m.json(http.MethodPost, "/recovery-codes", m.stepUp(second, "regenerate_recovery_codes"), nil), http.StatusOK)
			if len(codes.Codes) != 10 {
				t.Errorf("%d codes", len(codes.Codes))
			}
		})
	}
}

func TestPasskeyManagementRefusesWhoIsNotSignedIn(t *testing.T) {
	e := newEnv(t)

	for _, base := range []string{"/v1/native/me", "/v1/me"} {
		for _, r := range []struct{ method, path string }{
			{http.MethodPost, "/step-up/options"}, {http.MethodPost, "/step-up/verify"}, {http.MethodGet, "/passkeys"},
			{http.MethodPost, "/passkeys/options"}, {http.MethodPost, "/passkeys"},
			{http.MethodPatch, "/passkeys/0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"}, {http.MethodDelete, "/passkeys/0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"},
			{http.MethodPost, "/recovery-codes"},
		} {
			for _, token := range []string{"", "x.y.z"} {
				req := httptest.NewRequest(r.method, base+r.path, strings.NewReader(`{"operation":"delete_passkey","name":"x","challenge_id":"x","credential":{}}`))
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

func TestStepUpTokenFailuresAreAllTheSameStepUpRequired(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	second := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	m.addKey(m.stepUp(m.auth, "add_passkey"), second, "second")
	victim := m.keys()[1].ID

	other := nativeManage(t, e, "bob@example.test")
	foreign := other.stepUp(other.auth, "delete_passkey")

	valid := m.stepUp(m.auth, "delete_passkey")
	for name, token := range map[string]string{
		"none": "", "garbage": "x", "an unknown one": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"another user's": foreign, "for another operation": m.stepUp(m.auth, "regenerate_recovery_codes"),
	} {
		rec := m.call(http.MethodDelete, "/passkeys/"+victim, token, "")
		wantProblem(t, rec, http.StatusForbidden, "step_up_required")

		if len(m.keys()) != 2 {
			t.Fatalf("%s: a refused delete removed a key", name)
		}
	}
	// A token of this session is refused from another session of the same user.
	again, _ := e.signIn("alice@example.test")
	otherSession := manage{e: e, base: "/v1/native/me", token: again.AccessToken}
	wantProblem(t, otherSession.call(http.MethodDelete, "/passkeys/"+victim, valid, ""), http.StatusForbidden, "step_up_required")
	// The window is five minutes.
	e.clock.Advance(5 * time.Minute)
	wantProblem(t, m.call(http.MethodDelete, "/passkeys/"+victim, valid, ""), http.StatusForbidden, "step_up_required")
}

func TestStepUpCeremonyRefusalsAreInvalidProof(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	intruder := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	intruder.UserHandle = []byte("0123456789abcdef")

	begin := func() ceremonyResponse {
		return decode[ceremonyResponse](t, m.json(http.MethodPost, "/step-up/options", "", map[string]string{"operation": "delete_passkey"}), http.StatusOK)
	}
	verify := func(challenge string, credential []byte) *httptest.ResponseRecorder {
		return m.json(http.MethodPost, "/step-up/verify", "", map[string]any{"challenge_id": challenge, "credential": json.RawMessage(credential)})
	}
	b := begin()

	cases := map[string]*httptest.ResponseRecorder{
		"a key nobody registered": verify(b.ChallengeID, intruder.Assert(b.Options)),
		"an unknown challenge":    verify("0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", m.auth.Assert(b.Options)),
		"a malformed challenge":   verify("x", m.auth.Assert(b.Options)),
		"an empty credential":     verify(begin().ChallengeID, []byte(`{}`)),
	}
	for _, rec := range cases {
		wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
	}
	// An operation that needs no step-up is refused when the ceremony starts.
	wantProblem(t, m.json(http.MethodPost, "/step-up/options", "", map[string]string{"operation": "login"}), http.StatusBadRequest, "invalid_proof")
	wantProblem(t, m.call(http.MethodPost, "/step-up/options", "", `{"operation": 5}`), http.StatusBadRequest, "invalid_request")
	// Nothing above spent the right proof.
	if tok := m.stepUp(m.auth, "delete_passkey"); tok == "" {
		t.Error("no token")
	}
}

func TestPasskeyLabelsAndIdsAreChecked(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")

	id := m.keys()[0].ID
	for _, name := range []string{"", " ", strings.Repeat("x", 65), "a\nb"} {
		wantProblem(t, m.json(http.MethodPatch, "/passkeys/"+id, "", map[string]string{"name": name}), http.StatusBadRequest, "invalid_request")
	}
	// Another user's key and a missing one look the same.
	stranger := nativeManage(t, e, "bob@example.test")
	for _, target := range []string{id, "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", "x"} {
		wantProblem(t, stranger.json(http.MethodPatch, "/passkeys/"+target, "", map[string]string{"name": "mine"}), http.StatusNotFound, "not_found")
		wantProblem(t, stranger.call(http.MethodDelete, "/passkeys/"+target, stranger.stepUp(stranger.auth, "delete_passkey"), ""), http.StatusNotFound, "not_found")
	}

	if m.keys()[0].Name != "Passkey" {
		t.Error("a stranger renamed a key")
	}
}

func TestPasskeyRoutesNeverCacheAndTimesAreUTC(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("EEST", 3*60*60)

	t.Cleanup(func() { time.Local = previous })

	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	m.stepUp(m.auth, "delete_passkey") // a use of the key, so last_used_at is set

	rec := m.call(http.MethodGet, "/passkeys", "", "")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}

	var raw struct {
		Passkeys []map[string]any `json:"passkeys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"created_at", "last_used_at"} {
		v, _ := raw.Passkeys[0][field].(string)
		if !strings.HasSuffix(v, "Z") {
			t.Errorf("%s = %q, want UTC", field, v)
		}
	}

	for _, secret := range []string{"credential_id", "public_key", "publicKey", "secret"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the listing mentions %q", secret)
		}
	}

	tok := m.stepUp(m.auth, "regenerate_recovery_codes")
	if rec := m.json(http.MethodPost, "/recovery-codes", tok, nil); rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the recovery codes may be cached")
	}
}

func TestBrowserPasskeyManagementRefusesForeignPagesAndAllowsTrustedCORS(t *testing.T) {
	e := newEnvWithOrigins(t, appOrigin)
	m := browserManage(t, e, "alice@example.test")

	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/step-up/options"}, {http.MethodPost, "/step-up/verify"}, {http.MethodPost, "/passkeys/options"},
		{http.MethodPost, "/passkeys"}, {http.MethodPatch, "/passkeys/0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"},
		{http.MethodDelete, "/passkeys/0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"}, {http.MethodPost, "/recovery-codes"},
	} {
		req := httptest.NewRequest(r.method, "/v1/me"+r.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+m.token)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := e.do(req)
		wantProblem(t, rec, http.StatusForbidden, "permission_denied")

		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s %s: a refused request set a cookie", r.method, r.path)
		}
	}

	if len(m.keys()) != 1 {
		t.Error("a foreign page changed the keys")
	}

	// A trusted page may send the step-up header and use PATCH and DELETE.
	req := httptest.NewRequest(http.MethodOptions, "/v1/me/passkeys/x", nil)
	req.Header.Set("Origin", appOrigin)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Access-Control-Request-Method", "DELETE")
	req.Header.Set("Access-Control-Request-Headers", "authorization,x-step-up")

	h := e.do(req).Header()
	if !strings.Contains(h.Get("Access-Control-Allow-Headers"), "X-Step-Up") || !strings.Contains(h.Get("Access-Control-Allow-Methods"), "DELETE") ||
		!strings.Contains(h.Get("Access-Control-Allow-Methods"), "PATCH") {
		t.Errorf("preflight headers = %v", h)
	}
}

func TestStepUpTokensStayOutOfTheLogs(t *testing.T) {
	e := newEnv(t)
	m := nativeManage(t, e, "alice@example.test")
	token := m.stepUp(m.auth, "delete_passkey")
	m.call(http.MethodDelete, "/passkeys/"+m.keys()[0].ID, token, "") // the last key: refused
	m.call(http.MethodDelete, "/passkeys/x", "wrong-"+token, "")

	if strings.Contains(e.logs.String(), token) || strings.Contains(e.logs.String(), "wrong-") {
		t.Errorf("the logs contain a step-up token:\n%s", e.logs)
	}

	if !strings.Contains(e.logs.String(), `"operation":"delete_passkey"`) && !strings.Contains(e.logs.String(), `"reason":"step_up_required"`) {
		t.Errorf("the logs lack the safe fields:\n%s", e.logs)
	}
}
