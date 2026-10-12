package admin_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

type userJSON struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	BlockedAt *time.Time `json:"blocked_at"`
}

func TestUserListPagesAndFilters(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	for _, email := range []string{"carol@example.test", "alice@example.test", "ann@example.test", "bob@example.test"} {
		e.user(email)
	}

	var seen []string
	after := ""
	for i := 0; i < 5; i++ {
		res := e.get(api + "/users?limit=2&after=" + url.QueryEscape(after))
		if res.status != http.StatusOK {
			t.Fatalf("users = %d %s", res.status, res.body)
		}
		var body struct {
			Users []userJSON `json:"users"`
			Next  string     `json:"next"`
		}
		res.json(t, &body)
		for _, u := range body.Users {
			seen = append(seen, u.Email)
		}
		if body.Next == "" {
			break
		}
		after = body.Next
	}
	if got, want := strings.Join(seen, ","), "alice@example.test,ann@example.test,bob@example.test,carol@example.test"; got != want {
		t.Errorf("walked %s, want %s", got, want)
	}

	var filtered struct {
		Users []userJSON `json:"users"`
	}
	e.get(api+"/users?query=AN").json(t, &filtered)
	if len(filtered.Users) != 1 || filtered.Users[0].Email != "ann@example.test" {
		t.Errorf("query: %+v", filtered.Users)
	}
	var none struct {
		Users []userJSON `json:"users"`
	}
	res := e.get(api + "/users?query=zzz")
	res.json(t, &none)
	if none.Users == nil || len(none.Users) != 0 || !strings.Contains(string(res.body), `"users":[]`) {
		t.Errorf("an empty list must be [], got %s", res.body)
	}
	for _, q := range []string{"limit=abc", "limit=-1", "limit=101", "limit=1.5"} {
		if r := e.get(api + "/users?" + q); r.status != http.StatusBadRequest || r.errorCode() != "invalid_request" {
			t.Errorf("%s = %d %s", q, r.status, r.body)
		}
	}
}

func TestUserCard(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	sess := e.factory.Session(testutil.SessionSpec{User: u, DeviceName: "iPhone"})
	key := e.factory.Credential(testutil.CredentialSpec{User: u, Name: "Phone"})
	must(t, e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}
		if err := s.Credentials.Create(ctx, key); err != nil {
			return err
		}
		return s.Recovery.Replace(ctx, u.ID(), []*passkey.RecoveryCode{e.factory.RecoveryCode(u, "AAAA-BBBB")})
	}))

	res := e.get(api + "/users/" + u.ID().String())
	if res.status != http.StatusOK {
		t.Fatalf("card = %d %s", res.status, res.body)
	}
	var card struct {
		User     userJSON `json:"user"`
		Sessions []struct {
			ID         string `json:"id"`
			DeviceName string `json:"device_name"`
		} `json:"sessions"`
		Passkeys []struct {
			Name string `json:"name"`
		} `json:"passkeys"`
		RecoveryCodesLeft int `json:"recovery_codes_left"`
	}
	res.json(t, &card)
	if card.User.Email != "target@example.test" || len(card.Sessions) != 1 || card.Sessions[0].DeviceName != "iPhone" ||
		len(card.Passkeys) != 1 || card.Passkeys[0].Name != "Phone" || card.RecoveryCodesLeft != 1 {
		t.Errorf("card = %+v", card)
	}
	// No secret of the user is on the card: not a hash, a key, a binding.
	for _, secret := range []string{"public", "binding", "hash", "secret", "credential_id"} {
		if strings.Contains(strings.ToLower(string(res.body)), secret) {
			t.Errorf("the card mentions %q: %s", secret, res.body)
		}
	}
	for _, id := range []string{"nope", "00000000-0000-4000-8000-0000000000ff"} {
		if r := e.get(api + "/users/" + id); r.status != http.StatusNotFound || r.errorCode() != "not_found" {
			t.Errorf("card of %q = %d %s", id, r.status, r.body)
		}
	}
}

func TestBlockUnblockRevokeAndTheirAudit(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	path := api + "/users/" + u.ID().String()

	if r := e.post(path+"/block", nil); r.status != http.StatusNoContent {
		t.Fatalf("block = %d %s", r.status, r.body)
	}
	var card struct {
		User userJSON `json:"user"`
	}
	e.get(path).json(t, &card)
	if card.User.BlockedAt == nil || !card.User.BlockedAt.Equal(t0) {
		t.Errorf("blocked_at = %v", card.User.BlockedAt)
	}
	if r := e.post(path+"/revoke-sessions", nil); r.status != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.status, r.body)
	}
	if r := e.post(path+"/unblock", nil); r.status != http.StatusNoContent {
		t.Fatalf("unblock = %d %s", r.status, r.body)
	}
	e.get(path).json(t, &card)
	if card.User.BlockedAt != nil {
		t.Errorf("blocked_at after unblock = %v", card.User.BlockedAt)
	}

	for _, op := range []string{"block", "unblock", "revoke-sessions"} {
		if r := e.post(api+"/users/00000000-0000-4000-8000-0000000000ff/"+op, nil); r.status != http.StatusNotFound {
			t.Errorf("%s of nobody = %d", op, r.status)
		}
	}

	res := e.get(api + "/audit?type=admin.action&user_id=" + u.ID().String())
	var log struct {
		Entries []struct {
			Type       string            `json:"type"`
			OperatorID string            `json:"operator_id"`
			UserID     string            `json:"user_id"`
			Fields     map[string]string `json:"fields"`
		} `json:"entries"`
	}
	res.json(t, &log)
	var ops []string
	for _, en := range log.Entries {
		if en.OperatorID == "" || en.UserID != u.ID().String() {
			t.Errorf("entry %+v", en)
		}
		ops = append(ops, en.Fields["operation"])
	}
	if strings.Join(ops, ",") != "unblock,revoke_sessions,block" {
		t.Errorf("acts = %v (newest first)", ops)
	}
}

func TestDeleteUserNeedsReauthAndTheAddress(t *testing.T) {
	e := newEnv(t)
	key := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	path := api + "/users/" + u.ID().String() + "/delete"

	if r := e.post(path, map[string]string{"confirm_email": "wrong@example.test"}); r.status != http.StatusConflict || r.errorCode() != "confirm_mismatch" {
		t.Errorf("a wrong address = %d %s", r.status, r.body)
	}
	if r := e.send(request{method: "POST", path: path, raw: "{}"}); r.status != http.StatusConflict || r.errorCode() != "confirm_mismatch" {
		t.Errorf("no address = %d %s", r.status, r.body)
	}
	if r := e.send(request{method: "POST", path: path, raw: `{"confirm_email":"x","oops":1}`}); r.status != http.StatusBadRequest {
		t.Errorf("an unknown field = %d %s", r.status, r.body)
	}

	// An old sign-in cannot delete; a new one can.
	e.clock.Advance(operator.FreshFor)
	if r := e.get(api + "/session"); r.status != http.StatusOK {
		t.Fatalf("the session ended: %d", r.status)
	}
	if r := e.post(path, map[string]string{"confirm_email": "target@example.test"}); r.status != http.StatusForbidden || r.errorCode() != "reauth_required" {
		t.Errorf("an old sign-in = %d %s", r.status, r.body)
	}
	if r := e.get(api + "/users/" + u.ID().String()); r.status != http.StatusOK {
		t.Errorf("the user is gone after a refused delete: %d", r.status)
	}
	again := e.login(key)
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	again.json(t, &body)
	e.csrf = body.CSRFToken
	if r := e.post(path, map[string]string{"confirm_email": "Target@Example.test"}); r.status != http.StatusNoContent {
		t.Fatalf("delete = %d %s", r.status, r.body)
	}
	if r := e.get(api + "/users/" + u.ID().String()); r.status != http.StatusNotFound {
		t.Errorf("the user is still there: %d", r.status)
	}
}

func TestInvitationEndpoints(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	e.user("member@example.test")

	res := e.post(api+"/invitations", map[string]any{"email": "Guest@Example.test", "ttl_hours": 48})
	if res.status != http.StatusCreated {
		t.Fatalf("create = %d %s", res.status, res.body)
	}
	var inv struct {
		Email     string    `json:"email"`
		ExpiresAt time.Time `json:"expires_at"`
		Active    bool      `json:"active"`
	}
	res.json(t, &inv)
	if inv.Email != "guest@example.test" || !inv.Active || !inv.ExpiresAt.Equal(t0.Add(48*time.Hour)) {
		t.Errorf("invitation = %+v", inv)
	}
	if jobs := e.store.OutboxJobs(); len(jobs) != 1 || jobs[0].Kind != port.JobInvitation {
		t.Errorf("mail jobs = %+v", jobs)
	}

	var list struct {
		Invitations []struct {
			Email  string `json:"email"`
			Active bool   `json:"active"`
		} `json:"invitations"`
	}
	e.get(api+"/invitations").json(t, &list)
	if len(list.Invitations) != 1 || list.Invitations[0].Email != "guest@example.test" {
		t.Errorf("list = %+v", list)
	}

	if r := e.post(api+"/invitations", map[string]any{"email": "member@example.test"}); r.status != http.StatusConflict || r.errorCode() != "already_registered" {
		t.Errorf("inviting a member = %d %s", r.status, r.body)
	}
	for name, body := range map[string]map[string]any{
		"bad address": {"email": "nope"}, "negative ttl": {"email": "a@example.test", "ttl_hours": -1}, "ttl too long": {"email": "a@example.test", "ttl_hours": 24 * 91},
	} {
		if r := e.post(api+"/invitations", body); r.status != http.StatusBadRequest || r.errorCode() != "invalid_request" {
			t.Errorf("%s = %d %s", name, r.status, r.body)
		}
	}

	if r := e.post(api+"/invitations/revoke", map[string]string{"email": "guest@example.test"}); r.status != http.StatusNoContent {
		t.Errorf("revoke = %d %s", r.status, r.body)
	}
	if r := e.post(api+"/invitations/revoke", map[string]string{"email": "guest@example.test"}); r.status != http.StatusNotFound {
		t.Errorf("revoking twice = %d %s", r.status, r.body)
	}
}

func TestAuditEndpointFiltersAndRejectsBadParameters(t *testing.T) {
	e := newEnv(t)
	e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	for i := 0; i < 3; i++ {
		e.clock.Advance(time.Second)
		if r := e.post(api+"/users/"+u.ID().String()+"/revoke-sessions", nil); r.status != http.StatusNoContent {
			t.Fatal(r.status)
		}
	}
	var seen int
	before := ""
	for page := 0; page < 10; page++ {
		res := e.get(api + "/audit?limit=2&before=" + url.QueryEscape(before))
		var body struct {
			Entries []struct{ ID string } `json:"entries"`
			Next    string                `json:"next"`
		}
		res.json(t, &body)
		seen += len(body.Entries)
		if body.Next == "" {
			break
		}
		before = body.Next
	}
	if seen < 5 {
		t.Errorf("walked %d entries", seen)
	}
	for _, q := range []string{"user_id=nope", "operator_id=nope", "type=login.exploded", "before=!!!", "limit=0x", "limit=500"} {
		if r := e.get(api + "/audit?" + q); r.status != http.StatusBadRequest {
			t.Errorf("%s = %d %s", q, r.status, r.body)
		}
	}
	// An entry names its subjects by identifier only: no address is ever in the log.
	if r := e.get(api + "/audit"); strings.Contains(string(r.body), "@example.test") {
		t.Errorf("the audit response holds an address: %s", r.body)
	}
}
