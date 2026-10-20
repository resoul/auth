package admin

import (
	"net/http"
	"strconv"
	"time"

	appadmin "go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

type userBody struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	EmailVerifiedAt time.Time  `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	BlockedAt       *time.Time `json:"blocked_at"`
}

func userJSON(u *identity.User) userBody {
	return userBody{
		ID: u.ID().String(), Email: u.Email().String(), EmailVerifiedAt: u.EmailVerifiedAt().UTC(),
		CreatedAt: u.CreatedAt().UTC(), BlockedAt: timeOrNil(u.BlockedAt()),
	}
}

// queryInt reads an optional non-negative integer parameter; ok is false when it was not one.
func queryInt(r *http.Request, name string) (n int, ok bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, true
	}

	n, err := strconv.Atoi(raw)

	return n, err == nil && n >= 0
}

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request, p principal) {
	limit, ok := queryInt(r, "limit")
	if !ok {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "limit is not a number")
		return
	}

	q := r.URL.Query()

	res, err := h.Users.List(r.Context(), appadmin.ListUsersCommand{Actor: p.actor, Prefix: q.Get("query"), After: q.Get("after"), Limit: limit})
	if err != nil {
		h.fail(w, r, err)
		return
	}

	if h.outcome(w, r, "users", res.Outcome, "") {
		return
	}

	users := make([]userBody, 0, len(res.Users))
	for _, u := range res.Users {
		users = append(users, userJSON(u))
	}

	writeJSON(w, http.StatusOK, struct {
		Users []userBody `json:"users"`
		Next  string     `json:"next,omitempty"`
	}{users, res.Next})
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request, p principal) {
	res, err := h.Users.Get(r.Context(), appadmin.UserCommand{Actor: p.actor, UserID: r.PathValue("id")})
	if err != nil {
		h.fail(w, r, err)
		return
	}

	if h.outcome(w, r, "user", res.Outcome, "") {
		return
	}

	type sessionJSON struct {
		ID           string    `json:"id"`
		DeviceName   string    `json:"device_name"`
		CreatedAt    time.Time `json:"created_at"`
		LastActiveAt time.Time `json:"last_active_at"`
	}

	type keyJSON struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
		Synced     bool       `json:"synced"`
	}

	d := res.Detail

	body := struct {
		User              userBody      `json:"user"`
		Sessions          []sessionJSON `json:"sessions"`
		Passkeys          []keyJSON     `json:"passkeys"`
		RecoveryCodesLeft int           `json:"recovery_codes_left"`
	}{User: userJSON(d.User), Sessions: []sessionJSON{}, Passkeys: []keyJSON{}, RecoveryCodesLeft: d.RecoveryCodesLeft}
	for _, s := range d.Sessions {
		body.Sessions = append(body.Sessions, sessionJSON{ID: s.ID().String(), DeviceName: s.DeviceName(), CreatedAt: s.CreatedAt().UTC(), LastActiveAt: s.LastActiveAt().UTC()})
	}

	for _, k := range d.Keys {
		body.Passkeys = append(body.Passkeys, keyJSON{ID: k.ID().String(), Name: k.Name(), CreatedAt: k.CreatedAt().UTC(), LastUsedAt: timeOrNil(k.LastUsedAt()), Synced: k.BackupState()})
	}

	writeJSON(w, http.StatusOK, body)
}

// act runs an operation on one user that answers 204.
func (h *handler) act(operation string, run func(r *http.Request, p principal) (appadmin.Result, error)) func(http.ResponseWriter, *http.Request, principal) {
	return func(w http.ResponseWriter, r *http.Request, p principal) {
		res, err := run(r, p)
		if err != nil {
			h.fail(w, r, err)
			return
		}

		if h.outcome(w, r, operation, res.Outcome, res.Reason) {
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *handler) blockUser(w http.ResponseWriter, r *http.Request, p principal) {
	h.act("block", func(r *http.Request, p principal) (appadmin.Result, error) {
		return h.Users.Block(r.Context(), appadmin.UserCommand{Actor: p.actor, UserID: r.PathValue("id")})
	})(w, r, p)
}

func (h *handler) unblockUser(w http.ResponseWriter, r *http.Request, p principal) {
	h.act("unblock", func(r *http.Request, p principal) (appadmin.Result, error) {
		return h.Users.Unblock(r.Context(), appadmin.UserCommand{Actor: p.actor, UserID: r.PathValue("id")})
	})(w, r, p)
}

func (h *handler) revokeSessions(w http.ResponseWriter, r *http.Request, p principal) {
	h.act("revoke_sessions", func(r *http.Request, p principal) (appadmin.Result, error) {
		return h.Users.RevokeSessions(r.Context(), appadmin.UserCommand{Actor: p.actor, UserID: r.PathValue("id")})
	})(w, r, p)
}

func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		ConfirmEmail string `json:"confirm_email"`
	}
	if !decode(w, r, &body) {
		return
	}

	h.act("delete_user", func(r *http.Request, p principal) (appadmin.Result, error) {
		return h.Users.Delete(r.Context(), appadmin.DeleteCommand{
			UserCommand: appadmin.UserCommand{Actor: p.actor, UserID: r.PathValue("id")}, ConfirmEmail: body.ConfirmEmail,
		})
	})(w, r, p)
}

type invitationBody struct {
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Active is false for an invitation that expired but has not been cleaned up yet.
	Active bool `json:"active"`
}

func (h *handler) listInvitations(w http.ResponseWriter, r *http.Request, p principal) {
	res, err := h.Invitations.List(r.Context(), p.actor)
	if err != nil {
		h.fail(w, r, err)
		return
	}

	if h.outcome(w, r, "invitations", res.Outcome, "") {
		return
	}

	out := make([]invitationBody, 0, len(res.Invitations))
	for _, inv := range res.Invitations {
		out = append(out, invitationBody{Email: inv.Email().String(), CreatedAt: inv.CreatedAt().UTC(), ExpiresAt: inv.ExpiresAt().UTC(), Active: inv.Active(res.At)})
	}

	writeJSON(w, http.StatusOK, struct {
		Invitations []invitationBody `json:"invitations"`
	}{out})
}

func (h *handler) createInvitation(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		Email    string `json:"email"`
		TTLHours int    `json:"ttl_hours"`
		NoMail   bool   `json:"no_mail"`
	}
	if !decode(w, r, &body) {
		return
	}

	if body.TTLHours < 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "ttl_hours must not be negative")
		return
	}

	res, err := h.Invitations.Create(r.Context(), appadmin.CreateInvitationCommand{
		Actor: p.actor, Email: body.Email, TTL: time.Duration(body.TTLHours) * time.Hour, NoMail: body.NoMail,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}

	if h.outcome(w, r, "invite", res.Outcome, res.Reason) {
		return
	}

	inv := res.Invitation
	writeJSON(w, http.StatusCreated, invitationBody{Email: inv.Email().String(), CreatedAt: inv.CreatedAt().UTC(), ExpiresAt: inv.ExpiresAt().UTC(), Active: true})
}

func (h *handler) revokeInvitation(w http.ResponseWriter, r *http.Request, p principal) {
	var body struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &body) {
		return
	}

	h.act("uninvite", func(r *http.Request, p principal) (appadmin.Result, error) {
		return h.Invitations.Revoke(r.Context(), appadmin.RevokeInvitationCommand{Actor: p.actor, Email: body.Email})
	})(w, r, p)
}

func (h *handler) listAudit(w http.ResponseWriter, r *http.Request, p principal) {
	limit, ok := queryInt(r, "limit")
	if !ok {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "limit is not a number")
		return
	}

	q := r.URL.Query()

	res, err := h.Audit.List(r.Context(), appadmin.ListAuditCommand{
		Actor: p.actor, UserID: q.Get("user_id"), OperatorID: q.Get("operator_id"), Type: q.Get("type"), Before: q.Get("before"), Limit: limit,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}

	if h.outcome(w, r, "audit", res.Outcome, "") {
		return
	}

	type entry struct {
		ID         string            `json:"id"`
		Type       port.AuditType    `json:"type"`
		Result     port.AuditResult  `json:"result"`
		At         time.Time         `json:"at"`
		UserID     string            `json:"user_id,omitempty"`
		OperatorID string            `json:"operator_id,omitempty"`
		Fields     map[string]string `json:"fields,omitempty"`
	}

	entries := make([]entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		entries = append(entries, entry{
			ID: e.ID, Type: e.Type, Result: e.Result, At: e.At.UTC(),
			UserID: e.UserID.String(), OperatorID: e.OperatorID.String(), Fields: e.Fields,
		})
	}

	writeJSON(w, http.StatusOK, struct {
		Entries []entry `json:"entries"`
		Next    string  `json:"next,omitempty"`
	}{entries, res.Next})
}
