//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
)

type failingTicketCreate struct{ port.TicketRepository }

func (failingTicketCreate) Create(context.Context, *passkey.Ticket) error {
	return errBoom
}

type failingAuditLog struct{}

func (failingAuditLog) Record(context.Context, port.AuditEvent) error {
	return errBoom
}

type failingRecognizedRegister struct {
	port.RecognizedClientRepository
}

func (failingRecognizedRegister) Register(context.Context, *identity.RecognizedClient) (*identity.RecognizedClient, error) {
	return nil, errBoom
}

func rowCounts(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()

	counts := map[string]int{}
	for _, table := range []string{"users", "sessions", "refresh_tokens", "recognized_clients", "audit_events", "auth_tickets"} {
		counts[table] = count(t, db, table)
	}

	return counts
}

func TestAtomicVerifyWritesTheTicketOnPostgres(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("Alice@Example.test")

	res := a.check(flowID, a.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK || res.Next != emailauth.NextEnrollPasskey || res.TicketSecret == "" {
		t.Fatalf("verify = %+v", res)
	}
	// An email proof is a user, a ticket, a recognition and an audit event: never a session.
	want := map[string]int{"users": 1, "auth_tickets": 1, "recognized_clients": 1, "audit_events": 1}
	for table, n := range rowCounts(t, a.db) {
		if n != want[table] {
			t.Errorf("%s has %d rows, want %d", table, n, want[table])
		}
	}

	var (
		event, result, kind string
		userID, sessionID   sql.NullString
		fields              []byte
	)

	err := a.db.QueryRow(`SELECT event, result, user_id::text, session_id::text, fields FROM audit_events`).Scan(&event, &result, &userID, &sessionID, &fields)
	if err != nil {
		t.Fatal(err)
	}

	if event != "email.verified" || result != "success" || userID.String != res.User.ID().String() || sessionID.Valid {
		t.Errorf("event = %s/%s user=%s session=%v", event, result, userID.String, sessionID)
	}

	var decoded map[string]string
	if err := json.Unmarshal(fields, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["method"] != "otp" || decoded["new_user"] != "true" || decoded["quota_class"] != "unknown" || decoded["next"] != "enroll_passkey" || len(decoded) != 4 {
		t.Errorf("fields = %v", decoded)
	}

	if strings.Contains(string(fields), res.TicketSecret) {
		t.Error("the audit event carries the ticket secret")
	}

	if err := a.db.QueryRow(`SELECT kind FROM auth_tickets`).Scan(&kind); err != nil || kind != "enroll" {
		t.Errorf("ticket kind = %q, %v", kind, err)
	}
	// Only the hash of the secret is stored.
	var raw int
	if err := a.db.QueryRow(`SELECT count(*) FROM auth_tickets WHERE secret_hash = convert_to($1, 'UTF8')`, res.TicketSecret).Scan(&raw); err != nil || raw != 0 {
		t.Errorf("the ticket secret is stored as is: %d, %v", raw, err)
	}
}

func TestFailedVerifyLeavesNoRowsOnPostgres(t *testing.T) {
	stages := map[string]func(port.Stores) port.Stores{
		"ticket insert":     func(s port.Stores) port.Stores { s.Tickets = failingTicketCreate{s.Tickets}; return s },
		"recognized client": func(s port.Stores) port.Stores { s.Recognized = failingRecognizedRegister{s.Recognized}; return s },
		"audit event":       func(s port.Stores) port.Stores { s.Audit = failingAuditLog{}; return s },
	}
	for name, wrap := range stages {
		t.Run(name, func(t *testing.T) {
			a := newApp(t)
			flowID, binding := a.begin("alice@example.test")
			code := a.code(flowID)
			a.faults.wrap = wrap

			_, err := a.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
			if !errors.Is(err, errBoom) {
				t.Fatalf("error = %v, want boom", err)
			}

			for table, n := range rowCounts(t, a.db) {
				if n != 0 {
					t.Errorf("%s has %d rows after a failed verify", table, n)
				}
			}

			flow := a.flow(flowID)
			if flow.State() != authflow.StatePending || flow.Attempts() != 1 {
				t.Errorf("flow state=%s attempts=%d", flow.State(), flow.Attempts())
			}

			a.faults.wrap = nil
			if retry := a.check(flowID, code, binding); retry.Outcome != emailauth.OutcomeOK {
				t.Errorf("retry = %+v", retry)
			}
		})
	}
}

func TestConcurrentFirstVerifiesOfOneEmailMakeOneUserAndManyTickets(t *testing.T) {
	a := newApp(t)

	const devices = 8

	type login struct{ flowID, binding string }

	logins := make([]login, devices)
	for i := range logins {
		f, b := a.begin("race@example.test")
		logins[i] = login{f, b}
	}

	results := make([]emailauth.VerifyCodeResult, devices)

	var wg sync.WaitGroup
	for i := range logins {
		wg.Add(1)
		go func() {
			defer wg.Done()

			results[i] = a.check(logins[i].flowID, a.code(logins[i].flowID), logins[i].binding)
		}()
	}

	wg.Wait()

	created := 0

	for i, r := range results {
		if r.Outcome != emailauth.OutcomeOK || r.TicketSecret == "" {
			t.Fatalf("verify %d = %+v", i, r)
		}

		if r.UserCreated {
			created++
		}
	}

	counts := rowCounts(t, a.db)
	if created != 1 || counts["users"] != 1 || counts["auth_tickets"] != devices || counts["sessions"] != 0 ||
		counts["recognized_clients"] != devices || counts["audit_events"] != devices {
		t.Errorf("created=%d counts=%v, want one user and %d tickets, recognitions and events, no session", created, counts, devices)
	}
}

func TestConcurrentLoginsFromOneDeviceKeepOneRecognizedClient(t *testing.T) {
	a := newApp(t)

	flowID, binding := a.begin("alice@example.test")
	if res := a.check(flowID, a.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("first login = %+v", res)
	}

	// The same browser, with the same binding, signs in six more times at once.
	const logins = 6

	flows := make([]string, logins)
	for i := range flows {
		res, err := a.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test", BindingSecret: binding})
		if err != nil || res.Outcome != emailauth.OutcomeOK {
			t.Fatalf("start = %+v, %v", res, err)
		}

		flows[i] = res.FlowID.String()
		if got := a.flow(flows[i]).QuotaClass(); got != authflow.QuotaRecognized {
			t.Fatalf("flow %d class = %s, want recognized", i, got)
		}
	}

	var wg sync.WaitGroup
	for i := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if res := a.check(flows[i], a.code(flows[i]), binding); res.Outcome != emailauth.OutcomeOK {
				t.Errorf("login %d = %+v", i, res)
			}
		}()
	}

	wg.Wait()

	counts := rowCounts(t, a.db)
	if counts["recognized_clients"] != 1 || counts["auth_tickets"] != logins+1 || counts["users"] != 1 {
		t.Errorf("counts = %v, want one recognized client and %d tickets", counts, logins+1)
	}
}

func TestAuditEventsKeepNoPersonalDataAfterUserDeletion(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("alice@example.test")

	res := a.check(flowID, a.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("verify = %+v", res)
	}

	if _, err := a.db.Exec(`DELETE FROM users WHERE id = $1`, res.User.ID().String()); err != nil {
		t.Fatal(err)
	}

	var (
		userID, sessionID sql.NullString
		fields            []byte
	)
	if err := a.db.QueryRow(`SELECT user_id::text, session_id::text, fields FROM audit_events`).Scan(&userID, &sessionID, &fields); err != nil {
		t.Fatalf("the audit event must survive the deletion of the user: %v", err)
	}

	if userID.Valid || sessionID.Valid {
		t.Errorf("references survived: user=%v session=%v; they must be cleared", userID, sessionID)
	}

	for _, personal := range []string{"alice", "example.test", "@"} {
		if strings.Contains(string(fields), personal) {
			t.Errorf("event fields %s contain %q", fields, personal)
		}
	}

	if count(t, a.db, "auth_tickets") != 0 || count(t, a.db, "recognized_clients") != 0 {
		t.Error("the user's tickets and recognitions must be deleted with the user")
	}
}

func TestAuditTableConstraints(t *testing.T) {
	db := migratedDB(t)
	insert := func(event, result, fields string) (string, []any) {
		return `INSERT INTO audit_events (id, event, result, occurred_at, fields) VALUES ($1, $2, $3, now(), $4::jsonb)`,
			[]any{"018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3d01", event, result, fields}
	}
	q, args := insert("login.succeeded", "success", `{}`)
	exec(t, db, q, args...)

	for name, tc := range map[string]struct {
		constraint, event, result, fields string
	}{
		"bad event name":    {"audit_events_event", "Login Succeeded", "success", `{}`},
		"empty event":       {"audit_events_event", "", "success", `{}`},
		"unknown result":    {"audit_events_result", "login.succeeded", "ok", `{}`},
		"fields not object": {"audit_events_fields", "login.succeeded", "success", `["a"]`},
		"fields a string":   {"audit_events_fields", "login.succeeded", "success", `"x"`},
	} {
		t.Run(name, func(t *testing.T) {
			q, args := insert(tc.event, tc.result, tc.fields)
			args[0] = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3d02"
			mustViolate(t, db, tc.constraint, q, args...)
		})
	}
}
