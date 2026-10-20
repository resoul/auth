//go:build integration

package postgres_test

import (
	"context"
	"sync"
	"testing"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/id"
	apasskey "go.airlance.org/auth/internal/adapter/passkey"
	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

const (
	rpID     = "example.test"
	rpOrigin = "https://example.test"
)

// passkeys are the strong-factor use cases on the PostgreSQL store of an app.
type passkeys struct {
	a              *app
	beginEnroll    *passkey.BeginEnroll
	finishEnroll   *passkey.FinishEnroll
	beginLogin     *passkey.BeginLogin
	finishLogin    *passkey.FinishLogin
	redeemRecovery *passkey.RedeemRecovery

	beginStepUp  *passkey.BeginStepUp
	finishStepUp *passkey.FinishStepUp
	beginAdd     *passkey.BeginAddPasskey
	finishAdd    *passkey.FinishAddPasskey
	deleteKey    *passkey.DeleteCredential
	regenerate   *passkey.RegenerateRecoveryCodes
}

func newPasskeys(t *testing.T, a *app) *passkeys {
	t.Helper()

	web, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{rpOrigin}})
	if err != nil {
		t.Fatal(err)
	}

	p := &passkeys{a: a}
	sessions := passkey.SessionDeps{Sessions: a.issuer, Signer: a.signer}

	bindings, tickets := crypto.Binding{}, crypto.Ticket{}
	if p.beginEnroll, err = passkey.NewBeginEnroll(passkey.BeginEnrollDeps{
		UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Bindings: bindings, Tickets: tickets, PasskeyIDs: id.Generator{},
	}); err != nil {
		t.Fatal(err)
	}

	if p.finishEnroll, err = passkey.NewFinishEnroll(passkey.FinishEnrollDeps{
		UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Bindings: bindings, Tickets: tickets,
		PasskeyIDs: id.Generator{}, Recovery: crypto.Recovery{}, SessionDeps: sessions,
	}); err != nil {
		t.Fatal(err)
	}

	if p.beginLogin, err = passkey.NewBeginLogin(passkey.BeginLoginDeps{UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, PasskeyIDs: id.Generator{}}); err != nil {
		t.Fatal(err)
	}

	if p.finishLogin, err = passkey.NewFinishLogin(passkey.FinishLoginDeps{
		UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Bindings: bindings, Tickets: tickets, SessionDeps: sessions,
	}); err != nil {
		t.Fatal(err)
	}

	if p.redeemRecovery, err = passkey.NewRedeemRecovery(passkey.RedeemRecoveryDeps{
		UnitOfWork: a.faults, Clock: a.clock, Bindings: bindings, Tickets: tickets, Recovery: crypto.Recovery{}, PasskeyIDs: id.Generator{},
	}); err != nil {
		t.Fatal(err)
	}

	ids := id.Generator{}
	if p.beginStepUp, err = passkey.NewBeginStepUp(passkey.BeginStepUpDeps{UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, PasskeyIDs: ids}); err != nil {
		t.Fatal(err)
	}

	if p.finishStepUp, err = passkey.NewFinishStepUp(passkey.FinishStepUpDeps{UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Tickets: tickets, PasskeyIDs: ids}); err != nil {
		t.Fatal(err)
	}

	if p.beginAdd, err = passkey.NewBeginAddPasskey(passkey.BeginAddPasskeyDeps{UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Tickets: tickets, PasskeyIDs: ids}); err != nil {
		t.Fatal(err)
	}

	if p.finishAdd, err = passkey.NewFinishAddPasskey(passkey.FinishAddPasskeyDeps{UnitOfWork: a.faults, Clock: a.clock, WebAuthn: web, Tickets: tickets, PasskeyIDs: ids}); err != nil {
		t.Fatal(err)
	}

	if p.deleteKey, err = passkey.NewDeleteCredential(passkey.DeleteCredentialDeps{UnitOfWork: a.faults, Clock: a.clock, Tickets: tickets}); err != nil {
		t.Fatal(err)
	}

	if p.regenerate, err = passkey.NewRegenerateRecoveryCodes(passkey.RegenerateRecoveryCodesDeps{
		UnitOfWork: a.faults, Clock: a.clock, Tickets: tickets, Recovery: crypto.Recovery{}, PasskeyIDs: ids,
	}); err != nil {
		t.Fatal(err)
	}

	return p
}

// signedIn registers a first passkey for a new email and returns what the user holds.
type signedIn struct {
	auth  *testutil.SoftAuthenticator
	actor appsession.Actor
}

func (p *passkeys) signedIn(email string) signedIn {
	p.a.t.Helper()
	ticket, binding, _ := p.verified(email)
	auth, c := p.begin(ticket, binding)

	res := p.finish(ticket, binding, c)
	if res.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("enroll = %+v", res)
	}

	return signedIn{auth: auth, actor: appsession.Actor{UserID: res.User.ID(), SessionID: res.Session.ID()}}
}

// stepUp proves a fresh factor for the operation and returns the token.
func (p *passkeys) stepUp(s signedIn, auth *testutil.SoftAuthenticator, op dpasskey.Operation) string {
	p.a.t.Helper()

	begun, err := p.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: s.actor, Operation: op})
	if err != nil || begun.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("begin step-up = %+v, %v", begun, err)
	}

	got, err := p.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: s.actor, ChallengeID: begun.ChallengeID, Response: auth.Assert(begun.Options)})
	if err != nil || got.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("finish step-up = %+v, %v", got, err)
	}

	return got.TicketSecret
}

// addKey adds a passkey with a fresh step-up and returns its authenticator.
func (p *passkeys) addKey(s signedIn, proving *testutil.SoftAuthenticator) *testutil.SoftAuthenticator {
	p.a.t.Helper()
	token := p.stepUp(s, proving, dpasskey.OperationAddPasskey)
	auth := testutil.NewSoftAuthenticator(p.a.t, rpID, rpOrigin)

	begun, err := p.beginAdd.Execute(context.Background(), passkey.BeginAddCommand{Actor: s.actor, StepUpSecret: token})
	if err != nil || begun.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("begin add = %+v, %v", begun, err)
	}

	got, err := p.finishAdd.Execute(context.Background(), passkey.FinishAddCommand{
		Actor: s.actor, StepUpSecret: token, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options), Name: "added",
	})
	if err != nil || got.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("finish add = %+v, %v", got, err)
	}

	return auth
}

// credentialIDs lists the row IDs of the user's passkeys, oldest first.
func (p *passkeys) credentialIDs(s signedIn) []string {
	p.a.t.Helper()

	rows, err := p.a.db.Query(`SELECT id::text FROM passkey_credentials WHERE user_id = $1 ORDER BY created_at, id`, s.actor.UserID.String())
	if err != nil {
		p.a.t.Fatal(err)
	}

	defer func() { _ = rows.Close() }()

	var ids []string

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			p.a.t.Fatal(err)
		}

		ids = append(ids, id)
	}

	return ids
}

// ceremony is a registration begun for a ticket, ready to be finished.
type ceremony struct {
	challengeID string
	response    []byte
}

// begin runs the first half of a registration with a fresh authenticator.
func (p *passkeys) begin(ticket, binding string) (*testutil.SoftAuthenticator, ceremony) {
	p.a.t.Helper()
	auth := testutil.NewSoftAuthenticator(p.a.t, rpID, rpOrigin)

	return auth, p.beginWith(auth, ticket, binding)
}

// beginWith is begin for an authenticator the test has configured.
func (p *passkeys) beginWith(auth *testutil.SoftAuthenticator, ticket, binding string) ceremony {
	p.a.t.Helper()

	res, err := p.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: binding})
	if err != nil || res.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("begin enroll = %+v, %v", res, err)
	}

	return ceremony{challengeID: res.ChallengeID, response: auth.Register(res.Options)}
}

func (p *passkeys) finish(ticket, binding string, c ceremony) passkey.FinishEnrollResult {
	res, err := p.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: binding, ChallengeID: c.challengeID, Response: c.response,
	})
	if err != nil {
		p.a.t.Errorf("finish enroll: %v", err)
	}

	return res
}

// verified proves a new email and returns the ticket of the next step.
func (p *passkeys) verified(email string) (ticket, binding string, res emailauth.VerifyCodeResult) {
	p.a.t.Helper()
	flowID, binding := p.a.begin(email)

	res = p.a.check(flowID, p.a.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK {
		p.a.t.Fatalf("verify = %+v", res)
	}

	return res.TicketSecret, binding, res
}

func (p *passkeys) assertion(auth *testutil.SoftAuthenticator) (challengeID string, response []byte) {
	p.a.t.Helper()

	res, err := p.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
	if err != nil || res.Outcome != passkey.OutcomeOK {
		p.a.t.Fatalf("begin login = %+v, %v", res, err)
	}

	return res.ChallengeID, auth.Assert(res.Options)
}

func TestPasskeyJourneyOnPostgres(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, verified := p.verified("alice@example.test")

	auth, c := p.begin(ticket, binding)

	enrolled := p.finish(ticket, binding, c)
	if enrolled.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll = %+v", enrolled)
	}

	counts := rowCounts(t, a.db)
	if counts["sessions"] != 1 || counts["refresh_tokens"] != 1 || count(t, a.db, "passkey_credentials") != 1 || count(t, a.db, "recovery_codes") != 10 {
		t.Errorf("counts = %v, credentials %d, codes %d", counts, count(t, a.db, "passkey_credentials"), count(t, a.db, "recovery_codes"))
	}

	var consumed int
	if err := a.db.QueryRow(`SELECT count(*) FROM auth_tickets WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 1 {
		t.Errorf("%d tickets consumed, %v", consumed, err)
	}

	var amr string
	if err := a.db.QueryRow(`SELECT array_to_string(amr, ',') FROM sessions`).Scan(&amr); err != nil || amr != "otp,passkey" {
		t.Errorf("amr = %q, %v", amr, err)
	}
	// Recovery codes are stored hashed: no stored value is a code.
	for _, code := range enrolled.RecoveryCodes {
		var n int
		if err := a.db.QueryRow(`SELECT count(*) FROM recovery_codes WHERE code_hash = convert_to($1, 'UTF8')`, code).Scan(&n); err != nil || n != 0 {
			t.Fatalf("a recovery code is stored as is: %v", err)
		}
	}

	// The passkey signs in alone.
	challenge, response := p.assertion(auth)

	login, err := p.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{ChallengeID: challenge, Response: response})
	if err != nil || login.Outcome != passkey.OutcomeOK || login.NewBindingSecret == "" || login.User.ID() != verified.User.ID() {
		t.Fatalf("login = %+v, %v", login, err)
	}

	var signCount int64
	if err := a.db.QueryRow(`SELECT sign_count FROM passkey_credentials`).Scan(&signCount); err != nil || signCount != 1 {
		t.Errorf("sign count = %d, %v", signCount, err)
	}

	// The email code leads to the second factor; the passkey completes it once.
	ticket2, binding2, second := p.verified("alice@example.test")
	if second.Next != emailauth.NextSecondFactor {
		t.Fatalf("next = %q", second.Next)
	}

	challenge, response = p.assertion(auth)

	done, err := p.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
		ChallengeID: challenge, Response: response, TicketSecret: ticket2, BindingSecret: binding2,
	})
	if err != nil || done.Outcome != passkey.OutcomeOK {
		t.Fatalf("second factor = %+v, %v", done, err)
	}

	challenge, response = p.assertion(auth)

	again, err := p.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
		ChallengeID: challenge, Response: response, TicketSecret: ticket2, BindingSecret: binding2,
	})
	if err != nil || again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadTicket {
		t.Errorf("a second use of the ticket = %+v, %v", again, err)
	}

	// A lost device: a recovery code buys a new key and ends the old sessions.
	ticket3, binding3, _ := p.verified("alice@example.test")

	redeemed, err := p.redeemRecovery.Execute(context.Background(), passkey.RedeemRecoveryCommand{
		TicketSecret: ticket3, BindingSecret: binding3, Code: enrolled.RecoveryCodes[0],
	})
	if err != nil || redeemed.Outcome != passkey.OutcomeOK {
		t.Fatalf("recover = %+v, %v", redeemed, err)
	}

	_, c2 := p.begin(redeemed.TicketSecret, binding3)

	recovered := p.finish(redeemed.TicketSecret, binding3, c2)
	if recovered.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll after recovery = %+v", recovered)
	}

	var live, credentials, codes int
	if err := a.db.QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL`).Scan(&live); err != nil || live != 1 {
		t.Errorf("%d live sessions, want only the recovery one: %v", live, err)
	}

	credentials, codes = count(t, a.db, "passkey_credentials"), count(t, a.db, "recovery_codes")
	// The key that was lost is gone: only the one registered by the recovery is left.
	if credentials != 1 || codes != 10 {
		t.Errorf("credentials = %d, codes = %d", credentials, codes)
	}

	var used int
	if err := a.db.QueryRow(`SELECT count(*) FROM recovery_codes WHERE used_at IS NOT NULL`).Scan(&used); err != nil || used != 0 {
		t.Errorf("%d used codes: the fresh set replaces the old one entirely", used)
	}
}

func TestOnlyOneOfManyConcurrentRegistrationsWithOneTicketWins(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, _ := p.verified("race@example.test")

	const racers = 6

	ceremonies := make([]ceremony, racers)
	for i := range ceremonies {
		_, ceremonies[i] = p.begin(ticket, binding) // each racer has a valid challenge of its own
	}

	results := make([]passkey.FinishEnrollResult, racers)

	var wg sync.WaitGroup
	for i := range ceremonies {
		wg.Add(1)
		go func() {
			defer wg.Done()

			results[i] = p.finish(ticket, binding, ceremonies[i])
		}()
	}

	wg.Wait()

	won := 0

	for _, r := range results {
		switch r.Outcome {
		case passkey.OutcomeOK:
			won++
		case passkey.OutcomeDenied:
			if r.Reason != passkey.ReasonBadTicket {
				t.Errorf("a loser was refused for %q, want a spent ticket", r.Reason)
			}
		}
	}

	counts := rowCounts(t, a.db)
	if won != 1 || counts["sessions"] != 1 || count(t, a.db, "passkey_credentials") != 1 || count(t, a.db, "recovery_codes") != 10 {
		t.Errorf("won = %d, counts = %v, credentials %d, codes %d; want exactly one of each", won, counts, count(t, a.db, "passkey_credentials"), count(t, a.db, "recovery_codes"))
	}
}

func TestOnlyOneOfManyConcurrentAssertionsOfOneChallengeWins(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, _ := p.verified("race@example.test")
	// A synced passkey reports a counter of zero, so the counter cannot tell a replay from a
	// first use: only the single-use challenge stands between the replay and a second session.
	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	auth.Synced, auth.BackupEligible, auth.BackupState = true, true, true

	c := p.beginWith(auth, ticket, binding)
	if r := p.finish(ticket, binding, c); r.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll = %+v", r)
	}

	sessions := count(t, a.db, "sessions")

	challenge, response := p.assertion(auth)

	const racers = 12

	results := make([]passkey.FinishLoginResult, racers)

	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := p.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{ChallengeID: challenge, Response: response})
			if err != nil {
				t.Errorf("finish login: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	won := 0

	for _, r := range results {
		if r.Outcome == passkey.OutcomeOK {
			won++
		}
	}

	if won != 1 || count(t, a.db, "sessions") != sessions+1 {
		t.Errorf("won = %d, %d new sessions; a replayed assertion must open exactly one session", won, count(t, a.db, "sessions")-sessions)
	}
}

func TestOnlyOneOfManyConcurrentSecondFactorsOfOneTicketWins(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, _ := p.verified("race@example.test")

	auth, c := p.begin(ticket, binding)
	if r := p.finish(ticket, binding, c); r.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll = %+v", r)
	}

	second, secondBinding, _ := p.verified("race@example.test")
	sessions := count(t, a.db, "sessions")

	const racers = 4

	type attempt struct {
		challenge string
		response  []byte
	}

	attempts := make([]attempt, racers)
	for i := range attempts {
		attempts[i].challenge, attempts[i].response = p.assertion(auth)
	}

	results := make([]passkey.FinishLoginResult, racers)

	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := p.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
				ChallengeID: attempts[i].challenge, Response: attempts[i].response, TicketSecret: second, BindingSecret: secondBinding,
			})
			if err != nil {
				t.Errorf("finish login: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	won := 0

	for _, r := range results {
		if r.Outcome == passkey.OutcomeOK {
			won++
		}
	}

	if won != 1 || count(t, a.db, "sessions") != sessions+1 {
		t.Errorf("won = %d, %d new sessions; one email proof must open exactly one session", won, count(t, a.db, "sessions")-sessions)
	}
}

func TestOnlyOneOfManyConcurrentRedemptionsOfOneRecoveryCodeWins(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, _ := p.verified("race@example.test")
	_, c := p.begin(ticket, binding)

	enrolled := p.finish(ticket, binding, c)
	if enrolled.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll = %+v", enrolled)
	}

	const racers = 5

	type proof struct{ ticket, binding string }

	proofs := make([]proof, racers)
	for i := range proofs {
		proofs[i].ticket, proofs[i].binding, _ = p.verified("race@example.test")
	}

	results := make([]passkey.RedeemRecoveryResult, racers)

	var wg sync.WaitGroup
	for i := range proofs {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := p.redeemRecovery.Execute(context.Background(), passkey.RedeemRecoveryCommand{
				TicketSecret: proofs[i].ticket, BindingSecret: proofs[i].binding, Code: enrolled.RecoveryCodes[2],
			})
			if err != nil {
				t.Errorf("redeem: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	won := 0

	for _, r := range results {
		if r.Outcome == passkey.OutcomeOK {
			won++
		}
	}

	var used int
	if err := a.db.QueryRow(`SELECT count(*) FROM recovery_codes WHERE used_at IS NOT NULL`).Scan(&used); err != nil || won != 1 || used != 1 {
		t.Errorf("won = %d, used = %d (%v); a code buys one recovery", won, used, err)
	}
}

func TestFailedEnrollmentLeavesNothingOnPostgres(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	ticket, binding, _ := p.verified("alice@example.test")
	_, c := p.begin(ticket, binding)
	before := rowCounts(t, a.db)

	a.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAuditLog{}; return s }
	_, err := p.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: binding, ChallengeID: c.challengeID, Response: c.response,
	})
	a.faults.wrap = nil

	if err == nil {
		t.Fatal("an audit failure was swallowed")
	}

	after := rowCounts(t, a.db)
	if count(t, a.db, "passkey_credentials") != 0 || count(t, a.db, "recovery_codes") != 0 || after["sessions"] != before["sessions"] || after["refresh_tokens"] != before["refresh_tokens"] {
		t.Errorf("a failed enrollment left rows: credentials %d, codes %d, counts %v", count(t, a.db, "passkey_credentials"), count(t, a.db, "recovery_codes"), after)
	}
	// Nothing was spent: the same ceremony finishes once the fault is gone.
	if r := p.finish(ticket, binding, c); r.Outcome != passkey.OutcomeOK {
		t.Errorf("retry = %+v", r)
	}
}

func TestPasskeyTablesRefuseImpossibleRows(t *testing.T) {
	db := migratedDB(t)
	exec(t, db, `INSERT INTO users (id, email, email_verified_at, created_at, updated_at) VALUES ('6ba7b810-9dad-41d1-80b4-00c04fd430c8', 'a@example.test', now(), now(), now())`)

	insertCred := func(credID []byte, signCount int64, eligible, state bool, name string) (string, []any) {
		return `INSERT INTO passkey_credentials (id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, name, created_at)
		        VALUES (gen_random_uuid(), '6ba7b810-9dad-41d1-80b4-00c04fd430c8', $1, '\x01', $2, $3, $4, $5, now())`,
			[]any{credID, signCount, eligible, state, name}
	}
	q, args := insertCred([]byte("a"), 0, true, false, "ok")
	exec(t, db, q, args...)

	for name, tc := range map[string]struct {
		constraint string
		credID     []byte
		count      int64
		eligible   bool
		state      bool
		label      string
	}{
		"credential id twice":        {"passkey_credentials_credential_id_unique", []byte("a"), 0, true, false, "x"},
		"empty credential id":        {"passkey_credentials_credential_id_length", []byte{}, 0, true, false, "x"},
		"negative counter":           {"passkey_credentials_sign_count", []byte("b"), -1, true, false, "x"},
		"counter past 32 bits":       {"passkey_credentials_sign_count", []byte("c"), 1 << 32, true, false, "x"},
		"backed up but not eligible": {"passkey_credentials_backup", []byte("d"), 0, false, true, "x"},
		"empty name":                 {"passkey_credentials_name", []byte("e"), 0, true, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			q, args := insertCred(tc.credID, tc.count, tc.eligible, tc.state, tc.label)
			mustViolate(t, db, tc.constraint, q, args...)
		})
	}

	ticket := func(kind string, session, operation, binding any) (string, []any) {
		return `INSERT INTO auth_tickets (id, kind, user_id, session_id, operation, binding_hash, secret_hash, created_at, expires_at)
		        VALUES (gen_random_uuid(), $1, '6ba7b810-9dad-41d1-80b4-00c04fd430c8', $2, $3, $4, decode(md5(random()::text) || md5(random()::text), 'hex'), now(), now() + interval '5 minutes')`,
			[]any{kind, session, operation, binding}
	}

	hash := make([]byte, 32)
	for name, tc := range map[string]struct {
		constraint string
		kind       string
		session    any
		operation  any
		binding    any
	}{
		"unknown kind":                    {"auth_tickets_kind", "wipe", nil, nil, hash},
		"enroll without a binding":        {"auth_tickets_shape", "enroll", nil, nil, nil},
		"enroll with an operation":        {"auth_tickets_shape", "enroll", nil, "add_passkey", hash},
		"step-up without a session":       {"auth_tickets_shape", "step_up", nil, "add_passkey", nil},
		"step-up with an unknown binding": {"auth_tickets_shape", "step_up", "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3d01", "add_passkey", hash},
	} {
		t.Run(name, func(t *testing.T) {
			q, args := ticket(tc.kind, tc.session, tc.operation, tc.binding)
			mustViolate(t, db, tc.constraint, q, args...)
		})
	}
}

func TestStepUpAndKeyManagementOnPostgres(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	s := p.signedIn("alice@example.test")

	second := p.addKey(s, s.auth)
	if got := len(p.credentialIDs(s)); got != 2 {
		t.Fatalf("%d keys after adding one", got)
	}
	// Both step-ups are rows bound to this session and spent by the add.
	var spent, total int
	if err := a.db.QueryRow(`SELECT count(*) FILTER (WHERE consumed_at IS NOT NULL), count(*) FROM auth_tickets WHERE kind = 'step_up' AND session_id = $1`, s.actor.SessionID.String()).Scan(&spent, &total); err != nil || total != 1 || spent != 1 {
		t.Errorf("step-up tickets: %d spent of %d (%v)", spent, total, err)
	}

	// Delete the first key with a token for that operation; the survivor is the second.
	ids := p.credentialIDs(s)
	token := p.stepUp(s, second, dpasskey.OperationDeletePasskey)

	got, err := p.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: s.actor, StepUpSecret: token, ID: ids[0]})
	if err != nil || got.Outcome != passkey.OutcomeOK {
		t.Fatalf("delete = %+v, %v", got, err)
	}

	last, err := p.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: s.actor, StepUpSecret: p.stepUp(s, second, dpasskey.OperationDeletePasskey), ID: ids[1]})
	if err != nil || last.Outcome != passkey.OutcomeConflict || last.Reason != passkey.ReasonLastKey {
		t.Errorf("deleting the last key = %+v, %v", last, err)
	}

	if left := p.credentialIDs(s); len(left) != 1 || left[0] != ids[1] {
		t.Errorf("keys left = %v", left)
	}

	var deleted int
	if err := a.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event = 'passkey.deleted'`).Scan(&deleted); err != nil || deleted != 1 {
		t.Errorf("%d deletions audited (%v)", deleted, err)
	}

	// New recovery codes replace the whole set.
	before := count(t, a.db, "recovery_codes")

	codes, err := p.regenerate.Execute(context.Background(), passkey.RegenerateCommand{Actor: s.actor, StepUpSecret: p.stepUp(s, second, dpasskey.OperationRegenerateCodes)})
	if err != nil || codes.Outcome != passkey.OutcomeOK || len(codes.Codes) != 10 || before != 10 || count(t, a.db, "recovery_codes") != 10 {
		t.Errorf("regenerate = %+v, %v; codes before %d, after %d", codes, err, before, count(t, a.db, "recovery_codes"))
	}
	// Ending the session removes its step-up tickets and challenges with it.
	if _, err := a.db.Exec(`DELETE FROM sessions WHERE id = $1`, s.actor.SessionID.String()); err != nil {
		t.Fatal(err)
	}

	var left int
	if err := a.db.QueryRow(`SELECT (SELECT count(*) FROM auth_tickets WHERE kind = 'step_up') + (SELECT count(*) FROM passkey_challenges WHERE session_id IS NOT NULL)`).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d step-up rows survived their session (%v)", left, err)
	}
}

func TestOneStepUpTokenDeletesOnlyOneKeyEvenWhenUsedConcurrently(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	s := p.signedIn("race@example.test")
	last := p.addKey(s, s.auth)
	p.addKey(s, last)
	p.addKey(s, last) // four keys now
	ids := p.credentialIDs(s)
	token := p.stepUp(s, last, dpasskey.OperationDeletePasskey)

	results := make([]passkey.DeleteResult, len(ids))

	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := p.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: s.actor, StepUpSecret: token, ID: ids[i]})
			if err != nil {
				t.Errorf("delete: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	won := 0

	for _, r := range results {
		switch r.Outcome {
		case passkey.OutcomeOK:
			won++
		case passkey.OutcomeStepUpRequired:
		default:
			t.Errorf("a loser got %+v, want a spent token", r)
		}
	}

	if left := len(p.credentialIDs(s)); won != 1 || left != 3 {
		t.Errorf("won = %d, %d keys left; one token removes exactly one key", won, left)
	}
}

func TestConcurrentDeletesWithSeparateTokensNeverRemoveTheLastKey(t *testing.T) {
	a := newApp(t)
	p := newPasskeys(t, a)
	s := p.signedIn("race@example.test")
	second := p.addKey(s, s.auth)
	ids := p.credentialIDs(s)
	tokens := []string{p.stepUp(s, second, dpasskey.OperationDeletePasskey), p.stepUp(s, second, dpasskey.OperationDeletePasskey)}

	results := make([]passkey.DeleteResult, 2)

	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := p.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: s.actor, StepUpSecret: tokens[i], ID: ids[i]})
			if err != nil {
				t.Errorf("delete: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	ok, conflict := 0, 0

	for _, r := range results {
		switch r.Outcome {
		case passkey.OutcomeOK:
			ok++
		case passkey.OutcomeConflict:
			conflict++
		}
	}

	if left := len(p.credentialIDs(s)); ok != 1 || conflict != 1 || left != 1 {
		t.Errorf("%d deleted, %d refused, %d keys left: a user keeps at least one key", ok, conflict, left)
	}
}
