//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

type failingNoticeEnqueue struct{ port.Outbox }

func (f failingNoticeEnqueue) Enqueue(ctx context.Context, job port.MailJob) error {
	if job.Kind == port.JobEmailChanged {
		return errBoom
	}
	return f.Outbox.Enqueue(ctx, job)
}

type changeEnv struct {
	t       *testing.T
	store   *postgres.Store
	db      *sql.DB
	faults  *faultyUoW
	clock   *testutil.FakeClock
	f       *testutil.Factory
	otp     *crypto.OTP
	tickets crypto.Ticket
	start   *account.StartEmailChange
	confirm *account.ConfirmEmailChange
}

func newChangeEnv(t *testing.T, opts ...postgres.Option) *changeEnv {
	t.Helper()
	store, db := newStoreWith(t, append([]postgres.Option{postgres.WithQuota(quota.Unlimited())}, opts...)...)
	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := testutil.NewFactory(t, t0)
	e := &changeEnv{t: t, store: store, db: db, faults: &faultyUoW{inner: store}, clock: f.Clock, f: f, otp: otp}
	e.start, err = account.NewStartEmailChange(account.StartEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: crypto.Random{}, OTP: otp, Tickets: e.tickets, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.confirm, err = account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{UnitOfWork: e.faults, Clock: e.clock, OTP: otp, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type changer struct {
	user  *identity.User
	actor appsession.Actor
}

// account stores a user with a live session and a recognized client.
func (e *changeEnv) account(email string) changer {
	return e.accountWithBinding(email, testutil.DefaultBindingSecret)
}

func (e *changeEnv) accountWithBinding(email, binding string) changer {
	e.t.Helper()
	user := e.f.User(testutil.UserSpec{Email: email})
	sess := e.f.Session(testutil.SessionSpec{User: user, BindingSecret: binding})
	client := e.f.RecognizedClient(testutil.RecognizedSpec{User: user})
	err := e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		if _, _, err := s.Users.Ensure(ctx, user); err != nil {
			return err
		}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}
		_, err := s.Recognized.Register(ctx, client)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return changer{user: user, actor: appsession.Actor{UserID: user.ID(), SessionID: sess.ID()}}
}

func (e *changeEnv) stepUp(c changer) string {
	e.t.Helper()
	secret, hash, err := e.tickets.NewTicketSecret()
	if err != nil {
		e.t.Fatal(err)
	}
	pid, err := e.f.IDs.NewPasskeyID()
	if err != nil {
		e.t.Fatal(err)
	}
	ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
		ID: pid, Kind: dpasskey.TicketStepUp, UserID: c.actor.UserID, SessionID: c.actor.SessionID,
		Operation: dpasskey.OperationChangeEmail, SecretHash: hash, Now: e.clock.Now(),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, ticket) }); err != nil {
		e.t.Fatal(err)
	}
	return secret
}

// begin starts a change and returns its flow ID and code.
func (e *changeEnv) begin(c changer, email string) (flowID, code string) {
	e.t.Helper()
	res, err := e.start.Execute(context.Background(), account.StartEmailChangeCommand{Actor: c.actor, StepUpSecret: e.stepUp(c), Email: email})
	if err != nil || res.Outcome != account.OutcomeOK {
		e.t.Fatalf("start = %+v, %v", res, err)
	}
	var flow *authflow.Flow
	if err := e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		var err error
		flow, err = s.Flows.Get(ctx, res.FlowID)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	code, err = e.otp.Code(flow)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.FlowID.String(), code
}

func (e *changeEnv) confirmChange(c changer, flowID, code string) (account.ConfirmEmailChangeResult, error) {
	return e.confirm.Execute(context.Background(), account.ConfirmEmailChangeCommand{Actor: c.actor, FlowID: flowID, Code: code})
}

func (e *changeEnv) userEmail(c changer) string {
	e.t.Helper()
	var email string
	if err := e.db.QueryRow(`SELECT email FROM users WHERE id = $1`, c.user.ID().String()).Scan(&email); err != nil {
		e.t.Fatal(err)
	}
	return email
}

func (e *changeEnv) noticeCount() int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT count(*) FROM outbox WHERE kind = 'email_changed'`).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestEmailChangeCommitsEverythingTogetherOnPostgres(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("old@example.test")
	flowID, code := e.begin(c, "New@Example.test")
	e.clock.Advance(time.Minute)

	got, err := e.confirmChange(c, flowID, code)
	if err != nil || got.Outcome != account.OutcomeOK || got.Email.String() != "new@example.test" {
		t.Fatalf("confirm = %+v, %v", got, err)
	}

	if email := e.userEmail(c); email != "new@example.test" {
		t.Errorf("stored email = %q", email)
	}
	var verified, updated time.Time
	if err := e.db.QueryRow(`SELECT email_verified_at, updated_at FROM users WHERE id = $1`, c.user.ID().String()).Scan(&verified, &updated); err != nil {
		t.Fatal(err)
	}
	if !verified.Equal(t0.Add(time.Minute)) || !updated.Equal(t0.Add(time.Minute)) {
		t.Errorf("verified %v, updated %v; want the time of the new proof", verified, updated)
	}

	var state string
	if err := e.db.QueryRow(`SELECT state FROM auth_flows WHERE id = $1`, flowID).Scan(&state); err != nil || state != "consumed" {
		t.Errorf("flow state = %q, %v", state, err)
	}
	var kind, recipient string
	var kinds int
	if err := e.db.QueryRow(`SELECT kind, recipient, (SELECT count(*) FROM outbox) FROM outbox WHERE kind = 'email_changed'`).Scan(&kind, &recipient, &kinds); err != nil {
		t.Fatalf("no notice: %v", err)
	}
	if recipient != "old@example.test" || kinds != 2 {
		t.Errorf("notice recipient = %q among %d jobs", recipient, kinds)
	}
	var revoked int
	if err := e.db.QueryRow(`SELECT count(*) FROM recognized_clients WHERE user_id = $1 AND revoked_at IS NOT NULL`, c.user.ID().String()).Scan(&revoked); err != nil || revoked != 1 {
		t.Errorf("revoked recognized clients = %d, %v", revoked, err)
	}
	var live int
	if err := e.db.QueryRow(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, c.user.ID().String()).Scan(&live); err != nil || live != 1 {
		t.Errorf("live sessions = %d, %v: the change keeps them", live, err)
	}

	var event, result string
	var fields []byte
	if err := e.db.QueryRow(`SELECT event, result, fields FROM audit_events WHERE event = 'email.changed'`).Scan(&event, &result, &fields); err != nil {
		t.Fatalf("no audit event: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(fields, &decoded); err != nil || len(decoded) != 0 || result != "success" {
		t.Errorf("audit fields = %s (%v), result %q", fields, err, result)
	}
}

func TestFailedEmailChangeLeavesNothingBehindOnPostgres(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("old@example.test")
	flowID, code := e.begin(c, "new@example.test")
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingNoticeEnqueue{s.Outbox}; return s }

	if _, err := e.confirmChange(c, flowID, code); !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}
	if email := e.userEmail(c); email != "old@example.test" {
		t.Errorf("stored email = %q after a failed change", email)
	}
	var state string
	if err := e.db.QueryRow(`SELECT state FROM auth_flows WHERE id = $1`, flowID).Scan(&state); err != nil || state != "pending" {
		t.Errorf("flow state = %q, %v; want pending: the code was not spent", state, err)
	}
	var events, revoked int
	if err := e.db.QueryRow(`SELECT (SELECT count(*) FROM audit_events WHERE event = 'email.changed'), (SELECT count(*) FROM recognized_clients WHERE revoked_at IS NOT NULL)`).Scan(&events, &revoked); err != nil || events != 0 || revoked != 0 {
		t.Errorf("audit events = %d, revoked clients = %d, %v", events, revoked, err)
	}
	if e.noticeCount() != 0 {
		t.Error("a notice was queued for a change that did not happen")
	}

	e.faults.wrap = nil
	if got, err := e.confirmChange(c, flowID, code); err != nil || got.Outcome != account.OutcomeOK {
		t.Errorf("the retry = %+v, %v", got, err)
	}
}

func TestConcurrentConfirmsOfOneCodeMoveTheAccountOnce(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("old@example.test")
	flowID, code := e.begin(c, "new@example.test")

	const callers = 8
	results := make([]account.ConfirmEmailChangeResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.confirmChange(c, flowID, code)
		}()
	}
	wg.Wait()

	ok := 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if r.Outcome == account.OutcomeOK {
			ok++
		} else if r.Outcome != account.OutcomeDenied {
			t.Errorf("caller %d = %+v", i, r)
		}
	}
	if ok != 1 || e.noticeCount() != 1 || e.userEmail(c) != "new@example.test" {
		t.Errorf("%d callers succeeded, %d notices, email %q; want one of each", ok, e.noticeCount(), e.userEmail(c))
	}
}

func TestTwoAccountsConfirmingOneAddressAtOnceOnlyOneGetsIt(t *testing.T) {
	e := newChangeEnv(t)
	const movers = 6
	type attempt struct {
		who    changer
		flowID string
		code   string
	}
	attempts := make([]attempt, movers)
	for i := range attempts {
		who := e.account("")
		flowID, code := e.begin(who, "prize@example.test")
		attempts[i] = attempt{who, flowID, code}
	}

	results := make([]account.ConfirmEmailChangeResult, movers)
	errs := make([]error, movers)
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.confirmChange(attempts[i].who, attempts[i].flowID, attempts[i].code)
		}()
	}
	wg.Wait()

	won, lost := 0, 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("mover %d: %v", i, errs[i])
		}
		switch r.Outcome {
		case account.OutcomeOK:
			won++
		case account.OutcomeConflict:
			lost++
		default:
			t.Errorf("mover %d = %+v", i, r)
		}
	}
	if won != 1 || lost != movers-1 {
		t.Fatalf("%d got the address and %d lost; want 1 and %d", won, lost, movers-1)
	}
	var owners int
	if err := e.db.QueryRow(`SELECT count(*) FROM users WHERE email = 'prize@example.test'`).Scan(&owners); err != nil || owners != 1 {
		t.Errorf("accounts at the address = %d, %v", owners, err)
	}
	if e.noticeCount() != 1 {
		t.Errorf("notices = %d: only the change that happened is announced", e.noticeCount())
	}
}
