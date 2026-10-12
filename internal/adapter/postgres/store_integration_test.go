//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/jwt"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/emailauth"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
)

var (
	t0      = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	policy  = authflow.DefaultPolicy()
	errBoom = errors.New("boom")
)

// newStore opens a Store on a freshly migrated, isolated schema and also returns
// a plain handle for inspecting rows.
func newStore(t *testing.T) (*postgres.Store, *sql.DB) {
	t.Helper()
	return newStoreWith(t)
}

func newStoreWith(t *testing.T, opts ...postgres.Option) (*postgres.Store, *sql.DB) {
	t.Helper()
	dsn := schemaDSN(t)
	db := openDB(t, dsn)
	if _, err := postgres.MigrateUp(context.Background(), db); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := postgres.Open(context.Background(), dsn, id.Generator{}, append([]postgres.Option{postgres.WithMaxConns(4)}, opts...)...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	return store, db
}

func TestPostgresStoreContract(t *testing.T) {
	testutil.RunStoreContract(t, func(t *testing.T) port.UnitOfWork {
		store, _ := newStore(t)
		return store
	})
}

func TestOutboxEnqueueWritesAJobPerGeneration(t *testing.T) {
	store, db := newStore(t)
	flow := testutil.NewFactory(t, t0).Flow(testutil.FlowSpec{})

	err := store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		if err := s.Flows.Create(ctx, flow); err != nil {
			return err
		}
		return s.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: t0})
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	var jobID, status, class string
	var generation, attempts int
	var leaseNull bool
	err = db.QueryRow(`SELECT id::text, status, quota_class, generation, attempts, lease_until IS NULL FROM outbox WHERE flow_id = $1`, flow.ID().String()).
		Scan(&jobID, &status, &class, &generation, &attempts, &leaseNull)
	if err != nil {
		t.Fatal(err)
	}
	if status != "queued" || class != "unknown" || generation != 1 || attempts != 0 || !leaseNull {
		t.Errorf("job = status %s class %s generation %d attempts %d leaseNull %v", status, class, generation, attempts, leaseNull)
	}
	if jobID[14] != '7' {
		t.Errorf("job id %s is not a UUIDv7", jobID)
	}
}

func TestEnqueueingTheSameGenerationTwiceRollsBackTheTransaction(t *testing.T) {
	store, db := newStore(t)
	flow := testutil.NewFactory(t, t0).Flow(testutil.FlowSpec{})

	err := store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		if err := s.Flows.Create(ctx, flow); err != nil {
			return err
		}
		job := port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: t0}
		if err := s.Outbox.Enqueue(ctx, job); err != nil {
			return err
		}
		return s.Outbox.Enqueue(ctx, job)
	})
	if err == nil {
		t.Fatal("a duplicate generation was accepted")
	}
	if count(t, db, "auth_flows") != 0 || count(t, db, "outbox") != 0 {
		t.Error("the failed transaction left rows behind")
	}
}

func TestDoRollsBackOnPanicAndStaysUsable(t *testing.T) {
	store, db := newStore(t)
	user := testutil.NewFactory(t, t0).User(testutil.UserSpec{})

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		_ = store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}
			panic("handler bug")
		})
	}()

	if count(t, db, "users") != 0 {
		t.Error("a panicking transaction was committed")
	}
	if err := store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, user)
		return err
	}); err != nil {
		t.Errorf("the pool is stuck after a panic: %v", err)
	}
}

func TestDoRespectsCancelledContext(t *testing.T) {
	store, db := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := store.Do(ctx, func(context.Context, port.Stores) error { called = true; return nil })
	if err == nil || called {
		t.Errorf("error = %v, called = %v", err, called)
	}
	if count(t, db, "users") != 0 {
		t.Error("unexpected rows")
	}
}

func TestOpenErrorsDoNotLeakThePassword(t *testing.T) {
	for _, dsn := range []string{
		"postgres://airlance_auth:hunter2@127.0.0.1:1/airlance_auth?sslmode=disable",
		"postgres://airlance_auth:hunter2@127.0.0.1:notaport/airlance_auth",
		"postgres://airlance_auth:hunter2@%zz/airlance_auth",
	} {
		_, err := postgres.Open(context.Background(), dsn, id.Generator{})
		if err == nil {
			t.Errorf("Open(%q) succeeded", dsn)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error %q leaks the password", err)
		}
	}
	if _, err := postgres.Open(context.Background(), "postgres://u@h/db", nil); err == nil {
		t.Error("Open accepted a nil record id generator")
	}
}

// ---- use cases on the real database ----

type faultyUoW struct {
	inner port.UnitOfWork
	wrap  func(port.Stores) port.Stores
}

func (f *faultyUoW) Do(ctx context.Context, fn func(ctx context.Context, s port.Stores) error) error {
	return f.inner.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if f.wrap != nil {
			s = f.wrap(s)
		}
		return fn(ctx, s)
	})
}

type failingOutbox struct{ port.Outbox }

func (failingOutbox) Enqueue(context.Context, port.MailJob) error { return errBoom }

type failingUsers struct{ port.UserRepository }

func (failingUsers) Ensure(context.Context, *identity.User) (*identity.User, bool, error) {
	return nil, false, errBoom
}

type app struct {
	t      *testing.T
	store  *postgres.Store
	db     *sql.DB
	faults *faultyUoW
	clock  *testutil.FakeClock
	otp    *crypto.OTP
	start  *emailauth.Start
	resend *emailauth.Resend
	verify *emailauth.VerifyCode
	// issuer and signer open the sessions of the passkey use cases built on this app.
	issuer *appsession.Issuer
	signer port.AccessSigner
}

// newApp wires the use cases to a PostgreSQL store without quotas, so a test about
// something else is not stopped by a budget. Quota behavior has its own tests.
func newApp(t *testing.T) *app {
	t.Helper()
	return newAppWith(t, postgres.WithQuota(quota.Unlimited()))
}

func newAppWith(t *testing.T, opts ...postgres.Option) *app {
	t.Helper()
	store, db := newStoreWith(t, opts...)
	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{t: t, store: store, db: db, faults: &faultyUoW{inner: store}, clock: testutil.NewFakeClock(t0), otp: otp}
	bindings := crypto.Binding{}
	a.start, err = emailauth.NewStart(emailauth.StartDeps{UnitOfWork: a.faults, Clock: a.clock, FlowIDs: crypto.Random{}, OTP: otp, Bindings: bindings, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	a.resend, err = emailauth.NewResend(emailauth.ResendDeps{UnitOfWork: a.faults, Clock: a.clock, OTP: otp, Bindings: bindings, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	keys := testutil.NewSigningKeyPEM(t)
	jwtRing, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner(jwtRing, a.clock, "https://auth.example.test", "example", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := appsession.NewIssuer(appsession.IssuerDeps{SessionIDs: id.Generator{}, TokenIDs: id.Generator{}, Secrets: crypto.Refresh{}, Policy: session.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	a.verify, err = emailauth.NewVerifyCode(emailauth.VerifyCodeDeps{
		UnitOfWork: a.faults, Clock: a.clock, OTP: otp, Bindings: bindings, UserIDs: id.Generator{},
		RecognizedIDs: id.Generator{}, PasskeyIDs: id.Generator{}, Tickets: crypto.Ticket{}, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	a.issuer, a.signer = issuer, signer
	return a
}

func (a *app) begin(email string) (flowID, binding string) {
	a.t.Helper()
	res, err := a.start.Execute(context.Background(), emailauth.StartCommand{Email: email})
	if err != nil || res.Outcome != emailauth.OutcomeOK {
		a.t.Fatalf("start = %+v, %v", res, err)
	}
	return res.FlowID.String(), res.NewBindingSecret
}

func (a *app) flow(flowID string) *authflow.Flow {
	a.t.Helper()
	fid, err := authflow.ParseFlowID(flowID)
	if err != nil {
		a.t.Fatal(err)
	}
	var flow *authflow.Flow
	err = a.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		var err error
		flow, err = s.Flows.GetForUpdate(ctx, fid)
		return err
	})
	if err != nil {
		a.t.Fatalf("load flow: %v", err)
	}
	return flow
}

func (a *app) code(flowID string) string {
	a.t.Helper()
	code, err := a.otp.Code(a.flow(flowID))
	if err != nil {
		a.t.Fatal(err)
	}
	return code
}

func (a *app) check(flowID, code, binding string) emailauth.VerifyCodeResult {
	a.t.Helper()
	res, err := a.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
	if err != nil {
		a.t.Errorf("verify: %v", err)
	}
	return res
}

func wrongCode(code string) string {
	if code == "00000000" {
		return "00000001"
	}
	return "00000000"
}

func TestUseCasesHappyPathOnPostgres(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("Alice@Example.test")

	if count(t, a.db, "users") != 0 || count(t, a.db, "outbox") != 1 {
		t.Fatalf("after start: users=%d jobs=%d", count(t, a.db, "users"), count(t, a.db, "outbox"))
	}
	res := a.check(flowID, a.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK || !res.UserCreated || res.User.Email().String() != "alice@example.test" {
		t.Fatalf("verify = %+v", res)
	}
	flow := a.flow(flowID)
	if flow.State() != authflow.StateConsumed || len(flow.Salt()) != 0 {
		t.Errorf("state=%s salt=%d bytes", flow.State(), len(flow.Salt()))
	}
	if again := a.check(flowID, "00000000", binding); again.Outcome != emailauth.OutcomeDenied {
		t.Errorf("reuse = %+v", again)
	}
}

func TestConcurrentVerifyOfTheSameFlowHasOneWinner(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("alice@example.test")
	code := a.code(flowID)

	const workers = 16
	results := make([]emailauth.VerifyCodeResult, workers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.check(flowID, code, binding)
		}()
	}
	wg.Wait()

	ok := 0
	for _, r := range results {
		if r.Outcome == emailauth.OutcomeOK {
			ok++
		}
	}
	if ok != 1 || count(t, a.db, "users") != 1 {
		t.Errorf("successes=%d users=%d, want one of each", ok, count(t, a.db, "users"))
	}
	if a.flow(flowID).State() != authflow.StateConsumed {
		t.Error("the flow is not consumed")
	}
}

func TestConcurrentWrongCodesNeverExceedTheAttemptLimit(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("alice@example.test")
	wrong := wrongCode(a.code(flowID))

	const workers = 24
	results := make([]emailauth.VerifyCodeResult, workers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.check(flowID, wrong, binding)
		}()
	}
	wg.Wait()

	compared := 0
	for _, r := range results {
		if r.Outcome != emailauth.OutcomeDenied {
			t.Errorf("result = %+v", r)
		}
		if r.Reason == emailauth.ReasonWrongCode {
			compared++
		}
	}
	if compared > policy.MaxAttempts {
		t.Errorf("%d codes were compared, the limit is %d", compared, policy.MaxAttempts)
	}
	flow := a.flow(flowID)
	if flow.Attempts() != policy.MaxAttempts || flow.State() != authflow.StateLocked {
		t.Errorf("attempts=%d state=%s, want %d and locked", flow.Attempts(), flow.State(), policy.MaxAttempts)
	}
	if count(t, a.db, "users") != 0 {
		t.Error("a user was created without a proof")
	}
}

func TestResendRacingVerifyKeepsTheFlowConsistent(t *testing.T) {
	for i := 0; i < 25; i++ {
		// One subtest per round: its pool is closed at once, so 25 rounds never hold 25 pools open.
		t.Run(fmt.Sprintf("round_%d", i), func(t *testing.T) {
			a := newApp(t)
			flowID, binding := a.begin("alice@example.test")
			oldCode := a.code(flowID)
			a.clock.Advance(policy.ResendPause)

			var verifyRes emailauth.VerifyCodeResult
			var resendRes emailauth.ResendResult
			var resendErr error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); verifyRes = a.check(flowID, oldCode, binding) }()
			go func() {
				defer wg.Done()
				resendRes, resendErr = a.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding})
			}()
			wg.Wait()
			if resendErr != nil {
				t.Fatalf("resend: %v", resendErr)
			}

			flow := a.flow(flowID)
			jobs := count(t, a.db, "outbox")
			switch {
			case verifyRes.Outcome == emailauth.OutcomeOK && resendRes.Outcome == emailauth.OutcomeOK:
				t.Fatalf("round %d: both verify and resend succeeded", i)
			case verifyRes.Outcome == emailauth.OutcomeOK:
				if flow.State() != authflow.StateConsumed || jobs != 1 || resendRes.Outcome != emailauth.OutcomeDenied {
					t.Fatalf("round %d: verify won but state=%s jobs=%d resend=%+v", i, flow.State(), jobs, resendRes)
				}
			case resendRes.Outcome == emailauth.OutcomeOK:
				if flow.State() != authflow.StatePending || flow.Generation() != 2 || jobs != 2 || count(t, a.db, "users") != 0 {
					t.Fatalf("round %d: resend won but state=%s generation=%d jobs=%d", i, flow.State(), flow.Generation(), jobs)
				}
			default:
				t.Fatalf("round %d: neither succeeded: verify=%+v resend=%+v", i, verifyRes, resendRes)
			}
		})
	}
}

func TestConcurrentFirstLoginsOfOneEmailCreateOneUser(t *testing.T) {
	a := newApp(t)
	const flows = 8
	type login struct{ flowID, binding string }
	logins := make([]login, flows)
	for i := range logins {
		f, b := a.begin("race@example.test")
		logins[i] = login{f, b}
	}

	results := make([]emailauth.VerifyCodeResult, flows)
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
	var first identity.UserID
	for i, r := range results {
		if r.Outcome != emailauth.OutcomeOK {
			t.Fatalf("login %d = %+v", i, r)
		}
		if i == 0 {
			first = r.User.ID()
		} else if r.User.ID() != first {
			t.Errorf("login %d got user %s, login 0 got %s", i, r.User.ID(), first)
		}
		if r.UserCreated {
			created++
		}
	}
	if created != 1 || count(t, a.db, "users") != 1 {
		t.Errorf("created=%d users=%d, want one of each", created, count(t, a.db, "users"))
	}
}

func TestConcurrentStartsOfOneEmailMakeIndependentFlows(t *testing.T) {
	a := newApp(t)
	const workers = 12
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test"})
			if err != nil || res.Outcome != emailauth.OutcomeOK {
				t.Errorf("start = %+v, %v", res, err)
			}
		}()
	}
	wg.Wait()
	if count(t, a.db, "auth_flows") != workers || count(t, a.db, "outbox") != workers {
		t.Errorf("flows=%d jobs=%d, want %d each", count(t, a.db, "auth_flows"), count(t, a.db, "outbox"), workers)
	}
}

func TestFailedResultKeepsTheReservedAttemptOnPostgres(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("alice@example.test")
	code := a.code(flowID)
	a.faults.wrap = func(s port.Stores) port.Stores { s.Users = failingUsers{s.Users}; return s }

	_, err := a.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}
	flow := a.flow(flowID)
	if flow.State() != authflow.StatePending || flow.Attempts() != 1 || count(t, a.db, "users") != 0 {
		t.Errorf("state=%s attempts=%d users=%d: the reservation must stay, the result must not", flow.State(), flow.Attempts(), count(t, a.db, "users"))
	}

	a.faults.wrap = nil
	if res := a.check(flowID, code, binding); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("retry = %+v", res)
	}
	if got := a.flow(flowID).Attempts(); got != 2 {
		t.Errorf("attempts after the retry = %d, want 2", got)
	}
}

func TestOutboxFailureRollsBackFlowChangesOnPostgres(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		a := newApp(t)
		a.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }
		if _, err := a.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test"}); !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}
		if count(t, a.db, "auth_flows") != 0 || count(t, a.db, "outbox") != 0 {
			t.Error("start left rows behind")
		}
	})
	t.Run("resend", func(t *testing.T) {
		a := newApp(t)
		flowID, binding := a.begin("alice@example.test")
		a.clock.Advance(policy.ResendPause)
		a.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }

		_, err := a.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding})
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}
		if got := a.flow(flowID).Generation(); got != 1 {
			t.Errorf("generation = %d: the generation must not advance without a queued mail", got)
		}
	})
}

func TestExpiredFlowDenialIsCommittedOnPostgres(t *testing.T) {
	a := newApp(t)
	flowID, binding := a.begin("alice@example.test")
	code := a.code(flowID)
	a.clock.Advance(policy.TTL)

	res := a.check(flowID, code, binding)
	if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonExpired {
		t.Fatalf("result = %+v", res)
	}
	var state string
	var saltNull bool
	if err := a.db.QueryRow(`SELECT state, salt IS NULL FROM auth_flows WHERE id = $1`, flowID).Scan(&state, &saltNull); err != nil {
		t.Fatal(err)
	}
	if state != "expired" || !saltNull {
		t.Errorf("state=%s saltNull=%v: the denial's state change must be committed", state, saltNull)
	}
}
