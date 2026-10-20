package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/account"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

var (
	t0      = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	policy  = authflow.DefaultPolicy()
	errBoom = errors.New("boom")
)

type countingReader struct{ n byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}

	return len(p), nil
}

// faults wraps the Stores a use case sees, so a test can make one operation fail.
type faults struct {
	inner port.UnitOfWork
	wrap  func(port.Stores) port.Stores
}

func (f *faults) Do(ctx context.Context, fn func(ctx context.Context, s port.Stores) error) error {
	return f.inner.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if f.wrap != nil {
			s = f.wrap(s)
		}

		return fn(ctx, s)
	})
}

type failingNotice struct{ port.Outbox }

func (f failingNotice) Enqueue(ctx context.Context, job port.MailJob) error {
	if job.Kind == port.JobEmailChanged {
		return errBoom
	}

	return f.Outbox.Enqueue(ctx, job)
}

type env struct {
	t       *testing.T
	store   *memory.Store
	faults  *faults
	clock   *testutil.FakeClock
	factory *testutil.Factory
	otp     *crypto.OTP
	tickets crypto.Ticket

	start   *account.StartEmailChange
	confirm *account.ConfirmEmailChange
}

func newEnv(t *testing.T, opts ...memory.Option) *env {
	t.Helper()

	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	otp, err := crypto.NewOTP(ring, &countingReader{})
	if err != nil {
		t.Fatal(err)
	}

	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: memory.NewStore(opts...), clock: factory.Clock, factory: factory, otp: otp}
	e.faults = &faults{inner: e.store}

	e.start, err = account.NewStartEmailChange(account.StartEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: factory.IDs, OTP: otp, Tickets: e.tickets, Policy: policy,
	})
	must(t, err)
	e.confirm, err = account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: otp, Policy: policy,
	})
	must(t, err)

	return e
}

func withQuota(p quota.Profile) memory.Option { return memory.WithQuota(p) }

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(fn func(ctx context.Context, st port.Stores) error) {
	e.t.Helper()
	must(e.t, e.store.Do(context.Background(), fn))
}

// account is a stored user with a live session.
type signedIn struct {
	user  *identity.User
	actor appsession.Actor
	// binding is the secret of the session's client.
	binding string
}

func (e *env) signedIn(email string) signedIn {
	return e.signedInWith(email, testutil.DefaultBindingSecret)
}

func (e *env) signedInWith(email, bindingSecret string) signedIn {
	e.t.Helper()
	user := e.factory.User(testutil.UserSpec{Email: email})
	sess := e.factory.Session(testutil.SessionSpec{User: user, BindingSecret: bindingSecret})
	e.do(func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		return st.Sessions.Create(ctx, sess)
	})

	return signedIn{user: user, actor: appsession.Actor{UserID: user.ID(), SessionID: sess.ID()}, binding: bindingSecret}
}

// otherSession opens another session of the same user, from another client.
func (e *env) otherSession(s signedIn, bindingSecret string) appsession.Actor {
	e.t.Helper()
	sess := e.factory.Session(testutil.SessionSpec{User: s.user, BindingSecret: bindingSecret})
	e.do(func(ctx context.Context, st port.Stores) error { return st.Sessions.Create(ctx, sess) })

	return appsession.Actor{UserID: s.user.ID(), SessionID: sess.ID()}
}

func (e *env) revoke(actor appsession.Actor) {
	e.t.Helper()
	e.do(func(ctx context.Context, st port.Stores) error {
		s, err := st.Sessions.GetForUpdate(ctx, actor.SessionID)
		if err != nil {
			return err
		}

		s.Revoke(e.clock.Now())

		return st.Sessions.Save(ctx, s)
	})
}

// stepUp stores a step-up ticket for the operation of the session and returns its secret.
func (e *env) stepUp(actor appsession.Actor, op dpasskey.Operation) string {
	e.t.Helper()
	secret, hash, err := e.tickets.NewTicketSecret()
	must(e.t, err)
	id, err := e.factory.IDs.NewPasskeyID()
	must(e.t, err)
	ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
		ID: id, Kind: dpasskey.TicketStepUp, UserID: actor.UserID, SessionID: actor.SessionID, Operation: op,
		SecretHash: hash, Now: e.clock.Now(),
	})
	must(e.t, err)
	e.do(func(ctx context.Context, st port.Stores) error { return st.Tickets.Create(ctx, ticket) })

	return secret
}

// ticketUsed reports whether the step-up ticket of the secret was spent.
func (e *env) ticketUsed(actor appsession.Actor, secret string) bool {
	e.t.Helper()
	hash, err := e.tickets.HashTicketSecret(secret)
	must(e.t, err)

	var used bool

	e.do(func(ctx context.Context, st port.Stores) error {
		ticket, err := st.Tickets.GetByHashForUpdate(ctx, hash)
		if err != nil {
			return err
		}

		used = ticket.Check(e.clock.Now(), dpasskey.Presented{Kind: dpasskey.TicketStepUp, SessionID: actor.SessionID, Operation: dpasskey.OperationChangeEmail}) != nil

		return nil
	})

	return used
}

func (e *env) startChange(s signedIn, ticket, email string) account.StartEmailChangeResult {
	e.t.Helper()
	got, err := e.start.Execute(context.Background(), account.StartEmailChangeCommand{Actor: s.actor, StepUpSecret: ticket, Email: email})
	must(e.t, err)

	return got
}

// codeOf derives the code of the flow, like the mail worker does.
func (e *env) codeOf(id authflow.FlowID) string {
	e.t.Helper()

	flow, ok := e.store.Flow(id)
	if !ok {
		e.t.Fatalf("flow %s is not stored", id)
	}

	code, err := e.otp.Code(flow)
	must(e.t, err)

	return code
}

func (e *env) confirmChange(actor appsession.Actor, flowID, code string) account.ConfirmEmailChangeResult {
	e.t.Helper()
	got, err := e.confirm.Execute(context.Background(), account.ConfirmEmailChangeCommand{Actor: actor, FlowID: flowID, Code: code})
	must(e.t, err)

	return got
}

// begin starts a change and returns its flow ID and the right code.
func (e *env) begin(s signedIn, email string) (flowID, code string) {
	e.t.Helper()

	started := e.startChange(s, e.stepUp(s.actor, dpasskey.OperationChangeEmail), email)
	if started.Outcome != account.OutcomeOK {
		e.t.Fatalf("start refused: %+v", started)
	}

	return started.FlowID.String(), e.codeOf(started.FlowID)
}

func parseEmail(t *testing.T, raw string) identity.Email {
	t.Helper()

	email, err := identity.ParseEmail(raw)
	must(t, err)

	return email
}

func (e *env) userByEmail(raw string) (*identity.User, bool) {
	e.t.Helper()
	return e.store.User(parseEmail(e.t, raw))
}
