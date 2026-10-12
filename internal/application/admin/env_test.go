package admin_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/memory"
	apasskey "airlance.org/auth/internal/adapter/passkey"
	"airlance.org/auth/internal/application/admin"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

const (
	rpID   = "admin.example.test"
	origin = "https://admin.example.test"
)

var (
	t0      = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
	ip      = netip.MustParseAddr("198.51.100.7")
)

// faults lets a test break a repository to see the transaction roll back.
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

type env struct {
	t       *testing.T
	store   *memory.Store
	faults  *faults
	clock   *testutil.FakeClock
	factory *testutil.Factory

	auth        *admin.Auth
	users       *admin.Users
	invitations *admin.Invitations
	audit       *admin.Audit
	operators   *admin.Operators
}

func newEnv(t *testing.T, opts ...memory.Option) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: memory.NewStore(opts...), clock: factory.Clock, factory: factory}
	e.faults = &faults{inner: e.store}

	web, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Admin", Origins: []string{origin}})
	must(t, err)
	e.auth, err = admin.NewAuth(admin.AuthDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, PasskeyIDs: factory.IDs, Secrets: crypto.Ticket{}})
	must(t, err)
	e.users, err = admin.NewUsers(admin.UsersDeps{UnitOfWork: e.faults, Clock: e.clock})
	must(t, err)
	e.invitations, err = admin.NewInvitations(admin.InvitationsDeps{UnitOfWork: e.faults, Clock: e.clock})
	must(t, err)
	e.audit, err = admin.NewAudit(admin.AuditDeps{UnitOfWork: e.faults, Clock: e.clock})
	must(t, err)
	e.operators, err = admin.NewOperators(admin.OperatorsDeps{
		UnitOfWork: e.faults, Clock: e.clock, OperatorIDs: factory.IDs, PasskeyIDs: factory.IDs, Secrets: crypto.Ticket{},
	})
	must(t, err)
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(fn func(ctx context.Context, s port.Stores) error) {
	e.t.Helper()
	must(e.t, e.store.Do(context.Background(), fn))
}

// operator is an enrolled operator with the key that signs them in.
type operatorFixture struct {
	op   *operator.Operator
	auth *testutil.SoftAuthenticator
}

// enrolled creates an operator through the command-line use case and registers a key through the API.
func (e *env) enrolled(email string) operatorFixture {
	e.t.Helper()
	ctx := context.Background()
	op, enrollment, err := e.operators.Create(ctx, email)
	must(e.t, err)
	key := testutil.NewSoftAuthenticator(e.t, rpID, origin)
	begin, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
	must(e.t, err)
	if begin.Outcome != admin.OutcomeOK {
		e.t.Fatalf("BeginEnroll = %+v", begin)
	}
	finish, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: begin.ChallengeID, Response: key.Register(begin.Options), ClientIP: ip})
	must(e.t, err)
	if finish.Outcome != admin.OutcomeOK {
		e.t.Fatalf("FinishEnroll = %+v", finish)
	}
	return operatorFixture{op: op, auth: key}
}

// signedIn is an operator with an open session.
type signedIn struct {
	operatorFixture
	secret string
	actor  admin.Actor
}

// login signs the operator in with their key.
func (e *env) login(f operatorFixture) admin.FinishLoginResult {
	e.t.Helper()
	ctx := context.Background()
	begin, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip})
	must(e.t, err)
	if begin.Outcome != admin.OutcomeOK {
		e.t.Fatalf("BeginLogin = %+v", begin)
	}
	res, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: begin.ChallengeID, Response: f.auth.Assert(begin.Options), ClientIP: ip})
	must(e.t, err)
	return res
}

func (e *env) signedIn(email string) signedIn {
	e.t.Helper()
	f := e.enrolled(email)
	res := e.login(f)
	if res.Outcome != admin.OutcomeOK {
		e.t.Fatalf("login = %+v", res)
	}
	auth, err := e.auth.Authenticate(context.Background(), res.SessionSecret)
	must(e.t, err)
	if auth.Outcome != admin.OutcomeOK {
		e.t.Fatalf("Authenticate = %+v", auth)
	}
	return signedIn{operatorFixture: f, secret: res.SessionSecret, actor: auth.Actor}
}

// user stores a user with the address.
func (e *env) user(email string) *identity.User {
	e.t.Helper()
	u := e.factory.User(testutil.UserSpec{Email: email})
	e.do(func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, u)
		return err
	})
	return u
}

func (e *env) auditOf(t port.AuditType) []port.AuditEvent {
	e.t.Helper()
	var out []port.AuditEvent
	e.do(func(ctx context.Context, s port.Stores) error {
		entries, err := s.AuditReads.List(ctx, port.AuditQuery{Type: t, Limit: 100})
		for _, en := range entries {
			out = append(out, en.AuditEvent)
		}
		return err
	})
	return out
}

func tightAdminQuota(t *testing.T, limit int) memory.Option {
	t.Helper()
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.AdminIP: {{Limit: limit, Per: time.Hour}}})
	must(t, err)
	return memory.WithQuota(p)
}
