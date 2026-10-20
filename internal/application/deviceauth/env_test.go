package deviceauth_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/deviceauth"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

var (
	t0      = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
	ip      = netip.MustParseAddr("198.51.100.7")
)

// faults lets a test break a part of the signing to see the transaction roll back.
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

type switchSigner struct {
	fail  bool
	inner port.AccessSigner
}

func (s *switchSigner) SignAccess(c port.AccessClaims) (port.AccessToken, error) {
	if s.fail {
		return port.AccessToken{}, errBoom
	}

	return s.inner.SignAccess(c)
}

type env struct {
	t       *testing.T
	store   *memory.Store
	faults  *faults
	clock   *testutil.FakeClock
	factory *testutil.Factory
	signer  *switchSigner
	verify  port.AccessVerifier
	tickets crypto.Ticket
	binding crypto.Binding

	start    *deviceauth.Start
	status   *deviceauth.Status
	approver *deviceauth.Approver
	redeem   *deviceauth.Redeem
}

func newEnv(t *testing.T, opts ...memory.Option) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: memory.NewStore(opts...), clock: factory.Clock, factory: factory}
	e.faults = &faults{inner: e.store}

	keys := testutil.NewSigningKeyPEM(t)
	ring, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	must(t, err)
	inner, err := jwt.NewSigner(ring, e.clock, "https://auth.example.test", "example", 5*time.Minute)
	must(t, err)

	e.signer = &switchSigner{inner: inner}
	e.verify, err = jwt.NewVerifier(ring.PublicKeys(), e.clock, "https://auth.example.test", "example", 30*time.Second)
	must(t, err)
	issuer, err := appsession.NewIssuer(appsession.IssuerDeps{
		SessionIDs: factory.IDs, TokenIDs: factory.IDs, Secrets: crypto.Refresh{}, Policy: session.DefaultPolicy(),
	})
	must(t, err)

	e.start, err = deviceauth.NewStart(deviceauth.StartDeps{UnitOfWork: e.faults, Clock: e.clock, Secrets: crypto.Device{}, Tickets: e.tickets, Bindings: e.binding})
	must(t, err)
	e.status, err = deviceauth.NewStatus(deviceauth.StatusDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets, Bindings: e.binding})
	must(t, err)
	e.approver, err = deviceauth.NewApprover(deviceauth.ApproveDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets})
	must(t, err)
	e.redeem, err = deviceauth.NewRedeem(deviceauth.RedeemDeps{
		UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets, Bindings: e.binding,
		SessionDeps: passkey.SessionDeps{Sessions: issuer, Signer: e.signer},
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
	// faults.inner is the memory store unless a test put PostgreSQL there.
	must(e.t, e.faults.inner.Do(context.Background(), fn))
}

// phone is a signed-in user: the approving device.
type phone struct {
	user  *identity.User
	actor appsession.Actor
}

// noPhone is a caller with no session.
var noPhone phone

func (e *env) phone() phone {
	e.t.Helper()
	u := e.factory.User(testutil.UserSpec{})
	sess := e.factory.Session(testutil.SessionSpec{User: u})
	e.do(func(ctx context.Context, s port.Stores) error {
		if _, _, err := s.Users.Ensure(ctx, u); err != nil {
			return err
		}

		return s.Sessions.Create(ctx, sess)
	})

	return phone{user: u, actor: appsession.Actor{UserID: u.ID(), SessionID: sess.ID()}}
}

// stepUp stores a step-up ticket of the phone's session for the operation and returns its secret.
func (e *env) stepUp(p phone, op dpasskey.Operation) string {
	e.t.Helper()
	secret, hash, err := e.tickets.NewTicketSecret()
	must(e.t, err)
	id, err := e.factory.IDs.NewPasskeyID()
	must(e.t, err)
	ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
		ID: id, Kind: dpasskey.TicketStepUp, UserID: p.user.ID(), SessionID: p.actor.SessionID, Operation: op, SecretHash: hash, Now: e.clock.Now(),
	})
	must(e.t, err)
	e.do(func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, ticket) })

	return secret
}

// laptop is the new device: what it holds after it started a request.
type laptop struct {
	res deviceauth.StartResult
	// binding is the client binding the laptop keeps.
	binding string
}

func (e *env) newLaptop(name string) laptop {
	e.t.Helper()
	res, err := e.start.Execute(context.Background(), deviceauth.StartCommand{DeviceName: name, ClientIP: ip})
	must(e.t, err)

	if res.Outcome != deviceauth.OutcomeOK || res.NewBindingSecret == "" {
		e.t.Fatalf("Start = %+v", res)
	}

	return laptop{res: res, binding: res.NewBindingSecret}
}

// again is the same client asking once more: it keeps the binding it was given.
func (e *env) again(l laptop, name string) laptop {
	e.t.Helper()
	res, err := e.start.Execute(context.Background(), deviceauth.StartCommand{DeviceName: name, BindingSecret: l.binding, ClientIP: ip})
	must(e.t, err)

	if res.Outcome != deviceauth.OutcomeOK || res.NewBindingSecret != "" {
		e.t.Fatalf("Start = %+v", res)
	}

	return laptop{res: res, binding: l.binding}
}

func (l laptop) id() string {
	return l.res.RequestID.String()
}

func (e *env) approve(p phone, l laptop, code, stepUp string) deviceauth.Result {
	e.t.Helper()
	res, err := e.approver.Approve(context.Background(), deviceauth.ApproveCommand{Actor: p.actor, RequestID: l.id(), PairingCode: code, StepUpSecret: stepUp})
	must(e.t, err)

	return res
}

func (e *env) redeemFor(l laptop) deviceauth.RedeemResult {
	e.t.Helper()
	res, err := e.redeem.Execute(context.Background(), deviceauth.RedeemCommand{RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: l.binding, ClientIP: ip})
	must(e.t, err)

	return res
}

func (e *env) stateOf(l laptop) deviceauth.State {
	e.t.Helper()
	res, err := e.status.Execute(context.Background(), deviceauth.StatusCommand{RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: l.binding})
	must(e.t, err)

	if res.Outcome != deviceauth.OutcomeOK {
		e.t.Fatalf("Status = %+v", res)
	}

	return res.State
}

func (e *env) auditOf(t port.AuditType) []port.AuditEvent {
	var out []port.AuditEvent

	for _, ev := range e.store.AuditEvents() {
		if ev.Type == t {
			out = append(out, ev)
		}
	}

	return out
}
