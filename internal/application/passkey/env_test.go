package passkey_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	apasskey "go.airlance.org/auth/internal/adapter/passkey"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

const (
	rpID   = "example.test"
	origin = "https://example.test"
)

var (
	t0      = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
)

// faults lets a test break one repository or the signer to see the transaction roll back.
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

type failingSigner struct{}

func (failingSigner) SignAccess(port.AccessClaims) (port.AccessToken, error) {
	return port.AccessToken{}, errBoom
}

type env struct {
	t       *testing.T
	store   *memory.Store
	faults  *faults
	clock   *testutil.FakeClock
	factory *testutil.Factory
	tickets crypto.Ticket
	binding crypto.Binding
	verify  port.AccessVerifier

	beginEnroll    *passkey.BeginEnroll
	finishEnroll   *passkey.FinishEnroll
	beginLogin     *passkey.BeginLogin
	finishLogin    *passkey.FinishLogin
	redeemRecovery *passkey.RedeemRecovery

	beginStepUp  *passkey.BeginStepUp
	finishStepUp *passkey.FinishStepUp
	list         *passkey.ListCredentials
	rename       *passkey.RenameCredential
	beginAdd     *passkey.BeginAddPasskey
	finishAdd    *passkey.FinishAddPasskey
	deleteKey    *passkey.DeleteCredential
	regenerate   *passkey.RegenerateRecoveryCodes
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil, nil)
}

// newEnvWith lets a test replace the WebAuthn service and wrap the real access signer.
func newEnvWith(t *testing.T, web port.WebAuthn, wrapSigner func(port.AccessSigner) port.AccessSigner, opts ...memory.Option) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: memory.NewStore(opts...), clock: factory.Clock, factory: factory}
	e.faults = &faults{inner: e.store}

	if web == nil {
		service, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}})
		if err != nil {
			t.Fatal(err)
		}

		web = service
	}

	keys := testutil.NewSigningKeyPEM(t)

	ring, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	if err != nil {
		t.Fatal(err)
	}

	var signer port.AccessSigner

	signer, err = jwt.NewSigner(ring, e.clock, "https://auth.example.test", "example", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if wrapSigner != nil {
		signer = wrapSigner(signer)
	}

	e.verify, err = jwt.NewVerifier(ring.PublicKeys(), e.clock, "https://auth.example.test", "example", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := appsession.NewIssuer(appsession.IssuerDeps{
		SessionIDs: factory.IDs, TokenIDs: factory.IDs, Secrets: crypto.Refresh{}, Policy: session.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}

	sessions := passkey.SessionDeps{Sessions: issuer, Signer: signer}

	e.beginEnroll, err = passkey.NewBeginEnroll(passkey.BeginEnrollDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: e.binding, Tickets: e.tickets, PasskeyIDs: factory.IDs,
	})
	must(t, err)
	e.finishEnroll, err = passkey.NewFinishEnroll(passkey.FinishEnrollDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: e.binding, Tickets: e.tickets,
		PasskeyIDs: factory.IDs, Recovery: crypto.Recovery{}, SessionDeps: sessions,
	})
	must(t, err)
	e.beginLogin, err = passkey.NewBeginLogin(passkey.BeginLoginDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, PasskeyIDs: factory.IDs,
	})
	must(t, err)
	e.finishLogin, err = passkey.NewFinishLogin(passkey.FinishLoginDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: e.binding, Tickets: e.tickets, SessionDeps: sessions,
	})
	must(t, err)
	e.redeemRecovery, err = passkey.NewRedeemRecovery(passkey.RedeemRecoveryDeps{
		UnitOfWork: e.faults, Clock: e.clock, Bindings: e.binding, Tickets: e.tickets, Recovery: crypto.Recovery{}, PasskeyIDs: factory.IDs,
	})
	must(t, err)

	manage := passkey.ManageDeps{UnitOfWork: e.faults, Clock: e.clock}
	e.beginStepUp, err = passkey.NewBeginStepUp(passkey.BeginStepUpDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, PasskeyIDs: factory.IDs})
	must(t, err)
	e.finishStepUp, err = passkey.NewFinishStepUp(passkey.FinishStepUpDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: e.tickets, PasskeyIDs: factory.IDs})
	must(t, err)
	e.list, err = passkey.NewListCredentials(manage)
	must(t, err)
	e.rename, err = passkey.NewRenameCredential(manage)
	must(t, err)
	e.beginAdd, err = passkey.NewBeginAddPasskey(passkey.BeginAddPasskeyDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: e.tickets, PasskeyIDs: factory.IDs})
	must(t, err)
	e.finishAdd, err = passkey.NewFinishAddPasskey(passkey.FinishAddPasskeyDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: e.tickets, PasskeyIDs: factory.IDs})
	must(t, err)
	e.deleteKey, err = passkey.NewDeleteCredential(passkey.DeleteCredentialDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets})
	must(t, err)
	e.regenerate, err = passkey.NewRegenerateRecoveryCodes(passkey.RegenerateRecoveryCodesDeps{
		UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets, Recovery: crypto.Recovery{}, PasskeyIDs: factory.IDs,
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

// bindingSecret is the client binding of the tests: a real secret and its hash.
type bindingSecret struct {
	secret string
	hash   identity.BindingHash
}

func (e *env) newBinding() bindingSecret {
	e.t.Helper()
	secret, hash, err := e.binding.NewBinding()
	must(e.t, err)

	return bindingSecret{secret: secret, hash: hash}
}

func (e *env) do(fn func(ctx context.Context, st port.Stores) error) {
	e.t.Helper()
	// faults.inner is the memory store unless a test put PostgreSQL there.
	must(e.t, e.faults.inner.Do(context.Background(), fn))
}

// newUser stores a user.
func (e *env) newUser() *identity.User {
	e.t.Helper()
	user := e.factory.User(testutil.UserSpec{})
	e.do(func(ctx context.Context, st port.Stores) error {
		_, _, err := st.Users.Ensure(ctx, user)
		return err
	})

	return user
}

// ticketFor stores a ticket of the kind for the user and returns its secret.
func (e *env) ticketFor(user *identity.User, kind dpasskey.TicketKind, b bindingSecret) string {
	e.t.Helper()
	secret, hash, err := e.tickets.NewTicketSecret()
	must(e.t, err)
	id, err := e.factory.IDs.NewPasskeyID()
	must(e.t, err)
	ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{
		ID: id, Kind: kind, UserID: user.ID(), Binding: b.hash, SecretHash: hash, Now: e.clock.Now(),
	})
	must(e.t, err)
	e.do(func(ctx context.Context, st port.Stores) error { return st.Tickets.Create(ctx, ticket) })

	return secret
}

// enrolled is a user with one registered passkey, for tests of login and recovery.
type enrolled struct {
	user  *identity.User
	auth  *testutil.SoftAuthenticator
	codes []string
	// actor is the session the enrollment opened.
	actor appsession.Actor
}

// enroll registers a first passkey through the use cases and returns what the user holds.
func (e *env) enroll() enrolled {
	e.t.Helper()
	user := e.newUser()
	b := e.newBinding()
	auth := testutil.NewSoftAuthenticator(e.t, rpID, origin)

	got := e.enrollWith(user, auth, e.ticketFor(user, dpasskey.TicketEnroll, b), b)
	if got.Outcome != passkey.OutcomeOK {
		e.t.Fatalf("enrollment refused: %+v", got)
	}

	return enrolled{user: user, auth: auth, codes: got.RecoveryCodes, actor: appsession.Actor{UserID: user.ID(), SessionID: got.Session.ID()}}
}

func (e *env) enrollWith(user *identity.User, auth *testutil.SoftAuthenticator, ticket string, b bindingSecret) passkey.FinishEnrollResult {
	e.t.Helper()
	begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
	must(e.t, err)

	if begun.Outcome != passkey.OutcomeOK {
		return passkey.FinishEnrollResult{Outcome: begun.Outcome, Reason: begun.Reason}
	}

	got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options),
		CredentialName: "Laptop", DeviceName: "test",
	})
	must(e.t, err)

	return got
}

// signIn runs the whole passkey sign-in.
func (e *env) signIn(auth *testutil.SoftAuthenticator, ticket string, b bindingSecret) passkey.FinishLoginResult {
	e.t.Helper()
	begun, err := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
	must(e.t, err)
	got, err := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
		ChallengeID: begun.ChallengeID, Response: auth.Assert(begun.Options), TicketSecret: ticket, BindingSecret: b.secret,
		DeviceName: "test", ClientIP: clientAddr,
	})
	must(e.t, err)

	return got
}

// clientAddr is the address every sign-in of these tests comes from.
var clientAddr = netip.MustParseAddr("203.0.113.7")

func (e *env) credentials(user *identity.User) []*dpasskey.Credential {
	e.t.Helper()

	var list []*dpasskey.Credential

	e.do(func(ctx context.Context, st port.Stores) error {
		var err error

		list, err = st.Credentials.ListByUser(ctx, user.ID())

		return err
	})

	return list
}

func (e *env) unusedCodes(user *identity.User) int {
	e.t.Helper()

	var n int

	e.do(func(ctx context.Context, st port.Stores) error {
		var err error

		n, err = st.Recovery.CountUnused(ctx, user.ID())

		return err
	})

	return n
}

// switchSigner signs like the real one until told to fail.
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

func apasskeyService() (*apasskey.Service, error) {
	return apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}})
}
