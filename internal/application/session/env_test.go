package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
	"go.airlance.org/auth/internal/testutil"
)

var (
	t0      = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	policy  = session.DefaultPolicy()
	day     = 24 * time.Hour
	errBoom = errors.New("boom")
)

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

type failingTokenCreate struct{ port.RefreshTokenRepository }

func (failingTokenCreate) Create(context.Context, *token.RefreshToken) error { return errBoom }

// countingMetrics records what the use cases report.
type countingMetrics struct{ reuses int }

func (*countingMetrics) MailProcessed(authflow.QuotaClass, port.MailOutcome, time.Duration, time.Duration) {
}

func (m *countingMetrics) RefreshReuseDetected() { m.reuses++ }

type env struct {
	t         *testing.T
	store     *memory.Store
	clock     *testutil.FakeClock
	ids       *testutil.SequentialIDs
	factory   *testutil.Factory
	faults    *faults
	secrets   crypto.Refresh
	signer    port.AccessSigner
	metrics   *countingMetrics
	verify    port.AccessVerifier
	issuer    *appsession.Issuer
	refresh   *appsession.Refresh
	revoke    *appsession.RevokeSession
	revokeAll *appsession.RevokeAll
}

func newEnv(t *testing.T) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	metrics := &countingMetrics{}
	e := &env{metrics: metrics, t: t, store: memory.NewStore(), clock: factory.Clock, ids: factory.IDs, factory: factory}
	e.faults = &faults{inner: e.store}

	var err error

	e.issuer, err = appsession.NewIssuer(appsession.IssuerDeps{SessionIDs: e.ids, TokenIDs: e.ids, Secrets: e.secrets, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	keys := testutil.NewSigningKeyPEM(t)

	ring, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner(ring, e.clock, "https://auth.example.test", "example", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := jwt.NewVerifier(ring.PublicKeys(), e.clock, "https://auth.example.test", "example", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	e.signer, e.verify = signer, verifier

	e.refresh, err = appsession.NewRefresh(appsession.RefreshDeps{UnitOfWork: e.faults, Clock: e.clock, TokenIDs: e.ids, Secrets: e.secrets, Signer: e.signer, Metrics: e.metrics, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}

	e.revoke, err = appsession.NewRevokeSession(appsession.RevokeDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}

	e.revokeAll, err = appsession.NewRevokeAll(appsession.RevokeDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// login stores a user (new unless email repeats) and signs a device in.
func (e *env) login(email string) (appsession.Issued, *identity.User) {
	e.t.Helper()
	user := e.factory.User(testutil.UserSpec{Email: email})

	var issued appsession.Issued

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		u, _, err := st.Users.Ensure(ctx, user)
		if err != nil {
			return err
		}

		user = u
		issued, err = e.issuer.Issue(ctx, st, e.clock.Now(), appsession.IssueParams{
			UserID: u.ID(), Binding: testutil.BindingHash(testutil.DefaultBindingSecret),
			AMR: []string{"otp"}, AuthTime: e.clock.Now(), DeviceName: "laptop",
		})

		return err
	})
	if err != nil {
		e.t.Fatalf("login: %v", err)
	}

	return issued, user
}

// loginAgain signs another device of an existing user in.
func (e *env) loginAgain(user *identity.User) appsession.Issued {
	e.t.Helper()

	var issued appsession.Issued

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error

		issued, err = e.issuer.Issue(ctx, st, e.clock.Now(), appsession.IssueParams{
			UserID: user.ID(), Binding: testutil.BindingHash("other-device"),
			AMR: []string{"otp"}, AuthTime: e.clock.Now(), DeviceName: "phone",
		})

		return err
	})
	if err != nil {
		e.t.Fatalf("login again: %v", err)
	}

	return issued
}

func (e *env) exchange(secret string) appsession.RefreshResult {
	e.t.Helper()

	res, err := e.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: secret})
	if err != nil {
		e.t.Fatalf("refresh: %v", err)
	}

	return res
}

func (e *env) session(id session.ID) *session.Session {
	e.t.Helper()

	s, ok := e.store.Session(id)
	if !ok {
		e.t.Fatalf("session %s is not stored", id)
	}

	return s
}

func (e *env) tokens(id session.ID) []*token.RefreshToken { return e.store.TokensOfSession(id) }

func (e *env) allRevoked(id session.ID) bool {
	for _, tok := range e.tokens(id) {
		if tok.RevokedAt().IsZero() {
			return false
		}
	}

	return true
}
