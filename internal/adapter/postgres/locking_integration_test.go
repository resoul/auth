//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/oidc"
	dsession "go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

// These tests hold two transactions at known points to check the order in which row locks are taken. The order
// is what keeps a sign-in from waiting for a recovery that waits for the sign-in, and a revocation from missing a
// session that is being opened. A test that runs two requests and hopes they overlap proves nothing.

// quiet is how long a test waits to see that a transaction is still blocked.
const quiet = 400 * time.Millisecond

func inTx(store port.UnitOfWork, fn func(ctx context.Context, st port.Stores) error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- store.Do(context.Background(), fn) }()

	return done
}

// gate is a channel that can be opened more than once, and is opened when the test ends: a test that fails
// while a transaction is held must not leave it holding, or closing the pool waits for it forever.
func gate(t *testing.T) (wait <-chan struct{}, open func()) {
	t.Helper()

	ch := make(chan struct{})

	var once sync.Once

	open = func() { once.Do(func() { close(ch) }) }
	t.Cleanup(open)

	return ch, open
}

func within(t *testing.T, name string, done <-chan error, d time.Duration) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", name, d)
		return nil
	}
}

func TestLookingUpAKeyAndReplacingKeysQueueOnTheUser(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user := f.User(testutil.UserSpec{})
	key := f.Credential(testutil.CredentialSpec{User: user})

	seed := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		return st.Credentials.Create(ctx, key)
	})
	if seed != nil {
		t.Fatal(seed)
	}

	// A sign-in: locks the key, then wants the user. A recovery: wants the user, then every key. Whichever
	// comes first must finish before the other proceeds; neither may wait for the other until the database aborts one.
	holding := make(chan struct{})
	release, open := gate(t)
	signIn := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Credentials.GetForUpdate(ctx, key.CredentialID()); err != nil {
			return err
		}

		close(holding)
		<-release

		_, err := st.Users.GetForShare(ctx, user.ID())

		return err
	})

	<-holding

	recovery := inTx(store, func(ctx context.Context, st port.Stores) error {
		_, err := st.Credentials.DeleteAllForUser(ctx, user.ID())
		return err
	})

	time.Sleep(quiet) // the recovery is now at its first lock
	open()

	if err := within(t, "the sign-in", signIn, 5*time.Second); err != nil {
		t.Errorf("sign-in: %v", err)
	}

	if err := within(t, "the recovery", recovery, 5*time.Second); err != nil {
		t.Errorf("recovery: %v", err)
	}
}

func TestRevokingEverythingWaitsForASessionBeingOpened(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user := f.User(testutil.UserSpec{})

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, _, err := st.Users.Ensure(ctx, user)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	opened := f.Session(testutil.SessionSpec{User: user})

	// An issuer reads the user the way every sign-in does (a shared lock) and opens a session.
	holding := make(chan struct{})
	release, open := gate(t)
	issuer := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.GetForShare(ctx, user.ID()); err != nil {
			return err
		}

		close(holding)
		<-release

		return st.Sessions.Create(ctx, opened)
	})

	<-holding

	revoker := inTx(store, func(ctx context.Context, st port.Stores) error {
		return st.Sessions.RevokeAllForUser(ctx, user.ID(), time.Now())
	})

	select {
	case err := <-revoker:
		t.Fatalf("the revocation finished (%v) while a session was still being opened: it would miss it", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the issuer", issuer, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := within(t, "the revocation", revoker, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	active := -1

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		list, err := st.Sessions.ListActive(ctx, user.ID(), time.Now(), 10)
		active = len(list)

		return err
	}); err != nil {
		t.Fatal(err)
	}

	if active != 0 {
		t.Errorf("%d sessions are active after the revocation, want none: it ran before the new session was visible", active)
	}
}

// oidcRows seeds a user with a client, a sign-in, a grant and an unexchanged code, and returns what a test needs.
func oidcRows(t *testing.T, store port.UnitOfWork, f *testutil.Factory) (user identity.UserID, code oidc.SecretHash, grantID string) {
	t.Helper()

	u := f.User(testutil.UserSpec{})
	now := time.Now().UTC()

	client, err := oidc.NewClient(oidc.NewClientParams{ID: "lock-app", Name: "x", RedirectURIs: []string{"https://app.example.test/cb"}, Trusted: true}, now)
	if err != nil {
		t.Fatal(err)
	}

	opID, _ := f.IDs.NewOIDCID()
	grantID, _ = f.IDs.NewOIDCID()

	var secret, codeHash oidc.SecretHash

	secret[0], codeHash[0] = 1, 2
	op := &oidc.OPSession{ID: opID, UserID: u.ID(), SecretHash: secret, AuthTime: now, AMR: []string{"passkey"}, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	grant := &oidc.Grant{ID: grantID, ClientID: client.ID, UserID: u.ID(), OPSessionID: opID, Scopes: []string{"openid"}, PolicyVersion: 1, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	c := &oidc.AuthorizationCode{
		Hash: codeHash, GrantID: grantID, RedirectURI: "https://app.example.test/cb", CodeChallenge: oidc.Challenge("v" + strings.Repeat("a", 42)),
		Nonce: "n", Scopes: []string{"openid"}, AuthTime: now, AMR: []string{"passkey"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}

	var clientSecret oidc.SecretHash

	clientSecret[0] = 3
	secretID, _ := f.IDs.NewOIDCID()

	err = store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, u); err != nil {
			return err
		}

		for _, step := range []func() error{
			func() error { return st.OIDCClients.Create(ctx, client, secretID, clientSecret) },
			func() error { return st.OPSessions.Create(ctx, op) },
			func() error { return st.OIDCGrants.Create(ctx, grant) },
			func() error { return st.OIDCCodes.Create(ctx, c) },
		} {
			if err := step(); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return u.ID(), codeHash, grantID
}

func TestRevokingEverythingWaitsForAnExchangeInProgress(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user, code, grantID := oidcRows(t, store, f)

	// An exchange takes the user (shared) and the grant, then goes on to issue tokens.
	holding := make(chan struct{})
	release, open := gate(t)
	exchange := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.OIDCCodes.GetByHashForUpdate(ctx, code); err != nil {
			return err
		}

		close(holding)
		<-release
		// Issuing tokens reads the user next. If the exchange held the grant but not the user, the revocation would hold
		// the user and wait for the grant while this waited for the user: the database would abort one of them.
		_, err := st.Users.GetForShare(ctx, user)

		return err
	})

	<-holding

	revoker := inTx(store, func(ctx context.Context, st port.Stores) error {
		return st.OPSessions.RevokeAllForUser(ctx, user, time.Now())
	})
	select {
	case err := <-revoker:
		t.Fatalf("the revocation finished (%v) while an exchange held the grant: it would miss the tokens being issued", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the exchange", exchange, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := within(t, "the revocation", revoker, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		g, err := st.OIDCGrants.Get(ctx, grantID)
		if err != nil {
			return err
		}

		if g.RevokedAt.IsZero() {
			t.Error("the grant is not revoked after revoke-all")
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTwoExchangesOfOneCodeQueueOnTheGrant(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	_, code, _ := oidcRows(t, store, f)

	holding := make(chan struct{})
	release, open := gate(t)
	first := inTx(store, func(ctx context.Context, st port.Stores) error {
		c, _, err := st.OIDCCodes.GetByHashForUpdate(ctx, code)
		if err != nil {
			return err
		}

		close(holding)
		<-release

		c.ConsumedAt = time.Now().UTC()

		return st.OIDCCodes.Consume(ctx, c)
	})

	<-holding

	var seenConsumed bool

	second := inTx(store, func(ctx context.Context, st port.Stores) error {
		c, _, err := st.OIDCCodes.GetByHashForUpdate(ctx, code)
		if err != nil {
			return err
		}

		seenConsumed = !c.ConsumedAt.IsZero()

		return nil
	})
	select {
	case err := <-second:
		t.Fatalf("the second exchange read the code (%v) while the first held it", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the first", first, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := within(t, "the second", second, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if !seenConsumed {
		t.Error("the second exchange did not see the code consumed by the first")
	}
}

func TestRevokingEverythingWaitsForAGrantBeingOpened(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user, _, _ := oidcRows(t, store, f)
	now := time.Now().UTC()

	// A sign-in being completed: it reads the user the way every issuer does (shared), then opens a new OP session and
	// a grant that did not exist when a revocation started.
	opID, _ := f.IDs.NewOIDCID()
	grantID, _ := f.IDs.NewOIDCID()

	var secret oidc.SecretHash

	secret[0] = 9
	holding := make(chan struct{})
	release, open := gate(t)
	issuer := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.GetForShare(ctx, user); err != nil {
			return err
		}

		close(holding)
		<-release

		if err := st.OPSessions.Create(ctx, &oidc.OPSession{ID: opID, UserID: user, SecretHash: secret, AuthTime: now, AMR: []string{"passkey"}, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			return err
		}

		return st.OIDCGrants.Create(ctx, &oidc.Grant{ID: grantID, ClientID: "lock-app", UserID: user, OPSessionID: opID, Scopes: []string{"openid"}, PolicyVersion: 1, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)})
	})

	<-holding

	revoker := inTx(store, func(ctx context.Context, st port.Stores) error {
		return st.OPSessions.RevokeAllForUser(ctx, user, time.Now())
	})
	select {
	case err := <-revoker:
		t.Fatalf("the revocation finished (%v) while a grant was being opened: it would miss it", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the issuer", issuer, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := within(t, "the revocation", revoker, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		g, err := st.OIDCGrants.Get(ctx, grantID)
		if err != nil {
			return err
		}

		op, err := st.OPSessions.Get(ctx, opID)
		if err != nil {
			return err
		}

		if g.RevokedAt.IsZero() || op.RevokedAt.IsZero() {
			t.Errorf("the sign-in opened during the revocation survives it (grant revoked %v, session revoked %v)", !g.RevokedAt.IsZero(), !op.RevokedAt.IsZero())
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEndingASignInWaitsForAGrantBeingOpenedOnIt(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user, _, firstGrant := oidcRows(t, store, f)
	now := time.Now().UTC()

	var (
		opID         string
		secondClient *oidc.Client
	)

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		g, err := st.OIDCGrants.Get(ctx, firstGrant)
		if err != nil {
			return err
		}

		opID = g.OPSessionID

		secondClient, err = oidc.NewClient(oidc.NewClientParams{ID: "second-app", Name: "x", RedirectURIs: []string{"https://two.example.test/cb"}, Trusted: true, BackchannelLogoutURI: "https://two.example.test/bc"}, now)
		if err != nil {
			return err
		}

		var secret oidc.SecretHash

		secret[0] = 77
		secretID, _ := f.IDs.NewOIDCID()

		return st.OIDCClients.Create(ctx, secondClient, secretID, secret)
	}); err != nil {
		t.Fatal(err)
	}

	// A second application's sign-in being completed on the same shared sign-in: the issuer holds the user (shared) and
	// opens a grant that did not exist when the logout began.
	grantID, _ := f.IDs.NewOIDCID()
	holding := make(chan struct{})
	release, open := gate(t)
	issuer := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.GetForShare(ctx, user); err != nil {
			return err
		}

		close(holding)
		<-release

		return st.OIDCGrants.Create(ctx, &oidc.Grant{ID: grantID, ClientID: secondClient.ID, UserID: user, OPSessionID: opID, Scopes: []string{"openid"}, PolicyVersion: 1, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)})
	})

	<-holding

	ender := inTx(store, func(ctx context.Context, st port.Stores) error { return st.OPSessions.End(ctx, opID, time.Now()) })
	select {
	case err := <-ender:
		t.Fatalf("the logout finished (%v) while a grant was being opened on the sign-in: it would miss it", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the issuer", issuer, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := within(t, "the logout", ender, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		g, err := st.OIDCGrants.Get(ctx, grantID)
		if err != nil {
			return err
		}

		if g.RevokedAt.IsZero() {
			t.Error("the grant opened while the sign-in was ending survived the logout")
		}
		// And its application is told: the notice was queued for it, not only for grants that were visible at the start.
		n, err := st.OIDCLogout.Claim(ctx, time.Now().Add(time.Second), time.Now().Add(time.Hour))
		if err != nil || n.ClientID != "second-app" || n.SessionID != opID {
			t.Errorf("notice = %+v, %v; want one for second-app on %s", n, err, opID)
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestATicketUseAndARevocationQueueOnTheUser(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user := f.User(testutil.UserSpec{})
	ticket := f.Ticket(testutil.TicketSpec{User: user, Secret: "held"})

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		return st.Tickets.Create(ctx, ticket)
	}); err != nil {
		t.Fatal(err)
	}

	// A sign-in with the ticket: locks the ticket, then wants the user. A recovery: holds the user, then spends every
	// ticket. Loading the ticket takes the user first, so the recovery waits at the user and never holds what the
	// sign-in waits for.
	holding := make(chan struct{})
	release, open := gate(t)
	signIn := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Tickets.GetByHashForUpdate(ctx, testutil.SecretHash("held")); err != nil {
			return err
		}

		close(holding)
		<-release

		_, err := st.Users.GetForShare(ctx, user.ID())

		return err
	})

	<-holding

	recovery := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.GetForUpdate(ctx, user.ID()); err != nil {
			return err
		}

		return st.Tickets.RevokeAllForUser(ctx, user.ID(), ticket.SessionID(), time.Now())
	})

	time.Sleep(quiet) // the recovery is now waiting for the user

	open()

	if err := within(t, "the sign-in", signIn, 5*time.Second); err != nil {
		t.Errorf("the sign-in = %v", err)
	}

	if err := within(t, "the recovery", recovery, 5*time.Second); err != nil {
		t.Errorf("the recovery = %v", err)
	}
}

// pausingUnit stops a transaction right after the first row it locks, a user or a session, whichever comes first. It
// holds a use case at the point where its lock order matters without knowing which order the use case takes.
type pausingUnit struct {
	port.UnitOfWork
	pause func()
}

func (u pausingUnit) Do(ctx context.Context, fn func(ctx context.Context, st port.Stores) error) error {
	return u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		st.Users = pausingUsers{UserRepository: st.Users, pause: u.pause}
		st.Sessions = pausingSessions{SessionRepository: st.Sessions, pause: u.pause}

		return fn(ctx, st)
	})
}

type pausingUsers struct {
	port.UserRepository
	pause func()
}

func (r pausingUsers) GetForUpdate(ctx context.Context, id identity.UserID) (*identity.User, error) {
	u, err := r.UserRepository.GetForUpdate(ctx, id)
	r.pause()

	return u, err
}

type pausingSessions struct {
	port.SessionRepository
	pause func()
}

func (r pausingSessions) GetForUpdate(ctx context.Context, id dsession.ID) (*dsession.Session, error) {
	s, err := r.SessionRepository.GetForUpdate(ctx, id)
	r.pause()

	return s, err
}

func TestTwoSignOutsEverywhereQueueOnTheUser(t *testing.T) {
	store := testutil.PostgresStore(t)
	f := testutil.NewFactory(t, time.Now())
	user := f.User(testutil.UserSpec{})
	laptop := f.Session(testutil.SessionSpec{User: user})
	phone := f.Session(testutil.SessionSpec{User: user, BindingSecret: "other-device"})

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		if err := st.Sessions.Create(ctx, laptop); err != nil {
			return err
		}

		return st.Sessions.Create(ctx, phone)
	}); err != nil {
		t.Fatal(err)
	}

	signOut := func(uow port.UnitOfWork, sess *dsession.Session) <-chan error {
		done := make(chan error, 1)

		go func() {
			u, err := appsession.NewSignOut(appsession.RevokeDeps{UnitOfWork: uow, Clock: testutil.NewFakeClock(time.Now())})
			if err != nil {
				done <- err
				return
			}

			res, err := u.Execute(context.Background(), appsession.SignOutCommand{
				Actor: appsession.Actor{UserID: user.ID(), SessionID: sess.ID()}, Scope: appsession.ScopeAll,
			})
			if err == nil && res.Outcome != appsession.OutcomeOK {
				err = fmt.Errorf("outcome %v", res.Outcome)
			}

			done <- err
		}()

		return done
	}

	// The phone signs out everywhere and stops after its first lock. If that lock were its own session, the laptop
	// would take its own session and the user, then wait for the phone's session while the phone waited for the user:
	// the database would abort one of them (SQLSTATE 40P01).
	holding := make(chan struct{})
	release, open := gate(t)

	var once sync.Once

	phoneOut := signOut(pausingUnit{UnitOfWork: store, pause: func() {
		once.Do(func() {
			close(holding)
			<-release
		})
	}}, phone)

	<-holding

	laptopOut := signOut(store, laptop)
	select {
	case err := <-laptopOut:
		t.Fatalf("the laptop signed out everywhere (%v) while the phone was doing the same", err)
	case <-time.After(quiet):
	}

	open()

	if err := within(t, "the phone's sign-out", phoneOut, 5*time.Second); err != nil {
		t.Errorf("the phone's sign-out = %v", err)
	}

	if err := within(t, "the laptop's sign-out", laptopOut, 5*time.Second); err != nil {
		t.Errorf("the laptop's sign-out = %v", err)
	}

	active := -1

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		list, err := st.Sessions.ListActive(ctx, user.ID(), time.Now(), 10)
		active = len(list)

		return err
	}); err != nil {
		t.Fatal(err)
	}

	if active != 0 {
		t.Errorf("%d sessions are active after two sign-outs everywhere, want none", active)
	}
}
