//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

const (
	hour = time.Hour
	day  = 24 * time.Hour
)

// retention seeds records of chosen ages in a real database and sweeps it.
type retention struct {
	t     *testing.T
	store *postgres.Store
	db    *sql.DB
	now   time.Time
	f     *testutil.Factory // one factory: its ids never repeat
}

func newRetention(t *testing.T) *retention {
	store, db := newStore(t)
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)

	return &retention{t: t, store: store, db: db, now: now, f: testutil.NewFactory(t, now)}
}

// factory returns the shared factory with its clock set to at: what it builds is created then.
func (r *retention) factory(at time.Time) *testutil.Factory {
	r.f.Clock.Set(at)
	return r.f
}

func (r *retention) do(fn func(ctx context.Context, s port.Stores) error) {
	r.t.Helper()

	if err := r.store.Do(context.Background(), fn); err != nil {
		r.t.Fatal(err)
	}
}

// flowExpiredAgo stores a flow whose expires_at lies ago in the past, with one queued mail.
func (r *retention) flowExpiredAgo(ago time.Duration) authflow.FlowID {
	r.t.Helper()
	created := r.now.Add(-ago).Add(-authflow.DefaultPolicy().TTL)
	flow := r.factory(created).Flow(testutil.FlowSpec{})
	r.do(func(ctx context.Context, s port.Stores) error {
		if err := s.Flows.Create(ctx, flow); err != nil {
			return err
		}

		return s.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: created})
	})

	return flow.ID()
}

func (r *retention) user(at time.Time) *identity.User {
	r.t.Helper()
	user := r.factory(at).User(testutil.UserSpec{})
	r.do(func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, user)
		return err
	})

	return user
}

// recognizedEndedAgo registers a record that expired (or, with revoke, was revoked) ago in the past.
func (r *retention) recognizedEndedAgo(ago time.Duration, revoke bool) identity.RecognizedClientID {
	r.t.Helper()

	verified := r.now
	if !revoke {
		verified = r.now.Add(-ago).Add(-identity.RecognitionTTL)
	}

	user := r.user(verified)
	rc := r.factory(verified).RecognizedClient(testutil.RecognizedSpec{User: user})
	r.do(func(ctx context.Context, s port.Stores) error {
		if _, err := s.Recognized.Register(ctx, rc); err != nil {
			return err
		}

		if revoke {
			return s.Recognized.Revoke(ctx, user.ID(), rc.Record().Binding, r.now.Add(-ago))
		}

		return nil
	})

	return rc.ID()
}

type seededSession struct {
	id    session.ID
	user  *identity.User
	token string
}

// sessionEndedAgo stores a session whose idle limit passed ago in the past (revoke false) or
// that was revoked ago in the past (revoke true), with a refresh token.
func (r *retention) sessionEndedAgo(ago time.Duration, revoke bool) seededSession {
	r.t.Helper()

	created := r.now.Add(-ago).Add(-session.DefaultPolicy().IdleTTL)
	if revoke {
		created = r.now.Add(-ago).Add(-hour)
	}

	f := r.factory(created)
	user := r.user(created)
	sess := f.Session(testutil.SessionSpec{User: user})
	root, _ := f.RefreshToken(testutil.RefreshSpec{Session: sess})

	r.do(func(ctx context.Context, s port.Stores) error {
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}

		if err := s.Tokens.Create(ctx, root); err != nil {
			return err
		}

		if err := s.Audit.Record(ctx, port.AuditEvent{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: user.ID(), SessionID: sess.ID(), At: r.now.Add(-hour)}); err != nil {
			return err
		}

		if revoke {
			sess.Revoke(r.now.Add(-ago))
			return s.Sessions.Save(ctx, sess)
		}

		return nil
	})

	return seededSession{id: sess.ID(), user: user, token: root.ID().String()}
}

func (r *retention) auditAgo(ago time.Duration) {
	r.t.Helper()
	r.do(func(ctx context.Context, s port.Stores) error {
		return s.Audit.Record(ctx, port.AuditEvent{Type: port.AuditRefreshReuse, Result: port.AuditDenied, At: r.now.Add(-ago)})
	})
}

func (r *retention) exists(table, id string) bool {
	r.t.Helper()

	var n int
	if err := r.db.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s WHERE id = $1`, table), id).Scan(&n); err != nil {
		r.t.Fatal(err)
	}

	return n == 1
}

func (r *retention) rows(table string) int { return count(r.t, r.db, table) }

func (r *retention) sweep(p postgres.CleanupPolicy) postgres.CleanupResult {
	r.t.Helper()

	res, err := r.store.Cleanup(context.Background(), r.now, p)
	if err != nil {
		r.t.Fatal(err)
	}

	return res
}

// Verify the retention rules row by row.
func TestCleanupDeletesOnlyWhatRetentionNoLongerKeeps(t *testing.T) {
	r := newRetention(t)

	flows := map[string]struct {
		id   authflow.FlowID
		gone bool
	}{}
	add := func(name string, id authflow.FlowID, gone bool) {
		flows[name] = struct {
			id   authflow.FlowID
			gone bool
		}{id, gone}
	}
	add("expired 25h ago", r.flowExpiredAgo(25*hour), true)
	add("expired 23h ago", r.flowExpiredAgo(23*hour), false)
	add("still open", r.flowExpiredAgo(-5*time.Minute), false)

	leased := r.flowExpiredAgo(30 * hour)
	if _, err := r.db.Exec(`UPDATE outbox SET lease_until = $1 WHERE flow_id = $2`, r.now.Add(time.Minute), leased.String()); err != nil {
		t.Fatal(err)
	}

	add("expired 30h ago with a live lease", leased, false)

	rec := map[string]struct {
		id   identity.RecognizedClientID
		gone bool
	}{
		"expired 25h ago": {r.recognizedEndedAgo(25*hour, false), true},
		"expired 23h ago": {r.recognizedEndedAgo(23*hour, false), false},
		"revoked 25h ago": {r.recognizedEndedAgo(25*hour, true), true},
		"revoked 23h ago": {r.recognizedEndedAgo(23*hour, true), false},
		"active":          {r.recognizedEndedAgo(-30*day, false), false},
	}

	ended8 := r.sessionEndedAgo(8*day, false)
	revoked8 := r.sessionEndedAgo(8*day, true)
	ended6 := r.sessionEndedAgo(6*day, false)
	revoked6 := r.sessionEndedAgo(6*day, true)
	active := r.sessionEndedAgo(-10*day, false)

	r.auditAgo(91 * day)
	r.auditAgo(89 * day)

	res := r.sweep(postgres.DefaultCleanupPolicy())

	for name, f := range flows {
		if got := r.exists("auth_flows", f.id.String()); got == f.gone {
			t.Errorf("flow %s: exists = %v, want %v", name, got, !f.gone)
		}
	}

	if res.Flows != 1 {
		t.Errorf("flows deleted = %d, want 1", res.Flows)
	}

	var mails int
	if err := r.db.QueryRow(`SELECT count(*) FROM outbox`).Scan(&mails); err != nil || mails != 3 {
		t.Errorf("%d mails left (%v), want the 3 of the kept flows: the others went by cascade", mails, err)
	}

	for name, c := range rec {
		if got := r.exists("recognized_clients", c.id.String()); got == c.gone {
			t.Errorf("recognized client %s: exists = %v, want %v", name, got, !c.gone)
		}
	}

	for name, c := range map[string]struct {
		s    seededSession
		gone bool
	}{
		"ended 8 days ago": {ended8, true}, "revoked 8 days ago": {revoked8, true},
		"ended 6 days ago": {ended6, false}, "revoked 6 days ago": {revoked6, false}, "active": {active, false},
	} {
		if got := r.exists("sessions", c.s.id.String()); got == c.gone {
			t.Errorf("session %s: exists = %v, want %v", name, got, !c.gone)
		}

		if got := r.exists("refresh_tokens", c.s.token); got == c.gone {
			t.Errorf("token of the session %s: exists = %v, want %v (it goes with its session)", name, got, !c.gone)
		}
	}

	if res.Sessions != 2 || res.RecognizedClients != 2 || res.AuditEvents != 1 {
		t.Errorf("result = %+v", res)
	}

	// Audit keeps the events of deleted sessions and clears only the reference.
	var withSession, orphaned int
	if err := r.db.QueryRow(`SELECT count(*) FILTER (WHERE session_id IS NOT NULL), count(*) FILTER (WHERE session_id IS NULL AND event = 'login.succeeded') FROM audit_events`).Scan(&withSession, &orphaned); err != nil {
		t.Fatal(err)
	}

	if withSession != 3 || orphaned != 2 {
		t.Errorf("audit rows with a session = %d, orphaned logins = %d; want 3 and 2", withSession, orphaned)
	}

	if n := r.rows("audit_events"); n != 6 {
		t.Errorf("%d audit events, want 6 (5 logins and the 89-day reuse event)", n)
	}

	if n := r.rows("users"); n != 10 {
		t.Errorf("%d users, want all 10: cleanup never deletes users", n)
	}

	// A second sweep has nothing to do.
	if again := r.sweep(postgres.DefaultCleanupPolicy()); again.Total() != 0 || again.More {
		t.Errorf("second sweep = %+v", again)
	}
}

func TestCleanupWorksInBoundedBatches(t *testing.T) {
	r := newRetention(t)
	for i := 0; i < 25; i++ {
		r.flowExpiredAgo(48 * hour)
	}

	p := postgres.DefaultCleanupPolicy()
	p.BatchSize, p.MaxBatches = 10, 2

	first := r.sweep(p)
	if first.Flows != 20 || !first.More || r.rows("auth_flows") != 5 {
		t.Fatalf("first sweep = %+v, %d flows left; want 20 deleted and More", first, r.rows("auth_flows"))
	}

	second := r.sweep(p)
	if second.Flows != 5 || second.More || r.rows("auth_flows") != 0 {
		t.Fatalf("second sweep = %+v, %d flows left", second, r.rows("auth_flows"))
	}
}

func TestConcurrentSweepsDeleteEachRowOnce(t *testing.T) {
	r := newRetention(t)

	const flows = 100
	for i := 0; i < flows; i++ {
		r.flowExpiredAgo(48 * hour)
	}

	p := postgres.DefaultCleanupPolicy()
	p.BatchSize = 7

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		total int64
	)

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := r.store.Cleanup(context.Background(), r.now, p)
			if err != nil {
				t.Errorf("Cleanup: %v", err)
			}

			mu.Lock()
			total += res.Flows
			mu.Unlock()
		}()
	}

	wg.Wait()

	if total != flows || r.rows("auth_flows") != 0 || r.rows("outbox") != 0 {
		t.Errorf("deleted %d of %d flows, %d left, %d mails left", total, flows, r.rows("auth_flows"), r.rows("outbox"))
	}
}

func TestCleanupStopsWhenItsContextEnds(t *testing.T) {
	r := newRetention(t)
	r.flowExpiredAgo(48 * hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := r.store.Cleanup(ctx, r.now, postgres.DefaultCleanupPolicy()); err == nil {
		t.Error("a cancelled sweep reported success")
	}

	if r.rows("auth_flows") != 1 {
		t.Error("a cancelled sweep deleted a row")
	}
}

func TestCleanupRefusesAnImpossiblePolicy(t *testing.T) {
	r := newRetention(t)

	for name, mod := range map[string]func(*postgres.CleanupPolicy){
		"no batch":           func(p *postgres.CleanupPolicy) { p.BatchSize = 0 },
		"no batch budget":    func(p *postgres.CleanupPolicy) { p.MaxBatches = 0 },
		"negative grace":     func(p *postgres.CleanupPolicy) { p.FlowGrace = -time.Hour },
		"no audit retention": func(p *postgres.CleanupPolicy) { p.AuditRetention = 0 },
		"lasting retention shorter than the ordinary one": func(p *postgres.CleanupPolicy) { p.LastingAuditRetention = p.AuditRetention - time.Second },
	} {
		p := postgres.DefaultCleanupPolicy()
		mod(&p)

		if _, err := r.store.Cleanup(context.Background(), r.now, p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A challenge lives minutes and a ticket ten minutes; both go once they are long expired. The
// credentials and recovery codes of a user are never swept.
func TestCleanupDeletesExpiredChallengesAndTickets(t *testing.T) {
	r := newRetention(t)
	user := r.user(r.now.Add(-100 * day))

	challengeExpiredAgo := func(ago time.Duration, consume bool) passkey.ID {
		created := r.now.Add(-ago).Add(-passkey.ChallengeTTL)

		c := r.factory(created).Challenge(testutil.ChallengeSpec{Purpose: passkey.ChallengeLogin})
		if consume {
			if err := c.Consume(created.Add(time.Second), passkey.ChallengeLogin); err != nil {
				t.Fatal(err)
			}
		}

		r.do(func(ctx context.Context, s port.Stores) error { return s.Challenges.Create(ctx, c) })

		return c.ID()
	}
	ticketExpiredAgo := func(ago time.Duration, use bool) passkey.ID {
		created := r.now.Add(-ago).Add(-passkey.EnrollTicketTTL)

		tk := r.factory(created).Ticket(testutil.TicketSpec{User: user})
		if use {
			if err := tk.Use(created.Add(time.Second), passkey.Presented{Kind: passkey.TicketEnroll, Binding: testutil.BindingHash(testutil.DefaultBindingSecret)}); err != nil {
				t.Fatal(err)
			}
		}

		r.do(func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, tk) })

		return tk.ID()
	}

	challenges := map[string]struct {
		id   passkey.ID
		gone bool
	}{
		"expired 2h ago":            {challengeExpiredAgo(2*hour, false), true},
		"consumed, expired 2h ago":  {challengeExpiredAgo(2*hour, true), true},
		"expired 30 minutes ago":    {challengeExpiredAgo(30*time.Minute, false), false},
		"still valid":               {challengeExpiredAgo(-3*time.Minute, false), false},
		"consumed but still within": {challengeExpiredAgo(-3*time.Minute, true), false},
	}
	tickets := map[string]struct {
		id   passkey.ID
		gone bool
	}{
		"expired 25h ago":            {ticketExpiredAgo(25*hour, false), true},
		"used, expired 25h ago":      {ticketExpiredAgo(25*hour, true), true},
		"expired 23h ago":            {ticketExpiredAgo(23*hour, false), false},
		"still valid":                {ticketExpiredAgo(-5*time.Minute, false), false},
		"used but still within life": {ticketExpiredAgo(-5*time.Minute, true), false},
	}
	f := r.factory(r.now.Add(-100 * day))
	cred := f.Credential(testutil.CredentialSpec{User: user})

	r.do(func(ctx context.Context, s port.Stores) error {
		if err := s.Credentials.Create(ctx, cred); err != nil {
			return err
		}

		return s.Recovery.Replace(ctx, user.ID(), []*passkey.RecoveryCode{f.RecoveryCode(user, "old-code")})
	})

	res := r.sweep(postgres.DefaultCleanupPolicy())

	for name, c := range challenges {
		if got := r.exists("passkey_challenges", c.id.String()); got == c.gone {
			t.Errorf("challenge %s: exists = %v, want %v", name, got, !c.gone)
		}
	}

	for name, c := range tickets {
		if got := r.exists("auth_tickets", c.id.String()); got == c.gone {
			t.Errorf("ticket %s: exists = %v, want %v", name, got, !c.gone)
		}
	}

	if res.Challenges != 2 || res.Tickets != 2 {
		t.Errorf("result = %+v, want 2 challenges and 2 tickets", res)
	}

	if r.rows("passkey_credentials") != 1 || r.rows("recovery_codes") != 1 || r.rows("users") != 1 {
		t.Error("a sweep touched credentials, recovery codes or users")
	}

	if again := r.sweep(postgres.DefaultCleanupPolicy()); again.Total() != 0 {
		t.Errorf("second sweep = %+v", again)
	}
}

func (r *retention) auditEvent(e port.AuditEvent, ago time.Duration) {
	r.t.Helper()

	e.At = r.now.Add(-ago)
	if e.Result == "" {
		e.Result = port.AuditSuccess
	}

	r.do(func(ctx context.Context, s port.Stores) error { return s.Audit.Record(ctx, e) })
}

func (r *retention) auditEvents() map[string]int {
	r.t.Helper()

	rows, err := r.db.Query(`SELECT event || coalesce('/' || (fields ->> 'reason'), '') AS kind, count(*) FROM audit_events GROUP BY kind`)
	if err != nil {
		r.t.Fatal(err)
	}

	defer func() { _ = rows.Close() }()

	out := map[string]int{}

	for rows.Next() {
		var (
			kind string
			n    int
		)
		if err := rows.Scan(&kind, &n); err != nil {
			r.t.Fatal(err)
		}

		out[kind] = n
	}

	return out
}

// Events that change who can get into an account, and the sign of a copied key, outlive the rest.
func TestLastingAuditEventsOutliveTheOrdinaryOnes(t *testing.T) {
	r := newRetention(t)
	ordinary := []port.AuditEvent{
		{Type: port.AuditLoginSucceeded}, {Type: port.AuditEmailVerified}, {Type: port.AuditStepUpGranted},
		{Type: port.AuditRefreshReuse, Result: port.AuditDenied}, {Type: port.AuditSessionRevoked}, {Type: port.AuditAllSessionsRevoked},
		{Type: port.AuditPasskeyRefused, Result: port.AuditDenied, Fields: map[string]string{"reason": "ceremony_failed"}},
	}

	lasting := []port.AuditEvent{
		{Type: port.AuditPasskeyEnrolled}, {Type: port.AuditPasskeyDeleted}, {Type: port.AuditRecoveryCodeUsed},
		{Type: port.AuditRecoveryRenewed}, {Type: port.AuditEmailChanged}, {Type: port.AuditAccountDeleted},
		{Type: port.AuditPasskeyRefused, Result: port.AuditDenied, Fields: map[string]string{"reason": port.CloneSuspectedReason}},
	}
	for _, e := range append(append([]port.AuditEvent{}, ordinary...), lasting...) {
		r.auditEvent(e, 120*day) // past the ordinary retention, inside the lasting one
	}

	for _, e := range lasting {
		r.auditEvent(e, 30*day)
	}

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.AuditEvents != int64(len(ordinary)) {
		t.Errorf("deleted %d audit events, want the %d ordinary ones", res.AuditEvents, len(ordinary))
	}

	left := r.auditEvents()
	if len(left) != len(lasting) {
		t.Errorf("kinds left = %v, want only the %d lasting kinds", left, len(lasting))
	}

	for _, e := range lasting {
		kind := string(e.Type)
		if reason := e.Fields["reason"]; reason != "" {
			kind += "/" + reason
		}

		if left[kind] != 2 {
			t.Errorf("%s left %d times, want 2 (the 120-day and the 30-day one)", kind, left[kind])
		}
	}

	// A year and a day after the event the lasting ones go too, and only the old ones.
	r.now = r.now.Add(246 * day) // the 120-day events are 366 days old now; the 30-day ones are 276
	r.f.Clock.Set(r.now)

	res = r.sweep(postgres.DefaultCleanupPolicy())
	if res.AuditEvents != int64(len(lasting)) {
		t.Errorf("second sweep deleted %d, want the %d events that passed a year", res.AuditEvents, len(lasting))
	}

	if r.rows("audit_events") != len(lasting) {
		t.Errorf("%d audit events left, want the %d recent lasting ones", r.rows("audit_events"), len(lasting))
	}
}

// The oldest rows are the ones that must stay; the ones to delete wait behind them. A batch smaller
// than the pile of lasting rows must still reach them, or the sweep would stall for a year.
func TestLastingAuditEventsDoNotBlockTheSweepOfOrdinaryOnes(t *testing.T) {
	r := newRetention(t)
	for i := 0; i < 12; i++ {
		r.auditEvent(port.AuditEvent{Type: port.AuditEmailChanged}, 200*day+time.Duration(i)*time.Minute)
	}

	for i := 0; i < 5; i++ {
		r.auditEvent(port.AuditEvent{Type: port.AuditLoginSucceeded}, 100*day+time.Duration(i)*time.Minute)
	}

	p := postgres.DefaultCleanupPolicy()
	p.BatchSize, p.MaxBatches = 2, 10

	res := r.sweep(p)
	if res.AuditEvents != 5 || res.More {
		t.Errorf("deleted %d (more=%v), want the 5 ordinary events behind the 12 lasting ones", res.AuditEvents, res.More)
	}

	if left := r.auditEvents(); left["email.changed"] != 12 || left["login.succeeded"] != 0 {
		t.Errorf("left = %v", left)
	}
}

func TestAuditEventClassIsDecidedByTypeAndTheCloneReasonOnly(t *testing.T) {
	for _, tc := range []struct {
		event port.AuditEvent
		want  bool
	}{
		{port.AuditEvent{Type: port.AuditEmailChanged}, true},
		{port.AuditEvent{Type: port.AuditAccountDeleted}, true},
		{port.AuditEvent{Type: port.AuditPasskeyRefused, Fields: map[string]string{"reason": "clone_suspected"}}, true},
		{port.AuditEvent{Type: port.AuditPasskeyRefused, Fields: map[string]string{"reason": "ceremony_failed"}}, false},
		{port.AuditEvent{Type: port.AuditPasskeyRefused}, false},
		{port.AuditEvent{Type: port.AuditLoginSucceeded, Fields: map[string]string{"reason": "clone_suspected"}}, false},
		{port.AuditEvent{Type: port.AuditRefreshReuse}, false},
	} {
		if got := tc.event.Lasting(); got != tc.want {
			t.Errorf("%s %v: Lasting = %v, want %v", tc.event.Type, tc.event.Fields, got, tc.want)
		}
	}
}

func TestCleanupDeletesInvitationsOnlyLongAfterTheyExpired(t *testing.T) {
	r := newRetention(t)
	seed := func(raw string, expiresIn time.Duration) {
		email, err := identity.ParseEmail(raw)
		if err != nil {
			t.Fatal(err)
		}

		created := r.now.Add(expiresIn).Add(-identity.MinInvitationTTL)

		inv, err := identity.NewInvitation(email, created, identity.MinInvitationTTL)
		if err != nil {
			t.Fatal(err)
		}

		r.do(func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })
	}
	seed("live@example.test", 24*time.Hour)       // still valid
	seed("just-expired@example.test", -time.Hour) // expired, but the operator may still want to see it
	seed("long-expired@example.test", -8*day)     // past the grace of a week
	seed("also-long-expired@example.test", -30*day)

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.Invitations != 2 {
		t.Errorf("deleted %d invitations, want the 2 long expired ones", res.Invitations)
	}

	var left int
	if err := r.db.QueryRow(`SELECT count(*) FROM invitations WHERE email IN ('live@example.test', 'just-expired@example.test')`).Scan(&left); err != nil || left != 2 || r.rows("invitations") != 2 {
		t.Errorf("%d of the two kept invitations remain, %d in all, %v", left, r.rows("invitations"), err)
	}
}

// The mail of an invitation has no flow to cascade from: the sweep removes it a grace period after it was made,
// unless a worker holds it.
func TestCleanupDeletesTheMailOfOldInvitations(t *testing.T) {
	r := newRetention(t)
	guest, _ := identity.ParseEmail("guest@example.test")
	queue := func(age time.Duration) {
		created := r.now.Add(-age)
		if _, err := r.db.Exec(`INSERT INTO outbox (id, flow_id, generation, quota_class, kind, recipient, available_at, created_at)
			VALUES (gen_random_uuid(), NULL, 1, 'unknown', 'invitation', $1, $2, $2)`, guest.String(), created); err != nil {
			t.Fatal(err)
		}
	}
	queue(time.Hour) // fresh
	queue(6 * day)   // inside the grace
	queue(8 * day)   // past it
	queue(40 * day)  // long past it

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.InvitationMails != 2 || r.rows("outbox") != 2 {
		t.Errorf("deleted %d invitation mails, %d left; want 2 and 2", res.InvitationMails, r.rows("outbox"))
	}
}

// The notice of a new device is flowless too: a job that never finished must not keep the client address for ever.
func TestCleanupDeletesOldNewDeviceMailAndAFinishedJobKeepsNoAddress(t *testing.T) {
	r := newRetention(t)
	insertUser(t, r.db, userID, "owner@example.test")

	queue := func(age time.Duration) {
		created := r.now.Add(-age)
		if _, err := r.db.Exec(`INSERT INTO outbox (id, flow_id, generation, quota_class, kind, available_at, created_at, user_id, device_name, client_ip, event_at)
			VALUES (gen_random_uuid(), NULL, 1, 'recognized', 'new_device', $1, $1, $2, 'Office laptop', '203.0.113.7', $1)`, created, userID); err != nil {
			t.Fatal(err)
		}
	}
	queue(time.Hour) // fresh
	queue(40 * day)  // long past the grace

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.InvitationMails != 1 || r.rows("outbox") != 1 {
		t.Errorf("deleted %d flowless mails, %d left; want 1 and 1", res.InvitationMails, r.rows("outbox"))
	}

	// A job that was sent keeps no client address, a dead one neither, a queued one does until it ends.
	r.do(func(ctx context.Context, s port.Stores) error {
		claimed, err := s.Outbox.Claim(ctx, r.now, time.Minute)
		if err != nil {
			return err
		}

		return s.Outbox.Complete(ctx, claimed.ID)
	})

	var kept int
	if err := r.db.QueryRow(`SELECT count(*) FROM outbox WHERE client_ip IS NOT NULL`).Scan(&kept); err != nil || kept != 0 {
		t.Errorf("%d jobs keep a client address after the mail went out, %v", kept, err)
	}
}

func TestCleanupDeletesTheAdminAPIsShortLivedRows(t *testing.T) {
	r := newRetention(t)
	op := r.factory(r.now).Operator(testutil.OperatorSpec{})
	r.do(func(ctx context.Context, s port.Stores) error { return s.Operators.Create(ctx, op) })

	// Sessions: only one created before the horizon (a week) is gone; they last at most eight hours.
	for _, age := range []time.Duration{time.Hour, 6 * day, 8 * day, 30 * day} {
		sess := r.factory(r.now.Add(-age)).OperatorSession(op, "")
		r.do(func(ctx context.Context, s port.Stores) error { return s.OperatorSessions.Create(ctx, sess) })
	}
	// Enrollments: a day after they expired (the ticket grace); a live and a just-expired one stay.
	for _, age := range []time.Duration{10 * time.Minute, 2 * time.Hour, 3 * day, 40 * day} {
		e := r.factory(r.now.Add(-age)).Enrollment(op, "")
		r.do(func(ctx context.Context, s port.Stores) error { return s.Operators.CreateEnrollment(ctx, e) })
	}
	// Challenges: an hour after they expired.
	for _, age := range []time.Duration{time.Minute, 2 * time.Hour, 3 * day} {
		c := r.factory(r.now.Add(-age)).Challenge(testutil.ChallengeSpec{Purpose: passkey.ChallengeLogin})
		r.do(func(ctx context.Context, s port.Stores) error { return s.OperatorChallenges.Create(ctx, c) })
	}

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.OperatorRows != 2+2+2 {
		t.Errorf("deleted %d admin rows, want 6", res.OperatorRows)
	}

	for table, want := range map[string]int{"operator_sessions": 2, "operator_enrollments": 2, "operator_challenges": 1} {
		if got := r.rows(table); got != want {
			t.Errorf("%s keeps %d rows, want %d", table, got, want)
		}
	}

	if r.rows("operators") != 1 {
		t.Error("the sweep removed an operator")
	}
}

func TestOperatorCloneRefusalsOutliveOrdinaryAuditEvents(t *testing.T) {
	r := newRetention(t)
	op := r.factory(r.now).Operator(testutil.OperatorSpec{})
	r.do(func(ctx context.Context, s port.Stores) error { return s.Operators.Create(ctx, op) })
	old := r.now.Add(-100 * day) // past the ordinary 90 days, inside the long 365
	record := func(e port.AuditEvent) {
		e.At, e.OperatorID = old, op.ID()

		r.do(func(ctx context.Context, s port.Stores) error { return s.Audit.Record(ctx, e) })
	}
	record(port.AuditEvent{Type: port.AuditOperatorLogin, Result: port.AuditSuccess})
	record(port.AuditEvent{Type: port.AuditOperatorLogin, Result: port.AuditDenied, Fields: map[string]string{"reason": "ceremony_failed"}})
	record(port.AuditEvent{Type: port.AuditOperatorLogin, Result: port.AuditDenied, Fields: map[string]string{"reason": port.CloneSuspectedReason}})
	record(port.AuditEvent{Type: port.AuditAdminAction, Result: port.AuditSuccess, Fields: map[string]string{"operation": "block"}})
	record(port.AuditEvent{Type: port.AuditOperatorEnrolled, Result: port.AuditSuccess})
	record(port.AuditEvent{Type: port.AuditOperatorChanged, Result: port.AuditSuccess, Fields: map[string]string{"operation": "create"}})

	r.sweep(postgres.DefaultCleanupPolicy())

	var kept []string

	rows, err := r.db.Query(`SELECT event || '/' || result FROM audit_events ORDER BY event, result`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}

		kept = append(kept, s)
	}

	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// An ordinary login (success or refusal) is gone; the long ones stay: acts, enrollments, changes and the copied key.
	want := []string{"admin.action/success", "operator.changed/success", "operator.enrolled/success", "operator.login/denied"}
	if len(kept) != len(want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}

	for i := range want {
		if kept[i] != want[i] {
			t.Errorf("kept %v, want %v", kept, want)
			break
		}
	}

	var denied int
	if err := r.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event = 'operator.login' AND fields ->> 'reason' = $1`, port.CloneSuspectedReason).Scan(&denied); err != nil || denied != 1 {
		t.Errorf("the clone refusal: %d, %v", denied, err)
	}
}

func TestCleanupDeletesDeviceRequestsAnHourAfterTheyExpired(t *testing.T) {
	r := newRetention(t)
	for _, age := range []time.Duration{time.Minute, 30 * time.Minute, 2 * time.Hour, 3 * day} {
		// A request made age ago expires five minutes later.
		req := r.factory(r.now.Add(-age)).DeviceRequest(testutil.DeviceSpec{})
		r.do(func(ctx context.Context, s port.Stores) error { return s.Devices.Create(ctx, req) })
	}

	res := r.sweep(postgres.DefaultCleanupPolicy())
	if res.DeviceRequests != 2 || r.rows("device_requests") != 2 {
		t.Errorf("deleted %d device requests, %d left; want 2 and 2", res.DeviceRequests, r.rows("device_requests"))
	}
}
