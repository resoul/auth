package memory

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/deviceauth"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

var _ port.UnitOfWork = (*Store)(nil)

// Unlimited disables a quota in WithLimits.
const Unlimited = -1

type spendKey struct {
	kind  port.SpendKind
	email string
}

// state is everything a transaction can change. A transaction works on a copy
// and Do swaps it in on commit, so rollback is discarding the copy.
type state struct {
	flows map[string]authflow.Record
	users map[string]identity.UserRecord // by normalized email
	// recognized is keyed by user ID and binding hash: one record per pair.
	recognized map[string]identity.RecognizedClientRecord
	sessions   map[string]session.Record
	tokens     map[string]token.Record // by token ID
	// credentials is keyed by the hex of the WebAuthn credential ID; the others by row ID.
	credentials map[string]passkey.CredentialRecord
	challenges  map[string]passkey.ChallengeRecord
	tickets     map[string]passkey.TicketRecord
	recovery    map[string]passkey.RecoveryCodeRecord
	invitations map[string]identity.InvitationRecord // by normalized email
	devices     map[string]deviceauth.Record         // by request id
	audit       []port.AuditEvent
	// The admin API's data. Operators are keyed by ID, credentials by the hex of the credential ID,
	// sessions by row ID.
	operators           map[string]operator.Record
	operatorEnrollments map[string]operator.EnrollmentRecord
	operatorCredentials map[string]passkey.CredentialRecord
	operatorChallenges  map[string]passkey.ChallengeRecord
	operatorSessions    map[string]operator.SessionRecord
	outbox              []mailRecord
	events              map[string][]time.Time // admitted spends per budget
	spent               map[spendKey]int       // admitted spends per kind and email, for assertions
}

func (s *state) clone() *state {
	return &state{
		flows:       maps.Clone(s.flows),
		users:       maps.Clone(s.users),
		recognized:  maps.Clone(s.recognized),
		sessions:    maps.Clone(s.sessions),
		tokens:      maps.Clone(s.tokens),
		credentials: maps.Clone(s.credentials),
		challenges:  maps.Clone(s.challenges),
		tickets:     maps.Clone(s.tickets),
		recovery:    maps.Clone(s.recovery),
		invitations: maps.Clone(s.invitations),
		devices:     maps.Clone(s.devices),
		audit:       slices.Clone(s.audit),
		outbox:      slices.Clone(s.outbox),

		operators:           maps.Clone(s.operators),
		operatorEnrollments: maps.Clone(s.operatorEnrollments),
		operatorCredentials: maps.Clone(s.operatorCredentials),
		operatorChallenges:  maps.Clone(s.operatorChallenges),
		operatorSessions:    maps.Clone(s.operatorSessions),
		events:              maps.Clone(s.events),
		spent:               maps.Clone(s.spent),
	}
}

// Store is an in-memory database. Transactions run one at a time, which models
// the strongest locking; real concurrency is checked against PostgreSQL.
type Store struct {
	mu        sync.Mutex
	committed *state
	profile   quota.Profile
}

// Option configures a Store.
type Option func(*Store)

// WithQuota sets the budgets the limiter enforces. The default is no budgets at all.
func WithQuota(p quota.Profile) Option {
	return func(s *Store) { s.profile = p }
}

// WithLimits caps the spends of each kind per email within 24 hours, for unknown and
// recognized clients alike; pass Unlimited to leave one kind open. It is shorthand for
// tests that need a quota to run out.
func WithLimits(send, verify int) Option {
	windows := map[quota.Scope][]quota.Window{}
	capKind := func(limit int, scopes ...quota.Scope) {
		if limit == Unlimited {
			return
		}
		for _, scope := range scopes {
			windows[scope] = []quota.Window{{Limit: limit, Per: 24 * time.Hour}}
		}
	}
	capKind(send, quota.UnknownSendEmail, quota.RecognizedSendClient)
	capKind(verify, quota.UnknownVerifyEmail, quota.RecognizedVerifyClient)
	p, err := quota.NewProfile(windows)
	if err != nil {
		panic(err)
	}
	return WithQuota(p)
}

// NewStore returns an empty Store with unlimited quotas.
func NewStore(opts ...Option) *Store {
	s := &Store{
		committed: &state{
			flows:       map[string]authflow.Record{},
			users:       map[string]identity.UserRecord{},
			recognized:  map[string]identity.RecognizedClientRecord{},
			sessions:    map[string]session.Record{},
			tokens:      map[string]token.Record{},
			credentials: map[string]passkey.CredentialRecord{},
			challenges:  map[string]passkey.ChallengeRecord{},
			tickets:     map[string]passkey.TicketRecord{},
			recovery:    map[string]passkey.RecoveryCodeRecord{},
			invitations: map[string]identity.InvitationRecord{},
			devices:     map[string]deviceauth.Record{},

			operators:           map[string]operator.Record{},
			operatorEnrollments: map[string]operator.EnrollmentRecord{},
			operatorCredentials: map[string]passkey.CredentialRecord{},
			operatorChallenges:  map[string]passkey.ChallengeRecord{},
			operatorSessions:    map[string]operator.SessionRecord{},

			events: map[string][]time.Time{},
			spent:  map[spendKey]int{},
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Do runs fn on a copy of the data and commits it only if fn returns nil.
// Calling Do from inside fn would deadlock; transactions do not nest.
func (s *Store) Do(ctx context.Context, fn func(ctx context.Context, st port.Stores) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx := s.committed.clone()
	err := fn(ctx, port.Stores{
		AccountStores: port.AccountStores{
			Flows:       &flows{tx: tx},
			Users:       &users{tx: tx},
			Recognized:  &recognized{tx: tx},
			Sessions:    &sessions{tx: tx},
			Tokens:      &tokens{tx: tx},
			Credentials: &credentials{tx: tx},
			Challenges:  &challenges{m: tx.challenges},
			Tickets:     &tickets{tx: tx},
			Recovery:    &recovery{tx: tx},
			Invitations: &invitations{tx: tx},
			Devices:     &devices{tx: tx},
		},
		InfraStores: port.InfraStores{
			Outbox:     &outbox{tx: tx},
			Audit:      &audit{tx: tx},
			AuditReads: &audit{tx: tx},
			Limiter:    &limiter{tx: tx, profile: s.profile},
		},
		AdminStores: port.AdminStores{
			Operators:          &operators{tx: tx},
			OperatorSessions:   &operatorSessions{tx: tx},
			OperatorChallenges: &challenges{m: tx.operatorChallenges},
		},
		OIDCStores: s.oidcStores(),
	})
	if err != nil {
		return err
	}
	s.committed = tx
	return nil
}

// Flow returns the committed flow, for assertions.
func (s *Store) Flow(id authflow.FlowID) (*authflow.Flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.committed.flows[id.String()]
	if !ok {
		return nil, false
	}
	f, err := authflow.Restore(rec)
	if err != nil {
		panic(fmt.Sprintf("memory store holds an invalid flow: %v", err))
	}
	return f, true
}

// FlowCount returns the number of committed flows.
func (s *Store) FlowCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed.flows)
}

// User returns the committed user with the given email.
func (s *Store) User(email identity.Email) (*identity.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.committed.users[email.String()]
	if !ok {
		return nil, false
	}
	u, err := identity.RestoreUser(rec)
	if err != nil {
		panic(fmt.Sprintf("memory store holds an invalid user: %v", err))
	}
	return u, true
}

// UserCount returns the number of committed users.
func (s *Store) UserCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed.users)
}

// OutboxJobs returns the committed mail jobs in enqueue order, whatever their status.
func (s *Store) OutboxJobs() []port.MailJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := make([]port.MailJob, 0, len(s.committed.outbox))
	for _, r := range s.committed.outbox {
		jobs = append(jobs, r.job)
	}
	return jobs
}

// MailStatus is the committed state of one queued job, for assertions.
type MailStatus struct {
	Job       port.MailJob
	Status    string
	Attempts  int
	LastError string
	Leased    bool
}

// OutboxStatuses returns the committed state of every job in enqueue order.
func (s *Store) OutboxStatuses() []MailStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MailStatus, 0, len(s.committed.outbox))
	for _, r := range s.committed.outbox {
		out = append(out, MailStatus{Job: r.job, Status: r.status, Attempts: r.attempts, LastError: string(r.lastError), Leased: !r.leaseUntil.IsZero()})
	}
	return out
}

// Spent returns how many spends of the kind were admitted for the email.
func (s *Store) Spent(kind port.SpendKind, email identity.Email) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed.spent[spendKey{kind, email.String()}]
}

// Session returns the committed session, for assertions.
func (s *Store) Session(id session.ID) (*session.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.committed.sessions[id.String()]
	if !ok {
		return nil, false
	}
	sess, err := session.Restore(rec)
	if err != nil {
		panic(fmt.Sprintf("memory store holds an invalid session: %v", err))
	}
	return sess, true
}

// TokensOfSession returns the committed tokens of a session in creation order.
func (s *Store) TokensOfSession(id session.ID) []*token.RefreshToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*token.RefreshToken
	for _, rec := range s.committed.tokens {
		if rec.SessionID != id {
			continue
		}
		t, err := token.Restore(rec)
		if err != nil {
			panic(fmt.Sprintf("memory store holds an invalid token: %v", err))
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b *token.RefreshToken) int { return a.CreatedAt().Compare(b.CreatedAt()) })
	return out
}

// SessionCount returns the number of committed sessions.
func (s *Store) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed.sessions)
}

// TokenCount returns the number of committed refresh tokens.
func (s *Store) TokenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed.tokens)
}

// AuditEvents returns the committed audit events in recording order.
func (s *Store) AuditEvents() []port.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.committed.audit)
}

// TicketCount returns the number of committed tickets.
func (s *Store) TicketCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed.tickets)
}
