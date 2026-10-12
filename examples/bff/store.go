package bff

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrSessionEnded reports a session that would belong to a sign-in the provider has already ended.
var ErrSessionEnded = errors.New("bff: the sign-in has ended")

// ErrNoSession reports a session that is not there: never was, ended, or expired.
var ErrNoSession = errors.New("bff: no such session")

// LoginTx is one sign-in in progress: what the application must remember between sending the browser to the provider and
// receiving it back. It is used once, by the browser that began it, and for a short time.
type LoginTx struct {
	// Key is the hash of the value of the browser's transaction cookie.
	Key      string
	State    string
	Nonce    string
	Verifier string
	ReturnTo string
	// StartedAt is when the browser was sent to the provider; a sign-in that began before its provider session ended is over.
	StartedAt time.Time
	ExpiresAt time.Time
}

// Session is what the application knows of a signed-in browser. Everything that can be presented to someone else is sealed.
type Session struct {
	// Key is the hash of the value of the browser's session cookie, never the value.
	Key string
	// UserID is the application's own identifier of the person; (Issuer, Subject) is who they are to the provider.
	UserID  string
	Issuer  string
	Subject string
	// ProviderSession is the sid of the shared sign-in, which the provider's logout notices name.
	ProviderSession string
	IDTokenSealed   string
	RefreshSealed   string
	// Access are the sealed access tokens by the URI of the resource they are for.
	Access    map[string]SealedAccess
	CreatedAt time.Time
	// SignInStarted is when the sign-in that made the session began (LoginTx.StartedAt).
	SignInStarted time.Time
	ExpiresAt     time.Time
	// RefreshInterrupted is set by a store that records refreshes (RefreshMarker) when an earlier refresh of this session began
	// and never finished, by a crash or a lost connection: the provider may have rotated the token, so the one held must not
	// be presented again. It is read, never set, by the application.
	RefreshInterrupted bool
	// BeginRefresh is set by a store that survives the process, on the copy it gives to the function of WithSessionLock, and is
	// nil for one that does not. The function calls it before it asks the provider to rotate the refresh token: it durably records,
	// on the connection that holds the session, that a refresh has begun, and the store clears the record when the function
	// returns. A record still there at the next WithSessionLock means the process died in between, and that session comes back
	// with RefreshInterrupted. It is not part of what is stored.
	BeginRefresh func(ctx context.Context) error
}

// SealedAccess is a sealed access token and when it ends.
type SealedAccess struct {
	Sealed    string
	ExpiresAt time.Time
}

// Store is where an application keeps its sign-ins and sessions. The in-memory one below is for one process, a demonstration
// and the tests; a deployment of several instances needs a shared one, which must give the guarantees noted on each method.
type Store interface {
	// PutLogin stores a transaction.
	PutLogin(ctx context.Context, tx LoginTx) error
	// TakeLogin returns the transaction and removes it, in one step, so that it can be used once even by two requests at the
	// same moment. It reports false for one that is unknown or has expired.
	TakeLogin(ctx context.Context, key string, now time.Time) (LoginTx, bool, error)
	// UpsertUser finds or creates the person for (issuer, subject): the key of a profile is the pair, never an email.
	UpsertUser(ctx context.Context, issuer, subject string) (userID string, err error)
	// CreateSession stores a session. It returns ErrSessionEnded when the sign-in (issuer, ProviderSession) was ended by a
	// logout notice before: a notice that arrives between the code exchange and this call must not be undone by it.
	CreateSession(ctx context.Context, s Session) error
	// GetSession loads a session. It returns ErrNoSession.
	GetSession(ctx context.Context, key string) (Session, error)
	// DeleteSession ends a session; one that is gone is not an error.
	DeleteSession(ctx context.Context, key string) error
	// EndProviderSession handles a logout notice in ONE atomic step: it remembers the jti until exp, remembers that the sign-in
	// (issuer, sid) has ended (for CreateSession), and deletes its sessions. If it fails, none of that happened, so the
	// provider's next delivery is handled afresh. first is false when the jti was handled before.
	EndProviderSession(ctx context.Context, issuer, sid, jti string, exp time.Time) (first bool, ended int, err error)
	// WithSessionLock runs fn with an exclusive hold on the session, across requests, tabs and instances: in SQL a
	// `SELECT ... FOR UPDATE` of its row inside a transaction. fn changes the copy it is given, and the change is stored only
	// if fn returns nil. It returns ErrNoSession. This is what makes a rotating refresh token safe: two tabs never refresh
	// at once, and the second finds the first one's token.
	WithSessionLock(ctx context.Context, key string, fn func(s *Session) error) error
}

// MemoryStore is a Store in the memory of one process.
type MemoryStore struct {
	mu       sync.Mutex
	logins   map[string]LoginTx
	users    map[string]string
	sessions map[string]*Session
	locks    map[string]*sync.Mutex
	seen     map[string]time.Time
	ended    map[string]time.Time
	next     int
	now      func() time.Time
}

// NewMemoryStore returns an empty store; now is the clock, time.Now if nil.
func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		logins: map[string]LoginTx{}, users: map[string]string{}, sessions: map[string]*Session{}, locks: map[string]*sync.Mutex{},
		seen: map[string]time.Time{}, ended: map[string]time.Time{}, now: now,
	}
}

var _ Store = (*MemoryStore)(nil)

// PutLogin implements Store.
func (m *MemoryStore) PutLogin(_ context.Context, tx LoginTx) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, t := range m.logins {
		if !now.Before(t.ExpiresAt) {
			delete(m.logins, k)
		}
	}
	m.logins[tx.Key] = tx
	return nil
}

// TakeLogin implements Store.
func (m *MemoryStore) TakeLogin(_ context.Context, key string, now time.Time) (LoginTx, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.logins[key]
	delete(m.logins, key)
	if !ok || !now.Before(tx.ExpiresAt) {
		return LoginTx{}, false, nil
	}
	return tx, true, nil
}

// UpsertUser implements Store.
func (m *MemoryStore) UpsertUser(_ context.Context, issuer, subject string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := issuer + "\x00" + subject
	if id, ok := m.users[key]; ok {
		return id, nil
	}
	m.next++
	id := "user-" + itoa(m.next)
	m.users[key] = id
	return id, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// CreateSession implements Store.
func (m *MemoryStore) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Only a sign-in that began before the notice is ended by it: the provider's session may be signed in to again.
	if at, ok := m.ended[s.Issuer+"\x00"+s.ProviderSession]; ok && !s.SignInStarted.After(at) {
		return ErrSessionEnded
	}
	cp := s
	m.sessions[s.Key] = &cp
	return nil
}

// GetSession implements Store.
func (m *MemoryStore) GetSession(_ context.Context, key string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[key]
	if !ok {
		return Session{}, ErrNoSession
	}
	return clone(*s), nil
}

func clone(s Session) Session {
	access := make(map[string]SealedAccess, len(s.Access))
	for k, v := range s.Access {
		access[k] = v
	}
	s.Access = access
	return s
}

// DeleteSession implements Store.
func (m *MemoryStore) DeleteSession(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key)
	return nil
}

// WithSessionLock implements Store.
func (m *MemoryStore) WithSessionLock(_ context.Context, key string, fn func(s *Session) error) error {
	m.mu.Lock()
	lock, ok := m.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		m.locks[key] = lock
	}
	m.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	s, ok := m.sessions[key]
	var work Session
	if ok {
		work = clone(*s)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNoSession
	}
	if err := fn(&work); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, still := m.sessions[key]; still {
		cp := work
		m.sessions[key] = &cp
	}
	return nil
}

// endedMemory is how long a sign-in stays remembered as ended: longer than a session can live.
const endedMemory = 24 * time.Hour

// deliveryWindow is how long a provider may keep re-delivering a notice, with a margin.
const deliveryWindow = 26 * time.Hour

// EndProviderSession implements Store. One lock covers the whole step, so it is all or nothing.
func (m *MemoryStore) EndProviderSession(_ context.Context, issuer, sid, jti string, exp time.Time) (bool, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, until := range m.seen {
		if !now.Before(until) {
			delete(m.seen, k)
		}
	}
	for k, at := range m.ended {
		if !now.Before(at.Add(endedMemory)) {
			delete(m.ended, k)
		}
	}
	key := issuer + "\x00" + jti
	if _, ok := m.seen[key]; ok {
		return false, 0, nil
	}
	// The provider re-signs a notice with the same jti for as long as it keeps delivering (a day), whatever the JWT's own
	// lifetime, so the jti is remembered for that long: a forgotten one would end a later sign-in under the same sid.
	m.seen[key] = now.Add(deliveryWindow)
	if until := exp.Add(time.Hour); until.After(m.seen[key]) {
		m.seen[key] = until
	}
	m.ended[issuer+"\x00"+sid] = now
	n := 0
	for k, s := range m.sessions {
		if s.Issuer == issuer && s.ProviderSession == sid {
			delete(m.sessions, k)
			n++
		}
	}
	return true, n, nil
}
