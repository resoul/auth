//go:build integration

package deviceauth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/application/deviceauth"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
)

// readsThen runs after the approving session has been read, while the redeeming transaction is still open.
type readsThen struct {
	port.SessionRepository
	after func()
}

func (r readsThen) Get(ctx context.Context, id session.ID) (*session.Session, error) {
	s, err := r.SessionRepository.Get(ctx, id)
	r.after()
	return s, err
}

// An approved request must not turn into a session after the user's sessions were revoked. The redemption reads the
// approving session, the revocation commits, and only then does the redemption open its session: the interleaving
// that left a live session behind. The hook holds the redemption at that point; the locks decide what happens.
func TestARedemptionCannotOutliveTheRevocationOfEverySession(t *testing.T) {
	e := newEnv(t)
	e.faults.inner = testutil.PostgresStore(t)

	phone := e.phone()
	laptop := e.newLaptop("Laptop")
	if got := e.approve(phone, laptop, laptop.res.PairingCode, e.stepUp(phone, dpasskey.OperationApproveDevice)); got.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("approve = %+v", got)
	}

	read := make(chan struct{})
	revoked := make(chan struct{})
	var once sync.Once
	e.faults.wrap = func(s port.Stores) port.Stores {
		s.Sessions = readsThen{SessionRepository: s.Sessions, after: func() {
			once.Do(func() { close(read) })
			select {
			case <-revoked: // the revocation got through: the redemption now acts on a stale read
			case <-time.After(time.Second): // the revocation is queued behind this transaction, as it should be
			}
		}}
		return s
	}

	var redeemed deviceauth.RedeemResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		redeemed = e.redeemFor(laptop)
	}()
	go func() {
		defer wg.Done()
		<-read
		e.faults.wrap = nil
		e.do(func(ctx context.Context, st port.Stores) error {
			return appsession.RevokeEverything(ctx, st, phone.user.ID(), e.clock.Now())
		})
		close(revoked)
	}()
	wg.Wait()

	active := -1
	e.do(func(ctx context.Context, st port.Stores) error {
		list, err := st.Sessions.ListActive(ctx, phone.user.ID(), e.clock.Now(), 10)
		active = len(list)
		return err
	})
	if active != 0 {
		t.Errorf("%d sessions are active after every session was revoked (the redemption was %+v)", active, redeemed.Outcome)
	}
}
