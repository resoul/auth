package testutil

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/quota"
)

// NewQuotaUnitOfWork returns an empty UnitOfWork whose limiter enforces profile.
type NewQuotaUnitOfWork func(t *testing.T, profile quota.Profile) port.UnitOfWork

// contractProfile has small budgets so that a test can run each one out.
func contractProfile(t *testing.T) quota.Profile {
	t.Helper()

	day, hour := 24*time.Hour, time.Hour

	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{
		quota.UnknownSendEmail:       {{Limit: 3, Per: day}},
		quota.UnknownSendPair:        {{Limit: 2, Per: hour}},
		quota.UnknownSendIP:          {{Limit: 2, Per: hour}},
		quota.UnknownVerifyEmail:     {{Limit: 5, Per: day}},
		quota.RecognizedSendClient:   {{Limit: 2, Per: hour}, {Limit: 4, Per: day}},
		quota.RecognizedSendIP:       {{Limit: 3, Per: hour}},
		quota.RecognizedVerifyClient: {{Limit: 3, Per: day}},
		quota.PasskeyIP:              {{Limit: 4, Per: hour}},
		quota.PasskeyRef:             {{Limit: 2, Per: hour}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// RunLimiterContract checks the Limiter port: sliding windows, all-or-nothing charges,
// the separation of unknown and recognized budgets, rollback and concurrent spends.
func RunLimiterContract(t *testing.T, newUoW NewQuotaUnitOfWork) {
	t.Helper()
	lc := func(t *testing.T) *limiterCase {
		f := NewFactory(t, contractNow)
		return &limiterCase{t: t, uow: newUoW(t, contractProfile(t)), f: f}
	}

	t.Run("the window slides and a boundary gives no second burst", func(t *testing.T) {
		c := lc(t)
		email := c.email()

		late := contractNow.Add(23*time.Hour + 59*time.Minute)
		for i := 0; i < 5; i++ {
			if !c.allow(c.unknown(quota.KindVerify, email, i, "", late)) {
				t.Fatalf("spend %d denied inside the limit", i+1)
			}
		}

		if c.allow(c.unknown(quota.KindVerify, email, 9, "", late.Add(2*time.Minute))) {
			t.Error("a new calendar day opened a second burst two minutes after the first")
		}

		if c.allow(c.unknown(quota.KindVerify, email, 9, "", late.Add(24*time.Hour-time.Second))) {
			t.Error("a spend one second before the window ended was allowed")
		}

		if !c.allow(c.unknown(quota.KindVerify, email, 9, "", late.Add(24*time.Hour))) {
			t.Error("the budget did not recover when the window ended")
		}
	})

	t.Run("unknown clients share the address budget across bindings and IPs", func(t *testing.T) {
		c := lc(t)
		email := c.email()

		for i := 0; i < 5; i++ {
			ip := fmt.Sprintf("192.0.2.%d", i+1)
			if !c.allow(c.unknown(quota.KindVerify, email, i, ip, contractNow)) {
				t.Fatalf("spend %d denied", i+1)
			}
		}

		if c.allow(c.unknown(quota.KindVerify, email, 99, "203.0.113.9", contractNow)) {
			t.Error("a new binding and a new IP opened a new budget")
		}

		if !c.allow(c.unknown(quota.KindVerify, c.email(), 0, "192.0.2.1", contractNow)) {
			t.Error("another address shares the budget")
		}
	})

	t.Run("a denial charges no budget", func(t *testing.T) {
		c := lc(t)
		email := c.email()
		// The pair allows 2 an hour; the address allows 3 a day.
		for i := 0; i < 2; i++ {
			if !c.allow(c.unknown(quota.KindSend, email, 1, "", contractNow)) {
				t.Fatalf("send %d denied", i+1)
			}
		}

		if c.allow(c.unknown(quota.KindSend, email, 1, "", contractNow)) {
			t.Fatal("the pair budget was not enforced")
		}
		// Had the denial charged the address budget, it would be exhausted here.
		if !c.allow(c.unknown(quota.KindSend, email, 2, "", contractNow)) {
			t.Error("a denied spend charged the address budget")
		}

		if c.allow(c.unknown(quota.KindSend, email, 3, "", contractNow)) {
			t.Error("the address budget allowed a fourth send")
		}
	})

	t.Run("IP budgets are shared by emails, grouped by /64 and skipped without an IP", func(t *testing.T) {
		c := lc(t)
		for i, ip := range []string{"198.51.100.1", "198.51.100.1"} {
			if !c.allow(c.unknown(quota.KindSend, c.email(), i, ip, contractNow)) {
				t.Fatalf("send %d from %s denied", i+1, ip)
			}
		}

		if c.allow(c.unknown(quota.KindSend, c.email(), 5, "198.51.100.1", contractNow)) {
			t.Error("a third send from one IP was allowed")
		}

		if !c.allow(c.unknown(quota.KindSend, c.email(), 6, "198.51.100.2", contractNow)) {
			t.Error("another IP is limited by the first")
		}

		for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2:aaaa::2"} {
			if !c.allow(c.unknown(quota.KindSend, c.email(), 7, ip, contractNow)) {
				t.Fatalf("send from %s denied", ip)
			}
		}

		if c.allow(c.unknown(quota.KindSend, c.email(), 8, "2001:db8:1:2:bbbb::3", contractNow)) {
			t.Error("rotating inside one /64 opened a new budget")
		}

		for i := 0; i < 3; i++ {
			if !c.allow(c.unknown(quota.KindSend, c.email(), 10+i, "", contractNow)) {
				t.Fatal("an unknown IP was limited by an IP budget")
			}
		}
	})

	t.Run("recognized and unknown budgets do not touch each other", func(t *testing.T) {
		c := lc(t)
		email := c.email()

		rc := c.recognizedID()
		for i := 0; i < 5; i++ {
			c.allow(c.unknown(quota.KindVerify, email, i, "", contractNow))
		}

		if c.allow(c.unknown(quota.KindVerify, email, 7, "", contractNow)) {
			t.Fatal("the unknown budget is not exhausted")
		}

		for i := 0; i < 3; i++ {
			if !c.allow(c.recognized(quota.KindVerify, email, rc, "", contractNow)) {
				t.Fatalf("recognized verify %d denied while unknown clients are exhausted", i+1)
			}
		}

		if c.allow(c.recognized(quota.KindVerify, email, rc, "", contractNow)) {
			t.Error("the recognized budget was not enforced")
		}

		if !c.allow(c.recognized(quota.KindVerify, email, c.recognizedID(), "", contractNow)) {
			t.Error("another recognition record shares the budget")
		}

		// The other way round: a recognized client exhausting its send budget leaves unknown clients alone.
		other := c.email()

		orc := c.recognizedID()
		for i := 0; i < 2; i++ {
			c.allow(c.recognized(quota.KindSend, other, orc, "", contractNow))
		}

		if c.allow(c.recognized(quota.KindSend, other, orc, "", contractNow)) {
			t.Fatal("the recognized send budget was not enforced")
		}

		if !c.allow(c.unknown(quota.KindSend, other, 1, "", contractNow)) {
			t.Error("a recognized client spent the budget of unknown clients")
		}
	})

	t.Run("recognized clients have an IP budget of their own", func(t *testing.T) {
		c := lc(t)

		ip := "198.51.100.1"
		for i := 0; i < 2; i++ {
			c.allow(c.unknown(quota.KindSend, c.email(), i, ip, contractNow))
		}

		if c.allow(c.unknown(quota.KindSend, c.email(), 5, ip, contractNow)) {
			t.Fatal("the unknown IP budget is not exhausted")
		}

		if !c.allow(c.recognized(quota.KindSend, c.email(), c.recognizedID(), ip, contractNow)) {
			t.Error("unknown clients behind one NAT cut off a recognized client")
		}
	})

	t.Run("every window of a budget applies", func(t *testing.T) {
		c := lc(t)
		email, rc := c.email(), c.recognizedID()
		// 2 an hour and 4 a day.
		for i := 0; i < 2; i++ {
			if !c.allow(c.recognized(quota.KindSend, email, rc, "", contractNow)) {
				t.Fatalf("send %d denied", i+1)
			}
		}

		if c.allow(c.recognized(quota.KindSend, email, rc, "", contractNow.Add(30*time.Minute))) {
			t.Error("the hourly window was ignored")
		}

		hour2 := contractNow.Add(time.Hour)
		for i := 0; i < 2; i++ {
			if !c.allow(c.recognized(quota.KindSend, email, rc, "", hour2)) {
				t.Fatalf("send %d of the second hour denied", i+1)
			}
		}

		if c.allow(c.recognized(quota.KindSend, email, rc, "", hour2.Add(time.Hour))) {
			t.Error("the daily window was ignored")
		}
	})

	t.Run("a rolled back transaction keeps the budget", func(t *testing.T) {
		c := lc(t)

		email := c.email()
		for i := 0; i < 5; i++ {
			err := do(t, c.uow, func(ctx context.Context, s port.Stores) error {
				ok, err := s.Limiter.Allow(ctx, c.unknown(quota.KindVerify, email, i, "", contractNow))
				if err != nil || !ok {
					t.Fatalf("spend %d: %v %v", i+1, ok, err)
				}

				return errContractRollback
			})
			if !errors.Is(err, errContractRollback) {
				t.Fatalf("transaction = %v", err)
			}
		}

		for i := 0; i < 5; i++ {
			if !c.allow(c.unknown(quota.KindVerify, email, i, "", contractNow)) {
				t.Fatalf("spend %d denied after rollbacks: they charged the budget", i+1)
			}
		}
	})

	t.Run("a spend that is not valid is an error", func(t *testing.T) {
		c := lc(t)
		for name, s := range map[string]port.Spend{
			"unknown kind": {Kind: "other", Email: c.email(), Class: authflow.QuotaUnknown, Now: contractNow},
			"no time":      {Kind: quota.KindSend, Email: c.email(), Class: authflow.QuotaUnknown},
			"no record":    {Kind: quota.KindSend, Email: c.email(), Class: authflow.QuotaRecognized, Now: contractNow},
		} {
			err := do(t, c.uow, func(ctx context.Context, st port.Stores) error {
				_, err := st.Limiter.Allow(ctx, s)
				return err
			})
			if err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	})

	t.Run("passkey ceremonies draw from an address budget and a per-reference budget", func(t *testing.T) {
		c := lc(t)
		spend := func(ip, ref string, now time.Time) bool {
			return c.allow(port.Spend{Kind: quota.KindPasskey, IP: addr(ip), Ref: ref, Now: now})
		}
		// The reference budget (2) runs out before the address budget (4); a refusal charges nothing.
		for i := 0; i < 2; i++ {
			if !spend("192.0.2.1", "ticket-a", contractNow) {
				t.Fatalf("spend %d denied", i+1)
			}
		}

		if spend("192.0.2.1", "ticket-a", contractNow) {
			t.Error("a third ceremony of one ticket was admitted")
		}

		for i := 0; i < 2; i++ {
			if !spend("192.0.2.1", "", contractNow) {
				t.Fatalf("an address spend without a reference, %d, was denied after a refusal: the refusal must charge nothing", i+1)
			}
		}

		if spend("192.0.2.1", "ticket-b", contractNow) {
			t.Error("the address budget of 4 was exceeded through another ticket")
		}

		if !spend("192.0.2.2", "ticket-b", contractNow) {
			t.Error("another address was refused")
		}
		// An unknown address shares one budget instead of escaping the limit.
		for i := 0; i < 4; i++ {
			if !spend("", "", contractNow) {
				t.Fatalf("unknown address spend %d denied", i+1)
			}
		}

		if spend("", "", contractNow) {
			t.Error("unknown addresses escaped the limit")
		}
		// IPv6 clients are grouped by /64, and the window slides.
		if !spend("2001:db8::1", "", contractNow) || !spend("2001:db8::2", "", contractNow) {
			t.Fatal("IPv6 spends denied")
		}

		if !spend("2001:db8::ffff", "", contractNow.Add(time.Hour)) {
			t.Error("the budget did not recover after the window")
		}
	})

	t.Run("concurrent passkey spends never pass the limit", func(t *testing.T) {
		c := lc(t)

		const workers = 20

		var (
			wg sync.WaitGroup
			mu sync.Mutex
		)

		allowed := 0

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				if c.allow(port.Spend{Kind: quota.KindPasskey, IP: addr("198.51.100.7"), Now: contractNow}) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		if allowed != 4 {
			t.Errorf("%d of %d concurrent passkey spends admitted, want exactly 4", allowed, workers)
		}
	})

	t.Run("concurrent spends never pass the limit", func(t *testing.T) {
		c := lc(t)
		email := c.email()

		const workers = 40

		var (
			wg sync.WaitGroup
			mu sync.Mutex
		)

		allowed := 0

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Each request brings its own binding and IP: only the address budget holds.
				ip := fmt.Sprintf("10.0.%d.%d", i/200, i%200+1)
				if c.allow(c.unknown(quota.KindVerify, email, i, ip, contractNow)) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		if allowed != 5 {
			t.Errorf("%d of %d concurrent spends admitted, want exactly 5", allowed, workers)
		}
	})

	t.Run("concurrent spends of overlapping budgets do not deadlock", func(t *testing.T) {
		c := lc(t)
		emails := []identity.Email{c.email(), c.email(), c.email()}

		var wg sync.WaitGroup
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				c.allow(c.unknown(quota.KindSend, emails[i%3], i%4, fmt.Sprintf("192.0.2.%d", i%5), contractNow))
			}()
		}

		done := make(chan struct{})

		go func() { wg.Wait(); close(done) }()

		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("spends of overlapping budgets are stuck")
		}
	})
}

type limiterCase struct {
	t   *testing.T
	uow port.UnitOfWork
	f   *Factory
}

func (c *limiterCase) email() identity.Email { return c.f.User(UserSpec{}).Email() }

func (c *limiterCase) recognizedID() identity.RecognizedClientID {
	id, err := c.f.IDs.NewRecognizedClientID()
	if err != nil {
		c.t.Fatal(err)
	}

	return id
}

func (c *limiterCase) unknown(kind quota.Kind, email identity.Email, binding int, ip string, now time.Time) port.Spend {
	return port.Spend{
		Kind: kind, Email: email, Class: authflow.QuotaUnknown,
		Binding: BindingHash(fmt.Sprintf("binding-%d", binding)), IP: addr(ip), Now: now,
	}
}

func (c *limiterCase) recognized(kind quota.Kind, email identity.Email, id identity.RecognizedClientID, ip string, now time.Time) port.Spend {
	return port.Spend{
		Kind: kind, Email: email, Class: authflow.QuotaRecognized, RecognizedClientID: id,
		Binding: BindingHash("recognized"), IP: addr(ip), Now: now,
	}
}

func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}

	return netip.MustParseAddr(s)
}

// allow spends in a transaction of its own and fails the test on a technical error.
func (c *limiterCase) allow(s port.Spend) bool {
	c.t.Helper()

	var ok bool

	err := c.uow.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error

		ok, err = st.Limiter.Allow(ctx, s)

		return err
	})
	if err != nil {
		c.t.Errorf("Allow: %v", err)
	}

	return ok
}
