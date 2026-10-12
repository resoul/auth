//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/id"
	apasskey "airlance.org/auth/internal/adapter/passkey"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/quota"
)

// Exercise the real use cases, not just Allow: refused requests must not write
// challenges, flows or mail jobs, and must leave fresh step-up tickets available.
func TestDefaultPasskeyIPBudgetUnderContention(t *testing.T) {
	store, db := newStore(t)
	web, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{rpOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	begin, err := passkey.NewBeginLogin(passkey.BeginLoginDeps{
		UnitOfWork: store, Clock: fixedQuotaClock{}, WebAuthn: web, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]passkey.CeremonyResult, 180)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := begin.Execute(t.Context(), passkey.BeginLoginCommand{ClientIP: netip.MustParseAddr("203.0.113.1")})
			if err != nil {
				t.Errorf("begin login: %v", err)
			}
			results[i] = result
		}()
	}
	wg.Wait()
	admitted := 0
	for _, result := range results {
		switch result.Outcome {
		case passkey.OutcomeOK:
			admitted++
		case passkey.OutcomeRateLimited:
			if result.ChallengeID != "" || len(result.Options) != 0 {
				t.Error("a refused request received a challenge")
			}
		default:
			t.Errorf("unexpected outcome: %s", result.Outcome)
		}
	}
	if admitted != 60 || count(t, db, "passkey_challenges") != 60 || count(t, db, "quota_events") != 60 {
		t.Fatalf("admitted %d; challenges %d; quota rows %d; want 60 each", admitted, count(t, db, "passkey_challenges"), count(t, db, "quota_events"))
	}
}

func TestEmailChangeNewAddressBudgetUnderContention(t *testing.T) {
	e := newChangeEnv(t, postgres.WithQuota(quota.DefaultProfile()))
	commands := make([]account.StartEmailChangeCommand, 40)
	for i := range commands {
		changer := e.accountWithBinding(fmt.Sprintf("old-%d@example.test", i), fmt.Sprintf("binding-%d", i))
		commands[i] = account.StartEmailChangeCommand{
			Actor: changer.actor, StepUpSecret: e.stepUp(changer), Email: "target@example.test",
			ClientIP: netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}),
		}
	}
	var wg sync.WaitGroup
	results := make([]account.StartEmailChangeResult, len(commands))
	for i, command := range commands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := e.start.Execute(context.Background(), command)
			if err != nil {
				t.Errorf("start email change: %v", err)
			}
			results[i] = result
		}()
	}
	wg.Wait()
	admitted := 0
	for _, result := range results {
		switch result.Outcome {
		case account.OutcomeOK:
			admitted++
		case account.OutcomeRateLimited:
			if !result.FlowID.IsZero() {
				t.Error("a refused request received a flow")
			}
		default:
			t.Errorf("unexpected outcome: %s", result.Outcome)
		}
	}
	var spent int
	if err := e.db.QueryRow(`SELECT count(*) FROM auth_tickets WHERE consumed_at IS NOT NULL`).Scan(&spent); err != nil {
		t.Fatal(err)
	}
	if admitted != 10 || spent != 10 || count(t, e.db, "auth_flows") != 10 || count(t, e.db, "outbox") != 10 || count(t, e.db, "quota_events") != 30 {
		t.Fatalf("admitted %d, spent tickets %d, flows %d, outbox %d, quota rows %d; want 10/10/10/10/30",
			admitted, spent, count(t, e.db, "auth_flows"), count(t, e.db, "outbox"), count(t, e.db, "quota_events"))
	}
}

func TestDefaultPasskeyRefBudgetUnderContention(t *testing.T) {
	store, db := newStore(t)
	spends := make([]port.Spend, 100)
	for i := range spends {
		spends[i] = port.Spend{Kind: quota.KindPasskey, Ref: "same-ticket", Now: t0,
			IP: netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})}
	}
	for _, stage := range []struct {
		after time.Duration
		want  int
		rows  int
	}{{0, 10, 20}, {time.Hour - time.Microsecond, 0, 20}, {time.Hour, 10, 40}} {
		for i := range spends {
			spends[i].Now = t0.Add(stage.after)
		}
		samples, _ := runQuotaLoad(t, store, spends, 32)
		admitted := 0
		for _, sample := range samples {
			if sample.err != nil {
				t.Fatal(sample.err)
			}
			if sample.allowed {
				admitted++
			}
		}
		if admitted != stage.want || count(t, db, "quota_events") != stage.rows {
			t.Fatalf("at %v: admitted %d, rows %d; want %d/%d", stage.after, admitted, count(t, db, "quota_events"), stage.want, stage.rows)
		}
	}
}
