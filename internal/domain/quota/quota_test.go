package quota_test

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/quota"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mustEmail(t *testing.T) identity.Email {
	t.Helper()
	e, err := identity.ParseEmail("alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func scopes(ls []quota.Limit) []quota.Scope {
	var out []quota.Scope
	for _, l := range ls {
		out = append(out, l.Scope)
	}
	return out
}

func TestUnknownClientsShareTheAddressBudgetAcrossBindingsAndIPs(t *testing.T) {
	p := quota.DefaultProfile()
	email := mustEmail(t)
	a, err := p.Limits(quota.Spend{Kind: quota.KindVerify, Email: email, Class: authflow.QuotaUnknown, IP: netip.MustParseAddr("192.0.2.1"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Limits(quota.Spend{Kind: quota.KindVerify, Email: email, Class: authflow.QuotaUnknown, IP: netip.MustParseAddr("198.51.100.7"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Scope != quota.UnknownVerifyEmail || a[0].Key != b[0].Key {
		t.Errorf("the address budget differs per IP: %+v vs %+v", a[0], b[0])
	}
}

func TestIPBudgetsApplyToSendOnlyAndNeedAnIP(t *testing.T) {
	p := quota.DefaultProfile()
	email := mustEmail(t)
	withIP := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		name  string
		spend quota.Spend
		want  []quota.Scope
	}{
		{"send with ip", quota.Spend{Kind: quota.KindSend, Class: authflow.QuotaUnknown, IP: withIP}, []quota.Scope{quota.UnknownSendEmail, quota.UnknownSendPair, quota.UnknownSendIP}},
		{"send without ip", quota.Spend{Kind: quota.KindSend, Class: authflow.QuotaUnknown}, []quota.Scope{quota.UnknownSendEmail, quota.UnknownSendPair}},
		{"verify with ip", quota.Spend{Kind: quota.KindVerify, Class: authflow.QuotaUnknown, IP: withIP}, []quota.Scope{quota.UnknownVerifyEmail, quota.UnknownVerifyPair}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.spend.Email, tc.spend.Now = email, now
			got, err := p.Limits(tc.spend)
			if err != nil {
				t.Fatal(err)
			}
			if gs := scopes(got); len(gs) != len(tc.want) || gs[0] != tc.want[0] || gs[len(gs)-1] != tc.want[len(tc.want)-1] {
				t.Errorf("scopes = %v, want %v", gs, tc.want)
			}
		})
	}
}

func TestRecognizedClientsDrawOnTheirOwnBudgetsAndIPBudget(t *testing.T) {
	p := quota.DefaultProfile()
	rc, err := identity.ParseRecognizedClientID("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Limits(quota.Spend{
		Kind: quota.KindSend, Email: mustEmail(t), Class: authflow.QuotaRecognized, RecognizedClientID: rc,
		IP: netip.MustParseAddr("192.0.2.1"), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gs := scopes(got); len(gs) != 2 || gs[0] != quota.RecognizedSendClient || gs[1] != quota.RecognizedSendIP {
		t.Errorf("scopes = %v", gs)
	}
	if _, err := p.Limits(quota.Spend{Kind: quota.KindSend, Email: mustEmail(t), Class: authflow.QuotaRecognized, Now: now}); err == nil {
		t.Error("a recognized spend without a record was accepted")
	}
}

func TestIPv6IsGroupedBySubscriberBlockAndMappedIPv4IsIPv4(t *testing.T) {
	p := quota.DefaultProfile()
	key := func(ip string) string {
		ls, err := p.Limits(quota.Spend{Kind: quota.KindSend, Email: mustEmail(t), Class: authflow.QuotaUnknown, IP: netip.MustParseAddr(ip), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return ls[len(ls)-1].Key
	}
	if key("2001:db8:1:2::1") != key("2001:db8:1:2:ffff::9") {
		t.Error("addresses of one /64 got different budgets")
	}
	if key("2001:db8:1:2::1") == key("2001:db8:1:3::1") {
		t.Error("different /64 blocks share a budget")
	}
	if key("::ffff:192.0.2.1") != key("192.0.2.1") {
		t.Error("a mapped IPv4 address got a budget of its own")
	}
	if key("fe80::1%eth0") != key("fe80::1") {
		t.Error("the zone creates a new budget")
	}
}

func TestLimitsRejectsBadSpends(t *testing.T) {
	p := quota.DefaultProfile()
	if _, err := p.Limits(quota.Spend{Kind: "other", Email: mustEmail(t), Class: authflow.QuotaUnknown, Now: now}); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := p.Limits(quota.Spend{Kind: quota.KindSend, Email: mustEmail(t), Class: "vip", Now: now}); err == nil {
		t.Error("unknown class accepted")
	}
	if _, err := p.Limits(quota.Spend{Kind: quota.KindSend, Email: mustEmail(t), Class: authflow.QuotaUnknown}); err == nil {
		t.Error("a spend without time accepted")
	}
}

func TestNewProfileRejectsImpossibleWindows(t *testing.T) {
	for name, w := range map[string]quota.Window{
		"longer than a day": {Limit: 1, Per: 25 * time.Hour},
		"no length":         {Limit: 1},
		"negative limit":    {Limit: -1, Per: time.Hour},
	} {
		if _, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownSendEmail: {w}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := quota.NewProfile(map[quota.Scope][]quota.Window{"made_up": {{1, time.Hour}}}); err == nil {
		t.Error("unknown scope accepted")
	}
}

// Check the bound against the risk criterion.
func TestDefaultProfileMeetsTheRiskCriterion(t *testing.T) {
	const (
		codes    = 100_000_000
		attempts = 5
		criteria = 0.001
	)
	budget, err := quota.DefaultProfile().ComparisonBudget(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if budget != 50*366 {
		t.Errorf("budget = %d, want %d", budget, 50*366)
	}
	p := quota.GuessBound(codes, attempts, budget)
	if want := 18300.0 / (1e8 - 4); math.Abs(p-want) > 1e-12 || p > criteria {
		t.Errorf("bound = %.6f%%, want %.6f%% and at most %.1f%%", p*100, want*100, criteria*100)
	}
}

func TestRiskGrowsWithABiggerBudgetAndSaturates(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownVerifyEmail: {{1000, 24 * time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := p.ComparisonBudget(365 * 24 * time.Hour)
	if quota.GuessBound(1e8, 5, budget) <= 0.001 {
		t.Error("a 1000-a-day profile should fail the criterion")
	}
	if quota.GuessBound(10, 5, 1000) != 1 {
		t.Error("the bound exceeds 1")
	}
	if quota.GuessBound(0, 5, 1) != 1 {
		t.Error("an impossible input must not look safe")
	}
	if _, err := quota.Unlimited().ComparisonBudget(time.Hour); err == nil {
		t.Error("an unlimited profile has a finite budget")
	}
}

func TestTheTightestWindowDecidesTheBudget(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownVerifyEmail: {{50, 24 * time.Hour}, {1, time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	// One an hour over 24 hours touches 25 buckets: 25 comparisons beat 50 x 2.
	if got, _ := p.ComparisonBudget(24 * time.Hour); got != 25 {
		t.Errorf("budget = %d, want 25", got)
	}
}
