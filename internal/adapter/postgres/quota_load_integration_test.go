//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

type fixedQuotaClock struct{}

func (fixedQuotaClock) Now() time.Time { return t0 }

type quotaLoadCase struct {
	name  string
	limit int // zero means every independent request should be admitted
	rows  int // scopes written by each admitted request
	spend func(int) port.Spend
}

func quotaLoadCases(t *testing.T) []quotaLoadCase {
	t.Helper()

	email, err := identity.ParseEmail("target@example.test")
	if err != nil {
		t.Fatal(err)
	}

	ip := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	passkey := func(i int) port.Spend { return port.Spend{Kind: quota.KindPasskey, IP: ip(i), Now: t0} }
	send := func(i int) port.Spend {
		return port.Spend{Kind: quota.KindSend, Email: email, Class: authflow.QuotaUnknown,
			Binding: testutil.BindingHash(fmt.Sprintf("binding-%d", i)), IP: ip(i), Now: t0}
	}
	uniqueEmail := func(i int) identity.Email {
		email, err := identity.ParseEmail(fmt.Sprintf("new-%d@example.test", i))
		if err != nil {
			t.Fatal(err)
		}

		return email
	}

	return []quotaLoadCase{
		{"passkey_ip", 60, 1, func(i int) port.Spend { s := passkey(i); s.IP = ip(1); return s }},
		{"passkey_ref_rotating_ip", 10, 2, func(i int) port.Spend { s := passkey(i); s.Ref = "same-ticket"; return s }},
		{"passkey_ipv6_64", 60, 1, func(i int) port.Spend {
			s := passkey(i)
			addr := netip.MustParseAddr("2001:db8:1:2::").As16()
			addr[14], addr[15] = byte(i>>8), byte(i)
			s.IP = netip.AddrFrom16(addr)

			return s
		}},
		{"passkey_unknown_ip", 60, 1, func(i int) port.Spend { s := passkey(i); s.IP = netip.Addr{}; return s }},
		{"passkey_distributed", 0, 2, func(i int) port.Spend { s := passkey(i); s.Ref = fmt.Sprintf("ticket-%d", i); return s }},
		{"email_change_new_address", 10, 3, send},
		{"email_change_shared_ip", 20, 3, func(i int) port.Spend { s := send(i); s.Email = uniqueEmail(i); s.IP = ip(1); return s }},
		{"email_change_distributed", 0, 3, func(i int) port.Spend { s := send(i); s.Email = uniqueEmail(i); return s }},
		{"email_verify_rotating_clients", 50, 2, func(i int) port.Spend { s := send(i); s.Kind = quota.KindVerify; return s }},
	}
}

type quotaLoadSample struct {
	duration time.Duration
	allowed  bool
	err      error
}

func runQuotaLoad(t *testing.T, store port.UnitOfWork, spends []port.Spend, workers int) ([]quotaLoadSample, time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	samples := make([]quotaLoadSample, len(spends))
	jobs := make(chan int)

	var wg sync.WaitGroup

	started := time.Now()

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := range jobs {
				before := time.Now()
				err := store.Do(ctx, func(ctx context.Context, st port.Stores) error {
					var err error

					samples[i].allowed, err = st.Limiter.Allow(ctx, spends[i])

					return err
				})
				samples[i].duration, samples[i].err = time.Since(before), err
			}
		}()
	}

	for i := range spends {
		jobs <- i
	}

	close(jobs)
	wg.Wait()

	return samples, time.Since(started)
}

func latencyPercentiles(samples []quotaLoadSample) map[string]float64 {
	if len(samples) == 0 {
		return nil
	}

	durations := make([]time.Duration, len(samples))
	for i, sample := range samples {
		durations[i] = sample.duration
	}

	slices.Sort(durations)

	result := make(map[string]float64)

	for _, percentile := range []int{50, 95, 99} {
		index := (len(durations)*percentile+99)/100 - 1 // nearest-rank percentile
		result[fmt.Sprintf("p%d_ms", percentile)] = float64(durations[index]) / float64(time.Millisecond)
	}

	return result
}

// Opt-in load run: no SMTP, no HTTP, no production quota changes. All rows live in
// fresh schemas and are dropped by the existing integration harness.
func TestQuotaLoad(t *testing.T) {
	if os.Getenv("AIRLANCE_AUTH_QUOTA_LOAD") != "1" {
		t.Skip("run make quota-load to measure limiter transactions")
	}

	requests := loadInteger(t, "AIRLANCE_AUTH_QUOTA_LOAD_REQUESTS", 1000, 100, 100000)
	pool := loadInteger(t, "AIRLANCE_AUTH_QUOTA_LOAD_POOL", 8, 1, 64)

	workerText := os.Getenv("AIRLANCE_AUTH_QUOTA_LOAD_WORKERS")
	if workerText == "" {
		workerText = "1,8,32"
	}

	selected := strings.Split(os.Getenv("AIRLANCE_AUTH_QUOTA_LOAD_SCENARIOS"), ",")
	for _, worker := range strings.Split(workerText, ",") {
		workers, err := strconv.Atoi(worker)
		if err != nil || workers < 1 || workers > 256 {
			t.Fatal("load workers must be integers between 1 and 256")
		}

		for _, scenario := range quotaLoadCases(t) {
			if selected[0] != "" && !slices.Contains(selected, scenario.name) {
				continue
			}

			t.Run(fmt.Sprintf("%s/workers_%d", scenario.name, workers), func(t *testing.T) {
				store, db := newStoreWith(t, postgres.WithMaxConns(int32(pool)))

				spends := make([]port.Spend, requests)
				for i := range spends {
					spends[i] = scenario.spend(i)
				}

				samples, elapsed := runQuotaLoad(t, store, spends, workers)

				var admitted, refused []quotaLoadSample

				for _, sample := range samples {
					if sample.err != nil {
						t.Fatalf("limiter transaction: %v", sample.err)
					}

					if sample.allowed {
						admitted = append(admitted, sample)
					} else {
						refused = append(refused, sample)
					}
				}

				want := requests
				if scenario.limit > 0 {
					want = scenario.limit
				}

				rows := count(t, db, "quota_events")
				if len(admitted) != want || rows != want*scenario.rows {
					t.Fatalf("admitted %d (want %d), quota rows %d (want %d)", len(admitted), want, rows, want*scenario.rows)
				}

				var version string
				if err := db.QueryRow("SHOW server_version").Scan(&version); err != nil {
					t.Fatal(err)
				}

				report := map[string]any{"scenario": scenario.name, "requests": requests, "workers": workers,
					"pool_connections": pool, "postgres_version": version, "admitted": len(admitted), "refused": len(refused),
					"quota_rows": rows, "elapsed_seconds": elapsed.Seconds(), "transactions_per_second": float64(requests) / elapsed.Seconds(),
					"latency": latencyPercentiles(samples), "admitted_latency": latencyPercentiles(admitted), "refused_latency": latencyPercentiles(refused)}

				data, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}

				t.Log("QUOTA_LOAD " + string(data))
			})
		}
	}
}

func loadInteger(t *testing.T, name string, fallback, low, high int) int {
	t.Helper()

	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	number, err := strconv.Atoi(value)
	if err != nil || number < low || number > high {
		t.Fatalf("%s must be between %d and %d", name, low, high)
	}

	return number
}
