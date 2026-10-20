package testutil

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

type outboxFixture struct {
	uow  port.UnitOfWork
	f    *Factory
	user *identity.User
}

func newOutboxFixture(t *testing.T, newUoW NewUnitOfWork) outboxFixture {
	t.Helper()
	uow, f := newUoW(t), NewFactory(t, contractNow)

	return outboxFixture{uow: uow, f: f, user: seedUser(t, uow, f, "")}
}

// enqueue stores a flow of the class and queues its first mail, due at the given time.
func (fx outboxFixture) enqueue(t *testing.T, class authflow.QuotaClass, due time.Time) port.MailJob {
	t.Helper()

	spec := FlowSpec{}

	if class == authflow.QuotaRecognized {
		client := fx.f.RecognizedClient(RecognizedSpec{User: fx.user, BindingSecret: fx.f.RefreshSecret()})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			stored, err := s.Recognized.Register(ctx, client)
			spec.RecognizedClientID = stored.ID()

			return err
		})

		spec.QuotaClass = authflow.QuotaRecognized
	}

	flow := fx.f.Flow(spec)
	job := port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: class, AvailableAt: due}

	mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
		if err := s.Flows.Create(ctx, flow); err != nil {
			return err
		}

		return s.Outbox.Enqueue(ctx, job)
	})

	return job
}

func (fx outboxFixture) claim(t *testing.T, now time.Time, lease time.Duration) (port.ClaimedMail, error) {
	t.Helper()

	var claimed port.ClaimedMail

	err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
		var err error

		claimed, err = s.Outbox.Claim(ctx, now, lease)

		return err
	})

	return claimed, err
}

func outboxContract(t *testing.T, newUoW NewUnitOfWork) {
	const lease = 2 * time.Minute

	t.Run("a flow generation is queued once", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		job := fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) })
		if err == nil {
			t.Error("a second job for the same flow generation was accepted")
		}
	})

	t.Run("a notice is queued next to the code of its flow and keeps its recipient", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)

		old, err := identity.ParseEmail("old@example.test")
		if err != nil {
			t.Fatal(err)
		}

		flow := fx.f.Flow(FlowSpec{Purpose: authflow.PurposeChangeEmail, UserID: fx.user.ID()})
		code := port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow}
		notice := port.MailJob{Kind: port.JobEmailChanged, FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow.Add(time.Second), Recipient: old}

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Flows.Create(ctx, flow); err != nil {
				return err
			}

			if err := s.Outbox.Enqueue(ctx, code); err != nil {
				return err
			}

			return s.Outbox.Enqueue(ctx, notice)
		})

		now := contractNow.Add(time.Minute)

		first, err := fx.claim(t, now, lease)
		if err != nil || first.Kind != port.JobCode || !first.Recipient.IsZero() || first.FlowID != flow.ID() {
			t.Fatalf("first claim = %+v, %v; want the code job", first, err)
		}

		second, err := fx.claim(t, now, lease)
		if err != nil || second.Kind != port.JobEmailChanged || second.Recipient != old || second.FlowID != flow.ID() || second.Generation != 1 {
			t.Fatalf("second claim = %+v, %v; want the notice for the old address", second, err)
		}

		again := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, notice) })
		if again == nil {
			t.Error("a second notice for the same flow generation was accepted")
		}
	})

	t.Run("an invitation job has no flow, keeps its recipient and may repeat", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)

		guest, err := identity.ParseEmail("guest@example.test")
		if err != nil {
			t.Fatal(err)
		}

		job := port.MailJob{Kind: port.JobInvitation, Recipient: guest, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow}
		// The same address may be invited again: nothing identifies the job but its own row.
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Outbox.Enqueue(ctx, job); err != nil {
				return err
			}

			return s.Outbox.Enqueue(ctx, job)
		})

		for i := 0; i < 2; i++ {
			got, err := fx.claim(t, contractNow.Add(time.Minute), lease)
			if err != nil || got.Kind != port.JobInvitation || got.Recipient != guest || !got.FlowID.IsZero() || got.QuotaClass != authflow.QuotaUnknown {
				t.Fatalf("claim %d = %+v, %v; want an invitation job without a flow", i, got, err)
			}

			mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Complete(ctx, got.ID) })
		}
	})

	t.Run("a new device job has no flow, keeps what the mail shows and goes with its user", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		ip := netip.MustParseAddr("203.0.113.7")
		job := port.MailJob{
			Kind: port.JobNewDevice, QuotaClass: authflow.QuotaRecognized, AvailableAt: contractNow,
			UserID: fx.user.ID(), DeviceName: "Office laptop", ClientIP: ip, EventAt: contractNow,
		}
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) })

		got, err := fx.claim(t, contractNow.Add(time.Minute), lease)
		if err != nil || got.Kind != port.JobNewDevice || !got.FlowID.IsZero() || got.UserID != fx.user.ID() || got.DeviceName != "Office laptop" ||
			got.ClientIP != ip || !got.EventAt.Equal(contractNow) || !got.Recipient.IsZero() {
			t.Fatalf("claim = %+v, %v; want the new device job as queued", got, err)
		}
		// An unknown address is kept as unknown.
		job.ClientIP = netip.Addr{}

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) })

		if second, err := fx.claim(t, contractNow.Add(time.Minute), lease); err != nil || second.ClientIP.IsValid() {
			t.Fatalf("claim = %+v, %v; want an unknown address", second, err)
		}
		// The notices of a deleted user are deleted with them.
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) })
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Users.Delete(ctx, fx.user.ID()) })

		if got, err := fx.claim(t, contractNow.Add(time.Hour), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("the job of a deleted user survived: %+v, %v", got, err)
		}
	})

	t.Run("a new device job that does not fit its kind is refused", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		guest, _ := identity.ParseEmail("guest@example.test")
		flow := fx.f.Flow(FlowSpec{})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })
		ok := port.MailJob{Kind: port.JobNewDevice, QuotaClass: authflow.QuotaRecognized, AvailableAt: contractNow, UserID: fx.user.ID(), EventAt: contractNow}

		with := func(edit func(*port.MailJob)) port.MailJob { j := ok; edit(&j); return j }
		for name, job := range map[string]port.MailJob{
			"without a user":   with(func(j *port.MailJob) { j.UserID = identity.UserID{} }),
			"without a time":   with(func(j *port.MailJob) { j.EventAt = time.Time{} }),
			"with a flow":      with(func(j *port.MailJob) { j.FlowID, j.Generation = flow.ID(), 1 }),
			"with a recipient": with(func(j *port.MailJob) { j.Recipient = guest }),
			"with a bad name":  with(func(j *port.MailJob) { j.DeviceName = "line\nbreak" }),
		} {
			if err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) }); err == nil {
				t.Errorf("Enqueue accepted a new device job %s", name)
			}
		}
	})

	t.Run("an invitation job that does not fit its kind is refused", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		guest, _ := identity.ParseEmail("guest@example.test")
		flow := fx.f.Flow(FlowSpec{})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		for name, job := range map[string]port.MailJob{
			"without a recipient": {Kind: port.JobInvitation, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow},
			"with a flow":         {Kind: port.JobInvitation, FlowID: flow.ID(), Generation: 1, Recipient: guest, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow},
		} {
			if err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) }); err == nil {
				t.Errorf("Enqueue accepted an invitation job %s", name)
			}
		}
	})

	t.Run("a job no worker could carry out is refused", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		old, _ := identity.ParseEmail("old@example.test")
		flow := fx.f.Flow(FlowSpec{Purpose: authflow.PurposeChangeEmail, UserID: fx.user.ID()})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		base := port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: contractNow}
		for name, job := range map[string]port.MailJob{
			"a notice without a recipient": {Kind: port.JobEmailChanged, FlowID: base.FlowID, Generation: 1, QuotaClass: base.QuotaClass, AvailableAt: base.AvailableAt},
			"a code with a recipient":      {FlowID: base.FlowID, Generation: 1, QuotaClass: base.QuotaClass, AvailableAt: base.AvailableAt, Recipient: old},
			"an unknown kind":              {Kind: "newsletter", FlowID: base.FlowID, Generation: 1, QuotaClass: base.QuotaClass, AvailableAt: base.AvailableAt, Recipient: old},
		} {
			if err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Enqueue(ctx, job) }); err == nil {
				t.Errorf("Enqueue accepted %s", name)
			}
		}

		if _, err := fx.claim(t, contractNow.Add(time.Hour), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("a refused job was queued: %v", err)
		}
	})

	t.Run("claim takes the oldest due job, counts the attempt and leases it", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		late := fx.enqueue(t, authflow.QuotaUnknown, contractNow.Add(10*time.Second))
		early := fx.enqueue(t, authflow.QuotaUnknown, contractNow)
		now := contractNow.Add(time.Minute)

		first, err := fx.claim(t, now, lease)
		if err != nil || first.FlowID != early.FlowID || first.Attempts != 1 || first.Generation != 1 || first.QuotaClass != authflow.QuotaUnknown ||
			first.Kind != port.JobCode || !first.Recipient.IsZero() {
			t.Fatalf("first claim = %+v, %v; want the early job on attempt 1", first, err)
		}

		if !first.AvailableAt.Equal(early.AvailableAt) {
			t.Errorf("AvailableAt = %v", first.AvailableAt)
		}

		second, err := fx.claim(t, now, lease)
		if err != nil || second.FlowID != late.FlowID {
			t.Fatalf("second claim = %+v, %v; want the late job", second, err)
		}

		if _, err := fx.claim(t, now, lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("third claim = %v, want ErrNotFound: both jobs are leased", err)
		}
	})

	t.Run("a job that is not due yet is not claimed", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow.Add(time.Hour))

		if _, err := fx.claim(t, contractNow, lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("claim before the due time = %v", err)
		}

		if _, err := fx.claim(t, contractNow.Add(time.Hour), lease); err != nil {
			t.Errorf("claim at the due time: %v", err)
		}
	})

	t.Run("an expired lease makes the job claimable again", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)

		job := fx.enqueue(t, authflow.QuotaUnknown, contractNow)
		if _, err := fx.claim(t, contractNow, lease); err != nil {
			t.Fatal(err)
		}

		if _, err := fx.claim(t, contractNow.Add(lease-time.Second), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("claim inside the lease = %v", err)
		}

		again, err := fx.claim(t, contractNow.Add(lease), lease)
		if err != nil || again.FlowID != job.FlowID || again.Attempts != 2 {
			t.Errorf("claim after the lease = %+v, %v; want the same job on attempt 2", again, err)
		}
	})

	t.Run("recognized clients are served before older unknown jobs", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		for i := 0; i < 3; i++ {
			fx.enqueue(t, authflow.QuotaUnknown, contractNow)
		}

		recognized := fx.enqueue(t, authflow.QuotaRecognized, contractNow.Add(30*time.Second))

		got, err := fx.claim(t, contractNow.Add(time.Minute), lease)
		if err != nil || got.FlowID != recognized.FlowID || got.QuotaClass != authflow.QuotaRecognized {
			t.Errorf("claim = %+v, %v; want the recognized job first", got, err)
		}
	})

	t.Run("complete removes the job from the queue", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		claimed, err := fx.claim(t, contractNow, lease)
		if err != nil {
			t.Fatal(err)
		}

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Complete(ctx, claimed.ID) })

		if _, err := fx.claim(t, contractNow.Add(24*time.Hour), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("a sent job was claimed again: %v", err)
		}

		err = do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Complete(ctx, claimed.ID) })
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("second Complete = %v, want ErrNotFound", err)
		}
	})

	t.Run("retry delays the job, releases the lease and keeps the attempt count", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		claimed, err := fx.claim(t, contractNow, lease)
		if err != nil {
			t.Fatal(err)
		}

		retryAt := contractNow.Add(5 * time.Minute)

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Outbox.Retry(ctx, claimed.ID, retryAt, "smtp_temporary")
		})

		if _, err := fx.claim(t, retryAt.Add(-time.Second), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("claim before the retry time = %v", err)
		}

		again, err := fx.claim(t, retryAt, lease)
		if err != nil || again.ID != claimed.ID || again.Attempts != 2 || !again.AvailableAt.Equal(retryAt) {
			t.Errorf("claim at the retry time = %+v, %v", again, err)
		}
	})

	t.Run("abandon ends the job for good", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		claimed, err := fx.claim(t, contractNow, lease)
		if err != nil {
			t.Fatal(err)
		}

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Outbox.Abandon(ctx, claimed.ID, "smtp_rejected")
		})

		if _, err := fx.claim(t, contractNow.Add(24*time.Hour), lease); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("an abandoned job was claimed again: %v", err)
		}

		err = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Outbox.Retry(ctx, claimed.ID, contractNow, "late_retry")
		})
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Retry of a finished job = %v, want ErrNotFound", err)
		}
	})

	t.Run("reasons must be safe codes", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		claimed, err := fx.claim(t, contractNow, lease)
		if err != nil {
			t.Fatal(err)
		}

		for _, reason := range []port.MailReason{"", "550 5.1.1 alice@example.test unknown", "Upper", "with space", "1starts_with_digit"} {
			err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Abandon(ctx, claimed.ID, reason) })
			if err == nil {
				t.Errorf("Abandon accepted reason %q", reason)
			}

			err = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
				return s.Outbox.Retry(ctx, claimed.ID, contractNow, reason)
			})
			if err == nil {
				t.Errorf("Retry accepted reason %q", reason)
			}
		}
	})

	t.Run("a claim in a rolled back transaction leaves the job ready", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)

		_ = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Outbox.Claim(ctx, contractNow, lease); err != nil {
				return err
			}

			return errContractRollback
		})
		if got, err := fx.claim(t, contractNow, lease); err != nil || got.Attempts != 1 {
			t.Errorf("claim after the rollback = %+v, %v; want attempt 1", got, err)
		}
	})

	t.Run("stats count queued jobs per class and the oldest wait", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)
		fx.enqueue(t, authflow.QuotaUnknown, contractNow.Add(20*time.Second))
		fx.enqueue(t, authflow.QuotaRecognized, contractNow.Add(10*time.Second))
		fx.enqueue(t, authflow.QuotaUnknown, contractNow.Add(time.Hour)) // not due: counts as queued, adds no wait
		fx.enqueue(t, authflow.QuotaUnknown, contractNow)
		// One of the two oldest unknown jobs is sent; the other keeps the wait at a minute.
		claimed, err := fx.claim(t, contractNow, lease)
		if err != nil {
			t.Fatal(err)
		}

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Outbox.Complete(ctx, claimed.ID) })

		var stats port.QueueStats

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			var err error

			stats, err = s.Outbox.Stats(ctx, contractNow.Add(time.Minute))

			return err
		})

		if stats.Queued[authflow.QuotaUnknown] != 3 || stats.Queued[authflow.QuotaRecognized] != 1 {
			t.Errorf("queued = %v, want unknown 3 and recognized 1", stats.Queued)
		}

		if got := stats.OldestWait[authflow.QuotaUnknown]; got != time.Minute {
			t.Errorf("oldest unknown wait = %v, want 1m", got)
		}

		if got := stats.OldestWait[authflow.QuotaRecognized]; got != 50*time.Second {
			t.Errorf("oldest recognized wait = %v, want 50s", got)
		}
	})

	t.Run("concurrent workers never claim a job twice", func(t *testing.T) {
		fx := newOutboxFixture(t, newUoW)

		const jobs, workers = 12, 6

		want := map[authflow.FlowID]bool{}
		for i := 0; i < jobs; i++ {
			want[fx.enqueue(t, authflow.QuotaUnknown, contractNow).FlowID] = true
		}

		var mu sync.Mutex

		claimed := map[authflow.FlowID]int{}

		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for {
					var got port.ClaimedMail

					err := fx.uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
						var err error

						got, err = s.Outbox.Claim(ctx, contractNow, time.Hour)

						return err
					})
					if errors.Is(err, port.ErrNotFound) {
						return
					}

					if err != nil {
						t.Errorf("claim: %v", err)
						return
					}

					mu.Lock()
					claimed[got.FlowID]++
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		if len(claimed) != jobs {
			t.Errorf("%d jobs were claimed, want %d", len(claimed), jobs)
		}

		for flow, n := range claimed {
			if n != 1 || !want[flow] {
				t.Errorf("job of flow %s was claimed %d times", flow, n)
			}
		}
	})
}
