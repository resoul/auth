package testutil

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

func passkeyContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("credentials", func(t *testing.T) { credentialContract(t, newUoW) })
	t.Run("challenges", func(t *testing.T) { challengeContract(t, newUoW) })
	t.Run("tickets", func(t *testing.T) { ticketContract(t, newUoW) })
	t.Run("recovery codes", func(t *testing.T) { recoveryContract(t, newUoW) })
}

func credentialContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a stored credential is read back unchanged and listed oldest first", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		first := f.Credential(CredentialSpec{User: alice})
		f.Clock.Advance(time.Hour)
		second := f.Credential(CredentialSpec{User: alice})
		other := f.Credential(CredentialSpec{User: bob})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, c := range []*passkey.Credential{second, other, first} {
				if err := s.Credentials.Create(ctx, c); err != nil {
					return err
				}
			}

			return nil
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, err := s.Credentials.ListByUser(ctx, alice.ID())
			if err != nil || len(list) != 2 || !reflect.DeepEqual(list[0].Record(), first.Record()) || !reflect.DeepEqual(list[1].Record(), second.Record()) {
				t.Errorf("ListByUser = %+v, %v; want the user's two keys oldest first", list, err)
			}

			got, err := s.Credentials.GetForUpdate(ctx, second.CredentialID())
			if err != nil || !reflect.DeepEqual(got.Record(), second.Record()) {
				t.Errorf("GetForUpdate = %+v, %v", got, err)
			}

			if _, err := s.Credentials.GetForUpdate(ctx, []byte("missing")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate of a missing credential = %v", err)
			}

			return nil
		})
	})

	t.Run("every key of a user can be removed at once, and no one else's", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, c := range []*passkey.Credential{f.Credential(CredentialSpec{User: alice}), f.Credential(CredentialSpec{User: alice}), f.Credential(CredentialSpec{User: bob})} {
				if err := s.Credentials.Create(ctx, c); err != nil {
					return err
				}
			}

			return nil
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			n, err := s.Credentials.DeleteAllForUser(ctx, alice.ID())
			if err != nil || n != 2 {
				t.Errorf("DeleteAllForUser = %d, %v; want 2", n, err)
			}

			mine, _ := s.Credentials.ListByUser(ctx, alice.ID())

			theirs, _ := s.Credentials.ListByUser(ctx, bob.ID())
			if len(mine) != 0 || len(theirs) != 1 {
				t.Errorf("after the delete alice has %d keys and bob %d, want 0 and 1", len(mine), len(theirs))
			}

			if n, err := s.Credentials.DeleteAllForUser(ctx, alice.ID()); err != nil || n != 0 {
				t.Errorf("a second DeleteAllForUser = %d, %v; want 0 and no error", n, err)
			}

			return nil
		})
	})

	t.Run("a credential ID is registered once, for any user", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		c := f.Credential(CredentialSpec{User: alice, CredentialID: []byte("shared")})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Credentials.Create(ctx, c) })

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Credentials.Create(ctx, f.Credential(CredentialSpec{User: bob, CredentialID: []byte("shared")}))
		})
		if !errors.Is(err, port.ErrCredentialConflict) {
			t.Errorf("duplicate credential ID = %v, want ErrCredentialConflict", err)
		}
	})

	t.Run("a refused duplicate leaves the transaction usable", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Credentials.Create(ctx, f.Credential(CredentialSpec{User: alice, CredentialID: []byte("shared")}))
		})

		later := f.Credential(CredentialSpec{User: bob})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Credentials.Create(ctx, f.Credential(CredentialSpec{User: bob, CredentialID: []byte("shared")})); !errors.Is(err, port.ErrCredentialConflict) {
				t.Errorf("duplicate credential ID = %v, want ErrCredentialConflict", err)
			}

			return s.Credentials.Create(ctx, later)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, err := s.Credentials.ListByUser(ctx, bob.ID())
			if err != nil || len(list) != 1 || !bytes.Equal(list[0].CredentialID(), later.CredentialID()) {
				t.Errorf("keys of bob = %+v, %v; want only the one stored after the refusal", list, err)
			}

			return nil
		})
	})

	t.Run("a use is saved, a rolled back use is not", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		c := f.Credential(CredentialSpec{User: alice})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Credentials.Create(ctx, c) })

		use := func(ctx context.Context, s port.Stores) error {
			got, err := s.Credentials.GetForUpdate(ctx, c.CredentialID())
			if err != nil {
				return err
			}

			if err := got.RecordUse(contractNow.Add(time.Minute), 7, true); err != nil {
				return err
			}

			return s.Credentials.Save(ctx, got)
		}
		if err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := use(ctx, s); err != nil {
				return err
			}

			return errContractRollback
		}); !errors.Is(err, errContractRollback) {
			t.Fatalf("rollback = %v", err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, _ := s.Credentials.GetForUpdate(ctx, c.CredentialID())
			if got.SignCount() != 0 || !got.LastUsedAt().IsZero() {
				t.Errorf("a rolled back use is visible: %+v", got.Record())
			}

			return nil
		})
		mustDo(t, uow, use)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, _ := s.Credentials.GetForUpdate(ctx, c.CredentialID())
			if got.SignCount() != 7 || !got.BackupState() || !got.LastUsedAt().Equal(contractNow.Add(time.Minute)) {
				t.Errorf("saved use = %+v", got.Record())
			}

			return nil
		})
	})

	t.Run("delete removes one key but never the last", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		a1, a2 := f.Credential(CredentialSpec{User: alice}), f.Credential(CredentialSpec{User: alice})
		b1 := f.Credential(CredentialSpec{User: bob})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, c := range []*passkey.Credential{a1, a2, b1} {
				if err := s.Credentials.Create(ctx, c); err != nil {
					return err
				}
			}

			return nil
		})

		del := func(c *passkey.Credential, ownerIsAlice bool) error {
			user := alice
			if !ownerIsAlice {
				user = bob
			}

			return do(t, uow, func(ctx context.Context, s port.Stores) error {
				return s.Credentials.Delete(ctx, user.ID(), c.ID())
			})
		}
		if err := del(b1, false); !errors.Is(err, port.ErrLastCredential) {
			t.Errorf("deleting the only key = %v, want ErrLastCredential", err)
		}

		if err := del(b1, true); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("deleting another user's key = %v, want ErrNotFound", err)
		}

		if err := del(a1, true); err != nil {
			t.Errorf("deleting one of two keys = %v", err)
		}

		if err := del(a1, true); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("deleting twice = %v, want ErrNotFound", err)
		}

		if err := del(a2, true); !errors.Is(err, port.ErrLastCredential) {
			t.Errorf("deleting the remaining key = %v, want ErrLastCredential", err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, _ := s.Credentials.ListByUser(ctx, alice.ID())

			other, _ := s.Credentials.ListByUser(ctx, bob.ID())
			if len(list) != 1 || list[0].ID() != a2.ID() || len(other) != 1 {
				t.Errorf("keys left: alice %d, bob %d", len(list), len(other))
			}

			return nil
		})
	})

	t.Run("a delete waits for an open delete of the same user and then sees one key", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		a1, a2 := f.Credential(CredentialSpec{User: alice}), f.Credential(CredentialSpec{User: alice})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Credentials.Create(ctx, a1); err != nil {
				return err
			}

			return s.Credentials.Create(ctx, a2)
		})

		deleted := make(chan struct{})

		first := make(chan error, 1)
		go func() {
			first <- uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
				if err := s.Credentials.Delete(ctx, alice.ID(), a1.ID()); err != nil {
					return err
				}

				close(deleted)
				time.Sleep(300 * time.Millisecond)

				return nil
			})
		}()

		<-deleted

		second := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Credentials.Delete(ctx, alice.ID(), a2.ID())
		})
		if err := <-first; err != nil {
			t.Errorf("first delete = %v", err)
		}

		if !errors.Is(second, port.ErrLastCredential) {
			t.Errorf("second delete = %v, want ErrLastCredential", second)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, _ := s.Credentials.ListByUser(ctx, alice.ID())
			if len(list) != 1 || list[0].ID() != a2.ID() {
				t.Errorf("%d keys left, want exactly a2", len(list))
			}

			return nil
		})
	})
}

func challengeContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a challenge is read back and a consumption is saved", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		login := f.Challenge(ChallengeSpec{Purpose: passkey.ChallengeLogin})
		reg := f.Challenge(ChallengeSpec{User: alice, Purpose: passkey.ChallengeRegistration})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Challenges.Create(ctx, login); err != nil {
				return err
			}

			return s.Challenges.Create(ctx, reg)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Challenges.GetForUpdate(ctx, login.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), login.Record()) || !got.UserID().IsZero() {
				t.Errorf("a login challenge without a user = %+v, %v", got, err)
			}

			if _, err := s.Challenges.GetForUpdate(ctx, f.Challenge(ChallengeSpec{User: alice}).ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("a missing challenge = %v", err)
			}

			got, err = s.Challenges.GetForUpdate(ctx, reg.ID())
			if err != nil {
				return err
			}

			if err := got.Consume(contractNow.Add(time.Second), passkey.ChallengeRegistration); err != nil {
				return err
			}

			return s.Challenges.Save(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, _ := s.Challenges.GetForUpdate(ctx, reg.ID())
			if err := got.Consume(contractNow.Add(2*time.Second), passkey.ChallengeRegistration); !errors.Is(err, passkey.ErrChallengeUsed) {
				t.Errorf("second consumption = %v, want ErrChallengeUsed", err)
			}

			return nil
		})
	})

	t.Run("a step-up challenge keeps its session and operation", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		sess, _ := seedSession(t, uow, f, alice)
		c := f.Challenge(ChallengeSpec{User: alice, Purpose: passkey.ChallengeStepUp, Session: sess.ID(), Operation: passkey.OperationDeletePasskey})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Challenges.Create(ctx, c) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Challenges.GetForUpdate(ctx, c.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), c.Record()) {
				t.Errorf("GetForUpdate = %+v, %v", got, err)
			}

			return nil
		})
	})

	t.Run("two concurrent consumptions of one challenge: exactly one wins", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		c := f.Challenge(ChallengeSpec{Purpose: passkey.ChallengeLogin})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Challenges.Create(ctx, c) })

		var wg sync.WaitGroup

		results := make([]error, 4)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()

				results[i] = uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					got, err := s.Challenges.GetForUpdate(ctx, c.ID())
					if err != nil {
						return err
					}

					if err := got.Consume(contractNow.Add(time.Second), passkey.ChallengeLogin); err != nil {
						return err
					}

					return s.Challenges.Save(ctx, got)
				})
			}()
		}

		wg.Wait()

		won := 0

		for _, err := range results {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, passkey.ErrChallengeUsed):
				t.Errorf("loser = %v, want ErrChallengeUsed", err)
			}
		}

		if won != 1 {
			t.Errorf("%d consumptions won, want 1", won)
		}
	})
}

func ticketContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a ticket is found by the hash of its secret", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		tk := f.Ticket(TicketSpec{User: alice, Secret: "s-1"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, tk) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Tickets.GetByHashForUpdate(ctx, SecretHash("s-1"))
			if err != nil || !reflect.DeepEqual(got.Record(), tk.Record()) {
				t.Errorf("GetByHashForUpdate = %+v, %v", got, err)
			}

			byID, err := s.Tickets.GetForUpdate(ctx, tk.ID())
			if err != nil || byID.ID() != tk.ID() {
				t.Errorf("GetForUpdate = %+v, %v", byID, err)
			}

			if _, err := s.Tickets.GetByHashForUpdate(ctx, SecretHash("other")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("an unknown secret = %v", err)
			}

			return nil
		})
	})

	t.Run("a step-up ticket keeps its session and operation", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		sess, _ := seedSession(t, uow, f, alice)
		tk := f.Ticket(TicketSpec{User: alice, Kind: passkey.TicketStepUp, Session: sess.ID(), Operation: passkey.OperationChangeEmail})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, tk) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Tickets.GetForUpdate(ctx, tk.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), tk.Record()) {
				t.Errorf("GetForUpdate = %+v, %v", got, err)
			}

			return nil
		})
	})

	t.Run("a secret hash is stored once", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Tickets.Create(ctx, f.Ticket(TicketSpec{User: alice, Secret: "same"}))
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Tickets.Create(ctx, f.Ticket(TicketSpec{User: alice, Secret: "same"}))
		})
		if !errors.Is(err, port.ErrTicketConflict) {
			t.Errorf("duplicate hash = %v, want ErrTicketConflict", err)
		}
	})

	t.Run("two concurrent redemptions of one ticket: exactly one wins", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		tk := f.Ticket(TicketSpec{User: alice, Secret: "race"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, tk) })

		var wg sync.WaitGroup

		results := make([]error, 4)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()

				results[i] = uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					got, err := s.Tickets.GetByHashForUpdate(ctx, SecretHash("race"))
					if err != nil {
						return err
					}

					if err := got.Use(contractNow.Add(time.Second), passkey.Presented{Kind: passkey.TicketEnroll, Binding: BindingHash(DefaultBindingSecret)}); err != nil {
						return err
					}

					return s.Tickets.Save(ctx, got)
				})
			}()
		}

		wg.Wait()

		won := 0

		for _, err := range results {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, passkey.ErrTicketUsed):
				t.Errorf("loser = %v, want ErrTicketUsed", err)
			}
		}

		if won != 1 {
			t.Errorf("%d redemptions won, want 1", won)
		}
	})

	t.Run("revoking spends the live tickets of one user, except the step-up tickets of the kept session", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		bob := seedUser(t, uow, f, "bob@example.test")
		kept, _ := seedSession(t, uow, f, alice)
		other, _ := seedSession(t, uow, f, alice)

		enroll := f.Ticket(TicketSpec{User: alice})
		recovery := f.Ticket(TicketSpec{User: alice, Kind: passkey.TicketRecoveryEnroll})
		keptStepUp := f.Ticket(TicketSpec{User: alice, Kind: passkey.TicketStepUp, Session: kept.ID(), Operation: passkey.OperationAddPasskey})
		otherStepUp := f.Ticket(TicketSpec{User: alice, Kind: passkey.TicketStepUp, Session: other.ID(), Operation: passkey.OperationAddPasskey})
		spent := f.Ticket(TicketSpec{User: alice})
		bobs := f.Ticket(TicketSpec{User: bob})

		spentAt := contractNow.Add(time.Second)
		revokedAt := contractNow.Add(2 * time.Second)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, tk := range []*passkey.Ticket{enroll, recovery, keptStepUp, otherStepUp, spent, bobs} {
				if err := s.Tickets.Create(ctx, tk); err != nil {
					return err
				}
			}

			if err := spent.Use(spentAt, passkey.Presented{Kind: passkey.TicketEnroll, Binding: BindingHash(DefaultBindingSecret)}); err != nil {
				return err
			}

			if err := s.Tickets.Save(ctx, spent); err != nil {
				return err
			}

			return s.Tickets.RevokeAllForUser(ctx, alice.ID(), kept.ID(), revokedAt)
		})

		consumedAt := func(tk *passkey.Ticket) time.Time {
			t.Helper()

			var at time.Time

			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				got, err := s.Tickets.GetForUpdate(ctx, tk.ID())
				if err != nil {
					return err
				}

				at = got.ConsumedAt()

				return nil
			})

			return at
		}

		for name, tk := range map[string]*passkey.Ticket{"enroll": enroll, "recovery": recovery, "step-up of another session": otherStepUp} {
			if got := consumedAt(tk); !got.Equal(revokedAt) {
				t.Errorf("%s ticket consumed at %v, want %v", name, got, revokedAt)
			}
		}

		if got := consumedAt(keptStepUp); !got.IsZero() {
			t.Errorf("step-up ticket of the kept session consumed at %v, want live", got)
		}

		if got := consumedAt(spent); !got.Equal(spentAt) {
			t.Errorf("a spent ticket was rewritten: consumed at %v, want %v", got, spentAt)
		}

		if got := consumedAt(bobs); !got.IsZero() {
			t.Errorf("a ticket of another user consumed at %v, want live", got)
		}

		fresh := f.Ticket(TicketSpec{User: alice})
		late := contractNow.Add(passkey.StepUpTicketTTL + time.Minute)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Tickets.Create(ctx, fresh); err != nil {
				return err
			}

			return s.Tickets.RevokeAllForUser(ctx, alice.ID(), session.ID{}, late)
		})

		if got := consumedAt(fresh); !got.Equal(late) {
			t.Errorf("live ticket consumed at %v, want %v", got, late)
		}

		if got := consumedAt(keptStepUp); !got.IsZero() {
			t.Errorf("an expired ticket was rewritten: consumed at %v", got)
		}
	})
}

func recoveryContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("replace supersedes the whole set of one user only", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Recovery.Replace(ctx, alice.ID(), []*passkey.RecoveryCode{f.RecoveryCode(alice, "a1"), f.RecoveryCode(alice, "a2"), f.RecoveryCode(alice, "a3")}); err != nil {
				return err
			}

			return s.Recovery.Replace(ctx, bob.ID(), []*passkey.RecoveryCode{f.RecoveryCode(bob, "b1")})
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if n, _ := s.Recovery.CountUnused(ctx, alice.ID()); n != 3 {
				t.Errorf("alice has %d codes, want 3", n)
			}

			return s.Recovery.Replace(ctx, alice.ID(), []*passkey.RecoveryCode{f.RecoveryCode(alice, "a4"), f.RecoveryCode(alice, "a5")})
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if n, _ := s.Recovery.CountUnused(ctx, alice.ID()); n != 2 {
				t.Errorf("alice has %d codes after replace, want 2", n)
			}

			if n, _ := s.Recovery.CountUnused(ctx, bob.ID()); n != 1 {
				t.Errorf("bob has %d codes, want 1: replace must not touch other users", n)
			}

			if _, err := s.Recovery.GetByHashForUpdate(ctx, SecretHash("a1")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("a superseded code = %v, want ErrNotFound", err)
			}

			return nil
		})
	})

	t.Run("a code is used once", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Recovery.Replace(ctx, alice.ID(), []*passkey.RecoveryCode{f.RecoveryCode(alice, "c1"), f.RecoveryCode(alice, "c2")})
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			c, err := s.Recovery.GetByHashForUpdate(ctx, SecretHash("c1"))
			if err != nil {
				return err
			}

			if err := c.Use(contractNow.Add(time.Second)); err != nil {
				return err
			}

			return s.Recovery.Save(ctx, c)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			c, _ := s.Recovery.GetByHashForUpdate(ctx, SecretHash("c1"))
			if err := c.Use(contractNow.Add(2 * time.Second)); !errors.Is(err, passkey.ErrRecoveryCodeUsed) {
				t.Errorf("second use = %v", err)
			}

			if n, _ := s.Recovery.CountUnused(ctx, alice.ID()); n != 1 {
				t.Errorf("%d unused, want 1", n)
			}

			return nil
		})
	})

	t.Run("two concurrent redemptions of one code: exactly one wins", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Recovery.Replace(ctx, alice.ID(), []*passkey.RecoveryCode{f.RecoveryCode(alice, "race")})
		})

		var wg sync.WaitGroup

		results := make([]error, 4)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()

				results[i] = uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					c, err := s.Recovery.GetByHashForUpdate(ctx, SecretHash("race"))
					if err != nil {
						return err
					}

					if err := c.Use(contractNow.Add(time.Second)); err != nil {
						return err
					}

					return s.Recovery.Save(ctx, c)
				})
			}()
		}

		wg.Wait()

		won := 0

		for _, err := range results {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, passkey.ErrRecoveryCodeUsed):
				t.Errorf("loser = %v, want ErrRecoveryCodeUsed", err)
			}
		}

		if won != 1 {
			t.Errorf("%d redemptions won, want 1", won)
		}
	})
}
