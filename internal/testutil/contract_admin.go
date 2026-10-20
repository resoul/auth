package testutil

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
)

func adminContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("blocking", func(t *testing.T) { blockContract(t, newUoW) })
	t.Run("user list", func(t *testing.T) { userListContract(t, newUoW) })
	t.Run("audit list", func(t *testing.T) { auditListContract(t, newUoW) })
	t.Run("operators", func(t *testing.T) { operatorContract(t, newUoW) })
	t.Run("operator enrollments", func(t *testing.T) { enrollmentContract(t, newUoW) })
	t.Run("operator credentials", func(t *testing.T) { operatorCredentialContract(t, newUoW) })
	t.Run("operator challenges", func(t *testing.T) { operatorChallengeContract(t, newUoW) })
	t.Run("operator sessions", func(t *testing.T) { operatorSessionContract(t, newUoW) })
}

func blockContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("the blocked state is stored and cleared", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			_, _, err := s.Users.Ensure(ctx, user)
			return err
		})

		later := contractNow.Add(time.Hour)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if u.Blocked() {
				t.Error("a new user is blocked")
			}

			if err := u.Block(later); err != nil {
				return err
			}

			return s.Users.SetBlocked(ctx, u)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			byID, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			byEmail, err := s.Users.FindByEmail(ctx, user.Email())
			if err != nil {
				return err
			}

			for name, u := range map[string]*identity.User{"Get": byID, "FindByEmail": byEmail} {
				if !u.Blocked() || !u.BlockedAt().Equal(later) || !u.UpdatedAt().Equal(later) {
					t.Errorf("%s after Block: blocked=%v at=%v updated=%v", name, u.Blocked(), u.BlockedAt(), u.UpdatedAt())
				}
			}

			again, created, err := s.Users.Ensure(ctx, f.User(UserSpec{Email: user.Email().String()}))
			if err != nil || created || !again.Blocked() {
				t.Errorf("Ensure of a blocked address = blocked %v, created %v, %v", again != nil && again.Blocked(), created, err)
			}

			if err := byID.Unblock(later.Add(time.Hour)); err != nil {
				return err
			}

			return s.Users.SetBlocked(ctx, byID)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.Get(ctx, user.ID())
			if err != nil || u.Blocked() || !u.UpdatedAt().Equal(later.Add(time.Hour)) {
				t.Errorf("after Unblock: %+v, %v", u, err)
			}

			return nil
		})
	})

	t.Run("a user that is gone cannot be blocked", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)

		ghost := f.User(UserSpec{})
		if err := ghost.Block(contractNow); err != nil {
			t.Fatal(err)
		}

		err := do(t, uow, func(ctx context.Context, s port.Stores) error { return s.Users.SetBlocked(ctx, ghost) })
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("SetBlocked of an unknown user = %v, want ErrNotFound", err)
		}
	})
}

func userListContract(t *testing.T, newUoW NewUnitOfWork) {
	seed := func(t *testing.T, emails ...string) port.UnitOfWork {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, e := range emails {
				if _, _, err := s.Users.Ensure(ctx, f.User(UserSpec{Email: e})); err != nil {
					return err
				}
			}

			return nil
		})

		return uow
	}
	list := func(t *testing.T, uow port.UnitOfWork, q port.UserQuery) []string {
		t.Helper()

		var out []string

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			users, err := s.Users.List(ctx, q)
			for _, u := range users {
				out = append(out, u.Email().String())
			}

			return err
		})

		return out
	}

	t.Run("users come in address order and page by the last address", func(t *testing.T) {
		uow := seed(t, "dave@example.test", "alice@example.test", "carol@example.test", "bob@example.test")
		first := list(t, uow, port.UserQuery{Limit: 3})

		want := []string{"alice@example.test", "bob@example.test", "carol@example.test"}
		if strings.Join(first, ",") != strings.Join(want, ",") {
			t.Fatalf("first page = %v, want %v", first, want)
		}

		second := list(t, uow, port.UserQuery{After: first[len(first)-1], Limit: 3})
		if len(second) != 1 || second[0] != "dave@example.test" {
			t.Errorf("second page = %v, want [dave@example.test]", second)
		}

		if rest := list(t, uow, port.UserQuery{After: second[0], Limit: 3}); len(rest) != 0 {
			t.Errorf("page after the end = %v", rest)
		}
	})

	t.Run("a prefix selects addresses and treats LIKE characters literally", func(t *testing.T) {
		uow := seed(t, "ann@example.test", "anna@example.test", "bob@example.test", "a_b@example.test", "axb@example.test", "a%c@example.test", "abc@example.test")
		for prefix, want := range map[string]string{
			"an":   "ann@example.test,anna@example.test",
			"ann@": "ann@example.test",
			"a_":   "a_b@example.test",
			"a%":   "a%c@example.test",
			"zzz":  "",
		} {
			if got := strings.Join(list(t, uow, port.UserQuery{EmailPrefix: prefix, Limit: 10}), ","); got != want {
				t.Errorf("prefix %q = %q, want %q", prefix, got, want)
			}
		}
	})

	t.Run("a blocked user is listed as blocked", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{Email: "blocked@example.test"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			if err := user.Block(contractNow); err != nil {
				return err
			}

			return s.Users.SetBlocked(ctx, user)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			users, err := s.Users.List(ctx, port.UserQuery{Limit: 5})
			if err != nil || len(users) != 1 || !users[0].Blocked() {
				t.Errorf("List = %v, %v; want one blocked user", users, err)
			}

			return nil
		})
	})
}

func auditListContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("entries are newest first, filtered and paged by a cursor", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user, other := f.User(UserSpec{}), f.User(UserSpec{})
		op := f.Operator(OperatorSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, u := range []*identity.User{user, other} {
				if _, _, err := s.Users.Ensure(ctx, u); err != nil {
					return err
				}
			}

			return s.Operators.Create(ctx, op)
		})

		events := []port.AuditEvent{
			{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: user.ID(), At: contractNow, Fields: map[string]string{"method": "passkey"}},
			{Type: port.AuditAdminAction, Result: port.AuditSuccess, UserID: user.ID(), OperatorID: op.ID(), At: contractNow.Add(time.Minute), Fields: map[string]string{"operation": "block"}},
			{Type: port.AuditAdminAction, Result: port.AuditSuccess, UserID: other.ID(), OperatorID: op.ID(), At: contractNow.Add(time.Minute), Fields: map[string]string{"operation": "unblock"}},
			{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: other.ID(), At: contractNow.Add(2 * time.Minute)},
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, e := range events {
				if err := s.Audit.Record(ctx, e); err != nil {
					return err
				}
			}

			return nil
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			all, err := s.AuditReads.List(ctx, port.AuditQuery{Limit: 10})
			if err != nil {
				return err
			}

			if len(all) != 4 {
				return fmt.Errorf("the audit list returned %d entries, want 4", len(all))
			}

			if !all[0].At.Equal(contractNow.Add(2*time.Minute)) || !all[3].At.Equal(contractNow) {
				t.Errorf("entries are not newest first: %v ... %v", all[0].At, all[3].At)
			}

			for i, e := range all {
				if e.ID == "" || (i > 0 && e.ID == all[i-1].ID) {
					t.Errorf("entry %d has no distinct ID", i)
				}
			}

			var admin port.AuditEntry

			for _, e := range all {
				if e.Type == port.AuditAdminAction && e.UserID == user.ID() {
					admin = e
				}
			}

			if admin.OperatorID != op.ID() || admin.Fields["operation"] != "block" || admin.Result != port.AuditSuccess {
				t.Errorf("an administrative entry came back as %+v", admin)
			}

			byUser, err := s.AuditReads.List(ctx, port.AuditQuery{UserID: user.ID(), Limit: 10})
			if err != nil || len(byUser) != 2 {
				t.Errorf("by user = %d, %v; want 2", len(byUser), err)
			}

			byOperator, err := s.AuditReads.List(ctx, port.AuditQuery{OperatorID: op.ID(), Limit: 10})
			if err != nil || len(byOperator) != 2 {
				t.Errorf("by operator = %d, %v; want 2", len(byOperator), err)
			}

			byType, err := s.AuditReads.List(ctx, port.AuditQuery{Type: port.AuditLoginSucceeded, Limit: 10})
			if err != nil || len(byType) != 2 {
				t.Errorf("by type = %d, %v; want 2", len(byType), err)
			}

			both, err := s.AuditReads.List(ctx, port.AuditQuery{UserID: user.ID(), Type: port.AuditAdminAction, Limit: 10})
			if err != nil || len(both) != 1 {
				t.Errorf("by user and type = %d, %v; want 1", len(both), err)
			}

			var (
				walked []string
				cursor port.AuditCursor
			)
			for range all {
				page, err := s.AuditReads.List(ctx, port.AuditQuery{Before: cursor, Limit: 1})
				if err != nil {
					return err
				}

				if len(page) != 1 {
					return fmt.Errorf("the page after %v has %d entries, want 1", cursor, len(page))
				}

				walked = append(walked, page[0].ID)
				cursor = port.AuditCursor{At: page[0].At, ID: page[0].ID}
			}

			for i := range all {
				if walked[i] != all[i].ID {
					t.Errorf("walk step %d = %s, want %s", i, walked[i], all[i].ID)
				}
			}

			if end, err := s.AuditReads.List(ctx, port.AuditQuery{Before: cursor, Limit: 1}); err != nil || len(end) != 0 {
				t.Errorf("page after the oldest = %d, %v", len(end), err)
			}

			return nil
		})
	})

	t.Run("deleting a user clears the reference and keeps who acted", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user, op := f.User(UserSpec{}), f.Operator(OperatorSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.Audit.Record(ctx, port.AuditEvent{Type: port.AuditAdminAction, Result: port.AuditSuccess, UserID: user.ID(), OperatorID: op.ID(), At: contractNow, Fields: map[string]string{"operation": "delete_user"}})
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Users.Delete(ctx, user.ID()) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.AuditReads.List(ctx, port.AuditQuery{OperatorID: op.ID(), Limit: 5})
			if err != nil || len(got) != 1 || !got[0].UserID.IsZero() || got[0].OperatorID != op.ID() {
				t.Errorf("after the user was deleted: %+v, %v", got, err)
			}

			return nil
		})
	})
}

func operatorContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("an operator is stored, found by ID and address, and listed oldest first", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		first := f.Operator(OperatorSpec{Email: "first@example.test"})
		f.Clock.Advance(time.Minute)
		second := f.Operator(OperatorSpec{Email: "second@example.test"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, second); err != nil {
				return err
			}

			return s.Operators.Create(ctx, first)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.Get(ctx, first.ID())
			if err != nil || got.Record() != first.Record() {
				t.Errorf("Get = %+v, %v", got, err)
			}

			locked, err := s.Operators.GetForUpdate(ctx, first.ID())
			if err != nil || locked.Record() != first.Record() {
				t.Errorf("GetForUpdate = %+v, %v", locked, err)
			}

			byEmail, err := s.Operators.FindByEmail(ctx, second.Email())
			if err != nil || byEmail.Record() != second.Record() {
				t.Errorf("FindByEmail = %+v, %v", byEmail, err)
			}

			all, err := s.Operators.List(ctx)
			if err != nil || len(all) != 2 || all[0].ID() != first.ID() || all[1].ID() != second.ID() {
				t.Errorf("List = %v, %v", all, err)
			}

			ghost := f.Operator(OperatorSpec{})
			if _, err := s.Operators.Get(ctx, ghost.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Get of an unknown operator = %v", err)
			}

			if _, err := s.Operators.GetForUpdate(ctx, ghost.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate of an unknown operator = %v", err)
			}

			if _, err := s.Operators.FindByEmail(ctx, ghost.Email()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindByEmail of an unknown address = %v", err)
			}

			if err := s.Operators.Save(ctx, ghost); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Save of an unknown operator = %v", err)
			}

			return nil
		})
	})

	t.Run("an address cannot be registered twice", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Operators.Create(ctx, f.Operator(OperatorSpec{Email: "ops@example.test"}))
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Operators.Create(ctx, f.Operator(OperatorSpec{Email: "ops@example.test"}))
		})
		if !errors.Is(err, port.ErrOperatorExists) {
			t.Errorf("second Create = %v, want ErrOperatorExists", err)
		}
	})

	t.Run("disabling is stored and lifted", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Operators.Create(ctx, op) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := op.Disable(contractNow.Add(time.Hour)); err != nil {
				return err
			}

			return s.Operators.Save(ctx, op)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.Get(ctx, op.ID())
			if err != nil || !got.Disabled() || !got.DisabledAt().Equal(contractNow.Add(time.Hour)) {
				t.Errorf("after Disable: %+v, %v", got, err)
			}

			got.Enable()

			return s.Operators.Save(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.Get(ctx, op.ID())
			if err != nil || got.Disabled() {
				t.Errorf("after Enable: %+v, %v", got, err)
			}

			return nil
		})
	})
}

func enrollmentContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("an enrollment is found by its code and by ID, and spending it is stored", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})
		e := f.Enrollment(op, "code-one")

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.Operators.CreateEnrollment(ctx, e)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			byHash, err := s.Operators.GetEnrollmentByHashForUpdate(ctx, SecretHash("code-one"))
			if err != nil || byHash.Record() != e.Record() {
				t.Errorf("by hash = %+v, %v", byHash, err)
			}

			if _, err := s.Operators.GetEnrollmentByHashForUpdate(ctx, SecretHash("another")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("by an unknown hash = %v", err)
			}

			byID, err := s.Operators.GetEnrollmentForUpdate(ctx, e.ID())
			if err != nil {
				return err
			}

			if err := byID.Consume(contractNow.Add(time.Minute)); err != nil {
				return err
			}

			return s.Operators.SaveEnrollment(ctx, byID)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.GetEnrollmentForUpdate(ctx, e.ID())
			if err != nil || !got.ConsumedAt().Equal(contractNow.Add(time.Minute)) {
				t.Errorf("after Consume: %+v, %v", got, err)
			}

			return nil
		})
	})

	t.Run("a code hash cannot repeat", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.Operators.CreateEnrollment(ctx, f.Enrollment(op, "same"))
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Operators.CreateEnrollment(ctx, f.Enrollment(op, "same"))
		})
		if !errors.Is(err, port.ErrTicketConflict) {
			t.Errorf("second CreateEnrollment = %v, want ErrTicketConflict", err)
		}
	})

	t.Run("unknown enrollments are not found", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		ghost := f.Enrollment(f.Operator(OperatorSpec{}), "")

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Operators.GetEnrollmentForUpdate(ctx, ghost.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetEnrollmentForUpdate = %v", err)
			}

			if err := s.Operators.SaveEnrollment(ctx, ghost); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("SaveEnrollment = %v", err)
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func operatorCredentialContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("keys are stored per operator and a credential ID is unique", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		a, b := f.Operator(OperatorSpec{}), f.Operator(OperatorSpec{})
		keyA, keyB := f.OperatorCredential(a, nil), f.OperatorCredential(b, nil)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, o := range []*operator.Operator{a, b} {
				if err := s.Operators.Create(ctx, o); err != nil {
					return err
				}
			}

			if err := s.Operators.CreateCredential(ctx, keyA); err != nil {
				return err
			}

			return s.Operators.CreateCredential(ctx, keyB)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			listA, err := s.Operators.ListCredentials(ctx, a.ID())
			if err != nil || len(listA) != 1 || !reflect.DeepEqual(listA[0].Record(), keyA.Record()) {
				t.Errorf("ListCredentials(a) = %v, %v", listA, err)
			}

			got, err := s.Operators.GetCredentialForUpdate(ctx, keyB.CredentialID())
			if err != nil || got.UserID() != b.ID().Owner() {
				t.Errorf("GetCredentialForUpdate = %+v, %v", got, err)
			}

			if _, err := s.Operators.GetCredentialForUpdate(ctx, []byte("nothing")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetCredentialForUpdate of an unknown key = %v", err)
			}

			return nil
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.Operators.CreateCredential(ctx, f.OperatorCredential(a, keyA.CredentialID()))
		})
		if !errors.Is(err, port.ErrCredentialConflict) {
			t.Errorf("a repeated credential ID = %v, want ErrCredentialConflict", err)
		}

		later := f.OperatorCredential(a, nil)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.CreateCredential(ctx, f.OperatorCredential(b, keyA.CredentialID())); !errors.Is(err, port.ErrCredentialConflict) {
				t.Errorf("a repeated credential ID = %v, want ErrCredentialConflict", err)
			}

			return s.Operators.CreateCredential(ctx, later)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if list, err := s.Operators.ListCredentials(ctx, a.ID()); err != nil || len(list) != 2 {
				t.Errorf("keys of a = %d, %v; want the first and the one stored after the refusal", len(list), err)
			}

			return nil
		})
	})

	t.Run("a user's key is not an operator's key", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})
		userKey := f.Credential(CredentialSpec{User: user})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			return s.Credentials.Create(ctx, userKey)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Operators.GetCredentialForUpdate(ctx, userKey.CredentialID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("an operator lookup found a user's key: %v", err)
			}

			return nil
		})
	})

	t.Run("using a key stores the counter", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})
		key := f.OperatorCredential(op, nil)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.Operators.CreateCredential(ctx, key)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.GetCredentialForUpdate(ctx, key.CredentialID())
			if err != nil {
				return err
			}

			if err := got.RecordUse(contractNow.Add(time.Hour), 7, false); err != nil {
				return err
			}

			return s.Operators.SaveCredential(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Operators.GetCredentialForUpdate(ctx, key.CredentialID())
			if err != nil || got.SignCount() != 7 || !got.LastUsedAt().Equal(contractNow.Add(time.Hour)) {
				t.Errorf("after use: %+v, %v", got, err)
			}

			return nil
		})
	})
}

func operatorChallengeContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a registration challenge keeps its operator and enrollment, a login names neither", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})
		enrollment := f.Enrollment(op, "")

		reg, err := passkey.NewChallenge(passkey.NewChallengeParams{
			ID: mustPasskeyID(t, f), Purpose: passkey.ChallengeRegistration, UserID: op.ID().Owner(), TicketID: enrollment.ID(),
			Data: []byte(`{"state":"registration"}`), Now: contractNow,
		})
		if err != nil {
			t.Fatal(err)
		}

		login, err := passkey.NewChallenge(passkey.NewChallengeParams{
			ID: mustPasskeyID(t, f), Purpose: passkey.ChallengeLogin, Data: []byte(`{"state":"login"}`), Now: contractNow,
		})
		if err != nil {
			t.Fatal(err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			if err := s.Operators.CreateEnrollment(ctx, enrollment); err != nil {
				return err
			}

			if err := s.OperatorChallenges.Create(ctx, reg); err != nil {
				return err
			}

			return s.OperatorChallenges.Create(ctx, login)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for name, want := range map[string]*passkey.Challenge{"registration": reg, "login": login} {
				got, err := s.OperatorChallenges.GetForUpdate(ctx, want.ID())
				if err != nil || !reflect.DeepEqual(got.Record(), want.Record()) {
					t.Errorf("%s challenge came back as %+v, %v", name, got, err)
				}
			}

			got, err := s.OperatorChallenges.GetForUpdate(ctx, reg.ID())
			if err != nil {
				return err
			}

			if err := got.Consume(contractNow.Add(time.Second), passkey.ChallengeRegistration); err != nil {
				return err
			}

			return s.OperatorChallenges.Save(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.OperatorChallenges.GetForUpdate(ctx, reg.ID())
			if err != nil || got.ConsumedAt().IsZero() {
				t.Errorf("after Consume: %+v, %v", got, err)
			}

			if _, err := s.Challenges.GetForUpdate(ctx, reg.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("an operator challenge is in the users' table: %v", err)
			}

			return nil
		})
	})
}

func mustPasskeyID(t *testing.T, f *Factory) passkey.ID {
	t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func operatorSessionContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a session is found by its secret and by ID and saving keeps the use and revocation", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})
		sess := f.OperatorSession(op, "cookie-secret")

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.OperatorSessions.Create(ctx, sess)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.OperatorSessions.GetByHashForUpdate(ctx, SecretHash("cookie-secret"))
			if err != nil || got.Record() != sess.Record() {
				t.Errorf("by hash = %+v, %v", got, err)
			}

			if _, err := s.OperatorSessions.GetByHashForUpdate(ctx, SecretHash("wrong")); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("by an unknown hash = %v", err)
			}

			if !got.Touch(contractNow.Add(5 * time.Minute)) {
				t.Error("Touch did not change the session")
			}

			return s.OperatorSessions.Save(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.OperatorSessions.GetForUpdate(ctx, sess.ID())
			if err != nil || !got.LastSeenAt().Equal(contractNow.Add(5*time.Minute)) {
				t.Errorf("after Touch: %+v, %v", got, err)
			}

			got.Revoke(contractNow.Add(6 * time.Minute))

			return s.OperatorSessions.Save(ctx, got)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.OperatorSessions.GetForUpdate(ctx, sess.ID())
			if err != nil || !got.RevokedAt().Equal(contractNow.Add(6*time.Minute)) {
				t.Errorf("after Revoke: %+v, %v", got, err)
			}

			return nil
		})
	})

	t.Run("revoking all sessions of an operator leaves other operators alone", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		a, b := f.Operator(OperatorSpec{}), f.Operator(OperatorSpec{})
		sa1, sa2, sb := f.OperatorSession(a, ""), f.OperatorSession(a, ""), f.OperatorSession(b, "")

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, o := range []*operator.Operator{a, b} {
				if err := s.Operators.Create(ctx, o); err != nil {
					return err
				}
			}

			for _, x := range []*operator.Session{sa1, sa2, sb} {
				if err := s.OperatorSessions.Create(ctx, x); err != nil {
					return err
				}
			}

			return nil
		})

		revokedAt := contractNow.Add(time.Hour)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.OperatorSessions.RevokeAllForOperator(ctx, a.ID(), revokedAt)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, x := range []*operator.Session{sa1, sa2} {
				got, err := s.OperatorSessions.GetForUpdate(ctx, x.ID())
				if err != nil || !got.RevokedAt().Equal(revokedAt) {
					t.Errorf("a session of the revoked operator: %+v, %v", got, err)
				}
			}

			got, err := s.OperatorSessions.GetForUpdate(ctx, sb.ID())
			if err != nil || !got.RevokedAt().IsZero() {
				t.Errorf("a session of another operator was revoked: %+v, %v", got, err)
			}

			return nil
		})
	})

	t.Run("a secret hash cannot repeat", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		op := f.Operator(OperatorSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Operators.Create(ctx, op); err != nil {
				return err
			}

			return s.OperatorSessions.Create(ctx, f.OperatorSession(op, "same"))
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			return s.OperatorSessions.Create(ctx, f.OperatorSession(op, "same"))
		})
		if !errors.Is(err, port.ErrTicketConflict) {
			t.Errorf("second Create = %v, want ErrTicketConflict", err)
		}
	})
}
