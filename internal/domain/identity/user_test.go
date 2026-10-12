package identity_test

import (
	"errors"
	"testing"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestNewUserIsConfirmedAtCreation(t *testing.T) {
	f := testutil.NewFactory(t, now)
	user := f.User(testutil.UserSpec{Email: "Alice@Example.com"})

	if user.Email().String() != "alice@example.com" {
		t.Errorf("Email = %q", user.Email())
	}
	for name, got := range map[string]time.Time{
		"EmailVerifiedAt": user.EmailVerifiedAt(), "CreatedAt": user.CreatedAt(), "UpdatedAt": user.UpdatedAt(),
	} {
		if !got.Equal(now) {
			t.Errorf("%s = %v, want %v", name, got, now)
		}
	}
}

func TestNewUserRequiresAllInputs(t *testing.T) {
	f := testutil.NewFactory(t, now)
	valid := f.User(testutil.UserSpec{})

	if _, err := identity.NewUser(identity.UserID{}, valid.Email(), now); err == nil {
		t.Error("NewUser accepted zero id")
	}
	if _, err := identity.NewUser(valid.ID(), identity.Email{}, now); err == nil {
		t.Error("NewUser accepted zero email")
	}
	if _, err := identity.NewUser(valid.ID(), valid.Email(), time.Time{}); err == nil {
		t.Error("NewUser accepted zero time")
	}
}

func TestUserRecordRoundTrip(t *testing.T) {
	user := testutil.NewFactory(t, now).User(testutil.UserSpec{})

	restored, err := identity.RestoreUser(user.Record())
	if err != nil {
		t.Fatalf("RestoreUser: %v", err)
	}
	if restored.Record() != user.Record() {
		t.Errorf("round trip changed record: %+v vs %+v", restored.Record(), user.Record())
	}
}

func TestRestoreUserRejectsIncompleteRecord(t *testing.T) {
	good := testutil.NewFactory(t, now).User(testutil.UserSpec{}).Record()

	for name, mutate := range map[string]func(*identity.UserRecord){
		"id":         func(r *identity.UserRecord) { r.ID = identity.UserID{} },
		"email":      func(r *identity.UserRecord) { r.Email = identity.Email{} },
		"verifiedAt": func(r *identity.UserRecord) { r.EmailVerifiedAt = time.Time{} },
		"createdAt":  func(r *identity.UserRecord) { r.CreatedAt = time.Time{} },
		"updatedAt":  func(r *identity.UserRecord) { r.UpdatedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)
			if _, err := identity.RestoreUser(r); err == nil {
				t.Error("RestoreUser accepted incomplete record")
			}
		})
	}
}

func TestChangeEmailTakesTheTimeOfTheNewProof(t *testing.T) {
	f := testutil.NewFactory(t, now)
	user := f.User(testutil.UserSpec{Email: "old@example.test"})
	later := now.Add(48 * time.Hour)
	next, err := identity.ParseEmail(" New@Example.test ")
	if err != nil {
		t.Fatal(err)
	}

	if err := user.ChangeEmail(next, later); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if user.Email().String() != "new@example.test" || !user.EmailVerifiedAt().Equal(later) || !user.UpdatedAt().Equal(later) {
		t.Errorf("email=%q verified=%v updated=%v", user.Email(), user.EmailVerifiedAt(), user.UpdatedAt())
	}
	if !user.CreatedAt().Equal(now) {
		t.Errorf("CreatedAt moved to %v", user.CreatedAt())
	}
}

func TestChangeEmailRefusesWhatIsNotAChange(t *testing.T) {
	f := testutil.NewFactory(t, now)
	user := f.User(testutil.UserSpec{Email: "same@example.test"})
	before := user.Record()

	if err := user.ChangeEmail(user.Email(), now.Add(time.Hour)); !errors.Is(err, identity.ErrSameEmail) {
		t.Errorf("same address error = %v, want ErrSameEmail", err)
	}
	if err := user.ChangeEmail(identity.Email{}, now.Add(time.Hour)); err == nil {
		t.Error("ChangeEmail accepted a zero email")
	}
	other, _ := identity.ParseEmail("other@example.test")
	if err := user.ChangeEmail(other, time.Time{}); err == nil {
		t.Error("ChangeEmail accepted a zero time")
	}
	if user.Record() != before {
		t.Errorf("a refused change altered the user: %+v", user.Record())
	}
}

func TestUserBlockAndUnblock(t *testing.T) {
	user := testutil.NewFactory(t, now).User(testutil.UserSpec{})
	if user.Blocked() || !user.BlockedAt().IsZero() {
		t.Fatal("a new user is blocked")
	}
	later := now.Add(time.Hour)
	if err := user.Block(later); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !user.Blocked() || !user.BlockedAt().Equal(later) || !user.UpdatedAt().Equal(later) {
		t.Errorf("after Block: blocked=%v at=%v updated=%v", user.Blocked(), user.BlockedAt(), user.UpdatedAt())
	}
	// Blocking again keeps the first time.
	if err := user.Block(later.Add(time.Hour)); err != nil || !user.BlockedAt().Equal(later) {
		t.Errorf("second Block changed the time: %v, %v", user.BlockedAt(), err)
	}
	restored, err := identity.RestoreUser(user.Record())
	if err != nil || !restored.Blocked() || !restored.BlockedAt().Equal(later) {
		t.Errorf("round trip lost the block: %v, %v", restored, err)
	}
	if err := user.Unblock(later.Add(2 * time.Hour)); err != nil || user.Blocked() {
		t.Errorf("Unblock: blocked=%v err=%v", user.Blocked(), err)
	}
	if err := user.Block(time.Time{}); err == nil {
		t.Error("Block accepted the zero time")
	}
	if err := user.Unblock(time.Time{}); err == nil {
		t.Error("Unblock accepted the zero time")
	}
}
