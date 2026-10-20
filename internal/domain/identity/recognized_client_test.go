package identity_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

func newRecognized(t *testing.T, at time.Time) *identity.RecognizedClient {
	t.Helper()
	f := testutil.NewFactory(t, at)
	user := f.User(testutil.UserSpec{})

	id, err := f.IDs.NewRecognizedClientID()
	if err != nil {
		t.Fatal(err)
	}

	c, err := identity.NewRecognizedClient(id, user.ID(), user.Email(), testutil.BindingHash("device"), at)
	if err != nil {
		t.Fatalf("NewRecognizedClient: %v", err)
	}

	return c
}

func TestNewRecognizedClientStartsActiveFor90Days(t *testing.T) {
	c := newRecognized(t, now)

	if !c.VerifiedAt().Equal(now) || !c.ExpiresAt().Equal(now.Add(90*24*time.Hour)) || !c.RevokedAt().IsZero() {
		t.Errorf("record = %+v", c.Record())
	}

	if !c.Active(now) || !c.Active(c.ExpiresAt().Add(-time.Nanosecond)) {
		t.Error("record is not active inside its period")
	}

	if c.Active(c.ExpiresAt()) {
		t.Error("record is active at its expiry time")
	}
}

func TestNewRecognizedClientRequiresEveryInput(t *testing.T) {
	good := newRecognized(t, now).Record()
	for name, mutate := range map[string]func(*identity.RecognizedClientRecord){
		"id":      func(r *identity.RecognizedClientRecord) { r.ID = identity.RecognizedClientID{} },
		"user":    func(r *identity.RecognizedClientRecord) { r.UserID = identity.UserID{} },
		"email":   func(r *identity.RecognizedClientRecord) { r.Email = identity.Email{} },
		"binding": func(r *identity.RecognizedClientRecord) { r.Binding = identity.BindingHash{} },
	} {
		r := good
		mutate(&r)

		if _, err := identity.NewRecognizedClient(r.ID, r.UserID, r.Email, r.Binding, now); err == nil {
			t.Errorf("accepted a record without %s", name)
		}
	}

	if _, err := identity.NewRecognizedClient(good.ID, good.UserID, good.Email, good.Binding, time.Time{}); err == nil {
		t.Error("accepted a zero time")
	}
}

func TestExtendMovesExpiryButNotVerification(t *testing.T) {
	c := newRecognized(t, now)
	later := now.Add(30 * 24 * time.Hour)

	if err := c.Extend(later); err != nil {
		t.Fatalf("Extend: %v", err)
	}

	if want := later.Add(identity.RecognitionTTL); !c.ExpiresAt().Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", c.ExpiresAt(), want)
	}

	if !c.VerifiedAt().Equal(now) {
		t.Errorf("VerifiedAt = %v: only verify updates it", c.VerifiedAt())
	}
}

func TestExtendNeverShortensThePeriod(t *testing.T) {
	c := newRecognized(t, now)

	before := c.ExpiresAt()
	if err := c.Extend(now.Add(-time.Hour)); err != nil { // clock skew
		t.Fatal(err)
	}

	if c.ExpiresAt().Before(before) {
		t.Errorf("expiry moved back to %v", c.ExpiresAt())
	}
}

func TestExtendDoesNotRestoreExpiredOrRevokedRecords(t *testing.T) {
	expired := newRecognized(t, now)

	at := expired.ExpiresAt()
	if err := expired.Extend(at); !errors.Is(err, identity.ErrNotActive) {
		t.Errorf("Extend at expiry = %v, want ErrNotActive", err)
	}

	if !expired.ExpiresAt().Equal(at) {
		t.Error("a failed Extend changed the expiry")
	}

	revoked := newRecognized(t, now)
	revoked.Revoke(now.Add(time.Hour))

	if err := revoked.Extend(now.Add(2 * time.Hour)); !errors.Is(err, identity.ErrNotActive) {
		t.Errorf("Extend of a revoked record = %v, want ErrNotActive", err)
	}

	if revoked.Active(now.Add(2 * time.Hour)) {
		t.Error("revoked record is active")
	}
}

func TestRenewRestartsPeriodAndReactivates(t *testing.T) {
	c := newRecognized(t, now)
	c.Revoke(now.Add(time.Hour))
	later := now.Add(200 * 24 * time.Hour) // after the old expiry too

	c.Renew(later)

	if !c.Active(later) || !c.RevokedAt().IsZero() ||
		!c.VerifiedAt().Equal(later) || !c.ExpiresAt().Equal(later.Add(identity.RecognitionTTL)) {
		t.Errorf("record after Renew = %+v", c.Record())
	}
}

func TestRevokeKeepsTheFirstTime(t *testing.T) {
	c := newRecognized(t, now)
	first := now.Add(time.Hour)
	c.Revoke(first)
	c.Revoke(now.Add(2 * time.Hour))

	if !c.RevokedAt().Equal(first) {
		t.Errorf("RevokedAt = %v, want %v", c.RevokedAt(), first)
	}
}

func TestRecognizedClientRecordRoundTrip(t *testing.T) {
	c := newRecognized(t, now)
	c.Revoke(now.Add(time.Hour))

	restored, err := identity.RestoreRecognizedClient(c.Record())
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if !reflect.DeepEqual(restored.Record(), c.Record()) {
		t.Errorf("round trip changed the record")
	}
}

func TestRestoreRecognizedClientRejectsImpossibleRecords(t *testing.T) {
	good := newRecognized(t, now).Record()
	for name, mutate := range map[string]func(*identity.RecognizedClientRecord){
		"no id":            func(r *identity.RecognizedClientRecord) { r.ID = identity.RecognizedClientID{} },
		"no user":          func(r *identity.RecognizedClientRecord) { r.UserID = identity.UserID{} },
		"no email":         func(r *identity.RecognizedClientRecord) { r.Email = identity.Email{} },
		"no binding":       func(r *identity.RecognizedClientRecord) { r.Binding = identity.BindingHash{} },
		"no verified time": func(r *identity.RecognizedClientRecord) { r.VerifiedAt = time.Time{} },
		"expiry not after": func(r *identity.RecognizedClientRecord) { r.ExpiresAt = r.VerifiedAt },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)

			if _, err := identity.RestoreRecognizedClient(r); err == nil {
				t.Error("Restore accepted an impossible record")
			}
		})
	}
}

func TestBindingHashEqual(t *testing.T) {
	a, b := testutil.BindingHash("a"), testutil.BindingHash("b")
	if !a.Equal(testutil.BindingHash("a")) || a.Equal(b) {
		t.Error("Equal does not compare hashes")
	}

	var zero identity.BindingHash
	if zero.Equal(zero) || a.Equal(zero) || zero.Equal(a) {
		t.Error("a zero hash must equal nothing, not even itself")
	}
}
