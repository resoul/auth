package operator_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/passkey"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const (
	operatorIDText = "5b0f6a3e-7d1e-4a54-9a0b-0e1f2a3b4c5d"
	rowIDText      = "0199c0de-0000-7000-8000-000000000001"
)

func opID(t *testing.T) operator.ID {
	t.Helper()
	id, err := operator.ParseID(operatorIDText)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func rowID(t *testing.T) passkey.ID {
	t.Helper()
	id, err := passkey.ParseID(rowIDText)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func hash(t *testing.T) passkey.SecretHash {
	t.Helper()
	h, err := passkey.NewSecretHash(make([]byte, passkey.SecretHashLength))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func email(t *testing.T) identity.Email {
	t.Helper()
	e, err := identity.ParseEmail("Ops@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestParseIDAcceptsOnlyCanonicalUUIDv4(t *testing.T) {
	for _, bad := range []string{"", "x", strings.ToUpper(operatorIDText), rowIDText, operatorIDText + "0"} {
		if _, err := operator.ParseID(bad); !errors.Is(err, operator.ErrInvalidID) {
			t.Errorf("ParseID(%q) = %v, want ErrInvalidID", bad, err)
		}
	}
	id := opID(t)
	if id.String() != operatorIDText || id.IsZero() {
		t.Errorf("id = %q", id)
	}
	owner := id.Owner()
	if owner.String() != operatorIDText {
		t.Errorf("Owner = %q", owner)
	}
	back, err := operator.IDFromOwner(owner)
	if err != nil || back != id {
		t.Errorf("IDFromOwner = %v, %v", back, err)
	}
	if !(operator.ID{}).Owner().IsZero() {
		t.Error("the zero ID has an owner")
	}
}

func TestOperatorLifecycle(t *testing.T) {
	if _, err := operator.New(operator.ID{}, email(t), t0); err == nil {
		t.Error("New accepted a zero id")
	}
	if _, err := operator.New(opID(t), identity.Email{}, t0); err == nil {
		t.Error("New accepted a zero email")
	}
	if _, err := operator.New(opID(t), email(t), time.Time{}); err == nil {
		t.Error("New accepted a zero time")
	}
	o, err := operator.New(opID(t), email(t), t0)
	if err != nil {
		t.Fatal(err)
	}
	if o.Disabled() || o.Email().String() != "ops@example.com" {
		t.Errorf("new operator: disabled=%v email=%q", o.Disabled(), o.Email())
	}
	if err := o.Disable(time.Time{}); err == nil {
		t.Error("Disable accepted a zero time")
	}
	if err := o.Disable(t0.Add(time.Hour)); err != nil || !o.Disabled() {
		t.Fatalf("Disable: %v", err)
	}
	if err := o.Disable(t0.Add(2 * time.Hour)); err != nil || !o.DisabledAt().Equal(t0.Add(time.Hour)) {
		t.Errorf("a second Disable moved the time to %v", o.DisabledAt())
	}
	restored, err := operator.Restore(o.Record())
	if err != nil || restored.Record() != o.Record() {
		t.Fatalf("round trip: %v", err)
	}
	o.Enable()
	if o.Disabled() {
		t.Error("Enable did not lift the disable")
	}
	if _, err := operator.Restore(operator.Record{}); err == nil {
		t.Error("Restore accepted an empty record")
	}
}

func TestEnrollmentIsSingleUseAndExpires(t *testing.T) {
	e, err := operator.NewEnrollment(rowID(t), opID(t), hash(t), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Usable(t0.Add(operator.EnrollmentTTL - time.Nanosecond)); err != nil {
		t.Errorf("Usable before expiry: %v", err)
	}
	if err := e.Usable(t0.Add(operator.EnrollmentTTL)); !errors.Is(err, operator.ErrEnrollmentExpired) {
		t.Errorf("Usable at expiry = %v, want expired", err)
	}
	if err := e.Consume(t0.Add(time.Minute)); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := e.Consume(t0.Add(2 * time.Minute)); !errors.Is(err, operator.ErrEnrollmentUsed) {
		t.Errorf("second Consume = %v, want used", err)
	}
	restored, err := operator.RestoreEnrollment(e.Record())
	if err != nil || restored.Record() != e.Record() {
		t.Fatalf("round trip: %v", err)
	}
	bad := e.Record()
	bad.ExpiresAt = bad.CreatedAt
	if _, err := operator.RestoreEnrollment(bad); err == nil {
		t.Error("RestoreEnrollment accepted an expiry that is not after the creation")
	}
	for name, mk := range map[string]func() error{
		"id":       func() error { _, err := operator.NewEnrollment(passkey.ID{}, opID(t), hash(t), t0); return err },
		"operator": func() error { _, err := operator.NewEnrollment(rowID(t), operator.ID{}, hash(t), t0); return err },
		"hash": func() error {
			_, err := operator.NewEnrollment(rowID(t), opID(t), passkey.SecretHash{}, t0)
			return err
		},
		"time": func() error { _, err := operator.NewEnrollment(rowID(t), opID(t), hash(t), time.Time{}); return err },
	} {
		if mk() == nil {
			t.Errorf("NewEnrollment accepted a missing %s", name)
		}
	}
}

func TestSessionLifetimes(t *testing.T) {
	s, err := operator.NewSession(rowID(t), opID(t), hash(t), t0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active(t0) || !s.Fresh(t0) {
		t.Fatal("a new session is not active and fresh")
	}
	if !s.Fresh(t0.Add(operator.FreshFor-time.Nanosecond)) || s.Fresh(t0.Add(operator.FreshFor)) {
		t.Error("freshness does not end exactly at FreshFor")
	}
	if !s.Active(t0.Add(operator.IdleTimeout-time.Nanosecond)) || s.Active(t0.Add(operator.IdleTimeout)) {
		t.Error("idle expiry is not exactly IdleTimeout")
	}

	// A busy session writes at most once per TouchEvery and stays alive by that.
	if s.Touch(t0.Add(operator.TouchEvery - time.Nanosecond)) {
		t.Error("Touch wrote twice inside TouchEvery")
	}
	at := t0
	for i := 0; i < 5; i++ {
		at = at.Add(operator.IdleTimeout - time.Minute)
		if !s.Touch(at) || !s.Active(at) {
			t.Fatalf("a used session expired at step %d", i)
		}
	}
	// The absolute lifetime wins over use.
	if s.Active(t0.Add(operator.MaxAge)) {
		t.Error("session is active past MaxAge")
	}

	s.Revoke(at)
	first := s.RevokedAt()
	s.Revoke(at.Add(time.Hour))
	if s.Active(at) || !s.RevokedAt().Equal(first) {
		t.Errorf("revoked session: active=%v revokedAt=%v", s.Active(at), s.RevokedAt())
	}
	restored, err := operator.RestoreSession(s.Record())
	if err != nil || restored.Record() != s.Record() {
		t.Fatalf("round trip: %v", err)
	}
	bad := s.Record()
	bad.LastSeenAt = bad.CreatedAt.Add(-time.Second)
	if _, err := operator.RestoreSession(bad); err == nil {
		t.Error("RestoreSession accepted a last use before the sign-in")
	}
}

func TestCSRFTokenDependsOnTheSecret(t *testing.T) {
	a, b := operator.CSRFToken("secret-a"), operator.CSRFToken("secret-b")
	if a == b || a != operator.CSRFToken("secret-a") || len(a) != 64 {
		t.Errorf("tokens: %q %q", a, b)
	}
	if strings.Contains(a, "secret-a") {
		t.Error("the token contains the secret")
	}
}
