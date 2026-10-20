package session_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

var (
	now    = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	policy = session.DefaultPolicy()
	day    = 24 * time.Hour
)

func newSession(t *testing.T) *session.Session {
	t.Helper()
	f := testutil.NewFactory(t, now)

	return f.Session(testutil.SessionSpec{User: f.User(testutil.UserSpec{})})
}

func TestNewSessionHasIdleAndAbsoluteLimits(t *testing.T) {
	s := newSession(t)

	if !s.CreatedAt().Equal(now) || !s.LastActiveAt().Equal(now) || !s.AuthTime().Equal(now) {
		t.Errorf("times = %v / %v / %v", s.CreatedAt(), s.LastActiveAt(), s.AuthTime())
	}

	if !s.IdleExpiresAt().Equal(now.Add(30*day)) || !s.ExpiresAt().Equal(now.Add(90*day)) {
		t.Errorf("limits = %v / %v", s.IdleExpiresAt(), s.ExpiresAt())
	}

	if !s.RevokedAt().IsZero() || !s.Active(now) {
		t.Error("a new session must be active")
	}

	if !reflect.DeepEqual(s.AMR(), []string{"otp"}) || s.DeviceName() != "test device" {
		t.Errorf("amr=%v device=%q", s.AMR(), s.DeviceName())
	}
}

func TestSessionIsActiveOnlyInsideBothLimits(t *testing.T) {
	s := newSession(t)
	if !s.Active(s.IdleExpiresAt().Add(-time.Nanosecond)) {
		t.Error("inactive just before the idle limit")
	}

	if s.Active(s.IdleExpiresAt()) {
		t.Error("active at the idle limit")
	}

	// Regular activity keeps the session alive, but never past the absolute limit.
	for _, d := range []time.Duration{25, 50, 75} {
		if err := s.Touch(now.Add(d*day), policy); err != nil {
			t.Fatalf("Touch at day %d: %v", d, err)
		}
	}

	if !s.Active(s.ExpiresAt().Add(-time.Nanosecond)) {
		t.Error("inactive just before the absolute limit")
	}

	if s.Active(s.ExpiresAt()) {
		t.Error("active at the absolute limit")
	}
}

func TestTouchMovesIdleLimitButNeverPastTheAbsoluteLimit(t *testing.T) {
	s := newSession(t)

	at := now.Add(20 * day)
	if err := s.Touch(at, policy); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	if !s.LastActiveAt().Equal(at) || !s.IdleExpiresAt().Equal(at.Add(30*day)) {
		t.Errorf("after Touch: last=%v idle=%v", s.LastActiveAt(), s.IdleExpiresAt())
	}

	for _, d := range []time.Duration{45, 70} { // 70+30 would pass day 90
		if err := s.Touch(now.Add(d*day), policy); err != nil {
			t.Fatalf("Touch at day %d: %v", d, err)
		}
	}

	if !s.IdleExpiresAt().Equal(s.ExpiresAt()) {
		t.Errorf("idle limit %v should be capped at %v", s.IdleExpiresAt(), s.ExpiresAt())
	}
}

func TestTouchRefusesInactiveSessions(t *testing.T) {
	revoked := newSession(t)
	revoked.Revoke(now.Add(time.Hour))

	if err := revoked.Touch(now.Add(2*time.Hour), policy); !errors.Is(err, session.ErrNotActive) {
		t.Errorf("Touch of a revoked session = %v", err)
	}

	idle := newSession(t)

	before := idle.Record()
	if err := idle.Touch(now.Add(31*day), policy); !errors.Is(err, session.ErrNotActive) {
		t.Errorf("Touch of an idle-expired session = %v", err)
	}

	if !reflect.DeepEqual(idle.Record(), before) {
		t.Error("a refused Touch changed the session")
	}
}

func TestRefreshExpiryIsCappedBySessionLife(t *testing.T) {
	s := newSession(t)
	if got := s.RefreshExpiry(now, policy); !got.Equal(now.Add(30 * day)) {
		t.Errorf("early expiry = %v", got)
	}

	if got := s.RefreshExpiry(now.Add(80*day), policy); !got.Equal(s.ExpiresAt()) {
		t.Errorf("late expiry = %v, want the session end %v", got, s.ExpiresAt())
	}
}

func TestRevokeKeepsTheFirstTimeAndEndsTheSession(t *testing.T) {
	s := newSession(t)
	first := now.Add(time.Hour)
	s.Revoke(first)
	s.Revoke(now.Add(2 * time.Hour))

	if !s.RevokedAt().Equal(first) || s.Active(now.Add(3*time.Hour)) {
		t.Errorf("revokedAt=%v active=%v", s.RevokedAt(), s.Active(now.Add(3*time.Hour)))
	}
}

func TestNewSessionRejectsInvalidInput(t *testing.T) {
	f := testutil.NewFactory(t, now)
	user := f.User(testutil.UserSpec{})
	id, _ := f.IDs.NewSessionID()
	good := session.NewParams{ID: id, UserID: user.ID(), Binding: testutil.BindingHash("b"), AMR: []string{"otp"}, AuthTime: now, DeviceName: "phone"}

	tests := map[string]func(*session.NewParams){
		"no id":               func(p *session.NewParams) { p.ID = session.ID{} },
		"no user":             func(p *session.NewParams) { p.UserID = identity.UserID{} },
		"no binding":          func(p *session.NewParams) { p.Binding = identity.BindingHash{} },
		"no methods":          func(p *session.NewParams) { p.AMR = nil },
		"empty method":        func(p *session.NewParams) { p.AMR = []string{""} },
		"no auth time":        func(p *session.NewParams) { p.AuthTime = time.Time{} },
		"auth time in future": func(p *session.NewParams) { p.AuthTime = now.Add(time.Second) },
		"long device name":    func(p *session.NewParams) { p.DeviceName = strings.Repeat("x", 65) },
		"control character":   func(p *session.NewParams) { p.DeviceName = "phone\n" },
		"invalid utf8":        func(p *session.NewParams) { p.DeviceName = "\xff" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := good
			mutate(&p)

			if _, err := session.New(p, now, policy); err == nil {
				t.Error("New accepted invalid input")
			}
		})
	}

	for _, name := range []string{"", "Alice's iPhone", strings.Repeat("я", 64)} {
		p := good

		p.DeviceName = name
		if _, err := session.New(p, now, policy); err != nil {
			t.Errorf("device name %q rejected: %v", name, err)
		}
	}

	for name, bad := range map[string]session.Policy{
		"zero idle": {AbsoluteTTL: day}, "absolute shorter than idle": {IdleTTL: 2 * day, AbsoluteTTL: day},
	} {
		if _, err := session.New(good, now, bad); err == nil {
			t.Errorf("New accepted policy %s", name)
		}
	}
}

func TestSessionRecordRoundTripAndValidation(t *testing.T) {
	s := newSession(t)
	s.Revoke(now.Add(time.Hour))

	restored, err := session.Restore(s.Record())
	if err != nil || !reflect.DeepEqual(restored.Record(), s.Record()) {
		t.Fatalf("round trip = %v", err)
	}

	good := s.Record()
	for name, mutate := range map[string]func(*session.Record){
		"no id":                    func(r *session.Record) { r.ID = session.ID{} },
		"idle past absolute":       func(r *session.Record) { r.IdleExpiresAt = r.ExpiresAt.Add(time.Second) },
		"no methods":               func(r *session.Record) { r.AMR = nil },
		"activity before creation": func(r *session.Record) { r.LastActiveAt = r.CreatedAt.Add(-time.Second) },
	} {
		r := good
		mutate(&r)

		if _, err := session.Restore(r); err == nil {
			t.Errorf("Restore accepted a record with %s", name)
		}
	}
}

func TestSessionDoesNotAliasAMR(t *testing.T) {
	s := newSession(t)

	s.AMR()[0] = "changed"
	if s.AMR()[0] != "otp" {
		t.Error("AMR exposes internal state")
	}
}

func TestParseID(t *testing.T) {
	const v7 = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3a4b"
	if id, err := session.ParseID(v7); err != nil || id.String() != v7 {
		t.Fatalf("ParseID(%q) = %v, %v", v7, id, err)
	}

	for _, in := range []string{"", "3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f", "018F3B2A-1C4D-7A5E-8B6F-9C0D1E2F3A4B", "018f3b2a-1c4d-7a5e-cb6f-9c0d1e2f3a4b", "x"} {
		if _, err := session.ParseID(in); !errors.Is(err, session.ErrInvalidID) {
			t.Errorf("ParseID(%q) = %v, want ErrInvalidID", in, err)
		}
	}
}
