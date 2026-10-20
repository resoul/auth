package token_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
	"go.airlance.org/auth/internal/testutil"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type fixture struct {
	f    *testutil.Factory
	sess *session.Session
	root *token.RefreshToken
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := testutil.NewFactory(t, now)
	sess := f.Session(testutil.SessionSpec{User: f.User(testutil.UserSpec{})})
	root, _ := f.RefreshToken(testutil.RefreshSpec{Session: sess})

	return fixture{f, sess, root}
}

func (fx fixture) rotate(t *testing.T, tok *token.RefreshToken, at time.Time) (*token.RefreshToken, error) {
	t.Helper()

	id, err := fx.f.IDs.NewRefreshTokenID()
	if err != nil {
		t.Fatal(err)
	}

	hash := testutil.TokenHash(fx.f.RefreshSecret())

	return tok.Rotate(at, id, hash, fx.sess.RefreshExpiry(at, session.DefaultPolicy()))
}

func TestRootTokenExpiresWithTheIdlePeriod(t *testing.T) {
	fx := newFixture(t)
	if !fx.root.CreatedAt().Equal(now) || !fx.root.ExpiresAt().Equal(now.Add(30*24*time.Hour)) {
		t.Errorf("times = %v / %v", fx.root.CreatedAt(), fx.root.ExpiresAt())
	}

	if !fx.root.ParentID().IsZero() || !fx.root.UsedAt().IsZero() || !fx.root.RevokedAt().IsZero() {
		t.Error("a root token must have no parent and no history")
	}

	if fx.root.SessionID() != fx.sess.ID() {
		t.Error("the token belongs to another session")
	}
}

func TestRotateMarksUsedAndReturnsTheOnlyChild(t *testing.T) {
	fx := newFixture(t)
	at := now.Add(time.Hour)

	child, err := fx.rotate(t, fx.root, at)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !fx.root.UsedAt().Equal(at) {
		t.Errorf("parent UsedAt = %v", fx.root.UsedAt())
	}

	if child.ParentID() != fx.root.ID() || child.FamilyID() != fx.root.FamilyID() || child.SessionID() != fx.root.SessionID() {
		t.Errorf("child lineage wrong: parent=%s family=%s", child.ParentID(), child.FamilyID())
	}

	if child.Hash() == fx.root.Hash() || !child.CreatedAt().Equal(at) || !child.UsedAt().IsZero() {
		t.Error("child must be a fresh, unused token with its own secret")
	}
}

func TestUsedTokenIsAlwaysAReuse(t *testing.T) {
	fx := newFixture(t)
	if _, err := fx.rotate(t, fx.root, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	for name, at := range map[string]time.Time{
		"right away":   now.Add(time.Hour),
		"much later":   now.Add(10 * 24 * time.Hour),
		"after expiry": fx.root.ExpiresAt().Add(time.Hour),
		"long after":   fx.root.ExpiresAt().Add(365 * 24 * time.Hour),
	} {
		if err := fx.root.CheckUsable(at); !errors.Is(err, token.ErrReused) {
			t.Errorf("%s: CheckUsable = %v, want ErrReused", name, err)
		}

		before := fx.root.Record()
		if _, err := fx.rotate(t, fx.root, at); !errors.Is(err, token.ErrReused) {
			t.Errorf("%s: Rotate = %v, want ErrReused", name, err)
		}

		if !reflect.DeepEqual(fx.root.Record(), before) {
			t.Errorf("%s: a refused Rotate changed the token", name)
		}
	}

	fx.root.Revoke(now.Add(2 * time.Hour))

	if err := fx.root.CheckUsable(now.Add(3 * time.Hour)); !errors.Is(err, token.ErrReused) {
		t.Errorf("used and revoked: CheckUsable = %v, want ErrReused", err)
	}
}

func TestRevokedTokenCannotRotate(t *testing.T) {
	fx := newFixture(t)
	fx.root.Revoke(now.Add(time.Minute))

	if _, err := fx.rotate(t, fx.root, now.Add(time.Hour)); !errors.Is(err, token.ErrRevoked) {
		t.Errorf("Rotate = %v, want ErrRevoked", err)
	}

	if !fx.root.UsedAt().IsZero() {
		t.Error("a refused Rotate marked the token used")
	}
}

func TestExpiryBoundary(t *testing.T) {
	fx := newFixture(t)
	if err := fx.root.CheckUsable(fx.root.ExpiresAt().Add(-time.Nanosecond)); err != nil {
		t.Errorf("just before expiry: %v", err)
	}

	if err := fx.root.CheckUsable(fx.root.ExpiresAt()); !errors.Is(err, token.ErrExpired) {
		t.Errorf("at expiry: %v, want ErrExpired", err)
	}

	if _, err := fx.rotate(t, fx.root, fx.root.ExpiresAt()); !errors.Is(err, token.ErrExpired) {
		t.Errorf("Rotate at expiry = %v", err)
	}

	if !fx.root.UsedAt().IsZero() {
		t.Error("an expired token was marked used")
	}
}

func TestChildExpiryIsValidated(t *testing.T) {
	fx := newFixture(t)
	id, _ := fx.f.IDs.NewRefreshTokenID()
	hash := testutil.TokenHash(fx.f.RefreshSecret())

	at := now.Add(time.Hour)
	if _, err := fx.root.Rotate(at, id, hash, at); err == nil {
		t.Error("Rotate accepted a child that expires at once")
	}

	if !fx.root.UsedAt().IsZero() {
		t.Error("a failed Rotate marked the parent used")
	}
}

func TestRevokeKeepsTheFirstTime(t *testing.T) {
	fx := newFixture(t)
	first := now.Add(time.Hour)
	fx.root.Revoke(first)
	fx.root.Revoke(now.Add(2 * time.Hour))

	if !fx.root.RevokedAt().Equal(first) {
		t.Errorf("RevokedAt = %v", fx.root.RevokedAt())
	}
}

func TestRecordRoundTripAndValidation(t *testing.T) {
	fx := newFixture(t)

	child, err := fx.rotate(t, fx.root, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	for _, tok := range []*token.RefreshToken{fx.root, child} {
		restored, err := token.Restore(tok.Record())
		if err != nil || !reflect.DeepEqual(restored.Record(), tok.Record()) {
			t.Fatalf("round trip: %v", err)
		}
	}

	good := child.Record()
	for name, mutate := range map[string]func(*token.Record){
		"no id":        func(r *token.Record) { r.ID = token.ID{} },
		"no session":   func(r *token.Record) { r.SessionID = session.ID{} },
		"no family":    func(r *token.Record) { r.FamilyID = token.FamilyID{} },
		"no hash":      func(r *token.Record) { r.Hash = token.Hash{} },
		"expiry first": func(r *token.Record) { r.ExpiresAt = r.CreatedAt },
		"own parent":   func(r *token.Record) { r.ParentID = r.ID },
	} {
		r := good
		mutate(&r)

		if _, err := token.Restore(r); err == nil {
			t.Errorf("Restore accepted a record with %s", name)
		}
	}
}

func TestIDsAndHash(t *testing.T) {
	const v7 = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3a4b"
	if _, err := token.ParseID(v7); err != nil {
		t.Errorf("ParseID: %v", err)
	}

	if _, err := token.ParseFamilyID(v7); err != nil {
		t.Errorf("ParseFamilyID: %v", err)
	}

	for _, in := range []string{"", "3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f", "nope"} {
		if _, err := token.ParseID(in); !errors.Is(err, token.ErrInvalidID) {
			t.Errorf("ParseID(%q) = %v", in, err)
		}

		if _, err := token.ParseFamilyID(in); !errors.Is(err, token.ErrInvalidID) {
			t.Errorf("ParseFamilyID(%q) = %v", in, err)
		}
	}

	for _, n := range []int{0, 31, 33} {
		if _, err := token.NewHash(make([]byte, n)); err == nil {
			t.Errorf("NewHash accepted %d bytes", n)
		}
	}

	if h, err := token.NewHash(make([]byte, 32)); err != nil || h.IsZero() || len(h.Bytes()) != 32 {
		t.Errorf("NewHash(32) = %v, %v", h, err)
	}
}
