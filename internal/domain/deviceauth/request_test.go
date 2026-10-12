package deviceauth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/domain/deviceauth"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

const code = "123456"

func requestID(t *testing.T) deviceauth.RequestID {
	t.Helper()
	id, err := deviceauth.ParseRequestID("AAECAwQFBgcICQoLDA0ODw")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newRequest(t *testing.T) *deviceauth.Request {
	t.Helper()
	r, err := deviceauth.New(deviceauth.NewParams{
		ID: requestID(t), PollHash: testutil.SecretHash("poll"), Binding: testutil.BindingHash("binding"),
		DeviceName: "Office laptop", PairingCode: code,
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type approver struct {
	user identity.UserID
	sess session.ID
}

func someone(t *testing.T) approver {
	t.Helper()
	f := testutil.NewFactory(t, t0)
	u := f.User(testutil.UserSpec{})
	return approver{user: u.ID(), sess: f.Session(testutil.SessionSpec{User: u}).ID()}
}

func TestParseRequestIDAcceptsOnlyCanonicalSixteenBytes(t *testing.T) {
	for _, bad := range []string{"", "x", "AAECAwQFBgcICQoLDA0ODw=", "AAECAwQFBgcICQoLDA0ODw\n", "AAECAwQFBgcICQoLDA0ODwA", "AAECAwQFBgcICQoLDA0OD+", "AAECAwQFBgcICQoLDA0ODx"} {
		if _, err := deviceauth.ParseRequestID(bad); err == nil {
			t.Errorf("ParseRequestID(%q) accepted", bad)
		}
	}
	id := deviceauth.NewRequestID([16]byte{1, 2, 3})
	back, err := deviceauth.ParseRequestID(id.String())
	if err != nil || back != id || id.IsZero() || len(id.String()) != 22 {
		t.Errorf("round trip: %v, %v", back, err)
	}
	if !(deviceauth.RequestID{}).IsZero() {
		t.Error("the zero id is not zero")
	}
}

func TestANewRequestIsPendingAndLivesFiveMinutes(t *testing.T) {
	r := newRequest(t)
	if r.State() != deviceauth.StatePending || r.Attempts() != 0 || !r.UserID().IsZero() || r.PairingCode() != code || r.DeviceName() != "Office laptop" {
		t.Errorf("new request = %+v", r.Record())
	}
	if !r.ExpiresAt().Equal(t0.Add(deviceauth.TTL)) || deviceauth.TTL != 5*time.Minute {
		t.Errorf("expires at %v", r.ExpiresAt())
	}
	if !r.Live(t0.Add(deviceauth.TTL-time.Nanosecond)) || r.Live(t0.Add(deviceauth.TTL)) {
		t.Error("the request does not end exactly at its TTL")
	}
}

func TestNewRefusesWhatCannotBeKept(t *testing.T) {
	base := deviceauth.NewParams{
		ID: requestID(t), PollHash: testutil.SecretHash("poll"), Binding: testutil.BindingHash("binding"), DeviceName: "x", PairingCode: code,
	}
	for name, mutate := range map[string]func(*deviceauth.NewParams){
		"no id":           func(p *deviceauth.NewParams) { p.ID = deviceauth.RequestID{} },
		"no poll secret":  func(p *deviceauth.NewParams) { p.PollHash = passkey.SecretHash{} },
		"no binding":      func(p *deviceauth.NewParams) { p.Binding = identity.BindingHash{} },
		"device name":     func(p *deviceauth.NewParams) { p.DeviceName = strings.Repeat("x", 65) },
		"control name":    func(p *deviceauth.NewParams) { p.DeviceName = "a\nb" },
		"short code":      func(p *deviceauth.NewParams) { p.PairingCode = "12345" },
		"long code":       func(p *deviceauth.NewParams) { p.PairingCode = "1234567" },
		"letters in code": func(p *deviceauth.NewParams) { p.PairingCode = "12345a" },
		"space in code":   func(p *deviceauth.NewParams) { p.PairingCode = "123 56" },
		"newline in code": func(p *deviceauth.NewParams) { p.PairingCode = "12345\n" },
		"unicode digits":  func(p *deviceauth.NewParams) { p.PairingCode = "١٢٣٤٥٦" },
	} {
		p := base
		mutate(&p)
		if _, err := deviceauth.New(p, t0); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	if _, err := deviceauth.New(base, time.Time{}); err == nil {
		t.Error("New accepted a zero time")
	}
	base.DeviceName = ""
	if _, err := deviceauth.New(base, t0); err != nil {
		t.Errorf("an empty device name is allowed: %v", err)
	}
}

func TestApprovalNeedsTheRightCodeInTime(t *testing.T) {
	a := someone(t)
	r := newRequest(t)
	if err := r.Approve(t0.Add(time.Minute), a.user, a.sess, code); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if r.State() != deviceauth.StateApproved || r.UserID() != a.user || r.ApproverSessionID() != a.sess || r.Attempts() != 0 {
		t.Errorf("approved = %+v", r.Record())
	}
	if err := r.Approve(t0.Add(time.Minute), a.user, a.sess, code); !errors.Is(err, deviceauth.ErrNotPending) {
		t.Errorf("a second approval = %v, want ErrNotPending", err)
	}

	late := newRequest(t)
	if err := late.Approve(t0.Add(deviceauth.TTL), a.user, a.sess, code); !errors.Is(err, deviceauth.ErrExpired) {
		t.Errorf("an approval at the expiry instant = %v, want ErrExpired", err)
	}
	if late.State() != deviceauth.StatePending {
		t.Error("an expired approval changed the request")
	}
	if err := newRequest(t).Approve(t0, identity.UserID{}, a.sess, code); err == nil {
		t.Error("an approval without a user")
	}
	if err := newRequest(t).Approve(t0, a.user, session.ID{}, code); err == nil {
		t.Error("an approval without a session")
	}
}

func TestWrongCodesAreCountedAndTheThirdKillsTheRequest(t *testing.T) {
	a := someone(t)
	r := newRequest(t)
	for i := 1; i < deviceauth.MaxAttempts; i++ {
		if err := r.Approve(t0, a.user, a.sess, "000000"); !errors.Is(err, deviceauth.ErrWrongCode) || r.Attempts() != i || r.State() != deviceauth.StatePending {
			t.Fatalf("wrong code %d: %v, attempts %d, state %s", i, err, r.Attempts(), r.State())
		}
	}
	// The right code still works until the last attempt is spent.
	spare := newRequest(t)
	_ = spare.Approve(t0, a.user, a.sess, "000000")
	if err := spare.Approve(t0, a.user, a.sess, code); err != nil {
		t.Errorf("the right code after one mistake: %v", err)
	}

	if err := r.Approve(t0, a.user, a.sess, "000000"); !errors.Is(err, deviceauth.ErrAttemptsExhausted) || r.State() != deviceauth.StateDenied || !r.UserID().IsZero() {
		t.Fatalf("the last wrong code: %v, state %s", err, r.State())
	}
	if err := r.Approve(t0, a.user, a.sess, code); !errors.Is(err, deviceauth.ErrNotPending) {
		t.Errorf("the right code after the request died = %v, want ErrNotPending", err)
	}
	for _, typed := range []string{"", "12345", "1234567", "123456 ", " 123456", "12345６"} {
		fresh := newRequest(t)
		if err := fresh.Approve(t0, a.user, a.sess, typed); !errors.Is(err, deviceauth.ErrWrongCode) {
			t.Errorf("typed %q = %v, want ErrWrongCode", typed, err)
		}
	}
}

func TestDenyEndsAPendingRequestOnly(t *testing.T) {
	r := newRequest(t)
	if err := r.Deny(t0); err != nil || r.State() != deviceauth.StateDenied {
		t.Fatalf("Deny: %v, %s", err, r.State())
	}
	if err := r.Deny(t0); !errors.Is(err, deviceauth.ErrNotPending) {
		t.Errorf("a second Deny = %v", err)
	}
	a := someone(t)
	approved := newRequest(t)
	_ = approved.Approve(t0, a.user, a.sess, code)
	if err := approved.Deny(t0); !errors.Is(err, deviceauth.ErrNotPending) {
		t.Errorf("Deny of an approved request = %v: the approval stands", err)
	}
	if err := newRequest(t).Deny(t0.Add(deviceauth.TTL)); !errors.Is(err, deviceauth.ErrExpired) {
		t.Errorf("Deny after expiry = %v", err)
	}
}

func TestRedeemNeedsApprovalTheSecretTheBindingAndTime(t *testing.T) {
	a := someone(t)
	poll, binding := testutil.SecretHash("poll"), testutil.BindingHash("binding")
	approve := func() *deviceauth.Request {
		r := newRequest(t)
		if err := r.Approve(t0, a.user, a.sess, code); err != nil {
			t.Fatal(err)
		}
		return r
	}

	if err := newRequest(t).Redeem(t0, poll, binding); !errors.Is(err, deviceauth.ErrNotApproved) {
		t.Errorf("redeeming a pending request = %v", err)
	}
	denied := newRequest(t)
	_ = denied.Deny(t0)
	if err := denied.Redeem(t0, poll, binding); !errors.Is(err, deviceauth.ErrNotApproved) {
		t.Errorf("redeeming a denied request = %v", err)
	}
	for name, tc := range map[string]struct {
		poll    passkey.SecretHash
		binding identity.BindingHash
	}{
		"wrong secret":  {testutil.SecretHash("other"), binding},
		"wrong binding": {poll, testutil.BindingHash("other")},
		"no secret":     {passkey.SecretHash{}, binding},
		"no binding":    {poll, identity.BindingHash{}},
	} {
		r := approve()
		if err := r.Redeem(t0, tc.poll, tc.binding); !errors.Is(err, deviceauth.ErrMismatch) || r.State() != deviceauth.StateApproved {
			t.Errorf("%s: %v, state %s", name, err, r.State())
		}
	}
	if err := approve().Redeem(t0.Add(deviceauth.TTL), poll, binding); !errors.Is(err, deviceauth.ErrExpired) {
		t.Errorf("redeeming at the expiry instant = %v", err)
	}

	r := approve()
	if err := r.Redeem(t0.Add(time.Minute), poll, binding); err != nil || r.State() != deviceauth.StateRedeemed {
		t.Fatalf("Redeem: %v, %s", err, r.State())
	}
	if err := r.Redeem(t0.Add(time.Minute), poll, binding); !errors.Is(err, deviceauth.ErrNotApproved) {
		t.Errorf("a second Redeem = %v: a session is issued once", err)
	}
	if !r.Matches(poll, binding) || r.Matches(testutil.SecretHash("x"), binding) {
		t.Error("Matches does not compare the secret")
	}
}

func TestRecordRoundTripAndRestoreRejectsImpossibleStates(t *testing.T) {
	a := someone(t)
	r := newRequest(t)
	_ = r.Approve(t0.Add(time.Second), a.user, a.sess, code)
	_ = r.Redeem(t0.Add(2*time.Second), testutil.SecretHash("poll"), testutil.BindingHash("binding"))
	restored, err := deviceauth.Restore(r.Record())
	if err != nil || restored.Record() != r.Record() {
		t.Fatalf("round trip: %v", err)
	}
	pending := newRequest(t).Record()
	for name, mutate := range map[string]func(*deviceauth.Record){
		"unknown state":              func(r *deviceauth.Record) { r.State = "weird" },
		"approver on a pending":      func(r *deviceauth.Record) { r.UserID = a.user },
		"approved without approver":  func(r *deviceauth.Record) { r.State = deviceauth.StateApproved },
		"redeemed without time":      func(r *deviceauth.Record) { r.State = deviceauth.StateRedeemed; r.UserID = a.user; r.DecidedAt = t0 },
		"redemption time on pending": func(r *deviceauth.Record) { r.RedeemedAt = t0 },
		"too many attempts":          func(r *deviceauth.Record) { r.Attempts = deviceauth.MaxAttempts + 1 },
		"negative attempts":          func(r *deviceauth.Record) { r.Attempts = -1 },
		"expiry before creation":     func(r *deviceauth.Record) { r.ExpiresAt = r.CreatedAt },
		"bad code":                   func(r *deviceauth.Record) { r.Code = "abc" },
	} {
		rec := pending
		mutate(&rec)
		if _, err := deviceauth.Restore(rec); err == nil {
			t.Errorf("%s: Restore accepted it", name)
		}
	}
}
