package passkey_test

import (
	"context"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

func (e *env) redeem(ticket string, b bindingSecret, code string) passkey.RedeemRecoveryResult {
	e.t.Helper()
	got, err := e.redeemRecovery.Execute(context.Background(), passkey.RedeemRecoveryCommand{TicketSecret: ticket, BindingSecret: b.secret, Code: code})
	must(e.t, err)

	return got
}

func TestRecoveryAfterLosingEveryKey(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	// An old session, opened with the lost device.
	old := e.signIn(holder.auth, "", e.newBinding())
	if old.Outcome != passkey.OutcomeOK {
		t.Fatalf("old sign-in = %+v", old)
	}

	// The email code proved the mailbox; the user has no key, so they offer a recovery code.
	b := e.newBinding()
	second := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)

	redeemed := e.redeem(second, b, holder.codes[0])
	if redeemed.Outcome != passkey.OutcomeOK || redeemed.TicketSecret == "" || redeemed.TicketExpiresAt.IsZero() {
		t.Fatalf("redeem = %+v", redeemed)
	}

	if e.store.SessionCount() != 2 {
		t.Error("redeeming a code opened a session: recovery must end with a working key, not a session")
	}

	// The new ticket registers a new key, in place of every old one, and opens the session.
	fresh := testutil.NewSoftAuthenticator(t, rpID, origin)

	got := e.enrollWith(holder.user, fresh, redeemed.TicketSecret, b)
	if got.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll after recovery = %+v", got)
	}

	if want := []string{"otp", "recovery_code", "passkey"}; strings.Join(got.Session.AMR(), ",") != strings.Join(want, ",") {
		t.Errorf("amr = %v, want %v", got.Session.AMR(), want)
	}

	if len(e.credentials(holder.user)) != 1 {
		t.Errorf("%d keys, want only the new one: the lost key must not open the account again", len(e.credentials(holder.user)))
	}

	if r := e.signIn(holder.auth, "", e.newBinding()); r.Outcome == passkey.OutcomeOK {
		t.Error("the key that was lost signs in after the recovery")
	}

	if r := e.signIn(fresh, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Errorf("the new key does not sign in: %+v", r)
	}

	// What the lost device opened is closed.
	oldSession, _ := e.store.Session(old.Session.ID())
	if oldSession.RevokedAt().IsZero() {
		t.Error("the session of the lost device survived the recovery")
	}

	if live, _ := e.store.Session(got.Session.ID()); !live.RevokedAt().IsZero() {
		t.Error("the recovery session was revoked with the old ones")
	}

	// Every old code is gone, a fresh set exists, and the spent one is not in it.
	if len(got.RecoveryCodes) != dpasskey.RecoveryCodeCount || e.unusedCodes(holder.user) != dpasskey.RecoveryCodeCount {
		t.Errorf("%d codes shown, %d stored", len(got.RecoveryCodes), e.unusedCodes(holder.user))
	}

	b2 := e.newBinding()
	if r := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b2), b2, holder.codes[1]); r.Outcome != passkey.OutcomeDenied || r.Reason != passkey.ReasonBadRecoveryCode {
		t.Errorf("a code of the superseded set = %+v", r)
	}

	// And the new key signs in.
	if in := e.signIn(fresh, "", e.newBinding()); in.Outcome != passkey.OutcomeOK {
		t.Errorf("new key sign-in = %+v", in)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()

	b := e.newBinding()
	if r := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b), b, holder.codes[0]); r.Outcome != passkey.OutcomeOK {
		t.Fatalf("first = %+v", r)
	}

	if r := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b), b, holder.codes[0]); r.Outcome != passkey.OutcomeDenied || r.Reason != passkey.ReasonBadRecoveryCode {
		t.Errorf("second = %+v", r)
	}

	if e.unusedCodes(holder.user) != dpasskey.RecoveryCodeCount-1 {
		t.Errorf("%d unused codes, want %d", e.unusedCodes(holder.user), dpasskey.RecoveryCodeCount-1)
	}
}

func TestRecoveryCodeAcceptsHowPeopleTypeIt(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	typed := strings.ToLower(strings.ReplaceAll(holder.codes[0], "-", " "))

	b := e.newBinding()
	if r := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b), b, " "+typed+" "); r.Outcome != passkey.OutcomeOK {
		t.Errorf("a code typed in lower case with spaces = %+v", r)
	}
}

func TestAWrongRecoveryCodeSpendsTheTicket(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	b := e.newBinding()
	ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)

	for _, bad := range []string{"", "AAAA-AAAA-AAAA-AAAA", "short", "AAAAAAAAAAAAAAA1"} {
		t2 := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)
		if r := e.redeem(t2, b, bad); r.Outcome != passkey.OutcomeDenied || r.Reason != passkey.ReasonBadRecoveryCode {
			t.Errorf("code %q = %+v", bad, r)
		}
	}

	if r := e.redeem(ticket, b, "AAAA-AAAA-AAAA-AAAA"); r.Reason != passkey.ReasonBadRecoveryCode {
		t.Fatalf("a wrong code = %+v", r)
	}
	// The right code no longer works with that ticket: guessing costs an email proof each time.
	if r := e.redeem(ticket, b, holder.codes[0]); r.Outcome != passkey.OutcomeDenied || r.Reason != passkey.ReasonBadTicket {
		t.Errorf("the right code on a spent ticket = %+v", r)
	}

	if e.unusedCodes(holder.user) != dpasskey.RecoveryCodeCount {
		t.Error("a refused attempt spent a code")
	}

	refused := 0

	for _, ev := range e.store.AuditEvents() {
		if ev.Type == port.AuditPasskeyRefused && ev.Fields["reason"] == "bad_recovery_code" {
			refused++
		}
	}

	if refused != 5 {
		t.Errorf("%d refusals audited, want 5", refused)
	}
}

func TestRecoveryRefusals(t *testing.T) {
	t.Run("a code of another user", func(t *testing.T) {
		e := newEnv(t)
		victim, other := e.enroll(), e.enroll()
		b := e.newBinding()

		got := e.redeem(e.ticketFor(victim.user, dpasskey.TicketSecondFactor, b), b, other.codes[0])
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadRecoveryCode {
			t.Errorf("result = %+v", got)
		}

		if e.unusedCodes(other.user) != dpasskey.RecoveryCodeCount {
			t.Error("a code was spent on behalf of another user")
		}
	})

	t.Run("an enroll ticket is not a second factor", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		b := e.newBinding()

		got := e.redeem(e.ticketFor(holder.user, dpasskey.TicketEnroll, b), b, holder.codes[0])
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("another client's binding, a malformed ticket, an expired ticket", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		b := e.newBinding()

		ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)
		if r := e.redeem(ticket, e.newBinding(), holder.codes[0]); r.Reason != passkey.ReasonBadTicket {
			t.Errorf("another binding = %+v", r)
		}

		if r := e.redeem(ticket, bindingSecret{secret: "bad"}, holder.codes[0]); r.Reason != passkey.ReasonBadBinding {
			t.Errorf("malformed binding = %+v", r)
		}

		if r := e.redeem("nope", b, holder.codes[0]); r.Reason != passkey.ReasonBadTicket {
			t.Errorf("malformed ticket = %+v", r)
		}

		e.clock.Advance(dpasskey.SecondFactorTicketTTL)

		if r := e.redeem(ticket, b, holder.codes[0]); r.Reason != passkey.ReasonBadTicket {
			t.Errorf("expired ticket = %+v", r)
		}

		if e.unusedCodes(holder.user) != dpasskey.RecoveryCodeCount {
			t.Error("a refused request spent a code")
		}
	})
}
