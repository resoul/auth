package identity_test

import (
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

func TestRegistrationModes(t *testing.T) {
	for in, want := range map[string]identity.RegistrationMode{"open": identity.RegistrationOpen, "invite": identity.RegistrationInviteOnly} {
		got, err := identity.ParseRegistrationMode(in)
		if err != nil || got != want {
			t.Errorf("ParseRegistrationMode(%q) = %q, %v", in, got, err)
		}
	}

	for _, bad := range []string{"", "closed", "Open", "invite ", "INVITE"} {
		if _, err := identity.ParseRegistrationMode(bad); err == nil {
			t.Errorf("ParseRegistrationMode accepted %q", bad)
		}
	}

	if identity.RegistrationOpen.Invites() || identity.RegistrationMode("").Invites() || !identity.RegistrationInviteOnly.Invites() {
		t.Error("only the invite mode asks for an invitation, and the zero value is open")
	}
}

func TestInvitationLivesForItsLifetimeOnly(t *testing.T) {
	email, err := identity.ParseEmail("Guest@Example.test")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	inv, err := identity.NewInvitation(email, now, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if inv.Email().String() != "guest@example.test" || !inv.CreatedAt().Equal(now) || !inv.ExpiresAt().Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("invitation = %+v", inv.Record())
	}

	if !inv.Active(now) || !inv.Active(inv.ExpiresAt().Add(-time.Nanosecond)) || inv.Active(inv.ExpiresAt()) {
		t.Error("an invitation is active until its expiry instant, not at it")
	}
}

func TestInvitationRefusesWhatCannotBeKept(t *testing.T) {
	email, _ := identity.ParseEmail("guest@example.test")
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	for name, call := range map[string]func() error{
		"no email": func() error { _, err := identity.NewInvitation(identity.Email{}, now, 24*time.Hour); return err },
		"no time":  func() error { _, err := identity.NewInvitation(email, time.Time{}, 24*time.Hour); return err },
		"too short": func() error {
			_, err := identity.NewInvitation(email, now, identity.MinInvitationTTL-time.Second)
			return err
		},
		"too long": func() error {
			_, err := identity.NewInvitation(email, now, identity.MaxInvitationTTL+time.Second)
			return err
		},
		"zero": func() error { _, err := identity.NewInvitation(email, now, 0); return err },
		"restore bad": func() error {
			_, err := identity.RestoreInvitation(identity.InvitationRecord{Email: email, CreatedAt: now, ExpiresAt: now})
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := identity.NewInvitation(email, now, identity.MinInvitationTTL); err != nil {
		t.Errorf("the shortest lifetime: %v", err)
	}

	if _, err := identity.NewInvitation(email, now, identity.MaxInvitationTTL); err != nil {
		t.Errorf("the longest lifetime: %v", err)
	}

	rec, _ := identity.NewInvitation(email, now, 24*time.Hour)

	back, err := identity.RestoreInvitation(rec.Record())
	if err != nil || back.Record() != rec.Record() {
		t.Errorf("restore = %+v, %v", back, err)
	}
}
