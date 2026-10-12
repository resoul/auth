package passkey

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

func TestSignInRefusesABlockedUserBeforeTouchingAnything(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	user := testutil.NewFactory(t, now).User(testutil.UserSpec{})
	if err := user.Block(now); err != nil {
		t.Fatal(err)
	}
	_, err := SessionDeps{}.signIn(context.Background(), port.Stores{}, now, user, identity.BindingHash{}, nil, "", "otp", netip.Addr{})
	if err == nil {
		t.Fatal("signIn issued a session to a blocked user")
	}
}
