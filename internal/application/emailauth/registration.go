package emailauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

// mayReceiveCode says why a sign-in code must not be sent to the address, or "" when it should be. A
// blocked account never gets one. In the invite-only mode an address that has no account must hold an
// active invitation. Whoever is refused gets the same answer from the API and no mail, so neither rule
// can be used to find out who is registered, invited or blocked.
func mayReceiveCode(ctx context.Context, st port.Stores, mode identity.RegistrationMode, email identity.Email, now time.Time) (Reason, error) {
	user, err := st.Users.FindByEmail(ctx, email)
	switch {
	case err == nil:
		if user.Blocked() {
			return ReasonBlocked, nil
		}

		return "", nil
	case !errors.Is(err, port.ErrNotFound):
		return "", fmt.Errorf("look up user: %w", err)
	}

	if !mode.Invites() {
		return "", nil
	}

	if _, err := st.Invitations.FindActive(ctx, email, now); err == nil {
		return "", nil
	} else if !errors.Is(err, port.ErrNotFound) {
		return "", fmt.Errorf("look up invitation: %w", err)
	}

	return ReasonNotInvited, nil
}
