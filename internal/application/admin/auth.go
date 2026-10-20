package admin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
)

// AuthDeps are the dependencies of Auth.
type AuthDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	WebAuthn   port.WebAuthn
	PasskeyIDs port.PasskeyIDGenerator
	Secrets    port.TicketSecrets
}

// Auth enrolls the passkeys of operators and signs them in.
type Auth struct{ AuthDeps }

// NewAuth checks the dependencies once, at assembly time.
func NewAuth(d AuthDeps) (*Auth, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.WebAuthn == nil || d.PasskeyIDs == nil || d.Secrets == nil {
		return nil, errors.New("new admin auth: all dependencies are required")
	}

	return &Auth{d}, nil
}

// CeremonyResult is the output of the two Begin steps. ChallengeID and Options are set only for OutcomeOK.
type CeremonyResult struct {
	Outcome     Outcome
	Reason      Reason
	ChallengeID string
	// Options is the JSON the page passes to navigator.credentials.
	Options []byte
}

// spend charges the admin budget of an address. It reports whether the step may go on.
func (a *Auth) spend(ctx context.Context, st port.Stores, now time.Time, ip netip.Addr) (bool, error) {
	allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendAdmin, IP: ip, Now: now})
	if err != nil {
		return false, fmt.Errorf("spend admin quota: %w", err)
	}

	return allowed, nil
}
