package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
)

// RedeemDeps are the dependencies of Redeem.
type RedeemDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
	Bindings   port.BindingSecrets
	passkey.SessionDeps
}

// Redeem gives the device that made an approved request its own session.
type Redeem struct{ RedeemDeps }

// NewRedeem checks the dependencies once, at assembly time.
func NewRedeem(d RedeemDeps) (*Redeem, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil || d.Bindings == nil {
		return nil, errors.New("new device redeem: all dependencies are required")
	}
	if err := d.Validate("device redeem"); err != nil {
		return nil, err
	}
	return &Redeem{d}, nil
}

// RedeemCommand is the input of Redeem.
type RedeemCommand struct {
	RequestID     string
	PollSecret    string
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown. The notice of the new
	// device carries it and nothing else keeps it.
	ClientIP netip.Addr
}

// RedeemResult is the output of Redeem. The session is set only for OutcomeOK.
type RedeemResult struct {
	Outcome Outcome
	Reason  Reason
	passkey.SignedIn
}

// Execute opens the session, once. The request must be approved and live, the poll secret and the client binding
// the ones it was made with, the approving session still open and the user not blocked: approval is not a
// standing permission, it is good for the minutes it lives and only while what proved it still stands. The session
// does not copy the approving one; it is a new session of the same user with its own tokens.
func (u *Redeem) Execute(ctx context.Context, cmd RedeemCommand) (RedeemResult, error) {
	denied := func(reason Reason) (RedeemResult, error) {
		return RedeemResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	id, poll, binding, reason, err := proof(u.Tickets, u.Bindings, cmd.RequestID, cmd.PollSecret, cmd.BindingSecret)
	if err != nil {
		return RedeemResult{}, fmt.Errorf("redeem device request: %w", err)
	}
	if reason != "" {
		return denied(reason)
	}
	now := u.Clock.Now()
	var result RedeemResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		req, err := st.Devices.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonUnknownRequest)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device request: %w", err)
		}
		if err := req.Redeem(now, poll, binding); err != nil {
			reason, ok := denial(err)
			if !ok {
				return fmt.Errorf("redeem device request: %w", err)
			}
			result, _ = denied(reason)
			return nil
		}
		// The user is share-locked before the approving session is read. A revocation of the user's sessions queues on
		// the same row, so it either finished before this read, and the read sees the session revoked, or it starts
		// after this transaction and revokes the session opened below.
		user, err := st.Users.GetForShare(ctx, req.UserID())
		if errors.Is(err, port.ErrNotFound) {
			result, _ = denied(ReasonApproverGone)
			return nil
		}
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		// The approval counts only while the session that gave it is open.
		approver, err := st.Sessions.Get(ctx, req.ApproverSessionID())
		if err != nil && !errors.Is(err, port.ErrNotFound) {
			return fmt.Errorf("load approving session: %w", err)
		}
		if err != nil || !approver.Active(now) {
			result, _ = denied(ReasonApproverGone)
			return nil
		}
		if user.Blocked() {
			result, _ = denied(ReasonBlocked)
			return nil
		}
		if err := st.Devices.Save(ctx, req); err != nil {
			return fmt.Errorf("store device request: %w", err)
		}
		signed, err := u.SignIn(ctx, st, now, user, req.Binding(), amrDevice, req.DeviceName(), "qr", cmd.ClientIP)
		if err != nil {
			return err
		}
		result = RedeemResult{Outcome: OutcomeOK, SignedIn: signed}
		return nil
	})
	if err != nil {
		return RedeemResult{}, fmt.Errorf("redeem device request: %w", err)
	}
	return result, nil
}
