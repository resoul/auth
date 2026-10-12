package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
)

// Revoke is the revocation endpoint (RFC 7009): an application that logs a person out of itself tells the provider that
// its tokens are no longer wanted. A refresh token, or an access token, of the application ends the grant it belongs to, and
// with it every token of that grant: a client does not keep half of a grant alive.
type Revoke struct{ Deps }

// NewRevoke checks the dependencies once, at assembly time.
func NewRevoke(d Deps) (*Revoke, error) {
	if err := d.validate("revoke"); err != nil {
		return nil, err
	}
	return &Revoke{d}, nil
}

// RevokeCommand is the input of Revoke. A token type hint is not needed: the shape of the token tells.
type RevokeCommand struct {
	ClientID     string
	ClientSecret string
	Token        string
}

// RevokeResult is the output of Revoke. A nil Failure is the 200 of the RFC, whether or not the token existed, so the
// endpoint tells a client nothing about tokens that are not its own.
type RevokeResult struct {
	Failure *Failure
}

// Execute authenticates the client and ends the grant of the token if it is the client's own.
func (u *Revoke) Execute(ctx context.Context, cmd RevokeCommand) (RevokeResult, error) {
	now := u.Clock.Now()
	var result RevokeResult
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		client, err := u.authenticateClient(ctx, st, cmd.ClientID, cmd.ClientSecret, now)
		if err != nil {
			return err
		}
		if client == nil {
			result = RevokeResult{Failure: fail(ErrInvalidClient, "The client could not be authenticated.")}
			return nil
		}
		grantID := ""
		var owner identity.UserID
		if hash, err := u.Secrets.HashOIDCSecret(cmd.Token); err == nil {
			// An opaque refresh token. The user and the grant are locked in the order every statement uses.
			if _, grant, err := st.OIDCRefresh.GetByHashForUpdate(ctx, hash); err == nil && grant.ClientID == client.ID {
				grantID, owner = grant.ID, grant.UserID
			} else if err != nil && !errors.Is(err, port.ErrNotFound) {
				return fmt.Errorf("load refresh token: %w", err)
			}
		} else if strings.Count(cmd.Token, ".") == 2 {
			// A JWT access token of this provider, for its UserInfo.
			if claims, err := u.Verifier.VerifyOIDCAccess(cmd.Token, u.UserInfoAudience()); err == nil && claims.ClientID == client.ID {
				grantID, owner = claims.GrantID, claims.Subject
			}
		}
		if grantID == "" {
			return nil
		}
		if err := st.OIDCGrants.Revoke(ctx, grantID, now); err != nil {
			return fmt.Errorf("revoke grant: %w", err)
		}
		return st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditOIDCRevoked, Result: port.AuditSuccess, UserID: owner, At: now, Fields: map[string]string{"client": client.ID},
		})
	})
	if err != nil {
		return RevokeResult{}, fmt.Errorf("revoke: %w", err)
	}
	return result, nil
}
