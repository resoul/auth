package oidc

import (
	"context"
	"errors"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// ErrInvalidToken is the Bearer error of a token that does not authorize the request (RFC 6750).
const ErrInvalidToken = "invalid_token"

// UserInfo serves the claims of the user behind an access token. The signature and the claims of the token are not
// enough: the grant, the sign-in it stands on, the client and the user are read from the store on every request, so
// an ended grant stops working before the token's own expiry.
type UserInfo struct{ Deps }

// NewUserInfo checks the dependencies once, at assembly time.
func NewUserInfo(d Deps) (*UserInfo, error) {
	if err := d.validate("userinfo"); err != nil {
		return nil, err
	}

	return &UserInfo{d}, nil
}

// UserInfoClaims are the claims the access token's scopes allow. Email and EmailVerified are set only with the email
// scope.
type UserInfoClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	HasEmail      bool
}

// UserInfoResult is the output of UserInfo. Exactly one of Claims and Failure is set; every refusal looks alike.
type UserInfoResult struct {
	Claims  *UserInfoClaims
	Failure *Failure
}

// Execute checks the token and the state behind it and returns the user's claims.
func (u *UserInfo) Execute(ctx context.Context, accessToken string) (UserInfoResult, error) {
	denied := UserInfoResult{Failure: fail(ErrInvalidToken, "The access token is not valid.")}

	claims, err := u.Verifier.VerifyOIDCAccess(accessToken, u.UserInfoAudience())
	if errors.Is(err, port.ErrInvalidOIDCToken) {
		return denied, nil
	}

	if err != nil {
		return UserInfoResult{}, fmt.Errorf("userinfo: %w", err)
	}

	if !doidc.HasScope(claims.Scope, doidc.ScopeOpenID) {
		return denied, nil
	}

	now := u.Clock.Now()
	result := denied

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		grant, err := st.OIDCGrants.Get(ctx, claims.GrantID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load grant: %w", err)
		}

		if grant.ClientID != claims.ClientID || grant.UserID != claims.Subject || grant.OPSessionID != claims.SessionID || !covers(grant.Scopes, claims.Scope) {
			return nil
		}

		client, err := st.OIDCClients.Get(ctx, grant.ClientID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load client: %w", err)
		}

		if !client.Active() {
			return nil
		}

		op, user, err := u.liveGrant(ctx, st, now, grant)
		if err != nil {
			return err
		}

		if op == nil {
			return nil
		}

		out := &UserInfoClaims{Subject: user.ID().String()}
		if doidc.HasScope(claims.Scope, doidc.ScopeEmail) {
			out.HasEmail, out.Email, out.EmailVerified = true, user.Email().String(), !user.EmailVerifiedAt().IsZero()
		}

		result = UserInfoResult{Claims: out}

		return nil
	})
	if err != nil {
		return UserInfoResult{}, fmt.Errorf("userinfo: %w", err)
	}

	return result, nil
}
