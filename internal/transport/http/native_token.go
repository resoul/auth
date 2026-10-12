package http

import (
	"context"
	"fmt"

	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/transport/http/openapi"
)

// NativeRefreshToken rotates the refresh token from the body. Every refusal is the
// same invalid_refresh; a replay has already revoked the session when it is returned.
func (a *API) NativeRefreshToken(ctx context.Context, req openapi.NativeRefreshTokenRequestObject) (openapi.NativeRefreshTokenResponseObject, error) {
	res, err := a.refresh.Execute(ctx, appsession.RefreshCommand{RefreshSecret: req.Body.RefreshToken})
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case appsession.OutcomeOK:
		return openapi.NativeRefreshToken200JSONResponse{
			AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt, RefreshToken: res.NewRefreshSecret,
		}, nil
	case appsession.OutcomeDenied:
		a.denied(ctx, "refresh", string(res.Reason))
		return openapi.NativeRefreshToken401JSONResponse(problem(ctx, openapi.ErrorCodeInvalidRefresh)), nil
	}
	return nil, fmt.Errorf("refresh: unexpected outcome %q", res.Outcome)
}
