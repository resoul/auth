package http

import (
	"context"
	"fmt"

	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/transport/http/openapi"
)

// BrowserRefreshToken rotates the refresh token of the cookie. A token in the body is not
// read. A refusal clears the cookie: it is dead or forged, and keeping it only repeats the
// failure.
func (a *API) BrowserRefreshToken(ctx context.Context, _ openapi.BrowserRefreshTokenRequestObject) (openapi.BrowserRefreshTokenResponseObject, error) {
	res, err := a.refresh.Execute(ctx, appsession.RefreshCommand{RefreshSecret: requestCookie(ctx, RefreshCookieName)})
	if err != nil {
		return nil, err
	}

	switch res.Outcome {
	case appsession.OutcomeOK:
		setCookie(ctx, a.cookies.refresh(res.NewRefreshSecret, res.RefreshExpiresAt))
		return openapi.BrowserRefreshToken200JSONResponse{AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt}, nil
	case appsession.OutcomeDenied:
		a.denied(ctx, "refresh", string(res.Reason))
		setCookie(ctx, a.cookies.clearRefresh())

		return openapi.BrowserRefreshToken401JSONResponse(problem(ctx, openapi.ErrorCodeInvalidRefresh)), nil
	}

	return nil, fmt.Errorf("refresh: unexpected outcome %q", res.Outcome)
}
