package http

import (
	"context"

	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/transport/http/openapi"
)

func (a *API) deleteAccount(ctx context.Context, token *string) (account.DeleteAccountResult, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return account.DeleteAccountResult{}, err
	}
	if !ok {
		return account.DeleteAccountResult{Outcome: account.OutcomeDenied}, nil
	}
	return a.deleteAccountUC.Execute(ctx, account.DeleteAccountCommand{Actor: actor, StepUpSecret: stepUpToken(token)})
}

// BrowserDeleteAccount deletes the account and forgets the browser cookies after commit.
func (a *API) BrowserDeleteAccount(ctx context.Context, req openapi.BrowserDeleteAccountRequestObject) (openapi.BrowserDeleteAccountResponseObject, error) {
	res, err := a.deleteAccount(ctx, req.Params.XStepUp)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case account.OutcomeOK:
		setCookie(ctx, a.cookies.clearRefresh())
		setCookie(ctx, a.cookies.clearBinding())
		return openapi.BrowserDeleteAccount204Response{}, nil
	case account.OutcomeStepUpRequired:
		return openapi.BrowserDeleteAccount403JSONResponse(stepUpRequired(ctx)), nil
	default:
		return openapi.BrowserDeleteAccount401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
}

// NativeDeleteAccount deletes the account without browser cookies.
func (a *API) NativeDeleteAccount(ctx context.Context, req openapi.NativeDeleteAccountRequestObject) (openapi.NativeDeleteAccountResponseObject, error) {
	res, err := a.deleteAccount(ctx, req.Params.XStepUp)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case account.OutcomeOK:
		return openapi.NativeDeleteAccount204Response{}, nil
	case account.OutcomeStepUpRequired:
		return openapi.NativeDeleteAccount403JSONResponse(stepUpRequired(ctx)), nil
	default:
		return openapi.NativeDeleteAccount401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
}
