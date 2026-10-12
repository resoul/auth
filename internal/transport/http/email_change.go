package http

import (
	"context"
	"errors"
	"fmt"

	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/transport/http/openapi"
)

// The routes that change the address of the signed-in account. Each authenticates first and answers
// unauthenticated for every kind of credential failure alike. Every refusal of the code is the same
// invalid_code; a missing step-up is its own answer so a client knows to run the ceremony.

func emailTaken(ctx context.Context) openapi.Error { return problem(ctx, openapi.ErrorCodeEmailTaken) }

// startEmailChange runs the use case. unauth is true when the caller is not authenticated and
// invalid when the address is malformed or is the account's own.
func (a *API) startEmailChange(ctx context.Context, token *string, email string) (res account.StartEmailChangeResult, unauth, invalid bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return account.StartEmailChangeResult{}, !ok, false, err
	}
	res, err = a.startChangeUC.Execute(ctx, account.StartEmailChangeCommand{
		Actor: actor, StepUpSecret: stepUpToken(token), Email: email, ClientIP: clientIP(ctx),
	})
	if errors.Is(err, identity.ErrInvalidEmail) {
		return account.StartEmailChangeResult{}, false, true, nil
	}
	if err == nil && res.Outcome == account.OutcomeInvalid {
		return account.StartEmailChangeResult{}, false, true, nil
	}
	return res, false, false, err
}

func (a *API) confirmEmailChange(ctx context.Context, body openapi.EmailChangeConfirmRequest) (res account.ConfirmEmailChangeResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return account.ConfirmEmailChangeResult{}, !ok, err
	}
	res, err = a.confirmChangeUC.Execute(ctx, account.ConfirmEmailChangeCommand{
		Actor: actor, FlowID: body.FlowId, Code: body.Code, ClientIP: clientIP(ctx),
	})
	return res, false, err
}

func startChangeBody(res account.StartEmailChangeResult) openapi.EmailChangeStartResponse {
	return openapi.EmailChangeStartResponse{FlowId: res.FlowID.String(), ExpiresAt: res.ExpiresAt.UTC()}
}

// NativeStartEmailChange asks for a code at the new address; it needs the step-up token.
func (a *API) NativeStartEmailChange(ctx context.Context, req openapi.NativeStartEmailChangeRequestObject) (openapi.NativeStartEmailChangeResponseObject, error) {
	res, unauth, invalid, err := a.startEmailChange(ctx, req.Params.XStepUp, req.Body.Email)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeStartEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.NativeStartEmailChange400JSONResponse(invalidRequest(ctx)), nil
	}
	switch res.Outcome {
	case account.OutcomeOK:
		return openapi.NativeStartEmailChange202JSONResponse(startChangeBody(res)), nil
	case account.OutcomeStepUpRequired:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.NativeStartEmailChange403JSONResponse(stepUpRequired(ctx)), nil
	case account.OutcomeRateLimited:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.NativeStartEmailChange429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case account.OutcomeDenied:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.NativeStartEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return nil, fmt.Errorf("start email change: unexpected outcome %q", res.Outcome)
}

// NativeConfirmEmailChange proves the code and moves the account.
func (a *API) NativeConfirmEmailChange(ctx context.Context, req openapi.NativeConfirmEmailChangeRequestObject) (openapi.NativeConfirmEmailChangeResponseObject, error) {
	res, unauth, err := a.confirmEmailChange(ctx, *req.Body)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeConfirmEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	switch res.Outcome {
	case account.OutcomeOK:
		return openapi.NativeConfirmEmailChange200JSONResponse(openapi.EmailChangeResponse{Email: res.Email.String()}), nil
	case account.OutcomeConflict:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		return openapi.NativeConfirmEmailChange409JSONResponse(emailTaken(ctx)), nil
	case account.OutcomeRateLimited:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		return openapi.NativeConfirmEmailChange429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case account.OutcomeDenied, account.OutcomeInvalid:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		if res.Reason == account.ReasonNoSession {
			return openapi.NativeConfirmEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
		}
		return openapi.NativeConfirmEmailChange400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	}
	return nil, fmt.Errorf("confirm email change: unexpected outcome %q", res.Outcome)
}

// BrowserStartEmailChange asks for a code at the new address; it needs the step-up token.
func (a *API) BrowserStartEmailChange(ctx context.Context, req openapi.BrowserStartEmailChangeRequestObject) (openapi.BrowserStartEmailChangeResponseObject, error) {
	res, unauth, invalid, err := a.startEmailChange(ctx, req.Params.XStepUp, req.Body.Email)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserStartEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.BrowserStartEmailChange400JSONResponse(invalidRequest(ctx)), nil
	}
	switch res.Outcome {
	case account.OutcomeOK:
		return openapi.BrowserStartEmailChange202JSONResponse(startChangeBody(res)), nil
	case account.OutcomeStepUpRequired:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.BrowserStartEmailChange403JSONResponse(stepUpRequired(ctx)), nil
	case account.OutcomeRateLimited:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.BrowserStartEmailChange429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case account.OutcomeDenied:
		a.denied(ctx, "change_email_start", string(res.Reason))
		return openapi.BrowserStartEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return nil, fmt.Errorf("start email change: unexpected outcome %q", res.Outcome)
}

// BrowserConfirmEmailChange proves the code and moves the account.
func (a *API) BrowserConfirmEmailChange(ctx context.Context, req openapi.BrowserConfirmEmailChangeRequestObject) (openapi.BrowserConfirmEmailChangeResponseObject, error) {
	res, unauth, err := a.confirmEmailChange(ctx, *req.Body)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserConfirmEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	switch res.Outcome {
	case account.OutcomeOK:
		return openapi.BrowserConfirmEmailChange200JSONResponse(openapi.EmailChangeResponse{Email: res.Email.String()}), nil
	case account.OutcomeConflict:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		return openapi.BrowserConfirmEmailChange409JSONResponse(emailTaken(ctx)), nil
	case account.OutcomeRateLimited:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		return openapi.BrowserConfirmEmailChange429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case account.OutcomeDenied, account.OutcomeInvalid:
		a.denied(ctx, "change_email_confirm", string(res.Reason))
		if res.Reason == account.ReasonNoSession {
			return openapi.BrowserConfirmEmailChange401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
		}
		return openapi.BrowserConfirmEmailChange400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	}
	return nil, fmt.Errorf("confirm email change: unexpected outcome %q", res.Outcome)
}
