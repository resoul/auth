package http

import (
	"context"
	"errors"
	"fmt"

	"airlance.org/auth/internal/application/emailauth"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/transport/http/openapi"
)

// BrowserStartEmail starts a flow. The client binding is the cookie; a browser that has none
// (or a malformed one) gets a new one in Set-Cookie and never in the body.
func (a *API) BrowserStartEmail(ctx context.Context, req openapi.BrowserStartEmailRequestObject) (openapi.BrowserStartEmailResponseObject, error) {
	cmd := emailauth.StartCommand{
		Email: req.Body.Email, BindingSecret: requestCookie(ctx, BindingCookieName), ClientIP: clientIP(ctx),
	}
	res, err := a.start.Execute(ctx, cmd)
	if cmd.BindingSecret != "" && errors.Is(err, port.ErrInvalidBindingSecret) {
		cmd.BindingSecret = ""
		res, err = a.start.Execute(ctx, cmd)
	}
	if errors.Is(err, identity.ErrInvalidEmail) {
		return openapi.BrowserStartEmail400JSONResponse{InvalidRequestJSONResponse: openapi.InvalidRequestJSONResponse(problem(ctx, openapi.ErrorCodeInvalidRequest))}, nil
	}
	if err != nil {
		return nil, err
	}

	switch res.Outcome {
	case emailauth.OutcomeOK:
		if res.Reason == emailauth.ReasonNotInvited || res.Reason == emailauth.ReasonBlocked {
			a.denied(ctx, "start", string(res.Reason)) // the client sees an ordinary start; the operator sees the refusal
		}
		if res.NewBindingSecret != "" {
			setCookie(ctx, a.cookies.binding(res.NewBindingSecret))
		}
		return openapi.BrowserStartEmail202JSONResponse{FlowId: res.FlowID.String(), ExpiresAt: res.ExpiresAt, ResendAfter: res.ResendAfter}, nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "start", string(res.Reason))
		return openapi.BrowserStartEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}
	return nil, fmt.Errorf("start: unexpected outcome %q", res.Outcome)
}

// BrowserVerifyEmail proves the code with the binding cookie. A success opens no session and
// sets no cookie: it names the next step and carries the ticket, which is useless without the
// same binding cookie.
func (a *API) BrowserVerifyEmail(ctx context.Context, req openapi.BrowserVerifyEmailRequestObject) (openapi.BrowserVerifyEmailResponseObject, error) {
	res, err := a.verify.Execute(ctx, emailauth.VerifyCodeCommand{
		FlowID: req.Body.FlowId, Code: req.Body.Code, BindingSecret: requestCookie(ctx, BindingCookieName), ClientIP: clientIP(ctx),
	})
	if err != nil {
		return nil, err
	}

	switch res.Outcome {
	case emailauth.OutcomeOK:
		return openapi.BrowserVerifyEmail200JSONResponse(verifiedNextStep(res)), nil
	case emailauth.OutcomeDenied:
		a.denied(ctx, "verify", string(res.Reason))
		return openapi.BrowserVerifyEmail400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "verify", string(res.Reason))
		return openapi.BrowserVerifyEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}
	return nil, fmt.Errorf("verify: unexpected outcome %q", res.Outcome)
}

// BrowserResendEmail sends a new code for the flow of the binding cookie.
func (a *API) BrowserResendEmail(ctx context.Context, req openapi.BrowserResendEmailRequestObject) (openapi.BrowserResendEmailResponseObject, error) {
	res, err := a.resendFlow(ctx, req.Body.FlowId, requestCookie(ctx, BindingCookieName))
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case emailauth.OutcomeOK:
		if res.Reason == emailauth.ReasonNotInvited || res.Reason == emailauth.ReasonBlocked {
			a.denied(ctx, "resend", string(res.Reason))
		}
		return openapi.BrowserResendEmail202JSONResponse{FlowId: req.Body.FlowId, ExpiresAt: res.ExpiresAt, ResendAfter: res.ResendAfter}, nil
	case emailauth.OutcomeDenied:
		a.denied(ctx, "resend", string(res.Reason))
		return openapi.BrowserResendEmail400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "resend", string(res.Reason))
		return openapi.BrowserResendEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}
	return nil, fmt.Errorf("resend: unexpected outcome %q", res.Outcome)
}

// NativeResendEmail sends a new code for the flow of the explicit binding.
func (a *API) NativeResendEmail(ctx context.Context, req openapi.NativeResendEmailRequestObject) (openapi.NativeResendEmailResponseObject, error) {
	res, err := a.resendFlow(ctx, req.Body.FlowId, req.Body.ClientBinding)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case emailauth.OutcomeOK:
		if res.Reason == emailauth.ReasonNotInvited || res.Reason == emailauth.ReasonBlocked {
			a.denied(ctx, "resend", string(res.Reason))
		}
		return openapi.NativeResendEmail202JSONResponse{FlowId: req.Body.FlowId, ExpiresAt: res.ExpiresAt, ResendAfter: res.ResendAfter}, nil
	case emailauth.OutcomeDenied:
		a.denied(ctx, "resend", string(res.Reason))
		return openapi.NativeResendEmail400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "resend", string(res.Reason))
		return openapi.NativeResendEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}
	return nil, fmt.Errorf("resend: unexpected outcome %q", res.Outcome)
}

func (a *API) resendFlow(ctx context.Context, flowID, binding string) (emailauth.ResendResult, error) {
	return a.resend.Execute(ctx, emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding, ClientIP: clientIP(ctx)})
}
