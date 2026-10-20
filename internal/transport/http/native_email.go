package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/transport/http/openapi"
)

// NativeStartEmail starts a flow. A new client gets its binding secret in the response.
func (a *API) NativeStartEmail(ctx context.Context, req openapi.NativeStartEmailRequestObject) (openapi.NativeStartEmailResponseObject, error) {
	cmd := emailauth.StartCommand{Email: req.Body.Email, ClientIP: clientIP(ctx)}
	if req.Body.ClientBinding != nil {
		cmd.BindingSecret = *req.Body.ClientBinding
	}

	res, err := a.start.Execute(ctx, cmd)
	if errors.Is(err, identity.ErrInvalidEmail) || errors.Is(err, port.ErrInvalidBindingSecret) {
		return openapi.NativeStartEmail400JSONResponse{InvalidRequestJSONResponse: openapi.InvalidRequestJSONResponse(problem(ctx, openapi.ErrorCodeInvalidRequest))}, nil
	}

	if err != nil {
		return nil, err
	}

	switch res.Outcome {
	case emailauth.OutcomeOK:
		if res.Reason == emailauth.ReasonNotInvited || res.Reason == emailauth.ReasonBlocked {
			a.denied(ctx, "start", string(res.Reason)) // the client sees an ordinary start; the operator sees the refusal
		}

		body := openapi.NativeStartEmail202JSONResponse{
			FlowId: res.FlowID.String(), ExpiresAt: res.ExpiresAt, ResendAfter: res.ResendAfter,
		}
		if res.NewBindingSecret != "" {
			body.ClientBinding = &res.NewBindingSecret
		}

		return body, nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "start", string(res.Reason))
		return openapi.NativeStartEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	return nil, fmt.Errorf("start: unexpected outcome %q", res.Outcome)
}

// NativeVerifyEmail proves the code. Every refusal is the same invalid_code. A success opens no
// session: it names the next step and carries the ticket for it.
func (a *API) NativeVerifyEmail(ctx context.Context, req openapi.NativeVerifyEmailRequestObject) (openapi.NativeVerifyEmailResponseObject, error) {
	res, err := a.verify.Execute(ctx, emailauth.VerifyCodeCommand{
		FlowID: req.Body.FlowId, Code: req.Body.Code, BindingSecret: req.Body.ClientBinding, ClientIP: clientIP(ctx),
	})
	if err != nil {
		return nil, err
	}

	switch res.Outcome {
	case emailauth.OutcomeOK:
		return openapi.NativeVerifyEmail200JSONResponse(verifiedNextStep(res)), nil
	case emailauth.OutcomeDenied:
		a.denied(ctx, "verify", string(res.Reason))
		return openapi.NativeVerifyEmail400JSONResponse(problem(ctx, openapi.ErrorCodeInvalidCode)), nil
	case emailauth.OutcomeRateLimited:
		a.denied(ctx, "verify", string(res.Reason))
		return openapi.NativeVerifyEmail429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	return nil, fmt.Errorf("verify: unexpected outcome %q", res.Outcome)
}

func verifiedNextStep(res emailauth.VerifyCodeResult) openapi.NextStepResponse {
	return openapi.NextStepResponse{Next: openapi.NextStepResponseNext(res.Next), Ticket: res.TicketSecret, ExpiresAt: res.TicketExpiresAt}
}

// denied logs an expected refusal. The reason comes from a closed set and never
// reaches the client. Most refusals are routine (a wrong code, a rate limit) and stay at debug; the few that say
// someone may hold a secret they should not are warnings, so they show at the default level and can be alerted on.
func (a *API) denied(ctx context.Context, operation, reason string) {
	a.requests.AuthDenied(operation, reason)

	level := slog.LevelDebug
	if securitySignals[reason] {
		level = slog.LevelWarn
	}

	a.logger.Log(ctx, level, "request denied", "operation", operation, "reason", reason)
}

// securitySignals are the refusal reasons that point to a stolen or copied secret: a refresh token used twice,
// a passkey whose signature counter went backwards. The audit log and the metrics count them too.
var securitySignals = map[string]bool{
	string(appsession.ReasonTokenReused): true,
	string(passkey.ReasonCloneSuspected): true,
}
