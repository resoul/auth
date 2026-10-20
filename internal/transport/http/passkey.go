package http

import (
	"context"
	"errors"

	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/transport/http/openapi"
)

func invalidProof(ctx context.Context) openapi.Error {
	return problem(ctx, openapi.ErrorCodeInvalidProof)
}

func invalidRequest(ctx context.Context) openapi.Error {
	return problem(ctx, openapi.ErrorCodeInvalidRequest)
}

func optional(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func ceremony(res passkey.CeremonyResult) openapi.CeremonyResponse {
	return openapi.CeremonyResponse{ChallengeId: res.ChallengeID, Options: res.Options}
}

func (a *API) beginEnroll(ctx context.Context, ticket, binding string) (passkey.CeremonyResult, error) {
	return a.beginEnrollUC.Execute(ctx, passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: binding, ClientIP: clientIP(ctx)})
}

func (a *API) finishEnroll(ctx context.Context, cmd passkey.FinishEnrollCommand) (passkey.FinishEnrollResult, error) {
	return a.finishEnrollUC.Execute(ctx, cmd)
}

// NativeBeginPasskeyRegistration prepares the registration of a passkey.
func (a *API) NativeBeginPasskeyRegistration(ctx context.Context, req openapi.NativeBeginPasskeyRegistrationRequestObject) (openapi.NativeBeginPasskeyRegistrationResponseObject, error) {
	res, err := a.beginEnroll(ctx, req.Body.Ticket, req.Body.ClientBinding)
	if err != nil {
		return nil, err
	}

	if res.Outcome == passkey.OutcomeRateLimited {
		a.denied(ctx, "passkey_register_options", string(res.Reason))
		return openapi.NativeBeginPasskeyRegistration429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_register_options", string(res.Reason))
		return openapi.NativeBeginPasskeyRegistration400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeBeginPasskeyRegistration200JSONResponse(ceremony(res)), nil
}

// BrowserBeginPasskeyRegistration prepares the registration of a passkey; the binding is the cookie.
func (a *API) BrowserBeginPasskeyRegistration(ctx context.Context, req openapi.BrowserBeginPasskeyRegistrationRequestObject) (openapi.BrowserBeginPasskeyRegistrationResponseObject, error) {
	res, err := a.beginEnroll(ctx, req.Body.Ticket, requestCookie(ctx, BindingCookieName))
	if err != nil {
		return nil, err
	}

	if res.Outcome == passkey.OutcomeRateLimited {
		a.denied(ctx, "passkey_register_options", string(res.Reason))
		return openapi.BrowserBeginPasskeyRegistration429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_register_options", string(res.Reason))
		return openapi.BrowserBeginPasskeyRegistration400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.BrowserBeginPasskeyRegistration200JSONResponse(ceremony(res)), nil
}

// NativeFinishPasskeyRegistration verifies the new passkey and opens the session.
func (a *API) NativeFinishPasskeyRegistration(ctx context.Context, req openapi.NativeFinishPasskeyRegistrationRequestObject) (openapi.NativeFinishPasskeyRegistrationResponseObject, error) {
	res, err := a.finishEnroll(ctx, passkey.FinishEnrollCommand{
		TicketSecret: req.Body.Ticket, BindingSecret: req.Body.ClientBinding, ChallengeID: req.Body.ChallengeId,
		Response: req.Body.Credential, CredentialName: optional(req.Body.Name), DeviceName: optional(req.Body.DeviceName), ClientIP: clientIP(ctx),
	})
	if errors.Is(err, passkey.ErrInvalidName) {
		return openapi.NativeFinishPasskeyRegistration400JSONResponse(invalidRequest(ctx)), nil
	}

	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_register", string(res.Reason))
		return openapi.NativeFinishPasskeyRegistration400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeFinishPasskeyRegistration200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt, RefreshToken: res.RefreshSecret,
		RecoveryCodes: res.RecoveryCodes,
	}, nil
}

// BrowserFinishPasskeyRegistration verifies the new passkey and opens the session: the refresh
// token goes to its cookie and the binding cookie is renewed; the body never carries either.
func (a *API) BrowserFinishPasskeyRegistration(ctx context.Context, req openapi.BrowserFinishPasskeyRegistrationRequestObject) (openapi.BrowserFinishPasskeyRegistrationResponseObject, error) {
	binding := requestCookie(ctx, BindingCookieName)

	res, err := a.finishEnroll(ctx, passkey.FinishEnrollCommand{
		TicketSecret: req.Body.Ticket, BindingSecret: binding, ChallengeID: req.Body.ChallengeId,
		Response: req.Body.Credential, CredentialName: optional(req.Body.Name), DeviceName: optional(req.Body.DeviceName), ClientIP: clientIP(ctx),
	})
	if errors.Is(err, passkey.ErrInvalidName) {
		return openapi.BrowserFinishPasskeyRegistration400JSONResponse(invalidRequest(ctx)), nil
	}

	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_register", string(res.Reason))
		return openapi.BrowserFinishPasskeyRegistration400JSONResponse(invalidProof(ctx)), nil
	}

	setCookie(ctx, a.cookies.refresh(res.RefreshSecret, res.RefreshExpiresAt))
	setCookie(ctx, a.cookies.binding(binding))

	return openapi.BrowserFinishPasskeyRegistration200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt, RecoveryCodes: res.RecoveryCodes,
	}, nil
}

func (a *API) beginLogin(ctx context.Context) (passkey.CeremonyResult, error) {
	return a.beginLoginUC.Execute(ctx, passkey.BeginLoginCommand{ClientIP: clientIP(ctx)})
}

// NativeBeginPasskeyLogin prepares an assertion.
func (a *API) NativeBeginPasskeyLogin(ctx context.Context, _ openapi.NativeBeginPasskeyLoginRequestObject) (openapi.NativeBeginPasskeyLoginResponseObject, error) {
	res, err := a.beginLogin(ctx)
	if err != nil {
		return nil, err
	}

	if res.Outcome == passkey.OutcomeRateLimited {
		a.denied(ctx, "passkey_login_options", string(res.Reason))
		return openapi.NativeBeginPasskeyLogin429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	return openapi.NativeBeginPasskeyLogin200JSONResponse(ceremony(res)), nil
}

// BrowserBeginPasskeyLogin prepares an assertion.
func (a *API) BrowserBeginPasskeyLogin(ctx context.Context, _ openapi.BrowserBeginPasskeyLoginRequestObject) (openapi.BrowserBeginPasskeyLoginResponseObject, error) {
	res, err := a.beginLogin(ctx)
	if err != nil {
		return nil, err
	}

	if res.Outcome == passkey.OutcomeRateLimited {
		a.denied(ctx, "passkey_login_options", string(res.Reason))
		return openapi.BrowserBeginPasskeyLogin429JSONResponse{RateLimitedJSONResponse: openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))}, nil
	}

	return openapi.BrowserBeginPasskeyLogin200JSONResponse(ceremony(res)), nil
}

// NativeFinishPasskeyLogin verifies the assertion and opens the session.
func (a *API) NativeFinishPasskeyLogin(ctx context.Context, req openapi.NativeFinishPasskeyLoginRequestObject) (openapi.NativeFinishPasskeyLoginResponseObject, error) {
	res, err := a.finishLoginUC.Execute(ctx, passkey.FinishLoginCommand{
		ChallengeID: req.Body.ChallengeId, Response: req.Body.Credential, TicketSecret: optional(req.Body.Ticket),
		BindingSecret: optional(req.Body.ClientBinding), DeviceName: optional(req.Body.DeviceName), ClientIP: clientIP(ctx),
	})
	if errors.Is(err, passkey.ErrInvalidName) {
		return openapi.NativeFinishPasskeyLogin400JSONResponse(invalidRequest(ctx)), nil
	}

	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_login", string(res.Reason))
		return openapi.NativeFinishPasskeyLogin400JSONResponse(invalidProof(ctx)), nil
	}

	body := openapi.NativeFinishPasskeyLogin200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt, RefreshToken: res.RefreshSecret,
	}
	if res.NewBindingSecret != "" {
		body.ClientBinding = &res.NewBindingSecret
	}

	return body, nil
}

// BrowserFinishPasskeyLogin verifies the assertion and opens the session. A browser without a
// binding cookie gets a new one; the refresh token goes to its cookie. The body carries neither.
func (a *API) BrowserFinishPasskeyLogin(ctx context.Context, req openapi.BrowserFinishPasskeyLoginRequestObject) (openapi.BrowserFinishPasskeyLoginResponseObject, error) {
	cmd := passkey.FinishLoginCommand{
		ChallengeID: req.Body.ChallengeId, Response: req.Body.Credential, TicketSecret: optional(req.Body.Ticket),
		BindingSecret: requestCookie(ctx, BindingCookieName), DeviceName: optional(req.Body.DeviceName), ClientIP: clientIP(ctx),
	}

	res, err := a.finishLoginUC.Execute(ctx, cmd)
	if err == nil && res.Outcome == passkey.OutcomeDenied && res.Reason == passkey.ReasonBadBinding && cmd.TicketSecret == "" {
		// A malformed cookie is replaced like a missing one, but only when no ticket depends on it.
		cmd.BindingSecret = ""
		res, err = a.finishLoginUC.Execute(ctx, cmd)
	}

	if errors.Is(err, passkey.ErrInvalidName) {
		return openapi.BrowserFinishPasskeyLogin400JSONResponse(invalidRequest(ctx)), nil
	}

	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "passkey_login", string(res.Reason))
		return openapi.BrowserFinishPasskeyLogin400JSONResponse(invalidProof(ctx)), nil
	}

	setCookie(ctx, a.cookies.refresh(res.RefreshSecret, res.RefreshExpiresAt))
	// The binding cookie is renewed, or issued when the browser had none or a malformed one.
	binding := res.NewBindingSecret
	if binding == "" {
		binding = cmd.BindingSecret
	}

	if binding != "" {
		setCookie(ctx, a.cookies.binding(binding))
	}

	return openapi.BrowserFinishPasskeyLogin200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt,
	}, nil
}

func (a *API) redeem(ctx context.Context, ticket, binding, code string) (passkey.RedeemRecoveryResult, error) {
	return a.recoveryUC.Execute(ctx, passkey.RedeemRecoveryCommand{TicketSecret: ticket, BindingSecret: binding, Code: code})
}

func recoveryTicket(res passkey.RedeemRecoveryResult) openapi.NextStepResponse {
	return openapi.NextStepResponse{
		Next: openapi.NextStepResponseNext(emailauth.NextEnrollPasskey), Ticket: res.TicketSecret, ExpiresAt: res.TicketExpiresAt,
	}
}

// NativeRedeemRecoveryCode spends a recovery code and returns the ticket for a new passkey.
func (a *API) NativeRedeemRecoveryCode(ctx context.Context, req openapi.NativeRedeemRecoveryCodeRequestObject) (openapi.NativeRedeemRecoveryCodeResponseObject, error) {
	res, err := a.redeem(ctx, req.Body.Ticket, req.Body.ClientBinding, req.Body.Code)
	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "recovery", string(res.Reason))
		return openapi.NativeRedeemRecoveryCode400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeRedeemRecoveryCode200JSONResponse(recoveryTicket(res)), nil
}

// BrowserRedeemRecoveryCode spends a recovery code; the binding is the cookie.
func (a *API) BrowserRedeemRecoveryCode(ctx context.Context, req openapi.BrowserRedeemRecoveryCodeRequestObject) (openapi.BrowserRedeemRecoveryCodeResponseObject, error) {
	res, err := a.redeem(ctx, req.Body.Ticket, requestCookie(ctx, BindingCookieName), req.Body.Code)
	if err != nil {
		return nil, err
	}

	if res.Outcome != passkey.OutcomeOK {
		a.denied(ctx, "recovery", string(res.Reason))
		return openapi.BrowserRedeemRecoveryCode400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.BrowserRedeemRecoveryCode200JSONResponse(recoveryTicket(res)), nil
}
