package http

import (
	"context"
	"errors"

	appdevice "airlance.org/auth/internal/application/deviceauth"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/transport/http/openapi"
)

func deviceState(s appdevice.State) openapi.DeviceStatusResponseState {
	return openapi.DeviceStatusResponseState(s)
}

func (a *API) startDevice(ctx context.Context, name, binding string) (appdevice.StartResult, error) {
	return a.startDeviceUC.Execute(ctx, appdevice.StartCommand{DeviceName: name, BindingSecret: binding, ClientIP: clientIP(ctx)})
}

// NativeStartDeviceSignIn makes the request of a device that has no session.
func (a *API) NativeStartDeviceSignIn(ctx context.Context, req openapi.NativeStartDeviceSignInRequestObject) (openapi.NativeStartDeviceSignInResponseObject, error) {
	res, err := a.startDevice(ctx, optional(req.Body.DeviceName), optional(req.Body.ClientBinding))
	if errors.Is(err, appdevice.ErrInvalidName) {
		return openapi.NativeStartDeviceSignIn400JSONResponse(invalidRequest(ctx)), nil
	}
	if err != nil {
		return nil, err
	}
	if res.Outcome == appdevice.OutcomeRateLimited {
		a.denied(ctx, "device_start", string(res.Reason))
		return openapi.NativeStartDeviceSignIn429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	}
	body := openapi.NativeDeviceStartResponse{
		RequestId: res.RequestID.String(), PollSecret: res.PollSecret, PairingCode: res.PairingCode, ExpiresAt: res.ExpiresAt,
	}
	if res.NewBindingSecret != "" {
		body.ClientBinding = &res.NewBindingSecret
	}
	return openapi.NativeStartDeviceSignIn200JSONResponse(body), nil
}

// BrowserStartDeviceSignIn makes the request of a page that has no session. The poll secret goes to its cookie, the
// binding is the cookie too (a browser that has none, or a malformed one, gets a new one); the body carries neither.
func (a *API) BrowserStartDeviceSignIn(ctx context.Context, req openapi.BrowserStartDeviceSignInRequestObject) (openapi.BrowserStartDeviceSignInResponseObject, error) {
	binding := requestCookie(ctx, BindingCookieName)
	res, err := a.startDevice(ctx, optional(req.Body.DeviceName), binding)
	if binding != "" && errors.Is(err, port.ErrInvalidBindingSecret) {
		binding = ""
		res, err = a.startDevice(ctx, optional(req.Body.DeviceName), binding)
	}
	if errors.Is(err, appdevice.ErrInvalidName) {
		return openapi.BrowserStartDeviceSignIn400JSONResponse(invalidRequest(ctx)), nil
	}
	if err != nil {
		return nil, err
	}
	if res.Outcome == appdevice.OutcomeRateLimited {
		a.denied(ctx, "device_start", string(res.Reason))
		return openapi.BrowserStartDeviceSignIn429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	}
	if res.NewBindingSecret != "" {
		setCookie(ctx, a.cookies.binding(res.NewBindingSecret))
	}
	setCookie(ctx, a.cookies.device(res.PollSecret, res.ExpiresAt))
	return openapi.BrowserStartDeviceSignIn200JSONResponse{RequestId: res.RequestID.String(), PairingCode: res.PairingCode, ExpiresAt: res.ExpiresAt}, nil
}

func (a *API) deviceStatus(ctx context.Context, id, secret, binding string) (appdevice.StatusResult, error) {
	return a.statusDeviceUC.Execute(ctx, appdevice.StatusCommand{RequestID: id, PollSecret: secret, BindingSecret: binding})
}

// NativeDeviceSignInStatus tells the new device how its request stands.
func (a *API) NativeDeviceSignInStatus(ctx context.Context, req openapi.NativeDeviceSignInStatusRequestObject) (openapi.NativeDeviceSignInStatusResponseObject, error) {
	res, err := a.deviceStatus(ctx, req.Body.RequestId, req.Body.PollSecret, req.Body.ClientBinding)
	if err != nil {
		return nil, err
	}
	if res.Outcome != appdevice.OutcomeOK {
		a.denied(ctx, "device_status", string(res.Reason))
		return openapi.NativeDeviceSignInStatus400JSONResponse(invalidProof(ctx)), nil
	}
	return openapi.NativeDeviceSignInStatus200JSONResponse{State: deviceState(res.State)}, nil
}

// BrowserDeviceSignInStatus tells the page how its request stands; the secret and the binding are its cookies.
func (a *API) BrowserDeviceSignInStatus(ctx context.Context, req openapi.BrowserDeviceSignInStatusRequestObject) (openapi.BrowserDeviceSignInStatusResponseObject, error) {
	res, err := a.deviceStatus(ctx, req.Body.RequestId, requestCookie(ctx, DeviceCookieName), requestCookie(ctx, BindingCookieName))
	if err != nil {
		return nil, err
	}
	if res.Outcome != appdevice.OutcomeOK {
		a.denied(ctx, "device_status", string(res.Reason))
		return openapi.BrowserDeviceSignInStatus400JSONResponse(invalidProof(ctx)), nil
	}
	return openapi.BrowserDeviceSignInStatus200JSONResponse{State: deviceState(res.State)}, nil
}

func (a *API) redeemDevice(ctx context.Context, id, secret, binding string) (appdevice.RedeemResult, error) {
	return a.redeemDeviceUC.Execute(ctx, appdevice.RedeemCommand{RequestID: id, PollSecret: secret, BindingSecret: binding, ClientIP: clientIP(ctx)})
}

// NativeRedeemDeviceSignIn gives the device its session.
func (a *API) NativeRedeemDeviceSignIn(ctx context.Context, req openapi.NativeRedeemDeviceSignInRequestObject) (openapi.NativeRedeemDeviceSignInResponseObject, error) {
	res, err := a.redeemDevice(ctx, req.Body.RequestId, req.Body.PollSecret, req.Body.ClientBinding)
	if err != nil {
		return nil, err
	}
	if res.Outcome != appdevice.OutcomeOK {
		a.denied(ctx, "device_redeem", string(res.Reason))
		return openapi.NativeRedeemDeviceSignIn400JSONResponse(invalidProof(ctx)), nil
	}
	return openapi.NativeRedeemDeviceSignIn200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt, RefreshToken: res.RefreshSecret,
	}, nil
}

// BrowserRedeemDeviceSignIn gives the page its session: the refresh token goes to its cookie, the binding cookie is
// renewed and the poll secret, now spent, is cleared. The body carries only the access token.
func (a *API) BrowserRedeemDeviceSignIn(ctx context.Context, req openapi.BrowserRedeemDeviceSignInRequestObject) (openapi.BrowserRedeemDeviceSignInResponseObject, error) {
	binding := requestCookie(ctx, BindingCookieName)
	res, err := a.redeemDevice(ctx, req.Body.RequestId, requestCookie(ctx, DeviceCookieName), binding)
	if err != nil {
		return nil, err
	}
	if res.Outcome != appdevice.OutcomeOK {
		a.denied(ctx, "device_redeem", string(res.Reason))
		return openapi.BrowserRedeemDeviceSignIn400JSONResponse(invalidProof(ctx)), nil
	}
	setCookie(ctx, a.cookies.refresh(res.RefreshSecret, res.RefreshExpiresAt))
	setCookie(ctx, a.cookies.binding(binding))
	setCookie(ctx, a.cookies.clearDevice())
	return openapi.BrowserRedeemDeviceSignIn200JSONResponse{
		User:        openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		AccessToken: res.Access.Value, ExpiresAt: res.Access.ExpiresAt,
	}, nil
}

func deviceView(v appdevice.RequestView) openapi.DeviceRequestView {
	return openapi.DeviceRequestView{DeviceName: v.DeviceName, CreatedAt: v.CreatedAt.UTC(), ExpiresAt: v.ExpiresAt.UTC()}
}

// NativeGetDeviceRequest shows a pending request to a signed-in user.
func (a *API) NativeGetDeviceRequest(ctx context.Context, req openapi.NativeGetDeviceRequestRequestObject) (openapi.NativeGetDeviceRequestResponseObject, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.NativeGetDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	res, err := a.approverUC.Inspect(ctx, actor, req.RequestId)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case appdevice.OutcomeOK:
		return openapi.NativeGetDeviceRequest200JSONResponse(deviceView(res.View)), nil
	case appdevice.OutcomeDenied:
		return openapi.NativeGetDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.NativeGetDeviceRequest404JSONResponse(notFound(ctx)), nil
}

// BrowserGetDeviceRequest shows a pending request to a signed-in user.
func (a *API) BrowserGetDeviceRequest(ctx context.Context, req openapi.BrowserGetDeviceRequestRequestObject) (openapi.BrowserGetDeviceRequestResponseObject, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.BrowserGetDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	res, err := a.approverUC.Inspect(ctx, actor, req.RequestId)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case appdevice.OutcomeOK:
		return openapi.BrowserGetDeviceRequest200JSONResponse(deviceView(res.View)), nil
	case appdevice.OutcomeDenied:
		return openapi.BrowserGetDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.BrowserGetDeviceRequest404JSONResponse(notFound(ctx)), nil
}

func (a *API) approveDevice(ctx context.Context, id, code string, stepUp *string) (appdevice.Result, bool, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return appdevice.Result{}, false, err
	}
	res, err := a.approverUC.Approve(ctx, appdevice.ApproveCommand{Actor: actor, RequestID: id, PairingCode: code, StepUpSecret: stepUpToken(stepUp)})
	return res, true, err
}

// NativeApproveDeviceRequest lets the device sign in as this user. It needs the step-up token and the pairing code.
func (a *API) NativeApproveDeviceRequest(ctx context.Context, req openapi.NativeApproveDeviceRequestRequestObject) (openapi.NativeApproveDeviceRequestResponseObject, error) {
	res, authed, err := a.approveDevice(ctx, req.RequestId, req.Body.PairingCode, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case !authed:
		return openapi.NativeApproveDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	a.deniedDevice(ctx, "device_approve", res)
	switch res.Outcome {
	case appdevice.OutcomeOK:
		return openapi.NativeApproveDeviceRequest204Response{}, nil
	case appdevice.OutcomeStepUpRequired:
		return openapi.NativeApproveDeviceRequest403JSONResponse(stepUpRequired(ctx)), nil
	case appdevice.OutcomeNotFound:
		return openapi.NativeApproveDeviceRequest404JSONResponse(notFound(ctx)), nil
	case appdevice.OutcomeDenied:
		if res.Reason == appdevice.ReasonNoSession {
			return openapi.NativeApproveDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
		}
		if res.Reason == appdevice.ReasonExpired || res.Reason == appdevice.ReasonNotPending {
			return openapi.NativeApproveDeviceRequest404JSONResponse(notFound(ctx)), nil
		}
	}
	return openapi.NativeApproveDeviceRequest400JSONResponse(invalidProof(ctx)), nil
}

// BrowserApproveDeviceRequest lets the device sign in as this user. It needs the step-up token and the pairing code.
func (a *API) BrowserApproveDeviceRequest(ctx context.Context, req openapi.BrowserApproveDeviceRequestRequestObject) (openapi.BrowserApproveDeviceRequestResponseObject, error) {
	res, authed, err := a.approveDevice(ctx, req.RequestId, req.Body.PairingCode, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case !authed:
		return openapi.BrowserApproveDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	a.deniedDevice(ctx, "device_approve", res)
	switch res.Outcome {
	case appdevice.OutcomeOK:
		return openapi.BrowserApproveDeviceRequest204Response{}, nil
	case appdevice.OutcomeStepUpRequired:
		return openapi.BrowserApproveDeviceRequest403JSONResponse(stepUpRequired(ctx)), nil
	case appdevice.OutcomeNotFound:
		return openapi.BrowserApproveDeviceRequest404JSONResponse(notFound(ctx)), nil
	case appdevice.OutcomeDenied:
		if res.Reason == appdevice.ReasonNoSession {
			return openapi.BrowserApproveDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
		}
		if res.Reason == appdevice.ReasonExpired || res.Reason == appdevice.ReasonNotPending {
			return openapi.BrowserApproveDeviceRequest404JSONResponse(notFound(ctx)), nil
		}
	}
	return openapi.BrowserApproveDeviceRequest400JSONResponse(invalidProof(ctx)), nil
}

// deniedDevice counts an expected refusal for the alerts.
func (a *API) deniedDevice(ctx context.Context, operation string, res appdevice.Result) {
	if res.Outcome != appdevice.OutcomeOK {
		a.denied(ctx, operation, string(res.Reason))
	}
}

// NativeDenyDeviceRequest refuses a pending request.
func (a *API) NativeDenyDeviceRequest(ctx context.Context, req openapi.NativeDenyDeviceRequestRequestObject) (openapi.NativeDenyDeviceRequestResponseObject, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.NativeDenyDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	res, err := a.approverUC.Deny(ctx, actor, req.RequestId)
	if err != nil {
		return nil, err
	}
	switch {
	case res.Outcome == appdevice.OutcomeOK:
		return openapi.NativeDenyDeviceRequest204Response{}, nil
	case res.Reason == appdevice.ReasonNoSession:
		return openapi.NativeDenyDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.NativeDenyDeviceRequest404JSONResponse(notFound(ctx)), nil
}

// BrowserDenyDeviceRequest refuses a pending request.
func (a *API) BrowserDenyDeviceRequest(ctx context.Context, req openapi.BrowserDenyDeviceRequestRequestObject) (openapi.BrowserDenyDeviceRequestResponseObject, error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.BrowserDenyDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	res, err := a.approverUC.Deny(ctx, actor, req.RequestId)
	if err != nil {
		return nil, err
	}
	switch {
	case res.Outcome == appdevice.OutcomeOK:
		return openapi.BrowserDenyDeviceRequest204Response{}, nil
	case res.Reason == appdevice.ReasonNoSession:
		return openapi.BrowserDenyDeviceRequest401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.BrowserDenyDeviceRequest404JSONResponse(notFound(ctx)), nil
}
