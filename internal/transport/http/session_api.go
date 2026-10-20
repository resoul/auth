package http

import (
	"context"
	"strings"

	appsession "go.airlance.org/auth/internal/application/session"
	dsession "go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/transport/http/openapi"
)

const maxBearerLength = 4096

func bearerToken(ctx context.Context) (string, bool) {
	values := requestHeaderValues(ctx, "Authorization")
	if len(values) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxBearerLength || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}

	return token, true
}

func (a *API) authenticate(ctx context.Context) (appsession.Actor, bool, error) {
	token, ok := bearerToken(ctx)
	if !ok {
		a.denied(ctx, "authenticate", "no_credentials")
		return appsession.Actor{}, false, nil
	}

	res, err := a.auth.Execute(ctx, token)
	if err != nil {
		return appsession.Actor{}, false, err
	}

	if res.Outcome != appsession.OutcomeOK {
		a.denied(ctx, "authenticate", string(res.Reason))
		return appsession.Actor{}, false, nil
	}

	return res.Actor, true, nil
}

func unauthenticated(ctx context.Context) openapi.UnauthenticatedJSONResponse {
	return openapi.UnauthenticatedJSONResponse{
		Body:    problem(ctx, openapi.ErrorCodeUnauthenticated),
		Headers: openapi.UnauthenticatedResponseHeaders{WWWAuthenticate: "Bearer"},
	}
}

func apiSession(s *dsession.Session, current dsession.ID) openapi.Session {
	return openapi.Session{
		Id: s.ID().String(), DeviceName: s.DeviceName(),
		CreatedAt: s.CreatedAt().UTC(), LastActiveAt: s.LastActiveAt().UTC(), Current: s.ID() == current,
	}
}

func (a *API) me(ctx context.Context) (body openapi.MeResponse, ok bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return openapi.MeResponse{}, false, err
	}

	res, err := a.meUC.Execute(ctx, actor)
	if err != nil {
		return openapi.MeResponse{}, false, err
	}

	if res.Outcome != appsession.OutcomeOK {
		return openapi.MeResponse{}, false, nil
	}

	return openapi.MeResponse{
		User:    openapi.User{Id: res.User.ID().String(), Email: res.User.Email().String()},
		Session: apiSession(res.Session, actor.SessionID),
	}, true, nil
}

func (a *API) listSessions(ctx context.Context) (body openapi.SessionList, ok bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return openapi.SessionList{}, false, err
	}

	res, err := a.list.Execute(ctx, actor)
	if err != nil {
		return openapi.SessionList{}, false, err
	}

	if res.Outcome != appsession.OutcomeOK {
		return openapi.SessionList{}, false, nil
	}

	body.Sessions = make([]openapi.Session, 0, len(res.Sessions))
	for _, s := range res.Sessions {
		body.Sessions = append(body.Sessions, apiSession(s, actor.SessionID))
	}

	return body, true, nil
}

type signOutResult struct {
	invalid, unauthenticated bool
	// forget says the binding cookie should go too; revoked says the refresh cookie should.
	forget bool
}

func (a *API) signOut(ctx context.Context, body *openapi.SignOutRequest) (signOutResult, error) {
	cmd := appsession.SignOutCommand{Scope: appsession.ScopeCurrent}
	if body != nil {
		if body.Scope != nil {
			if !body.Scope.Valid() {
				return signOutResult{invalid: true}, nil
			}

			cmd.Scope = appsession.SignOutScope(*body.Scope)
		}

		if body.ForgetClient != nil {
			cmd.ForgetClient = *body.ForgetClient
		}
	}

	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return signOutResult{}, err
	}

	if !ok {
		return signOutResult{unauthenticated: true}, nil
	}

	cmd.Actor = actor

	res, err := a.signout.Execute(ctx, cmd)
	if err != nil {
		return signOutResult{}, err
	}

	if res.Outcome != appsession.OutcomeOK {
		a.denied(ctx, "signout", "session_gone")
		return signOutResult{unauthenticated: true}, nil
	}

	return signOutResult{forget: cmd.ForgetClient || cmd.Scope == appsession.ScopeAll}, nil
}

func (a *API) revokeSession(ctx context.Context, id string) (current, unauthenticated bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil {
		return false, false, err
	}

	if !ok {
		return false, true, nil
	}

	res, err := a.revoke.Execute(ctx, appsession.RevokeSessionCommand{ActorUserID: actor.UserID, SessionID: id})
	if err != nil {
		return false, false, err
	}

	if res.Outcome != appsession.OutcomeOK {
		a.denied(ctx, "revoke_session", "not_found")
		return false, false, nil
	}

	return id == actor.SessionID.String(), false, nil
}

func (a *API) BrowserGetMe(ctx context.Context, _ openapi.BrowserGetMeRequestObject) (openapi.BrowserGetMeResponseObject, error) {
	body, ok, err := a.me(ctx)
	if err != nil {
		return nil, err
	}

	if !ok {
		return openapi.BrowserGetMe401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserGetMe200JSONResponse(body), nil
}

func (a *API) BrowserListSessions(ctx context.Context, _ openapi.BrowserListSessionsRequestObject) (openapi.BrowserListSessionsResponseObject, error) {
	body, ok, err := a.listSessions(ctx)
	if err != nil {
		return nil, err
	}

	if !ok {
		return openapi.BrowserListSessions401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserListSessions200JSONResponse(body), nil
}

func (a *API) BrowserRevokeSession(ctx context.Context, req openapi.BrowserRevokeSessionRequestObject) (openapi.BrowserRevokeSessionResponseObject, error) {
	current, unauth, err := a.revokeSession(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	if unauth {
		return openapi.BrowserRevokeSession401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	if current {
		setCookie(ctx, a.cookies.clearRefresh())
	}

	return openapi.BrowserRevokeSession204Response{}, nil
}

func (a *API) BrowserSignOut(ctx context.Context, req openapi.BrowserSignOutRequestObject) (openapi.BrowserSignOutResponseObject, error) {
	res, err := a.signOut(ctx, req.Body)
	switch {
	case err != nil:
		return nil, err
	case res.invalid:
		return openapi.BrowserSignOut400JSONResponse{InvalidRequestJSONResponse: openapi.InvalidRequestJSONResponse(problem(ctx, openapi.ErrorCodeInvalidRequest))}, nil
	case res.unauthenticated:
		return openapi.BrowserSignOut401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	setCookie(ctx, a.cookies.clearRefresh())

	if res.forget {
		setCookie(ctx, a.cookies.clearBinding())
	}

	return openapi.BrowserSignOut204Response{}, nil
}

func (a *API) NativeGetMe(ctx context.Context, _ openapi.NativeGetMeRequestObject) (openapi.NativeGetMeResponseObject, error) {
	body, ok, err := a.me(ctx)
	if err != nil {
		return nil, err
	}

	if !ok {
		return openapi.NativeGetMe401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeGetMe200JSONResponse(body), nil
}

func (a *API) NativeListSessions(ctx context.Context, _ openapi.NativeListSessionsRequestObject) (openapi.NativeListSessionsResponseObject, error) {
	body, ok, err := a.listSessions(ctx)
	if err != nil {
		return nil, err
	}

	if !ok {
		return openapi.NativeListSessions401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeListSessions200JSONResponse(body), nil
}

func (a *API) NativeRevokeSession(ctx context.Context, req openapi.NativeRevokeSessionRequestObject) (openapi.NativeRevokeSessionResponseObject, error) {
	_, unauth, err := a.revokeSession(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	if unauth {
		return openapi.NativeRevokeSession401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeRevokeSession204Response{}, nil
}

func (a *API) NativeSignOut(ctx context.Context, req openapi.NativeSignOutRequestObject) (openapi.NativeSignOutResponseObject, error) {
	res, err := a.signOut(ctx, req.Body)
	switch {
	case err != nil:
		return nil, err
	case res.invalid:
		return openapi.NativeSignOut400JSONResponse{InvalidRequestJSONResponse: openapi.InvalidRequestJSONResponse(problem(ctx, openapi.ErrorCodeInvalidRequest))}, nil
	case res.unauthenticated:
		return openapi.NativeSignOut401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeSignOut204Response{}, nil
}
