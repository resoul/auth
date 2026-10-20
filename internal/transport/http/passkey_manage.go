package http

import (
	"context"
	"errors"
	"strings"

	"go.airlance.org/auth/internal/application/passkey"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/transport/http/openapi"
)

// The routes of a signed-in user's passkeys. Each one authenticates first and answers
// unauthenticated for every kind of credential failure alike; a missing or wrong step-up
// token is its own answer, step_up_required, so a client knows to run the ceremony.

func stepUpRequired(ctx context.Context) openapi.Error {
	return problem(ctx, openapi.ErrorCodeStepUpRequired)
}

func notFound(ctx context.Context) openapi.Error { return problem(ctx, openapi.ErrorCodeNotFound) }

func rateLimited(ctx context.Context) openapi.RateLimitedJSONResponse {
	return openapi.RateLimitedJSONResponse(problem(ctx, openapi.ErrorCodeRateLimited))
}

// stepUpToken reads the X-Step-Up header: one header with one token or nothing.
func stepUpToken(values *string) string {
	if values == nil {
		return ""
	}

	return strings.TrimSpace(*values)
}

func apiPasskey(c passkey.CredentialSummary) openapi.Passkey {
	out := openapi.Passkey{
		Id: c.ID, Name: c.Name, CreatedAt: c.CreatedAt.UTC(), BackupEligible: c.BackupEligible, BackedUp: c.BackupState,
		Transports: c.Transports,
	}
	if out.Transports == nil {
		out.Transports = []string{}
	}

	if !c.LastUsedAt.IsZero() {
		t := c.LastUsedAt.UTC()
		out.LastUsedAt = &t
	}

	return out
}

// stepUpOptions begins the proof. ok is false when the caller is not authenticated.
func (a *API) stepUpOptions(ctx context.Context, operation string) (res passkey.CeremonyResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.CeremonyResult{}, !ok, err
	}

	res, err = a.beginStepUpUC.Execute(ctx, passkey.BeginStepUpCommand{Actor: actor, Operation: dpasskey.Operation(operation), ClientIP: clientIP(ctx)})

	return res, false, err
}

func (a *API) stepUpVerify(ctx context.Context, challengeID string, credential []byte) (res passkey.FinishStepUpResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.FinishStepUpResult{}, !ok, err
	}

	res, err = a.finishStepUpUC.Execute(ctx, passkey.FinishStepUpCommand{Actor: actor, ChallengeID: challengeID, Response: credential})

	return res, false, err
}

func stepUpResponse(res passkey.FinishStepUpResult) openapi.StepUpResponse {
	return openapi.StepUpResponse{StepUpToken: res.TicketSecret, Operation: string(res.Operation), ExpiresAt: res.TicketExpiresAt.UTC()}
}

func (a *API) listPasskeys(ctx context.Context) (body openapi.PasskeyList, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return openapi.PasskeyList{}, !ok, err
	}

	res, err := a.listKeysUC.Execute(ctx, actor)
	if err != nil {
		return openapi.PasskeyList{}, false, err
	}

	if res.Outcome != passkey.OutcomeOK {
		return openapi.PasskeyList{}, true, nil
	}

	body.Passkeys = make([]openapi.Passkey, 0, len(res.Credentials))
	for _, c := range res.Credentials {
		body.Passkeys = append(body.Passkeys, apiPasskey(c))
	}

	return body, false, nil
}

func (a *API) renamePasskey(ctx context.Context, id, name string) (res passkey.RenameResult, unauth, invalid bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.RenameResult{}, !ok, false, err
	}

	res, err = a.renameKeyUC.Execute(ctx, passkey.RenameCommand{Actor: actor, ID: id, Name: name})
	if errors.Is(err, passkey.ErrInvalidName) {
		return passkey.RenameResult{}, false, true, nil
	}

	if err == nil && res.Outcome == passkey.OutcomeDenied {
		return passkey.RenameResult{}, true, false, nil
	}

	return res, false, false, err
}

func (a *API) beginAddPasskey(ctx context.Context, token *string) (res passkey.CeremonyResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.CeremonyResult{}, !ok, err
	}

	res, err = a.beginAddKeyUC.Execute(ctx, passkey.BeginAddCommand{Actor: actor, StepUpSecret: stepUpToken(token), ClientIP: clientIP(ctx)})

	return res, false, err
}

func (a *API) finishAddPasskey(ctx context.Context, token *string, body openapi.PasskeyAddRequest) (res passkey.FinishAddResult, unauth, invalid bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.FinishAddResult{}, !ok, false, err
	}

	res, err = a.finishAddKeyUC.Execute(ctx, passkey.FinishAddCommand{
		Actor: actor, StepUpSecret: stepUpToken(token), ChallengeID: body.ChallengeId, Response: body.Credential, Name: optional(body.Name),
	})
	if errors.Is(err, passkey.ErrInvalidName) {
		return passkey.FinishAddResult{}, false, true, nil
	}

	return res, false, false, err
}

func (a *API) deletePasskey(ctx context.Context, id string, token *string) (res passkey.DeleteResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.DeleteResult{}, !ok, err
	}

	res, err = a.deleteKeyUC.Execute(ctx, passkey.DeleteCommand{Actor: actor, StepUpSecret: stepUpToken(token), ID: id})

	return res, false, err
}

func (a *API) regenerateCodes(ctx context.Context, token *string) (res passkey.RegenerateResult, unauth bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return passkey.RegenerateResult{}, !ok, err
	}

	res, err = a.newCodesUC.Execute(ctx, passkey.RegenerateCommand{Actor: actor, StepUpSecret: stepUpToken(token)})

	return res, false, err
}

// NativeBeginStepUp starts the fresh proof for one operation.
func (a *API) NativeBeginStepUp(ctx context.Context, req openapi.NativeBeginStepUpRequestObject) (openapi.NativeBeginStepUpResponseObject, error) {
	res, unauth, err := a.stepUpOptions(ctx, string(req.Body.Operation))
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeBeginStepUp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeRateLimited:
		a.denied(ctx, "step_up_options", string(res.Reason))
		return openapi.NativeBeginStepUp429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "step_up_options", string(res.Reason))
		return openapi.NativeBeginStepUp400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeBeginStepUp200JSONResponse(ceremony(res)), nil
}

// NativeFinishStepUp verifies the proof and hands out the step-up token.
func (a *API) NativeFinishStepUp(ctx context.Context, req openapi.NativeFinishStepUpRequestObject) (openapi.NativeFinishStepUpResponseObject, error) {
	res, unauth, err := a.stepUpVerify(ctx, req.Body.ChallengeId, req.Body.Credential)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeFinishStepUp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "step_up", string(res.Reason))
		return openapi.NativeFinishStepUp400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeFinishStepUp200JSONResponse(stepUpResponse(res)), nil
}

// NativeListPasskeys lists the passkeys of the signed-in user.
func (a *API) NativeListPasskeys(ctx context.Context, _ openapi.NativeListPasskeysRequestObject) (openapi.NativeListPasskeysResponseObject, error) {
	body, unauth, err := a.listPasskeys(ctx)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeListPasskeys401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeListPasskeys200JSONResponse(body), nil
}

// NativeRenamePasskey changes the label of a passkey.
func (a *API) NativeRenamePasskey(ctx context.Context, req openapi.NativeRenamePasskeyRequestObject) (openapi.NativeRenamePasskeyResponseObject, error) {
	res, unauth, invalid, err := a.renamePasskey(ctx, req.Id, req.Body.Name)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeRenamePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.NativeRenamePasskey400JSONResponse(invalidRequest(ctx)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "rename_passkey", "not_found")
		return openapi.NativeRenamePasskey404JSONResponse(notFound(ctx)), nil
	}

	return openapi.NativeRenamePasskey200JSONResponse(apiPasskey(res.Credential)), nil
}

// NativeBeginAddPasskey starts adding a passkey; it needs the step-up token.
func (a *API) NativeBeginAddPasskey(ctx context.Context, req openapi.NativeBeginAddPasskeyRequestObject) (openapi.NativeBeginAddPasskeyResponseObject, error) {
	res, unauth, err := a.beginAddPasskey(ctx, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeBeginAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.NativeBeginAddPasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeRateLimited:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.NativeBeginAddPasskey429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.NativeBeginAddPasskey409JSONResponse(problem(ctx, openapi.ErrorCodeTooManyPasskeys)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.NativeBeginAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeBeginAddPasskey200JSONResponse(ceremony(res)), nil
}

// NativeFinishAddPasskey stores the new passkey; it needs the step-up token.
func (a *API) NativeFinishAddPasskey(ctx context.Context, req openapi.NativeFinishAddPasskeyRequestObject) (openapi.NativeFinishAddPasskeyResponseObject, error) {
	res, unauth, invalid, err := a.finishAddPasskey(ctx, req.Params.XStepUp, *req.Body)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeFinishAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.NativeFinishAddPasskey400JSONResponse(invalidRequest(ctx)), nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.NativeFinishAddPasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.NativeFinishAddPasskey409JSONResponse(problem(ctx, openapi.ErrorCodeTooManyPasskeys)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.NativeFinishAddPasskey400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.NativeFinishAddPasskey201JSONResponse(apiPasskey(res.Credential)), nil
}

// NativeDeletePasskey removes a passkey; it needs the step-up token and never removes the last one.
func (a *API) NativeDeletePasskey(ctx context.Context, req openapi.NativeDeletePasskeyRequestObject) (openapi.NativeDeletePasskeyResponseObject, error) {
	res, unauth, err := a.deletePasskey(ctx, req.Id, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeDeletePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.NativeDeletePasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeNotFound:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.NativeDeletePasskey404JSONResponse(notFound(ctx)), nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.NativeDeletePasskey409JSONResponse(problem(ctx, openapi.ErrorCodeLastPasskey)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.NativeDeletePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeDeletePasskey204Response{}, nil
}

// NativeRegenerateRecoveryCodes replaces the recovery codes; it needs the step-up token.
func (a *API) NativeRegenerateRecoveryCodes(ctx context.Context, req openapi.NativeRegenerateRecoveryCodesRequestObject) (openapi.NativeRegenerateRecoveryCodesResponseObject, error) {
	res, unauth, err := a.regenerateCodes(ctx, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.NativeRegenerateRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "regenerate_recovery_codes", string(res.Reason))
		return openapi.NativeRegenerateRecoveryCodes403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "regenerate_recovery_codes", string(res.Reason))
		return openapi.NativeRegenerateRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.NativeRegenerateRecoveryCodes200JSONResponse(openapi.RecoveryCodesResponse{RecoveryCodes: res.Codes}), nil
}

// BrowserBeginStepUp starts the fresh proof for one operation.
func (a *API) BrowserBeginStepUp(ctx context.Context, req openapi.BrowserBeginStepUpRequestObject) (openapi.BrowserBeginStepUpResponseObject, error) {
	res, unauth, err := a.stepUpOptions(ctx, string(req.Body.Operation))
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserBeginStepUp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeRateLimited:
		a.denied(ctx, "step_up_options", string(res.Reason))
		return openapi.BrowserBeginStepUp429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "step_up_options", string(res.Reason))
		return openapi.BrowserBeginStepUp400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.BrowserBeginStepUp200JSONResponse(ceremony(res)), nil
}

// BrowserFinishStepUp verifies the proof and hands out the step-up token.
func (a *API) BrowserFinishStepUp(ctx context.Context, req openapi.BrowserFinishStepUpRequestObject) (openapi.BrowserFinishStepUpResponseObject, error) {
	res, unauth, err := a.stepUpVerify(ctx, req.Body.ChallengeId, req.Body.Credential)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserFinishStepUp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "step_up", string(res.Reason))
		return openapi.BrowserFinishStepUp400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.BrowserFinishStepUp200JSONResponse(stepUpResponse(res)), nil
}

// BrowserListPasskeys lists the passkeys of the signed-in user.
func (a *API) BrowserListPasskeys(ctx context.Context, _ openapi.BrowserListPasskeysRequestObject) (openapi.BrowserListPasskeysResponseObject, error) {
	body, unauth, err := a.listPasskeys(ctx)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserListPasskeys401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserListPasskeys200JSONResponse(body), nil
}

// BrowserRenamePasskey changes the label of a passkey.
func (a *API) BrowserRenamePasskey(ctx context.Context, req openapi.BrowserRenamePasskeyRequestObject) (openapi.BrowserRenamePasskeyResponseObject, error) {
	res, unauth, invalid, err := a.renamePasskey(ctx, req.Id, req.Body.Name)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserRenamePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.BrowserRenamePasskey400JSONResponse(invalidRequest(ctx)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "rename_passkey", "not_found")
		return openapi.BrowserRenamePasskey404JSONResponse(notFound(ctx)), nil
	}

	return openapi.BrowserRenamePasskey200JSONResponse(apiPasskey(res.Credential)), nil
}

// BrowserBeginAddPasskey starts adding a passkey; it needs the step-up token.
func (a *API) BrowserBeginAddPasskey(ctx context.Context, req openapi.BrowserBeginAddPasskeyRequestObject) (openapi.BrowserBeginAddPasskeyResponseObject, error) {
	res, unauth, err := a.beginAddPasskey(ctx, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserBeginAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.BrowserBeginAddPasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeRateLimited:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.BrowserBeginAddPasskey429JSONResponse{RateLimitedJSONResponse: rateLimited(ctx)}, nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.BrowserBeginAddPasskey409JSONResponse(problem(ctx, openapi.ErrorCodeTooManyPasskeys)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "add_passkey_options", string(res.Reason))
		return openapi.BrowserBeginAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserBeginAddPasskey200JSONResponse(ceremony(res)), nil
}

// BrowserFinishAddPasskey stores the new passkey; it needs the step-up token.
func (a *API) BrowserFinishAddPasskey(ctx context.Context, req openapi.BrowserFinishAddPasskeyRequestObject) (openapi.BrowserFinishAddPasskeyResponseObject, error) {
	res, unauth, invalid, err := a.finishAddPasskey(ctx, req.Params.XStepUp, *req.Body)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserFinishAddPasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case invalid:
		return openapi.BrowserFinishAddPasskey400JSONResponse(invalidRequest(ctx)), nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.BrowserFinishAddPasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.BrowserFinishAddPasskey409JSONResponse(problem(ctx, openapi.ErrorCodeTooManyPasskeys)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "add_passkey", string(res.Reason))
		return openapi.BrowserFinishAddPasskey400JSONResponse(invalidProof(ctx)), nil
	}

	return openapi.BrowserFinishAddPasskey201JSONResponse(apiPasskey(res.Credential)), nil
}

// BrowserDeletePasskey removes a passkey; it needs the step-up token and never removes the last one.
func (a *API) BrowserDeletePasskey(ctx context.Context, req openapi.BrowserDeletePasskeyRequestObject) (openapi.BrowserDeletePasskeyResponseObject, error) {
	res, unauth, err := a.deletePasskey(ctx, req.Id, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserDeletePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.BrowserDeletePasskey403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome == passkey.OutcomeNotFound:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.BrowserDeletePasskey404JSONResponse(notFound(ctx)), nil
	case res.Outcome == passkey.OutcomeConflict:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.BrowserDeletePasskey409JSONResponse(problem(ctx, openapi.ErrorCodeLastPasskey)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "delete_passkey", string(res.Reason))
		return openapi.BrowserDeletePasskey401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserDeletePasskey204Response{}, nil
}

// BrowserRegenerateRecoveryCodes replaces the recovery codes; it needs the step-up token.
func (a *API) BrowserRegenerateRecoveryCodes(ctx context.Context, req openapi.BrowserRegenerateRecoveryCodesRequestObject) (openapi.BrowserRegenerateRecoveryCodesResponseObject, error) {
	res, unauth, err := a.regenerateCodes(ctx, req.Params.XStepUp)
	switch {
	case err != nil:
		return nil, err
	case unauth:
		return openapi.BrowserRegenerateRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	case res.Outcome == passkey.OutcomeStepUpRequired:
		a.denied(ctx, "regenerate_recovery_codes", string(res.Reason))
		return openapi.BrowserRegenerateRecoveryCodes403JSONResponse(stepUpRequired(ctx)), nil
	case res.Outcome != passkey.OutcomeOK:
		a.denied(ctx, "regenerate_recovery_codes", string(res.Reason))
		return openapi.BrowserRegenerateRecoveryCodes401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}

	return openapi.BrowserRegenerateRecoveryCodes200JSONResponse(openapi.RecoveryCodesResponse{RecoveryCodes: res.Codes}), nil
}
