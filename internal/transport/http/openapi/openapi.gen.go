//go:build go1.22

package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	stdjson "encoding/json"

	"github.com/oapi-codegen/runtime"
)

// Defines values for DeviceStatusResponseState.
const (
	Approved DeviceStatusResponseState = "approved"
	Denied   DeviceStatusResponseState = "denied"
	Expired  DeviceStatusResponseState = "expired"
	Pending  DeviceStatusResponseState = "pending"
	Redeemed DeviceStatusResponseState = "redeemed"
)

// Valid indicates whether the value is a known member of the DeviceStatusResponseState enum.
func (e DeviceStatusResponseState) Valid() bool {
	switch e {
	case Approved:
		return true
	case Denied:
		return true
	case Expired:
		return true
	case Pending:
		return true
	case Redeemed:
		return true
	default:
		return false
	}
}

// Defines values for ErrorCode.
const (
	ErrorCodeEmailTaken             ErrorCode = "email_taken"
	ErrorCodeInvalidCode            ErrorCode = "invalid_code"
	ErrorCodeInvalidProof           ErrorCode = "invalid_proof"
	ErrorCodeInvalidRefresh         ErrorCode = "invalid_refresh"
	ErrorCodeInvalidRequest         ErrorCode = "invalid_request"
	ErrorCodeLastPasskey            ErrorCode = "last_passkey"
	ErrorCodeNotFound               ErrorCode = "not_found"
	ErrorCodePermissionDenied       ErrorCode = "permission_denied"
	ErrorCodeRateLimited            ErrorCode = "rate_limited"
	ErrorCodeStepUpRequired         ErrorCode = "step_up_required"
	ErrorCodeTemporarilyUnavailable ErrorCode = "temporarily_unavailable"
	ErrorCodeTooManyPasskeys        ErrorCode = "too_many_passkeys"
	ErrorCodeUnauthenticated        ErrorCode = "unauthenticated"
)

// Valid indicates whether the value is a known member of the ErrorCode enum.
func (e ErrorCode) Valid() bool {
	switch e {
	case ErrorCodeEmailTaken:
		return true
	case ErrorCodeInvalidCode:
		return true
	case ErrorCodeInvalidProof:
		return true
	case ErrorCodeInvalidRefresh:
		return true
	case ErrorCodeInvalidRequest:
		return true
	case ErrorCodeLastPasskey:
		return true
	case ErrorCodeNotFound:
		return true
	case ErrorCodePermissionDenied:
		return true
	case ErrorCodeRateLimited:
		return true
	case ErrorCodeStepUpRequired:
		return true
	case ErrorCodeTemporarilyUnavailable:
		return true
	case ErrorCodeTooManyPasskeys:
		return true
	case ErrorCodeUnauthenticated:
		return true
	default:
		return false
	}
}

// Defines values for HealthStatus.
const (
	Ok          HealthStatus = "ok"
	Unavailable HealthStatus = "unavailable"
)

// Valid indicates whether the value is a known member of the HealthStatus enum.
func (e HealthStatus) Valid() bool {
	switch e {
	case Ok:
		return true
	case Unavailable:
		return true
	default:
		return false
	}
}

// Defines values for NextStepResponseNext.
const (
	EnrollPasskey NextStepResponseNext = "enroll_passkey"
	SecondFactor  NextStepResponseNext = "second_factor"
)

// Valid indicates whether the value is a known member of the NextStepResponseNext enum.
func (e NextStepResponseNext) Valid() bool {
	switch e {
	case EnrollPasskey:
		return true
	case SecondFactor:
		return true
	default:
		return false
	}
}

// Defines values for SignOutRequestScope.
const (
	All     SignOutRequestScope = "all"
	Current SignOutRequestScope = "current"
)

// Valid indicates whether the value is a known member of the SignOutRequestScope enum.
func (e SignOutRequestScope) Valid() bool {
	switch e {
	case All:
		return true
	case Current:
		return true
	default:
		return false
	}
}

// Defines values for StepUpOptionsRequestOperation.
const (
	AddPasskey              StepUpOptionsRequestOperation = "add_passkey"
	ApproveDevice           StepUpOptionsRequestOperation = "approve_device"
	ChangeEmail             StepUpOptionsRequestOperation = "change_email"
	DeleteAccount           StepUpOptionsRequestOperation = "delete_account"
	DeletePasskey           StepUpOptionsRequestOperation = "delete_passkey"
	RegenerateRecoveryCodes StepUpOptionsRequestOperation = "regenerate_recovery_codes"
)

// Valid indicates whether the value is a known member of the StepUpOptionsRequestOperation enum.
func (e StepUpOptionsRequestOperation) Valid() bool {
	switch e {
	case AddPasskey:
		return true
	case ApproveDevice:
		return true
	case ChangeEmail:
		return true
	case DeleteAccount:
		return true
	case DeletePasskey:
		return true
	case RegenerateRecoveryCodes:
		return true
	default:
		return false
	}
}

// BrowserDeviceRedeemRequest defines model for BrowserDeviceRedeemRequest.
type BrowserDeviceRedeemRequest struct {
	RequestId string `json:"request_id"`
}

// BrowserDeviceStartRequest defines model for BrowserDeviceStartRequest.
type BrowserDeviceStartRequest struct {
	DeviceName *string `json:"device_name,omitempty"`
}

// BrowserDeviceStartResponse defines model for BrowserDeviceStartResponse.
type BrowserDeviceStartResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	PairingCode string    `json:"pairing_code"`
	RequestId   string    `json:"request_id"`
}

// BrowserDeviceStatusRequest defines model for BrowserDeviceStatusRequest.
type BrowserDeviceStatusRequest struct {
	RequestId string `json:"request_id"`
}

// BrowserPasskeyLoginRequest defines model for BrowserPasskeyLoginRequest.
type BrowserPasskeyLoginRequest struct {
	ChallengeId string `json:"challenge_id"`

	// Credential The PublicKeyCredential from navigator.credentials.get, as JSON.
	Credential stdjson.RawMessage `json:"credential"`
	DeviceName *string            `json:"device_name,omitempty"`

	// Ticket The second_factor ticket of a verify; omit for a passkey-only sign-in.
	Ticket *string `json:"ticket,omitempty"`
}

// BrowserPasskeyLoginResponse defines model for BrowserPasskeyLoginResponse.
type BrowserPasskeyLoginResponse struct {
	AccessToken string `json:"access_token"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

// BrowserPasskeyOptionsRequest defines model for BrowserPasskeyOptionsRequest.
type BrowserPasskeyOptionsRequest struct {
	Ticket string `json:"ticket"`
}

// BrowserPasskeyRegisterRequest defines model for BrowserPasskeyRegisterRequest.
type BrowserPasskeyRegisterRequest struct {
	ChallengeId string `json:"challenge_id"`

	// Credential The PublicKeyCredential from navigator.credentials.create, as JSON.
	Credential stdjson.RawMessage `json:"credential"`
	DeviceName *string            `json:"device_name,omitempty"`
	Name       *string            `json:"name,omitempty"`
	Ticket     string             `json:"ticket"`
}

// BrowserPasskeyRegisterResponse defines model for BrowserPasskeyRegisterResponse.
type BrowserPasskeyRegisterResponse struct {
	AccessToken string `json:"access_token"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt time.Time `json:"expires_at"`

	// RecoveryCodes Shown once. Keep them offline; each works once.
	RecoveryCodes []string `json:"recovery_codes"`
	User          User     `json:"user"`
}

// BrowserRecoveryRequest defines model for BrowserRecoveryRequest.
type BrowserRecoveryRequest struct {
	// Code A recovery code as shown, with or without dashes.
	Code   string `json:"code"`
	Ticket string `json:"ticket"`
}

// BrowserRefreshResponse defines model for BrowserRefreshResponse.
type BrowserRefreshResponse struct {
	AccessToken string `json:"access_token"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt time.Time `json:"expires_at"`
}

// BrowserResendRequest defines model for BrowserResendRequest.
type BrowserResendRequest struct {
	FlowId string `json:"flow_id"`
}

// BrowserStartRequest defines model for BrowserStartRequest.
type BrowserStartRequest struct {
	// Email Example: alice@example.com
	Email string `json:"email"`
}

// BrowserVerifyRequest defines model for BrowserVerifyRequest.
type BrowserVerifyRequest struct {
	// Code The 8 digits from the email, without spaces.
	//
	// Example: 30999009
	Code   string `json:"code"`
	FlowId string `json:"flow_id"`
}

// CeremonyResponse defines model for CeremonyResponse.
type CeremonyResponse struct {
	// ChallengeId Send it back with the result of the ceremony.
	ChallengeId string `json:"challenge_id"`

	// Options The WebAuthn options to pass to navigator.credentials.create or .get.
	Options stdjson.RawMessage `json:"options"`
}

// ConnectedApp defines model for ConnectedApp.
type ConnectedApp struct {
	// ClientId Names the application, to take back all its grants.
	ClientId  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt When the grant ends if nothing ends it first.
	ExpiresAt time.Time `json:"expires_at"`

	// GrantId Names the grant to take back.
	GrantId string `json:"grant_id"`

	// LastActiveAt When the application last used the grant.
	LastActiveAt time.Time `json:"last_active_at"`

	// Name The application's name.
	Name string `json:"name"`

	// Resources The APIs the application may call for the user, with the rights held of each.
	Resources []ConnectedAppResource `json:"resources"`

	// Scopes What the application may read about the user, such as openid and email.
	Scopes []string `json:"scopes"`
}

// ConnectedAppList defines model for ConnectedAppList.
type ConnectedAppList struct {
	Apps []ConnectedApp `json:"apps"`
}

// ConnectedAppResource defines model for ConnectedAppResource.
type ConnectedAppResource struct {
	// Id The identifier of the API the grant holds rights of.
	Id   string `json:"id"`
	Name string `json:"name"`

	// Scopes The rights of that API the grant holds; each is a whole scope such as messages:send.
	Scopes []string `json:"scopes"`
}

// DeviceApproveRequest defines model for DeviceApproveRequest.
type DeviceApproveRequest struct {
	// PairingCode The six digits shown on the new device.
	PairingCode string `json:"pairing_code"`
}

// DeviceRequestView defines model for DeviceRequestView.
type DeviceRequestView struct {
	CreatedAt  time.Time `json:"created_at"`
	DeviceName string    `json:"device_name"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DeviceStatusResponse defines model for DeviceStatusResponse.
type DeviceStatusResponse struct {
	State DeviceStatusResponseState `json:"state"`
}

// DeviceStatusResponseState defines model for DeviceStatusResponse.State.
type DeviceStatusResponseState string

// EmailChangeConfirmRequest defines model for EmailChangeConfirmRequest.
type EmailChangeConfirmRequest struct {
	// Code The 8 digits from the email sent to the new address, without spaces.
	//
	// Example: 30999009
	Code   string `json:"code"`
	FlowId string `json:"flow_id"`
}

// EmailChangeResponse defines model for EmailChangeResponse.
type EmailChangeResponse struct {
	// Email The address the account has now.
	Email string `json:"email"`
}

// EmailChangeStartRequest defines model for EmailChangeStartRequest.
type EmailChangeStartRequest struct {
	// Email Example: new@example.com
	Email string `json:"email"`
}

// EmailChangeStartResponse defines model for EmailChangeStartResponse.
type EmailChangeStartResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	FlowId    string    `json:"flow_id"`
}

// Error defines model for Error.
type Error struct {
	Code      ErrorCode `json:"code"`
	RequestId string    `json:"request_id"`
}

// ErrorCode defines model for Error.Code.
type ErrorCode string

// Health defines model for Health.
type Health struct {
	Status HealthStatus `json:"status"`
}

// HealthStatus defines model for Health.Status.
type HealthStatus string

// JWKS defines model for JWKS.
type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

// MeResponse defines model for MeResponse.
type MeResponse struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
}

// NativeDeviceRedeemRequest defines model for NativeDeviceRedeemRequest.
type NativeDeviceRedeemRequest struct {
	ClientBinding string `json:"client_binding"`
	PollSecret    string `json:"poll_secret"`
	RequestId     string `json:"request_id"`
}

// NativeDeviceStartRequest defines model for NativeDeviceStartRequest.
type NativeDeviceStartRequest struct {
	// ClientBinding The client binding of this device; omit it and one is issued.
	ClientBinding *string `json:"client_binding,omitempty"`

	// DeviceName How the new device is named on the approving one.
	DeviceName *string `json:"device_name,omitempty"`
}

// NativeDeviceStartResponse defines model for NativeDeviceStartResponse.
type NativeDeviceStartResponse struct {
	// ClientBinding Present only when this call issued a new binding; store it in secure storage.
	ClientBinding *string   `json:"client_binding,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`

	// PairingCode Six digits to show on this device; the person types them on the approving one.
	PairingCode string `json:"pairing_code"`

	// PollSecret Keep it; it proves this device owns the request. Never put it in the QR code.
	PollSecret string `json:"poll_secret"`

	// RequestId What the QR code carries.
	RequestId string `json:"request_id"`
}

// NativeDeviceStatusRequest defines model for NativeDeviceStatusRequest.
type NativeDeviceStatusRequest struct {
	ClientBinding string `json:"client_binding"`
	PollSecret    string `json:"poll_secret"`
	RequestId     string `json:"request_id"`
}

// NativePasskeyLoginRequest defines model for NativePasskeyLoginRequest.
type NativePasskeyLoginRequest struct {
	ChallengeId string `json:"challenge_id"`

	// ClientBinding Required with a ticket. Without one a new binding is issued.
	ClientBinding *string `json:"client_binding,omitempty"`

	// Credential The PublicKeyCredential from navigator.credentials.get, as JSON.
	Credential stdjson.RawMessage `json:"credential"`
	DeviceName *string            `json:"device_name,omitempty"`

	// Ticket The second_factor ticket of a verify; omit for a passkey-only sign-in.
	Ticket *string `json:"ticket,omitempty"`
}

// NativePasskeyLoginResponse defines model for NativePasskeyLoginResponse.
type NativePasskeyLoginResponse struct {
	AccessToken string `json:"access_token"`

	// ClientBinding Present only when this call issued a new binding; store it in secure storage.
	ClientBinding *string `json:"client_binding,omitempty"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	User         User      `json:"user"`
}

// NativePasskeyOptionsRequest defines model for NativePasskeyOptionsRequest.
type NativePasskeyOptionsRequest struct {
	ClientBinding string `json:"client_binding"`
	Ticket        string `json:"ticket"`
}

// NativePasskeyRegisterRequest defines model for NativePasskeyRegisterRequest.
type NativePasskeyRegisterRequest struct {
	ChallengeId   string `json:"challenge_id"`
	ClientBinding string `json:"client_binding"`

	// Credential The PublicKeyCredential from navigator.credentials.create, as JSON.
	Credential stdjson.RawMessage `json:"credential"`

	// DeviceName Optional label of the new session.
	DeviceName *string `json:"device_name,omitempty"`

	// Name Optional label of the passkey, such as "Work laptop".
	Name   *string `json:"name,omitempty"`
	Ticket string  `json:"ticket"`
}

// NativePasskeyRegisterResponse defines model for NativePasskeyRegisterResponse.
type NativePasskeyRegisterResponse struct {
	AccessToken string `json:"access_token"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt time.Time `json:"expires_at"`

	// RecoveryCodes Shown once. Keep them offline; each works once.
	RecoveryCodes []string `json:"recovery_codes"`
	RefreshToken  string   `json:"refresh_token"`
	User          User     `json:"user"`
}

// NativeRecoveryRequest defines model for NativeRecoveryRequest.
type NativeRecoveryRequest struct {
	ClientBinding string `json:"client_binding"`

	// Code A recovery code as shown, with or without dashes.
	Code   string `json:"code"`
	Ticket string `json:"ticket"`
}

// NativeRefreshRequest defines model for NativeRefreshRequest.
type NativeRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// NativeRefreshResponse defines model for NativeRefreshResponse.
type NativeRefreshResponse struct {
	AccessToken string `json:"access_token"`

	// ExpiresAt Expiry of access_token.
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
}

// NativeResendRequest defines model for NativeResendRequest.
type NativeResendRequest struct {
	ClientBinding string `json:"client_binding"`
	FlowId        string `json:"flow_id"`
}

// NativeStartRequest defines model for NativeStartRequest.
type NativeStartRequest struct {
	// ClientBinding The binding secret received from an earlier start; omit it on the first start.
	ClientBinding *string `json:"client_binding,omitempty"`

	// Email Example: alice@example.com
	Email string `json:"email"`
}

// NativeStartResponse defines model for NativeStartResponse.
type NativeStartResponse struct {
	// ClientBinding Present only when this call issued a new binding; store it in secure storage.
	ClientBinding *string   `json:"client_binding,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	FlowId        string    `json:"flow_id"`
	ResendAfter   time.Time `json:"resend_after"`
}

// NativeVerifyRequest defines model for NativeVerifyRequest.
type NativeVerifyRequest struct {
	ClientBinding string `json:"client_binding"`

	// Code The 8 digits from the email, without spaces.
	//
	// Example: 30999009
	Code   string `json:"code"`
	FlowId string `json:"flow_id"`
}

// NextStepResponse defines model for NextStepResponse.
type NextStepResponse struct {
	ExpiresAt time.Time `json:"expires_at"`

	// Next `enroll_passkey`: register a passkey with the ticket. `second_factor`: prove a
	// passkey with the ticket, or spend a recovery code.
	Next NextStepResponseNext `json:"next"`

	// Ticket A one-time secret for the next step; short-lived and bound to the client binding.
	Ticket string `json:"ticket"`
}

// NextStepResponseNext `enroll_passkey`: register a passkey with the ticket. `second_factor`: prove a
// passkey with the ticket, or spend a recovery code.
type NextStepResponseNext string

// Passkey defines model for Passkey.
type Passkey struct {
	BackedUp       bool       `json:"backed_up"`
	BackupEligible bool       `json:"backup_eligible"`
	CreatedAt      time.Time  `json:"created_at"`
	Id             string     `json:"id"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	Name           string     `json:"name"`
	Transports     []string   `json:"transports"`
}

// PasskeyAddRequest defines model for PasskeyAddRequest.
type PasskeyAddRequest struct {
	ChallengeId string `json:"challenge_id"`

	// Credential The PublicKeyCredential from navigator.credentials.create, as JSON.
	Credential stdjson.RawMessage `json:"credential"`
	Name       *string            `json:"name,omitempty"`
}

// PasskeyList defines model for PasskeyList.
type PasskeyList struct {
	Passkeys []Passkey `json:"passkeys"`
}

// PasskeyRenameRequest defines model for PasskeyRenameRequest.
type PasskeyRenameRequest struct {
	Name string `json:"name"`
}

// RecoveryCodesResponse defines model for RecoveryCodesResponse.
type RecoveryCodesResponse struct {
	// RecoveryCodes Shown once; the previous set no longer works.
	RecoveryCodes []string `json:"recovery_codes"`
}

// ResendResponse defines model for ResendResponse.
type ResendResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	FlowId      string    `json:"flow_id"`
	ResendAfter time.Time `json:"resend_after"`
}

// Session defines model for Session.
type Session struct {
	CreatedAt time.Time `json:"created_at"`

	// Current True for the session of the access token that made the call.
	Current bool `json:"current"`

	// DeviceName The label the client gave; empty when it gave none.
	DeviceName   string    `json:"device_name"`
	Id           string    `json:"id"`
	LastActiveAt time.Time `json:"last_active_at"`
}

// SessionList defines model for SessionList.
type SessionList struct {
	Sessions []Session `json:"sessions"`
}

// SignOutRequest defines model for SignOutRequest.
type SignOutRequest struct {
	// ForgetClient Also forget this device (ignored with scope all, which forgets every device).
	ForgetClient *bool                `json:"forget_client,omitempty"`
	Scope        *SignOutRequestScope `json:"scope,omitempty"`
}

// SignOutRequestScope defines model for SignOutRequest.Scope.
type SignOutRequestScope string

// StepUpOptionsRequest defines model for StepUpOptionsRequest.
type StepUpOptionsRequest struct {
	Operation StepUpOptionsRequestOperation `json:"operation"`
}

// StepUpOptionsRequestOperation defines model for StepUpOptionsRequest.Operation.
type StepUpOptionsRequestOperation string

// StepUpResponse defines model for StepUpResponse.
type StepUpResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	Operation string    `json:"operation"`

	// StepUpToken Send it in the X-Step-Up header of the operation; it works once.
	StepUpToken string `json:"step_up_token"`
}

// StepUpVerifyRequest defines model for StepUpVerifyRequest.
type StepUpVerifyRequest struct {
	ChallengeId string `json:"challenge_id"`

	// Credential The PublicKeyCredential from navigator.credentials.get, as JSON.
	Credential stdjson.RawMessage `json:"credential"`
}

// User defines model for User.
type User struct {
	Email string `json:"email"`

	// Id The sub claim of access tokens.
	Id string `json:"id"`
}

// InvalidRequest defines model for InvalidRequest.
type InvalidRequest = Error

// PermissionDenied defines model for PermissionDenied.
type PermissionDenied = Error

// RateLimited defines model for RateLimited.
type RateLimited = Error

// TemporarilyUnavailable defines model for TemporarilyUnavailable.
type TemporarilyUnavailable = Error

// Unauthenticated defines model for Unauthenticated.
type Unauthenticated = Error

// BrowserApproveDeviceRequestParams defines parameters for BrowserApproveDeviceRequest.
type BrowserApproveDeviceRequestParams struct {
	// XStepUp The step-up token for approve_device; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserDeleteAccountParams defines parameters for BrowserDeleteAccount.
type BrowserDeleteAccountParams struct {
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserStartEmailChangeParams defines parameters for BrowserStartEmailChange.
type BrowserStartEmailChangeParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserFinishAddPasskeyParams defines parameters for BrowserFinishAddPasskey.
type BrowserFinishAddPasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserBeginAddPasskeyParams defines parameters for BrowserBeginAddPasskey.
type BrowserBeginAddPasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserDeletePasskeyParams defines parameters for BrowserDeletePasskey.
type BrowserDeletePasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserRegenerateRecoveryCodesParams defines parameters for BrowserRegenerateRecoveryCodes.
type BrowserRegenerateRecoveryCodesParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeApproveDeviceRequestParams defines parameters for NativeApproveDeviceRequest.
type NativeApproveDeviceRequestParams struct {
	// XStepUp The step-up token for approve_device; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeDeleteAccountParams defines parameters for NativeDeleteAccount.
type NativeDeleteAccountParams struct {
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeStartEmailChangeParams defines parameters for NativeStartEmailChange.
type NativeStartEmailChangeParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeFinishAddPasskeyParams defines parameters for NativeFinishAddPasskey.
type NativeFinishAddPasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeBeginAddPasskeyParams defines parameters for NativeBeginAddPasskey.
type NativeBeginAddPasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeDeletePasskeyParams defines parameters for NativeDeletePasskey.
type NativeDeletePasskeyParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// NativeRegenerateRecoveryCodesParams defines parameters for NativeRegenerateRecoveryCodes.
type NativeRegenerateRecoveryCodesParams struct {
	// XStepUp The step-up token of the operation; without a valid one the answer is step_up_required.
	XStepUp *string `json:"X-Step-Up,omitempty"`
}

// BrowserRedeemDeviceSignInJSONRequestBody defines body for BrowserRedeemDeviceSignIn for application/json ContentType.
type BrowserRedeemDeviceSignInJSONRequestBody = BrowserDeviceRedeemRequest

// BrowserStartDeviceSignInJSONRequestBody defines body for BrowserStartDeviceSignIn for application/json ContentType.
type BrowserStartDeviceSignInJSONRequestBody = BrowserDeviceStartRequest

// BrowserDeviceSignInStatusJSONRequestBody defines body for BrowserDeviceSignInStatus for application/json ContentType.
type BrowserDeviceSignInStatusJSONRequestBody = BrowserDeviceStatusRequest

// BrowserResendEmailJSONRequestBody defines body for BrowserResendEmail for application/json ContentType.
type BrowserResendEmailJSONRequestBody = BrowserResendRequest

// BrowserStartEmailJSONRequestBody defines body for BrowserStartEmail for application/json ContentType.
type BrowserStartEmailJSONRequestBody = BrowserStartRequest

// BrowserVerifyEmailJSONRequestBody defines body for BrowserVerifyEmail for application/json ContentType.
type BrowserVerifyEmailJSONRequestBody = BrowserVerifyRequest

// BrowserFinishPasskeyLoginJSONRequestBody defines body for BrowserFinishPasskeyLogin for application/json ContentType.
type BrowserFinishPasskeyLoginJSONRequestBody = BrowserPasskeyLoginRequest

// BrowserBeginPasskeyRegistrationJSONRequestBody defines body for BrowserBeginPasskeyRegistration for application/json ContentType.
type BrowserBeginPasskeyRegistrationJSONRequestBody = BrowserPasskeyOptionsRequest

// BrowserFinishPasskeyRegistrationJSONRequestBody defines body for BrowserFinishPasskeyRegistration for application/json ContentType.
type BrowserFinishPasskeyRegistrationJSONRequestBody = BrowserPasskeyRegisterRequest

// BrowserRedeemRecoveryCodeJSONRequestBody defines body for BrowserRedeemRecoveryCode for application/json ContentType.
type BrowserRedeemRecoveryCodeJSONRequestBody = BrowserRecoveryRequest

// BrowserApproveDeviceRequestJSONRequestBody defines body for BrowserApproveDeviceRequest for application/json ContentType.
type BrowserApproveDeviceRequestJSONRequestBody = DeviceApproveRequest

// BrowserStartEmailChangeJSONRequestBody defines body for BrowserStartEmailChange for application/json ContentType.
type BrowserStartEmailChangeJSONRequestBody = EmailChangeStartRequest

// BrowserConfirmEmailChangeJSONRequestBody defines body for BrowserConfirmEmailChange for application/json ContentType.
type BrowserConfirmEmailChangeJSONRequestBody = EmailChangeConfirmRequest

// BrowserFinishAddPasskeyJSONRequestBody defines body for BrowserFinishAddPasskey for application/json ContentType.
type BrowserFinishAddPasskeyJSONRequestBody = PasskeyAddRequest

// BrowserRenamePasskeyJSONRequestBody defines body for BrowserRenamePasskey for application/json ContentType.
type BrowserRenamePasskeyJSONRequestBody = PasskeyRenameRequest

// BrowserBeginStepUpJSONRequestBody defines body for BrowserBeginStepUp for application/json ContentType.
type BrowserBeginStepUpJSONRequestBody = StepUpOptionsRequest

// BrowserFinishStepUpJSONRequestBody defines body for BrowserFinishStepUp for application/json ContentType.
type BrowserFinishStepUpJSONRequestBody = StepUpVerifyRequest

// NativeRedeemDeviceSignInJSONRequestBody defines body for NativeRedeemDeviceSignIn for application/json ContentType.
type NativeRedeemDeviceSignInJSONRequestBody = NativeDeviceRedeemRequest

// NativeStartDeviceSignInJSONRequestBody defines body for NativeStartDeviceSignIn for application/json ContentType.
type NativeStartDeviceSignInJSONRequestBody = NativeDeviceStartRequest

// NativeDeviceSignInStatusJSONRequestBody defines body for NativeDeviceSignInStatus for application/json ContentType.
type NativeDeviceSignInStatusJSONRequestBody = NativeDeviceStatusRequest

// NativeResendEmailJSONRequestBody defines body for NativeResendEmail for application/json ContentType.
type NativeResendEmailJSONRequestBody = NativeResendRequest

// NativeStartEmailJSONRequestBody defines body for NativeStartEmail for application/json ContentType.
type NativeStartEmailJSONRequestBody = NativeStartRequest

// NativeVerifyEmailJSONRequestBody defines body for NativeVerifyEmail for application/json ContentType.
type NativeVerifyEmailJSONRequestBody = NativeVerifyRequest

// NativeFinishPasskeyLoginJSONRequestBody defines body for NativeFinishPasskeyLogin for application/json ContentType.
type NativeFinishPasskeyLoginJSONRequestBody = NativePasskeyLoginRequest

// NativeBeginPasskeyRegistrationJSONRequestBody defines body for NativeBeginPasskeyRegistration for application/json ContentType.
type NativeBeginPasskeyRegistrationJSONRequestBody = NativePasskeyOptionsRequest

// NativeFinishPasskeyRegistrationJSONRequestBody defines body for NativeFinishPasskeyRegistration for application/json ContentType.
type NativeFinishPasskeyRegistrationJSONRequestBody = NativePasskeyRegisterRequest

// NativeRedeemRecoveryCodeJSONRequestBody defines body for NativeRedeemRecoveryCode for application/json ContentType.
type NativeRedeemRecoveryCodeJSONRequestBody = NativeRecoveryRequest

// NativeApproveDeviceRequestJSONRequestBody defines body for NativeApproveDeviceRequest for application/json ContentType.
type NativeApproveDeviceRequestJSONRequestBody = DeviceApproveRequest

// NativeStartEmailChangeJSONRequestBody defines body for NativeStartEmailChange for application/json ContentType.
type NativeStartEmailChangeJSONRequestBody = EmailChangeStartRequest

// NativeConfirmEmailChangeJSONRequestBody defines body for NativeConfirmEmailChange for application/json ContentType.
type NativeConfirmEmailChangeJSONRequestBody = EmailChangeConfirmRequest

// NativeFinishAddPasskeyJSONRequestBody defines body for NativeFinishAddPasskey for application/json ContentType.
type NativeFinishAddPasskeyJSONRequestBody = PasskeyAddRequest

// NativeRenamePasskeyJSONRequestBody defines body for NativeRenamePasskey for application/json ContentType.
type NativeRenamePasskeyJSONRequestBody = PasskeyRenameRequest

// NativeBeginStepUpJSONRequestBody defines body for NativeBeginStepUp for application/json ContentType.
type NativeBeginStepUpJSONRequestBody = StepUpOptionsRequest

// NativeFinishStepUpJSONRequestBody defines body for NativeFinishStepUp for application/json ContentType.
type NativeFinishStepUpJSONRequestBody = StepUpVerifyRequest

// NativeSignOutJSONRequestBody defines body for NativeSignOut for application/json ContentType.
type NativeSignOutJSONRequestBody = SignOutRequest

// NativeRefreshTokenJSONRequestBody defines body for NativeRefreshToken for application/json ContentType.
type NativeRefreshTokenJSONRequestBody = NativeRefreshRequest

// BrowserSignOutJSONRequestBody defines body for BrowserSignOut for application/json ContentType.
type BrowserSignOutJSONRequestBody = SignOutRequest

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// GetJWKS Public keys that verify access tokens
	// (GET /.well-known/jwks.json)
	GetJWKS(w http.ResponseWriter, r *http.Request)
	// GetHealthAlive The process serves requests
	// (GET /health/alive)
	GetHealthAlive(w http.ResponseWriter, r *http.Request)
	// GetHealthReady The service can handle sign-in requests
	// (GET /health/ready)
	GetHealthReady(w http.ResponseWriter, r *http.Request)
	// BrowserRedeemDeviceSignIn Take the session of an approved request
	// (POST /v1/auth/device/redeem)
	BrowserRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request)
	// BrowserStartDeviceSignIn Ask for a session on this device, to be approved on another
	// (POST /v1/auth/device/start)
	BrowserStartDeviceSignIn(w http.ResponseWriter, r *http.Request)
	// BrowserDeviceSignInStatus Ask how the request stands
	// (POST /v1/auth/device/status)
	BrowserDeviceSignInStatus(w http.ResponseWriter, r *http.Request)
	// BrowserResendEmail Send a new code for the same flow
	// (POST /v1/auth/email/resend)
	BrowserResendEmail(w http.ResponseWriter, r *http.Request)
	// BrowserStartEmail Start an email sign-in flow and queue the code
	// (POST /v1/auth/email/start)
	BrowserStartEmail(w http.ResponseWriter, r *http.Request)
	// BrowserVerifyEmail Prove the code and receive the ticket for the next step
	// (POST /v1/auth/email/verify)
	BrowserVerifyEmail(w http.ResponseWriter, r *http.Request)
	// BrowserBeginPasskeyLogin Start a passkey assertion
	// (POST /v1/auth/passkey/login/options)
	BrowserBeginPasskeyLogin(w http.ResponseWriter, r *http.Request)
	// BrowserFinishPasskeyLogin Verify the assertion and sign in
	// (POST /v1/auth/passkey/login/verify)
	BrowserFinishPasskeyLogin(w http.ResponseWriter, r *http.Request)
	// BrowserBeginPasskeyRegistration Start registering a passkey
	// (POST /v1/auth/passkey/register/options)
	BrowserBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	// BrowserFinishPasskeyRegistration Finish registering a passkey and sign in
	// (POST /v1/auth/passkey/register/verify)
	BrowserFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	// BrowserRedeemRecoveryCode Spend a recovery code in place of a passkey
	// (POST /v1/auth/recovery/verify)
	BrowserRedeemRecoveryCode(w http.ResponseWriter, r *http.Request)
	// BrowserGetDeviceRequest See who asks to sign in
	// (GET /v1/device/requests/{request_id})
	BrowserGetDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string)
	// BrowserApproveDeviceRequest Let the device sign in as this user
	// (POST /v1/device/requests/{request_id}/approve)
	BrowserApproveDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string, params BrowserApproveDeviceRequestParams)
	// BrowserDenyDeviceRequest Refuse the request
	// (POST /v1/device/requests/{request_id}/deny)
	BrowserDenyDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string)
	// BrowserDeleteAccount Permanently delete the signed-in account
	// (DELETE /v1/me)
	BrowserDeleteAccount(w http.ResponseWriter, r *http.Request, params BrowserDeleteAccountParams)
	// BrowserGetMe The signed-in user and the current session
	// (GET /v1/me)
	BrowserGetMe(w http.ResponseWriter, r *http.Request)
	// BrowserListApps The applications the user has connected
	// (GET /v1/me/apps)
	BrowserListApps(w http.ResponseWriter, r *http.Request)
	// BrowserRevokeApp Take every grant of one application back
	// (DELETE /v1/me/apps/clients/{client_id})
	BrowserRevokeApp(w http.ResponseWriter, r *http.Request, clientId string)
	// BrowserRevokeAppGrant Take one grant of an application back
	// (DELETE /v1/me/apps/grants/{id})
	BrowserRevokeAppGrant(w http.ResponseWriter, r *http.Request, id string)
	// BrowserStartEmailChange Ask for a code at a new email address
	// (POST /v1/me/email/change)
	BrowserStartEmailChange(w http.ResponseWriter, r *http.Request, params BrowserStartEmailChangeParams)
	// BrowserConfirmEmailChange Prove the code from the new address and move the account
	// (POST /v1/me/email/change/confirm)
	BrowserConfirmEmailChange(w http.ResponseWriter, r *http.Request)
	// BrowserListPasskeys The user's passkeys
	// (GET /v1/me/passkeys)
	BrowserListPasskeys(w http.ResponseWriter, r *http.Request)
	// BrowserFinishAddPasskey Finish adding a passkey
	// (POST /v1/me/passkeys)
	BrowserFinishAddPasskey(w http.ResponseWriter, r *http.Request, params BrowserFinishAddPasskeyParams)
	// BrowserBeginAddPasskey Start adding a passkey
	// (POST /v1/me/passkeys/options)
	BrowserBeginAddPasskey(w http.ResponseWriter, r *http.Request, params BrowserBeginAddPasskeyParams)
	// BrowserDeletePasskey Delete a passkey
	// (DELETE /v1/me/passkeys/{id})
	BrowserDeletePasskey(w http.ResponseWriter, r *http.Request, id string, params BrowserDeletePasskeyParams)
	// BrowserRenamePasskey Rename a passkey
	// (PATCH /v1/me/passkeys/{id})
	BrowserRenamePasskey(w http.ResponseWriter, r *http.Request, id string)
	// BrowserRegenerateRecoveryCodes Replace the recovery codes
	// (POST /v1/me/recovery-codes)
	BrowserRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request, params BrowserRegenerateRecoveryCodesParams)
	// BrowserBeginStepUp Start a fresh strong proof for one operation
	// (POST /v1/me/step-up/options)
	BrowserBeginStepUp(w http.ResponseWriter, r *http.Request)
	// BrowserFinishStepUp Prove the passkey and receive the step-up token
	// (POST /v1/me/step-up/verify)
	BrowserFinishStepUp(w http.ResponseWriter, r *http.Request)
	// NativeRedeemDeviceSignIn Take the session of an approved request
	// (POST /v1/native/auth/device/redeem)
	NativeRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request)
	// NativeStartDeviceSignIn Ask for a session on this device, to be approved on another
	// (POST /v1/native/auth/device/start)
	NativeStartDeviceSignIn(w http.ResponseWriter, r *http.Request)
	// NativeDeviceSignInStatus Ask how the request stands
	// (POST /v1/native/auth/device/status)
	NativeDeviceSignInStatus(w http.ResponseWriter, r *http.Request)
	// NativeResendEmail Send a new code for the same flow
	// (POST /v1/native/auth/email/resend)
	NativeResendEmail(w http.ResponseWriter, r *http.Request)
	// NativeStartEmail Start an email sign-in flow and queue the code
	// (POST /v1/native/auth/email/start)
	NativeStartEmail(w http.ResponseWriter, r *http.Request)
	// NativeVerifyEmail Prove the code and receive the ticket for the next step
	// (POST /v1/native/auth/email/verify)
	NativeVerifyEmail(w http.ResponseWriter, r *http.Request)
	// NativeBeginPasskeyLogin Start a passkey assertion
	// (POST /v1/native/auth/passkey/login/options)
	NativeBeginPasskeyLogin(w http.ResponseWriter, r *http.Request)
	// NativeFinishPasskeyLogin Verify the assertion and sign in
	// (POST /v1/native/auth/passkey/login/verify)
	NativeFinishPasskeyLogin(w http.ResponseWriter, r *http.Request)
	// NativeBeginPasskeyRegistration Start registering a passkey
	// (POST /v1/native/auth/passkey/register/options)
	NativeBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	// NativeFinishPasskeyRegistration Finish registering a passkey and sign in
	// (POST /v1/native/auth/passkey/register/verify)
	NativeFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request)
	// NativeRedeemRecoveryCode Spend a recovery code in place of a passkey
	// (POST /v1/native/auth/recovery/verify)
	NativeRedeemRecoveryCode(w http.ResponseWriter, r *http.Request)
	// NativeGetDeviceRequest See who asks to sign in
	// (GET /v1/native/device/requests/{request_id})
	NativeGetDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string)
	// NativeApproveDeviceRequest Let the device sign in as this user
	// (POST /v1/native/device/requests/{request_id}/approve)
	NativeApproveDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string, params NativeApproveDeviceRequestParams)
	// NativeDenyDeviceRequest Refuse the request
	// (POST /v1/native/device/requests/{request_id}/deny)
	NativeDenyDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string)
	// NativeDeleteAccount Permanently delete the signed-in account
	// (DELETE /v1/native/me)
	NativeDeleteAccount(w http.ResponseWriter, r *http.Request, params NativeDeleteAccountParams)
	// NativeGetMe The signed-in user and the current session
	// (GET /v1/native/me)
	NativeGetMe(w http.ResponseWriter, r *http.Request)
	// NativeListApps The applications the user has connected
	// (GET /v1/native/me/apps)
	NativeListApps(w http.ResponseWriter, r *http.Request)
	// NativeRevokeApp Take every grant of one application back
	// (DELETE /v1/native/me/apps/clients/{client_id})
	NativeRevokeApp(w http.ResponseWriter, r *http.Request, clientId string)
	// NativeRevokeAppGrant Take one grant of an application back
	// (DELETE /v1/native/me/apps/grants/{id})
	NativeRevokeAppGrant(w http.ResponseWriter, r *http.Request, id string)
	// NativeStartEmailChange Ask for a code at a new email address
	// (POST /v1/native/me/email/change)
	NativeStartEmailChange(w http.ResponseWriter, r *http.Request, params NativeStartEmailChangeParams)
	// NativeConfirmEmailChange Prove the code from the new address and move the account
	// (POST /v1/native/me/email/change/confirm)
	NativeConfirmEmailChange(w http.ResponseWriter, r *http.Request)
	// NativeListPasskeys The user's passkeys
	// (GET /v1/native/me/passkeys)
	NativeListPasskeys(w http.ResponseWriter, r *http.Request)
	// NativeFinishAddPasskey Finish adding a passkey
	// (POST /v1/native/me/passkeys)
	NativeFinishAddPasskey(w http.ResponseWriter, r *http.Request, params NativeFinishAddPasskeyParams)
	// NativeBeginAddPasskey Start adding a passkey
	// (POST /v1/native/me/passkeys/options)
	NativeBeginAddPasskey(w http.ResponseWriter, r *http.Request, params NativeBeginAddPasskeyParams)
	// NativeDeletePasskey Delete a passkey
	// (DELETE /v1/native/me/passkeys/{id})
	NativeDeletePasskey(w http.ResponseWriter, r *http.Request, id string, params NativeDeletePasskeyParams)
	// NativeRenamePasskey Rename a passkey
	// (PATCH /v1/native/me/passkeys/{id})
	NativeRenamePasskey(w http.ResponseWriter, r *http.Request, id string)
	// NativeRegenerateRecoveryCodes Replace the recovery codes
	// (POST /v1/native/me/recovery-codes)
	NativeRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request, params NativeRegenerateRecoveryCodesParams)
	// NativeBeginStepUp Start a fresh strong proof for one operation
	// (POST /v1/native/me/step-up/options)
	NativeBeginStepUp(w http.ResponseWriter, r *http.Request)
	// NativeFinishStepUp Prove the passkey and receive the step-up token
	// (POST /v1/native/me/step-up/verify)
	NativeFinishStepUp(w http.ResponseWriter, r *http.Request)
	// NativeListSessions The user's active sessions
	// (GET /v1/native/sessions)
	NativeListSessions(w http.ResponseWriter, r *http.Request)
	// NativeRevokeSession End one of the user's sessions
	// (DELETE /v1/native/sessions/{id})
	NativeRevokeSession(w http.ResponseWriter, r *http.Request, id string)
	// NativeSignOut End the current session or all sessions
	// (POST /v1/native/signout)
	NativeSignOut(w http.ResponseWriter, r *http.Request)
	// NativeRefreshToken Exchange a refresh token for new tokens
	// (POST /v1/native/token/refresh)
	NativeRefreshToken(w http.ResponseWriter, r *http.Request)
	// BrowserListSessions The user's active sessions
	// (GET /v1/sessions)
	BrowserListSessions(w http.ResponseWriter, r *http.Request)
	// BrowserRevokeSession End one of the user's sessions
	// (DELETE /v1/sessions/{id})
	BrowserRevokeSession(w http.ResponseWriter, r *http.Request, id string)
	// BrowserSignOut End the current session or all sessions
	// (POST /v1/signout)
	BrowserSignOut(w http.ResponseWriter, r *http.Request)
	// BrowserRefreshToken Exchange the refresh cookie for a new access token
	// (POST /v1/token/refresh)
	BrowserRefreshToken(w http.ResponseWriter, r *http.Request)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// GetJWKS operation middleware
func (siw *ServerInterfaceWrapper) GetJWKS(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetJWKS(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetHealthAlive operation middleware
func (siw *ServerInterfaceWrapper) GetHealthAlive(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetHealthAlive(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetHealthReady operation middleware
func (siw *ServerInterfaceWrapper) GetHealthReady(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetHealthReady(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRedeemDeviceSignIn operation middleware
func (siw *ServerInterfaceWrapper) BrowserRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRedeemDeviceSignIn(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserStartDeviceSignIn operation middleware
func (siw *ServerInterfaceWrapper) BrowserStartDeviceSignIn(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserStartDeviceSignIn(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserDeviceSignInStatus operation middleware
func (siw *ServerInterfaceWrapper) BrowserDeviceSignInStatus(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserDeviceSignInStatus(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserResendEmail operation middleware
func (siw *ServerInterfaceWrapper) BrowserResendEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserResendEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserStartEmail operation middleware
func (siw *ServerInterfaceWrapper) BrowserStartEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserStartEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserVerifyEmail operation middleware
func (siw *ServerInterfaceWrapper) BrowserVerifyEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserVerifyEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserBeginPasskeyLogin operation middleware
func (siw *ServerInterfaceWrapper) BrowserBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserBeginPasskeyLogin(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserFinishPasskeyLogin operation middleware
func (siw *ServerInterfaceWrapper) BrowserFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserFinishPasskeyLogin(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserBeginPasskeyRegistration operation middleware
func (siw *ServerInterfaceWrapper) BrowserBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserBeginPasskeyRegistration(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserFinishPasskeyRegistration operation middleware
func (siw *ServerInterfaceWrapper) BrowserFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserFinishPasskeyRegistration(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRedeemRecoveryCode operation middleware
func (siw *ServerInterfaceWrapper) BrowserRedeemRecoveryCode(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRedeemRecoveryCode(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserGetDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) BrowserGetDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserGetDeviceRequest(w, r, requestId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserApproveDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) BrowserApproveDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserApproveDeviceRequestParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserApproveDeviceRequest(w, r, requestId, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserDenyDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) BrowserDenyDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserDenyDeviceRequest(w, r, requestId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserDeleteAccount operation middleware
func (siw *ServerInterfaceWrapper) BrowserDeleteAccount(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserDeleteAccountParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserDeleteAccount(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserGetMe operation middleware
func (siw *ServerInterfaceWrapper) BrowserGetMe(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserGetMe(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserListApps operation middleware
func (siw *ServerInterfaceWrapper) BrowserListApps(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserListApps(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRevokeApp operation middleware
func (siw *ServerInterfaceWrapper) BrowserRevokeApp(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "client_id" -------------
	var clientId string

	err = runtime.BindStyledParameterWithOptions("simple", "client_id", r.PathValue("client_id"), &clientId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "client_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRevokeApp(w, r, clientId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRevokeAppGrant operation middleware
func (siw *ServerInterfaceWrapper) BrowserRevokeAppGrant(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRevokeAppGrant(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserStartEmailChange operation middleware
func (siw *ServerInterfaceWrapper) BrowserStartEmailChange(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserStartEmailChangeParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserStartEmailChange(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserConfirmEmailChange operation middleware
func (siw *ServerInterfaceWrapper) BrowserConfirmEmailChange(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserConfirmEmailChange(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserListPasskeys operation middleware
func (siw *ServerInterfaceWrapper) BrowserListPasskeys(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserListPasskeys(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserFinishAddPasskey operation middleware
func (siw *ServerInterfaceWrapper) BrowserFinishAddPasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserFinishAddPasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserFinishAddPasskey(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserBeginAddPasskey operation middleware
func (siw *ServerInterfaceWrapper) BrowserBeginAddPasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserBeginAddPasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserBeginAddPasskey(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserDeletePasskey operation middleware
func (siw *ServerInterfaceWrapper) BrowserDeletePasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserDeletePasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserDeletePasskey(w, r, id, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRenamePasskey operation middleware
func (siw *ServerInterfaceWrapper) BrowserRenamePasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRenamePasskey(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRegenerateRecoveryCodes operation middleware
func (siw *ServerInterfaceWrapper) BrowserRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params BrowserRegenerateRecoveryCodesParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRegenerateRecoveryCodes(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserBeginStepUp operation middleware
func (siw *ServerInterfaceWrapper) BrowserBeginStepUp(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserBeginStepUp(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserFinishStepUp operation middleware
func (siw *ServerInterfaceWrapper) BrowserFinishStepUp(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserFinishStepUp(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRedeemDeviceSignIn operation middleware
func (siw *ServerInterfaceWrapper) NativeRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRedeemDeviceSignIn(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeStartDeviceSignIn operation middleware
func (siw *ServerInterfaceWrapper) NativeStartDeviceSignIn(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeStartDeviceSignIn(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeDeviceSignInStatus operation middleware
func (siw *ServerInterfaceWrapper) NativeDeviceSignInStatus(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeDeviceSignInStatus(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeResendEmail operation middleware
func (siw *ServerInterfaceWrapper) NativeResendEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeResendEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeStartEmail operation middleware
func (siw *ServerInterfaceWrapper) NativeStartEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeStartEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeVerifyEmail operation middleware
func (siw *ServerInterfaceWrapper) NativeVerifyEmail(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeVerifyEmail(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeBeginPasskeyLogin operation middleware
func (siw *ServerInterfaceWrapper) NativeBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeBeginPasskeyLogin(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeFinishPasskeyLogin operation middleware
func (siw *ServerInterfaceWrapper) NativeFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeFinishPasskeyLogin(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeBeginPasskeyRegistration operation middleware
func (siw *ServerInterfaceWrapper) NativeBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeBeginPasskeyRegistration(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeFinishPasskeyRegistration operation middleware
func (siw *ServerInterfaceWrapper) NativeFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeFinishPasskeyRegistration(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRedeemRecoveryCode operation middleware
func (siw *ServerInterfaceWrapper) NativeRedeemRecoveryCode(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRedeemRecoveryCode(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeGetDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) NativeGetDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeGetDeviceRequest(w, r, requestId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeApproveDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) NativeApproveDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeApproveDeviceRequestParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeApproveDeviceRequest(w, r, requestId, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeDenyDeviceRequest operation middleware
func (siw *ServerInterfaceWrapper) NativeDenyDeviceRequest(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "request_id" -------------
	var requestId string

	err = runtime.BindStyledParameterWithOptions("simple", "request_id", r.PathValue("request_id"), &requestId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "request_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeDenyDeviceRequest(w, r, requestId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeDeleteAccount operation middleware
func (siw *ServerInterfaceWrapper) NativeDeleteAccount(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeDeleteAccountParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeDeleteAccount(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeGetMe operation middleware
func (siw *ServerInterfaceWrapper) NativeGetMe(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeGetMe(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeListApps operation middleware
func (siw *ServerInterfaceWrapper) NativeListApps(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeListApps(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRevokeApp operation middleware
func (siw *ServerInterfaceWrapper) NativeRevokeApp(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "client_id" -------------
	var clientId string

	err = runtime.BindStyledParameterWithOptions("simple", "client_id", r.PathValue("client_id"), &clientId, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "client_id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRevokeApp(w, r, clientId)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRevokeAppGrant operation middleware
func (siw *ServerInterfaceWrapper) NativeRevokeAppGrant(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRevokeAppGrant(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeStartEmailChange operation middleware
func (siw *ServerInterfaceWrapper) NativeStartEmailChange(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeStartEmailChangeParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeStartEmailChange(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeConfirmEmailChange operation middleware
func (siw *ServerInterfaceWrapper) NativeConfirmEmailChange(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeConfirmEmailChange(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeListPasskeys operation middleware
func (siw *ServerInterfaceWrapper) NativeListPasskeys(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeListPasskeys(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeFinishAddPasskey operation middleware
func (siw *ServerInterfaceWrapper) NativeFinishAddPasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeFinishAddPasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeFinishAddPasskey(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeBeginAddPasskey operation middleware
func (siw *ServerInterfaceWrapper) NativeBeginAddPasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeBeginAddPasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeBeginAddPasskey(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeDeletePasskey operation middleware
func (siw *ServerInterfaceWrapper) NativeDeletePasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeDeletePasskeyParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeDeletePasskey(w, r, id, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRenamePasskey operation middleware
func (siw *ServerInterfaceWrapper) NativeRenamePasskey(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRenamePasskey(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRegenerateRecoveryCodes operation middleware
func (siw *ServerInterfaceWrapper) NativeRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// Parameter object where we will unmarshal all parameters from the context
	var params NativeRegenerateRecoveryCodesParams

	headers := r.Header

	// ------------- Optional header parameter "X-Step-Up" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Step-Up")]; found {
		var XStepUp string
		n := len(valueList)
		if n != 1 {
			siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "X-Step-Up", Count: n})
			return
		}

		err = runtime.BindStyledParameterWithOptions("simple", "X-Step-Up", valueList[0], &XStepUp, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationHeader, Explode: false, Required: false, Type: "string", Format: ""})
		if err != nil {
			siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "X-Step-Up", Err: err})
			return
		}

		params.XStepUp = &XStepUp

	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRegenerateRecoveryCodes(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeBeginStepUp operation middleware
func (siw *ServerInterfaceWrapper) NativeBeginStepUp(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeBeginStepUp(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeFinishStepUp operation middleware
func (siw *ServerInterfaceWrapper) NativeFinishStepUp(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeFinishStepUp(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeListSessions operation middleware
func (siw *ServerInterfaceWrapper) NativeListSessions(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeListSessions(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRevokeSession operation middleware
func (siw *ServerInterfaceWrapper) NativeRevokeSession(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRevokeSession(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeSignOut operation middleware
func (siw *ServerInterfaceWrapper) NativeSignOut(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeSignOut(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// NativeRefreshToken operation middleware
func (siw *ServerInterfaceWrapper) NativeRefreshToken(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.NativeRefreshToken(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserListSessions operation middleware
func (siw *ServerInterfaceWrapper) BrowserListSessions(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserListSessions(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRevokeSession operation middleware
func (siw *ServerInterfaceWrapper) BrowserRevokeSession(w http.ResponseWriter, r *http.Request) {

	var err error
	_ = err

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithOptions("simple", "id", r.PathValue("id"), &id, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true, Type: "string", Format: "", ValueIsUnescaped: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "id", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRevokeSession(w, r, id)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserSignOut operation middleware
func (siw *ServerInterfaceWrapper) BrowserSignOut(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserSignOut(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// BrowserRefreshToken operation middleware
func (siw *ServerInterfaceWrapper) BrowserRefreshToken(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.BrowserRefreshToken(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshalingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshalingParamError) Error() string {
	return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, StdHTTPServerOptions{})
}

// ServeMux is an abstraction of [http.ServeMux].
type ServeMux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
	http.Handler
}

type StdHTTPServerOptions struct {
	BaseURL          string
	BaseRouter       ServeMux
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, m ServeMux) http.Handler {
	return HandlerWithOptions(si, StdHTTPServerOptions{
		BaseRouter: m,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, m ServeMux, baseURL string) http.Handler {
	return HandlerWithOptions(si, StdHTTPServerOptions{
		BaseURL:    baseURL,
		BaseRouter: m,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options StdHTTPServerOptions) http.Handler {
	m := options.BaseRouter

	if m == nil {
		m = http.NewServeMux()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}

	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/email/start", wrapper.NativeStartEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/email/verify", wrapper.NativeVerifyEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/passkey/register/options", wrapper.NativeBeginPasskeyRegistration)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/passkey/register/verify", wrapper.NativeFinishPasskeyRegistration)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/passkey/login/options", wrapper.NativeBeginPasskeyLogin)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/passkey/login/verify", wrapper.NativeFinishPasskeyLogin)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/recovery/verify", wrapper.NativeRedeemRecoveryCode)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/passkey/register/options", wrapper.BrowserBeginPasskeyRegistration)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/passkey/register/verify", wrapper.BrowserFinishPasskeyRegistration)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/passkey/login/options", wrapper.BrowserBeginPasskeyLogin)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/passkey/login/verify", wrapper.BrowserFinishPasskeyLogin)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/recovery/verify", wrapper.BrowserRedeemRecoveryCode)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/token/refresh", wrapper.NativeRefreshToken)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/email/resend", wrapper.NativeResendEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/email/start", wrapper.BrowserStartEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/email/verify", wrapper.BrowserVerifyEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/email/resend", wrapper.BrowserResendEmail)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/token/refresh", wrapper.BrowserRefreshToken)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/signout", wrapper.BrowserSignOut)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/me", wrapper.BrowserDeleteAccount)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/me", wrapper.BrowserGetMe)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/sessions", wrapper.BrowserListSessions)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/sessions/{id}", wrapper.BrowserRevokeSession)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/me/apps", wrapper.BrowserListApps)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/me/apps/grants/{id}", wrapper.BrowserRevokeAppGrant)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/me/apps/clients/{client_id}", wrapper.BrowserRevokeApp)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/native/me/apps", wrapper.NativeListApps)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/native/me/apps/grants/{id}", wrapper.NativeRevokeAppGrant)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/native/me/apps/clients/{client_id}", wrapper.NativeRevokeApp)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/signout", wrapper.NativeSignOut)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/native/me", wrapper.NativeDeleteAccount)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/native/me", wrapper.NativeGetMe)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/native/sessions", wrapper.NativeListSessions)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/native/sessions/{id}", wrapper.NativeRevokeSession)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/step-up/options", wrapper.NativeBeginStepUp)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/step-up/verify", wrapper.NativeFinishStepUp)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/native/me/passkeys", wrapper.NativeListPasskeys)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/passkeys", wrapper.NativeFinishAddPasskey)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/passkeys/options", wrapper.NativeBeginAddPasskey)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/native/me/passkeys/{id}", wrapper.NativeDeletePasskey)
	m.HandleFunc(http.MethodPatch+" "+options.BaseURL+"/v1/native/me/passkeys/{id}", wrapper.NativeRenamePasskey)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/recovery-codes", wrapper.NativeRegenerateRecoveryCodes)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/email/change", wrapper.NativeStartEmailChange)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/me/email/change/confirm", wrapper.NativeConfirmEmailChange)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/step-up/options", wrapper.BrowserBeginStepUp)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/step-up/verify", wrapper.BrowserFinishStepUp)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/me/passkeys", wrapper.BrowserListPasskeys)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/passkeys", wrapper.BrowserFinishAddPasskey)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/passkeys/options", wrapper.BrowserBeginAddPasskey)
	m.HandleFunc(http.MethodDelete+" "+options.BaseURL+"/v1/me/passkeys/{id}", wrapper.BrowserDeletePasskey)
	m.HandleFunc(http.MethodPatch+" "+options.BaseURL+"/v1/me/passkeys/{id}", wrapper.BrowserRenamePasskey)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/recovery-codes", wrapper.BrowserRegenerateRecoveryCodes)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/email/change", wrapper.BrowserStartEmailChange)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/me/email/change/confirm", wrapper.BrowserConfirmEmailChange)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/.well-known/jwks.json", wrapper.GetJWKS)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/health/alive", wrapper.GetHealthAlive)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/health/ready", wrapper.GetHealthReady)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/device/start", wrapper.NativeStartDeviceSignIn)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/device/status", wrapper.NativeDeviceSignInStatus)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/auth/device/redeem", wrapper.NativeRedeemDeviceSignIn)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/native/device/requests/{request_id}", wrapper.NativeGetDeviceRequest)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/device/requests/{request_id}/approve", wrapper.NativeApproveDeviceRequest)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/native/device/requests/{request_id}/deny", wrapper.NativeDenyDeviceRequest)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/device/start", wrapper.BrowserStartDeviceSignIn)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/device/status", wrapper.BrowserDeviceSignInStatus)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/auth/device/redeem", wrapper.BrowserRedeemDeviceSignIn)
	m.HandleFunc(http.MethodGet+" "+options.BaseURL+"/v1/device/requests/{request_id}", wrapper.BrowserGetDeviceRequest)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/device/requests/{request_id}/approve", wrapper.BrowserApproveDeviceRequest)
	m.HandleFunc(http.MethodPost+" "+options.BaseURL+"/v1/device/requests/{request_id}/deny", wrapper.BrowserDenyDeviceRequest)

	return m
}

type InvalidRequestJSONResponse Error

type PermissionDeniedJSONResponse Error

type RateLimitedJSONResponse Error

type TemporarilyUnavailableJSONResponse Error

type UnauthenticatedResponseHeaders struct {
	WWWAuthenticate string
}
type UnauthenticatedJSONResponse struct {
	Body Error

	Headers UnauthenticatedResponseHeaders
}

type GetJWKSRequestObject struct {
}

type GetJWKSResponseObject interface {
	VisitGetJWKSResponse(w http.ResponseWriter) error
}

type GetJWKS200JSONResponse JWKS

func (response GetJWKS200JSONResponse) VisitGetJWKSResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type GetHealthAliveRequestObject struct {
}

type GetHealthAliveResponseObject interface {
	VisitGetHealthAliveResponse(w http.ResponseWriter) error
}

type GetHealthAlive200JSONResponse Health

func (response GetHealthAlive200JSONResponse) VisitGetHealthAliveResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type GetHealthReadyRequestObject struct {
}

type GetHealthReadyResponseObject interface {
	VisitGetHealthReadyResponse(w http.ResponseWriter) error
}

type GetHealthReady200JSONResponse Health

func (response GetHealthReady200JSONResponse) VisitGetHealthReadyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type GetHealthReady503JSONResponse Health

func (response GetHealthReady503JSONResponse) VisitGetHealthReadyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemDeviceSignInRequestObject struct {
	Body *BrowserRedeemDeviceSignInJSONRequestBody
}

type BrowserRedeemDeviceSignInResponseObject interface {
	VisitBrowserRedeemDeviceSignInResponse(w http.ResponseWriter) error
}

type BrowserRedeemDeviceSignIn200JSONResponse BrowserPasskeyLoginResponse

func (response BrowserRedeemDeviceSignIn200JSONResponse) VisitBrowserRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemDeviceSignIn400JSONResponse Error

func (response BrowserRedeemDeviceSignIn400JSONResponse) VisitBrowserRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemDeviceSignIn503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRedeemDeviceSignIn503JSONResponse) VisitBrowserRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartDeviceSignInRequestObject struct {
	Body *BrowserStartDeviceSignInJSONRequestBody
}

type BrowserStartDeviceSignInResponseObject interface {
	VisitBrowserStartDeviceSignInResponse(w http.ResponseWriter) error
}

type BrowserStartDeviceSignIn200JSONResponse BrowserDeviceStartResponse

func (response BrowserStartDeviceSignIn200JSONResponse) VisitBrowserStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartDeviceSignIn400JSONResponse Error

func (response BrowserStartDeviceSignIn400JSONResponse) VisitBrowserStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartDeviceSignIn429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserStartDeviceSignIn429JSONResponse) VisitBrowserStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartDeviceSignIn503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserStartDeviceSignIn503JSONResponse) VisitBrowserStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeviceSignInStatusRequestObject struct {
	Body *BrowserDeviceSignInStatusJSONRequestBody
}

type BrowserDeviceSignInStatusResponseObject interface {
	VisitBrowserDeviceSignInStatusResponse(w http.ResponseWriter) error
}

type BrowserDeviceSignInStatus200JSONResponse DeviceStatusResponse

func (response BrowserDeviceSignInStatus200JSONResponse) VisitBrowserDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeviceSignInStatus400JSONResponse Error

func (response BrowserDeviceSignInStatus400JSONResponse) VisitBrowserDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeviceSignInStatus503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserDeviceSignInStatus503JSONResponse) VisitBrowserDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserResendEmailRequestObject struct {
	Body *BrowserResendEmailJSONRequestBody
}

type BrowserResendEmailResponseObject interface {
	VisitBrowserResendEmailResponse(w http.ResponseWriter) error
}

type BrowserResendEmail202JSONResponse ResendResponse

func (response BrowserResendEmail202JSONResponse) VisitBrowserResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserResendEmail400JSONResponse Error

func (response BrowserResendEmail400JSONResponse) VisitBrowserResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserResendEmail403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserResendEmail403JSONResponse) VisitBrowserResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserResendEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserResendEmail429JSONResponse) VisitBrowserResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserResendEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserResendEmail503JSONResponse) VisitBrowserResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailRequestObject struct {
	Body *BrowserStartEmailJSONRequestBody
}

type BrowserStartEmailResponseObject interface {
	VisitBrowserStartEmailResponse(w http.ResponseWriter) error
}

type BrowserStartEmail202JSONResponse ResendResponse

func (response BrowserStartEmail202JSONResponse) VisitBrowserStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmail400JSONResponse struct{ InvalidRequestJSONResponse }

func (response BrowserStartEmail400JSONResponse) VisitBrowserStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmail403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserStartEmail403JSONResponse) VisitBrowserStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserStartEmail429JSONResponse) VisitBrowserStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserStartEmail503JSONResponse) VisitBrowserStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserVerifyEmailRequestObject struct {
	Body *BrowserVerifyEmailJSONRequestBody
}

type BrowserVerifyEmailResponseObject interface {
	VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error
}

type BrowserVerifyEmail200JSONResponse NextStepResponse

func (response BrowserVerifyEmail200JSONResponse) VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserVerifyEmail400JSONResponse Error

func (response BrowserVerifyEmail400JSONResponse) VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserVerifyEmail403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserVerifyEmail403JSONResponse) VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserVerifyEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserVerifyEmail429JSONResponse) VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserVerifyEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserVerifyEmail503JSONResponse) VisitBrowserVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyLoginRequestObject struct {
}

type BrowserBeginPasskeyLoginResponseObject interface {
	VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error
}

type BrowserBeginPasskeyLogin200JSONResponse CeremonyResponse

func (response BrowserBeginPasskeyLogin200JSONResponse) VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyLogin400JSONResponse Error

func (response BrowserBeginPasskeyLogin400JSONResponse) VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyLogin403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserBeginPasskeyLogin403JSONResponse) VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyLogin429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserBeginPasskeyLogin429JSONResponse) VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyLogin503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserBeginPasskeyLogin503JSONResponse) VisitBrowserBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyLoginRequestObject struct {
	Body *BrowserFinishPasskeyLoginJSONRequestBody
}

type BrowserFinishPasskeyLoginResponseObject interface {
	VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error
}

type BrowserFinishPasskeyLogin200JSONResponse BrowserPasskeyLoginResponse

func (response BrowserFinishPasskeyLogin200JSONResponse) VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyLogin400JSONResponse Error

func (response BrowserFinishPasskeyLogin400JSONResponse) VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyLogin403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserFinishPasskeyLogin403JSONResponse) VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyLogin429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserFinishPasskeyLogin429JSONResponse) VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyLogin503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserFinishPasskeyLogin503JSONResponse) VisitBrowserFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyRegistrationRequestObject struct {
	Body *BrowserBeginPasskeyRegistrationJSONRequestBody
}

type BrowserBeginPasskeyRegistrationResponseObject interface {
	VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error
}

type BrowserBeginPasskeyRegistration200JSONResponse CeremonyResponse

func (response BrowserBeginPasskeyRegistration200JSONResponse) VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyRegistration400JSONResponse Error

func (response BrowserBeginPasskeyRegistration400JSONResponse) VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyRegistration403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserBeginPasskeyRegistration403JSONResponse) VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyRegistration429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserBeginPasskeyRegistration429JSONResponse) VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginPasskeyRegistration503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserBeginPasskeyRegistration503JSONResponse) VisitBrowserBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyRegistrationRequestObject struct {
	Body *BrowserFinishPasskeyRegistrationJSONRequestBody
}

type BrowserFinishPasskeyRegistrationResponseObject interface {
	VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error
}

type BrowserFinishPasskeyRegistration200JSONResponse BrowserPasskeyRegisterResponse

func (response BrowserFinishPasskeyRegistration200JSONResponse) VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyRegistration400JSONResponse Error

func (response BrowserFinishPasskeyRegistration400JSONResponse) VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyRegistration403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserFinishPasskeyRegistration403JSONResponse) VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyRegistration429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserFinishPasskeyRegistration429JSONResponse) VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishPasskeyRegistration503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserFinishPasskeyRegistration503JSONResponse) VisitBrowserFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemRecoveryCodeRequestObject struct {
	Body *BrowserRedeemRecoveryCodeJSONRequestBody
}

type BrowserRedeemRecoveryCodeResponseObject interface {
	VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error
}

type BrowserRedeemRecoveryCode200JSONResponse NextStepResponse

func (response BrowserRedeemRecoveryCode200JSONResponse) VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemRecoveryCode400JSONResponse Error

func (response BrowserRedeemRecoveryCode400JSONResponse) VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemRecoveryCode403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserRedeemRecoveryCode403JSONResponse) VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemRecoveryCode429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserRedeemRecoveryCode429JSONResponse) VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRedeemRecoveryCode503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRedeemRecoveryCode503JSONResponse) VisitBrowserRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
}

type BrowserGetDeviceRequestResponseObject interface {
	VisitBrowserGetDeviceRequestResponse(w http.ResponseWriter) error
}

type BrowserGetDeviceRequest200JSONResponse DeviceRequestView

func (response BrowserGetDeviceRequest200JSONResponse) VisitBrowserGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserGetDeviceRequest401JSONResponse) VisitBrowserGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetDeviceRequest404JSONResponse Error

func (response BrowserGetDeviceRequest404JSONResponse) VisitBrowserGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserGetDeviceRequest503JSONResponse) VisitBrowserGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserApproveDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
	Params    BrowserApproveDeviceRequestParams
	Body      *BrowserApproveDeviceRequestJSONRequestBody
}

type BrowserApproveDeviceRequestResponseObject interface {
	VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error
}

type BrowserApproveDeviceRequest204Response struct {
}

func (response BrowserApproveDeviceRequest204Response) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserApproveDeviceRequest400JSONResponse Error

func (response BrowserApproveDeviceRequest400JSONResponse) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserApproveDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserApproveDeviceRequest401JSONResponse) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserApproveDeviceRequest403JSONResponse Error

func (response BrowserApproveDeviceRequest403JSONResponse) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserApproveDeviceRequest404JSONResponse Error

func (response BrowserApproveDeviceRequest404JSONResponse) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserApproveDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserApproveDeviceRequest503JSONResponse) VisitBrowserApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDenyDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
}

type BrowserDenyDeviceRequestResponseObject interface {
	VisitBrowserDenyDeviceRequestResponse(w http.ResponseWriter) error
}

type BrowserDenyDeviceRequest204Response struct {
}

func (response BrowserDenyDeviceRequest204Response) VisitBrowserDenyDeviceRequestResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserDenyDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserDenyDeviceRequest401JSONResponse) VisitBrowserDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDenyDeviceRequest404JSONResponse Error

func (response BrowserDenyDeviceRequest404JSONResponse) VisitBrowserDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDenyDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserDenyDeviceRequest503JSONResponse) VisitBrowserDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeleteAccountRequestObject struct {
	Params BrowserDeleteAccountParams
}

type BrowserDeleteAccountResponseObject interface {
	VisitBrowserDeleteAccountResponse(w http.ResponseWriter) error
}

type BrowserDeleteAccount204Response struct {
}

func (response BrowserDeleteAccount204Response) VisitBrowserDeleteAccountResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserDeleteAccount401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserDeleteAccount401JSONResponse) VisitBrowserDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeleteAccount403JSONResponse Error

func (response BrowserDeleteAccount403JSONResponse) VisitBrowserDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeleteAccount503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserDeleteAccount503JSONResponse) VisitBrowserDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetMeRequestObject struct {
}

type BrowserGetMeResponseObject interface {
	VisitBrowserGetMeResponse(w http.ResponseWriter) error
}

type BrowserGetMe200JSONResponse MeResponse

func (response BrowserGetMe200JSONResponse) VisitBrowserGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetMe401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserGetMe401JSONResponse) VisitBrowserGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserGetMe503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserGetMe503JSONResponse) VisitBrowserGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListAppsRequestObject struct {
}

type BrowserListAppsResponseObject interface {
	VisitBrowserListAppsResponse(w http.ResponseWriter) error
}

type BrowserListApps200JSONResponse ConnectedAppList

func (response BrowserListApps200JSONResponse) VisitBrowserListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListApps401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserListApps401JSONResponse) VisitBrowserListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListApps503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserListApps503JSONResponse) VisitBrowserListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeAppRequestObject struct {
	ClientId string `json:"client_id"`
}

type BrowserRevokeAppResponseObject interface {
	VisitBrowserRevokeAppResponse(w http.ResponseWriter) error
}

type BrowserRevokeApp204Response struct {
}

func (response BrowserRevokeApp204Response) VisitBrowserRevokeAppResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserRevokeApp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserRevokeApp401JSONResponse) VisitBrowserRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeApp403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserRevokeApp403JSONResponse) VisitBrowserRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeApp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRevokeApp503JSONResponse) VisitBrowserRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeAppGrantRequestObject struct {
	Id string `json:"id"`
}

type BrowserRevokeAppGrantResponseObject interface {
	VisitBrowserRevokeAppGrantResponse(w http.ResponseWriter) error
}

type BrowserRevokeAppGrant204Response struct {
}

func (response BrowserRevokeAppGrant204Response) VisitBrowserRevokeAppGrantResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserRevokeAppGrant401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserRevokeAppGrant401JSONResponse) VisitBrowserRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeAppGrant403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserRevokeAppGrant403JSONResponse) VisitBrowserRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeAppGrant503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRevokeAppGrant503JSONResponse) VisitBrowserRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChangeRequestObject struct {
	Params BrowserStartEmailChangeParams
	Body   *BrowserStartEmailChangeJSONRequestBody
}

type BrowserStartEmailChangeResponseObject interface {
	VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error
}

type BrowserStartEmailChange202JSONResponse EmailChangeStartResponse

func (response BrowserStartEmailChange202JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChange400JSONResponse Error

func (response BrowserStartEmailChange400JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChange401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserStartEmailChange401JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChange403JSONResponse Error

func (response BrowserStartEmailChange403JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChange429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserStartEmailChange429JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserStartEmailChange503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserStartEmailChange503JSONResponse) VisitBrowserStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChangeRequestObject struct {
	Body *BrowserConfirmEmailChangeJSONRequestBody
}

type BrowserConfirmEmailChangeResponseObject interface {
	VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error
}

type BrowserConfirmEmailChange200JSONResponse EmailChangeResponse

func (response BrowserConfirmEmailChange200JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChange400JSONResponse Error

func (response BrowserConfirmEmailChange400JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChange401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserConfirmEmailChange401JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChange409JSONResponse Error

func (response BrowserConfirmEmailChange409JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChange429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserConfirmEmailChange429JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserConfirmEmailChange503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserConfirmEmailChange503JSONResponse) VisitBrowserConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListPasskeysRequestObject struct {
}

type BrowserListPasskeysResponseObject interface {
	VisitBrowserListPasskeysResponse(w http.ResponseWriter) error
}

type BrowserListPasskeys200JSONResponse PasskeyList

func (response BrowserListPasskeys200JSONResponse) VisitBrowserListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListPasskeys401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserListPasskeys401JSONResponse) VisitBrowserListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListPasskeys503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserListPasskeys503JSONResponse) VisitBrowserListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskeyRequestObject struct {
	Params BrowserFinishAddPasskeyParams
	Body   *BrowserFinishAddPasskeyJSONRequestBody
}

type BrowserFinishAddPasskeyResponseObject interface {
	VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error
}

type BrowserFinishAddPasskey201JSONResponse Passkey

func (response BrowserFinishAddPasskey201JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey400JSONResponse Error

func (response BrowserFinishAddPasskey400JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserFinishAddPasskey401JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey403JSONResponse Error

func (response BrowserFinishAddPasskey403JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey409JSONResponse Error

func (response BrowserFinishAddPasskey409JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserFinishAddPasskey429JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishAddPasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserFinishAddPasskey503JSONResponse) VisitBrowserFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskeyRequestObject struct {
	Params BrowserBeginAddPasskeyParams
}

type BrowserBeginAddPasskeyResponseObject interface {
	VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error
}

type BrowserBeginAddPasskey200JSONResponse CeremonyResponse

func (response BrowserBeginAddPasskey200JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserBeginAddPasskey401JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskey403JSONResponse Error

func (response BrowserBeginAddPasskey403JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskey409JSONResponse Error

func (response BrowserBeginAddPasskey409JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskey429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserBeginAddPasskey429JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginAddPasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserBeginAddPasskey503JSONResponse) VisitBrowserBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeletePasskeyRequestObject struct {
	Id     string `json:"id"`
	Params BrowserDeletePasskeyParams
}

type BrowserDeletePasskeyResponseObject interface {
	VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error
}

type BrowserDeletePasskey204Response struct {
}

func (response BrowserDeletePasskey204Response) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserDeletePasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserDeletePasskey401JSONResponse) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeletePasskey403JSONResponse Error

func (response BrowserDeletePasskey403JSONResponse) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeletePasskey404JSONResponse Error

func (response BrowserDeletePasskey404JSONResponse) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeletePasskey409JSONResponse Error

func (response BrowserDeletePasskey409JSONResponse) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserDeletePasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserDeletePasskey503JSONResponse) VisitBrowserDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskeyRequestObject struct {
	Id   string `json:"id"`
	Body *BrowserRenamePasskeyJSONRequestBody
}

type BrowserRenamePasskeyResponseObject interface {
	VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error
}

type BrowserRenamePasskey200JSONResponse Passkey

func (response BrowserRenamePasskey200JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskey400JSONResponse Error

func (response BrowserRenamePasskey400JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserRenamePasskey401JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskey403JSONResponse Error

func (response BrowserRenamePasskey403JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskey404JSONResponse Error

func (response BrowserRenamePasskey404JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRenamePasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRenamePasskey503JSONResponse) VisitBrowserRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRegenerateRecoveryCodesRequestObject struct {
	Params BrowserRegenerateRecoveryCodesParams
}

type BrowserRegenerateRecoveryCodesResponseObject interface {
	VisitBrowserRegenerateRecoveryCodesResponse(w http.ResponseWriter) error
}

type BrowserRegenerateRecoveryCodes200JSONResponse RecoveryCodesResponse

func (response BrowserRegenerateRecoveryCodes200JSONResponse) VisitBrowserRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRegenerateRecoveryCodes401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserRegenerateRecoveryCodes401JSONResponse) VisitBrowserRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRegenerateRecoveryCodes403JSONResponse Error

func (response BrowserRegenerateRecoveryCodes403JSONResponse) VisitBrowserRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRegenerateRecoveryCodes503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRegenerateRecoveryCodes503JSONResponse) VisitBrowserRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUpRequestObject struct {
	Body *BrowserBeginStepUpJSONRequestBody
}

type BrowserBeginStepUpResponseObject interface {
	VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error
}

type BrowserBeginStepUp200JSONResponse CeremonyResponse

func (response BrowserBeginStepUp200JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUp400JSONResponse Error

func (response BrowserBeginStepUp400JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserBeginStepUp401JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUp403JSONResponse Error

func (response BrowserBeginStepUp403JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUp429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserBeginStepUp429JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserBeginStepUp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserBeginStepUp503JSONResponse) VisitBrowserBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUpRequestObject struct {
	Body *BrowserFinishStepUpJSONRequestBody
}

type BrowserFinishStepUpResponseObject interface {
	VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error
}

type BrowserFinishStepUp200JSONResponse StepUpResponse

func (response BrowserFinishStepUp200JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUp400JSONResponse Error

func (response BrowserFinishStepUp400JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserFinishStepUp401JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUp403JSONResponse Error

func (response BrowserFinishStepUp403JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUp429JSONResponse struct{ RateLimitedJSONResponse }

func (response BrowserFinishStepUp429JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserFinishStepUp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserFinishStepUp503JSONResponse) VisitBrowserFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemDeviceSignInRequestObject struct {
	Body *NativeRedeemDeviceSignInJSONRequestBody
}

type NativeRedeemDeviceSignInResponseObject interface {
	VisitNativeRedeemDeviceSignInResponse(w http.ResponseWriter) error
}

type NativeRedeemDeviceSignIn200JSONResponse NativePasskeyLoginResponse

func (response NativeRedeemDeviceSignIn200JSONResponse) VisitNativeRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemDeviceSignIn400JSONResponse Error

func (response NativeRedeemDeviceSignIn400JSONResponse) VisitNativeRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemDeviceSignIn503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRedeemDeviceSignIn503JSONResponse) VisitNativeRedeemDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartDeviceSignInRequestObject struct {
	Body *NativeStartDeviceSignInJSONRequestBody
}

type NativeStartDeviceSignInResponseObject interface {
	VisitNativeStartDeviceSignInResponse(w http.ResponseWriter) error
}

type NativeStartDeviceSignIn200JSONResponse NativeDeviceStartResponse

func (response NativeStartDeviceSignIn200JSONResponse) VisitNativeStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartDeviceSignIn400JSONResponse Error

func (response NativeStartDeviceSignIn400JSONResponse) VisitNativeStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartDeviceSignIn429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeStartDeviceSignIn429JSONResponse) VisitNativeStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartDeviceSignIn503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeStartDeviceSignIn503JSONResponse) VisitNativeStartDeviceSignInResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeviceSignInStatusRequestObject struct {
	Body *NativeDeviceSignInStatusJSONRequestBody
}

type NativeDeviceSignInStatusResponseObject interface {
	VisitNativeDeviceSignInStatusResponse(w http.ResponseWriter) error
}

type NativeDeviceSignInStatus200JSONResponse DeviceStatusResponse

func (response NativeDeviceSignInStatus200JSONResponse) VisitNativeDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeviceSignInStatus400JSONResponse Error

func (response NativeDeviceSignInStatus400JSONResponse) VisitNativeDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeviceSignInStatus503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeDeviceSignInStatus503JSONResponse) VisitNativeDeviceSignInStatusResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeResendEmailRequestObject struct {
	Body *NativeResendEmailJSONRequestBody
}

type NativeResendEmailResponseObject interface {
	VisitNativeResendEmailResponse(w http.ResponseWriter) error
}

type NativeResendEmail202JSONResponse ResendResponse

func (response NativeResendEmail202JSONResponse) VisitNativeResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type NativeResendEmail400JSONResponse Error

func (response NativeResendEmail400JSONResponse) VisitNativeResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeResendEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeResendEmail429JSONResponse) VisitNativeResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeResendEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeResendEmail503JSONResponse) VisitNativeResendEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailRequestObject struct {
	Body *NativeStartEmailJSONRequestBody
}

type NativeStartEmailResponseObject interface {
	VisitNativeStartEmailResponse(w http.ResponseWriter) error
}

type NativeStartEmail202JSONResponse NativeStartResponse

func (response NativeStartEmail202JSONResponse) VisitNativeStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmail400JSONResponse struct{ InvalidRequestJSONResponse }

func (response NativeStartEmail400JSONResponse) VisitNativeStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeStartEmail429JSONResponse) VisitNativeStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeStartEmail503JSONResponse) VisitNativeStartEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeVerifyEmailRequestObject struct {
	Body *NativeVerifyEmailJSONRequestBody
}

type NativeVerifyEmailResponseObject interface {
	VisitNativeVerifyEmailResponse(w http.ResponseWriter) error
}

type NativeVerifyEmail200JSONResponse NextStepResponse

func (response NativeVerifyEmail200JSONResponse) VisitNativeVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeVerifyEmail400JSONResponse Error

func (response NativeVerifyEmail400JSONResponse) VisitNativeVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeVerifyEmail429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeVerifyEmail429JSONResponse) VisitNativeVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeVerifyEmail503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeVerifyEmail503JSONResponse) VisitNativeVerifyEmailResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyLoginRequestObject struct {
}

type NativeBeginPasskeyLoginResponseObject interface {
	VisitNativeBeginPasskeyLoginResponse(w http.ResponseWriter) error
}

type NativeBeginPasskeyLogin200JSONResponse CeremonyResponse

func (response NativeBeginPasskeyLogin200JSONResponse) VisitNativeBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyLogin400JSONResponse Error

func (response NativeBeginPasskeyLogin400JSONResponse) VisitNativeBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyLogin429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeBeginPasskeyLogin429JSONResponse) VisitNativeBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyLogin503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeBeginPasskeyLogin503JSONResponse) VisitNativeBeginPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyLoginRequestObject struct {
	Body *NativeFinishPasskeyLoginJSONRequestBody
}

type NativeFinishPasskeyLoginResponseObject interface {
	VisitNativeFinishPasskeyLoginResponse(w http.ResponseWriter) error
}

type NativeFinishPasskeyLogin200JSONResponse NativePasskeyLoginResponse

func (response NativeFinishPasskeyLogin200JSONResponse) VisitNativeFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyLogin400JSONResponse Error

func (response NativeFinishPasskeyLogin400JSONResponse) VisitNativeFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyLogin429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeFinishPasskeyLogin429JSONResponse) VisitNativeFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyLogin503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeFinishPasskeyLogin503JSONResponse) VisitNativeFinishPasskeyLoginResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyRegistrationRequestObject struct {
	Body *NativeBeginPasskeyRegistrationJSONRequestBody
}

type NativeBeginPasskeyRegistrationResponseObject interface {
	VisitNativeBeginPasskeyRegistrationResponse(w http.ResponseWriter) error
}

type NativeBeginPasskeyRegistration200JSONResponse CeremonyResponse

func (response NativeBeginPasskeyRegistration200JSONResponse) VisitNativeBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyRegistration400JSONResponse Error

func (response NativeBeginPasskeyRegistration400JSONResponse) VisitNativeBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyRegistration429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeBeginPasskeyRegistration429JSONResponse) VisitNativeBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginPasskeyRegistration503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeBeginPasskeyRegistration503JSONResponse) VisitNativeBeginPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyRegistrationRequestObject struct {
	Body *NativeFinishPasskeyRegistrationJSONRequestBody
}

type NativeFinishPasskeyRegistrationResponseObject interface {
	VisitNativeFinishPasskeyRegistrationResponse(w http.ResponseWriter) error
}

type NativeFinishPasskeyRegistration200JSONResponse NativePasskeyRegisterResponse

func (response NativeFinishPasskeyRegistration200JSONResponse) VisitNativeFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyRegistration400JSONResponse Error

func (response NativeFinishPasskeyRegistration400JSONResponse) VisitNativeFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyRegistration429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeFinishPasskeyRegistration429JSONResponse) VisitNativeFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishPasskeyRegistration503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeFinishPasskeyRegistration503JSONResponse) VisitNativeFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemRecoveryCodeRequestObject struct {
	Body *NativeRedeemRecoveryCodeJSONRequestBody
}

type NativeRedeemRecoveryCodeResponseObject interface {
	VisitNativeRedeemRecoveryCodeResponse(w http.ResponseWriter) error
}

type NativeRedeemRecoveryCode200JSONResponse NextStepResponse

func (response NativeRedeemRecoveryCode200JSONResponse) VisitNativeRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemRecoveryCode400JSONResponse Error

func (response NativeRedeemRecoveryCode400JSONResponse) VisitNativeRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemRecoveryCode429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeRedeemRecoveryCode429JSONResponse) VisitNativeRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRedeemRecoveryCode503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRedeemRecoveryCode503JSONResponse) VisitNativeRedeemRecoveryCodeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
}

type NativeGetDeviceRequestResponseObject interface {
	VisitNativeGetDeviceRequestResponse(w http.ResponseWriter) error
}

type NativeGetDeviceRequest200JSONResponse DeviceRequestView

func (response NativeGetDeviceRequest200JSONResponse) VisitNativeGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeGetDeviceRequest401JSONResponse) VisitNativeGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetDeviceRequest404JSONResponse Error

func (response NativeGetDeviceRequest404JSONResponse) VisitNativeGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeGetDeviceRequest503JSONResponse) VisitNativeGetDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeApproveDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
	Params    NativeApproveDeviceRequestParams
	Body      *NativeApproveDeviceRequestJSONRequestBody
}

type NativeApproveDeviceRequestResponseObject interface {
	VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error
}

type NativeApproveDeviceRequest204Response struct {
}

func (response NativeApproveDeviceRequest204Response) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeApproveDeviceRequest400JSONResponse Error

func (response NativeApproveDeviceRequest400JSONResponse) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeApproveDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeApproveDeviceRequest401JSONResponse) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeApproveDeviceRequest403JSONResponse Error

func (response NativeApproveDeviceRequest403JSONResponse) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeApproveDeviceRequest404JSONResponse Error

func (response NativeApproveDeviceRequest404JSONResponse) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type NativeApproveDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeApproveDeviceRequest503JSONResponse) VisitNativeApproveDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDenyDeviceRequestRequestObject struct {
	RequestId string `json:"request_id"`
}

type NativeDenyDeviceRequestResponseObject interface {
	VisitNativeDenyDeviceRequestResponse(w http.ResponseWriter) error
}

type NativeDenyDeviceRequest204Response struct {
}

func (response NativeDenyDeviceRequest204Response) VisitNativeDenyDeviceRequestResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeDenyDeviceRequest401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeDenyDeviceRequest401JSONResponse) VisitNativeDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDenyDeviceRequest404JSONResponse Error

func (response NativeDenyDeviceRequest404JSONResponse) VisitNativeDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDenyDeviceRequest503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeDenyDeviceRequest503JSONResponse) VisitNativeDenyDeviceRequestResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeleteAccountRequestObject struct {
	Params NativeDeleteAccountParams
}

type NativeDeleteAccountResponseObject interface {
	VisitNativeDeleteAccountResponse(w http.ResponseWriter) error
}

type NativeDeleteAccount204Response struct {
}

func (response NativeDeleteAccount204Response) VisitNativeDeleteAccountResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeDeleteAccount401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeDeleteAccount401JSONResponse) VisitNativeDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeleteAccount403JSONResponse Error

func (response NativeDeleteAccount403JSONResponse) VisitNativeDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeleteAccount503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeDeleteAccount503JSONResponse) VisitNativeDeleteAccountResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetMeRequestObject struct {
}

type NativeGetMeResponseObject interface {
	VisitNativeGetMeResponse(w http.ResponseWriter) error
}

type NativeGetMe200JSONResponse MeResponse

func (response NativeGetMe200JSONResponse) VisitNativeGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetMe401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeGetMe401JSONResponse) VisitNativeGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeGetMe503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeGetMe503JSONResponse) VisitNativeGetMeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListAppsRequestObject struct {
}

type NativeListAppsResponseObject interface {
	VisitNativeListAppsResponse(w http.ResponseWriter) error
}

type NativeListApps200JSONResponse ConnectedAppList

func (response NativeListApps200JSONResponse) VisitNativeListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListApps401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeListApps401JSONResponse) VisitNativeListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListApps503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeListApps503JSONResponse) VisitNativeListAppsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeAppRequestObject struct {
	ClientId string `json:"client_id"`
}

type NativeRevokeAppResponseObject interface {
	VisitNativeRevokeAppResponse(w http.ResponseWriter) error
}

type NativeRevokeApp204Response struct {
}

func (response NativeRevokeApp204Response) VisitNativeRevokeAppResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeRevokeApp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeRevokeApp401JSONResponse) VisitNativeRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeApp403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response NativeRevokeApp403JSONResponse) VisitNativeRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeApp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRevokeApp503JSONResponse) VisitNativeRevokeAppResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeAppGrantRequestObject struct {
	Id string `json:"id"`
}

type NativeRevokeAppGrantResponseObject interface {
	VisitNativeRevokeAppGrantResponse(w http.ResponseWriter) error
}

type NativeRevokeAppGrant204Response struct {
}

func (response NativeRevokeAppGrant204Response) VisitNativeRevokeAppGrantResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeRevokeAppGrant401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeRevokeAppGrant401JSONResponse) VisitNativeRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeAppGrant403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response NativeRevokeAppGrant403JSONResponse) VisitNativeRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeAppGrant503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRevokeAppGrant503JSONResponse) VisitNativeRevokeAppGrantResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChangeRequestObject struct {
	Params NativeStartEmailChangeParams
	Body   *NativeStartEmailChangeJSONRequestBody
}

type NativeStartEmailChangeResponseObject interface {
	VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error
}

type NativeStartEmailChange202JSONResponse EmailChangeStartResponse

func (response NativeStartEmailChange202JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChange400JSONResponse Error

func (response NativeStartEmailChange400JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChange401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeStartEmailChange401JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChange403JSONResponse Error

func (response NativeStartEmailChange403JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChange429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeStartEmailChange429JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeStartEmailChange503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeStartEmailChange503JSONResponse) VisitNativeStartEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChangeRequestObject struct {
	Body *NativeConfirmEmailChangeJSONRequestBody
}

type NativeConfirmEmailChangeResponseObject interface {
	VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error
}

type NativeConfirmEmailChange200JSONResponse EmailChangeResponse

func (response NativeConfirmEmailChange200JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChange400JSONResponse Error

func (response NativeConfirmEmailChange400JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChange401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeConfirmEmailChange401JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChange409JSONResponse Error

func (response NativeConfirmEmailChange409JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChange429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeConfirmEmailChange429JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeConfirmEmailChange503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeConfirmEmailChange503JSONResponse) VisitNativeConfirmEmailChangeResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListPasskeysRequestObject struct {
}

type NativeListPasskeysResponseObject interface {
	VisitNativeListPasskeysResponse(w http.ResponseWriter) error
}

type NativeListPasskeys200JSONResponse PasskeyList

func (response NativeListPasskeys200JSONResponse) VisitNativeListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListPasskeys401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeListPasskeys401JSONResponse) VisitNativeListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListPasskeys503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeListPasskeys503JSONResponse) VisitNativeListPasskeysResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskeyRequestObject struct {
	Params NativeFinishAddPasskeyParams
	Body   *NativeFinishAddPasskeyJSONRequestBody
}

type NativeFinishAddPasskeyResponseObject interface {
	VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error
}

type NativeFinishAddPasskey201JSONResponse Passkey

func (response NativeFinishAddPasskey201JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey400JSONResponse Error

func (response NativeFinishAddPasskey400JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeFinishAddPasskey401JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey403JSONResponse Error

func (response NativeFinishAddPasskey403JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey409JSONResponse Error

func (response NativeFinishAddPasskey409JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeFinishAddPasskey429JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishAddPasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeFinishAddPasskey503JSONResponse) VisitNativeFinishAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskeyRequestObject struct {
	Params NativeBeginAddPasskeyParams
}

type NativeBeginAddPasskeyResponseObject interface {
	VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error
}

type NativeBeginAddPasskey200JSONResponse CeremonyResponse

func (response NativeBeginAddPasskey200JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeBeginAddPasskey401JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskey403JSONResponse Error

func (response NativeBeginAddPasskey403JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskey409JSONResponse Error

func (response NativeBeginAddPasskey409JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskey429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeBeginAddPasskey429JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginAddPasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeBeginAddPasskey503JSONResponse) VisitNativeBeginAddPasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeletePasskeyRequestObject struct {
	Id     string `json:"id"`
	Params NativeDeletePasskeyParams
}

type NativeDeletePasskeyResponseObject interface {
	VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error
}

type NativeDeletePasskey204Response struct {
}

func (response NativeDeletePasskey204Response) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeDeletePasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeDeletePasskey401JSONResponse) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeletePasskey403JSONResponse Error

func (response NativeDeletePasskey403JSONResponse) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeletePasskey404JSONResponse Error

func (response NativeDeletePasskey404JSONResponse) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeletePasskey409JSONResponse Error

func (response NativeDeletePasskey409JSONResponse) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(409)
	_, err := buf.WriteTo(w)
	return err
}

type NativeDeletePasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeDeletePasskey503JSONResponse) VisitNativeDeletePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRenamePasskeyRequestObject struct {
	Id   string `json:"id"`
	Body *NativeRenamePasskeyJSONRequestBody
}

type NativeRenamePasskeyResponseObject interface {
	VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error
}

type NativeRenamePasskey200JSONResponse Passkey

func (response NativeRenamePasskey200JSONResponse) VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRenamePasskey400JSONResponse Error

func (response NativeRenamePasskey400JSONResponse) VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRenamePasskey401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeRenamePasskey401JSONResponse) VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRenamePasskey404JSONResponse Error

func (response NativeRenamePasskey404JSONResponse) VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRenamePasskey503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRenamePasskey503JSONResponse) VisitNativeRenamePasskeyResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRegenerateRecoveryCodesRequestObject struct {
	Params NativeRegenerateRecoveryCodesParams
}

type NativeRegenerateRecoveryCodesResponseObject interface {
	VisitNativeRegenerateRecoveryCodesResponse(w http.ResponseWriter) error
}

type NativeRegenerateRecoveryCodes200JSONResponse RecoveryCodesResponse

func (response NativeRegenerateRecoveryCodes200JSONResponse) VisitNativeRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRegenerateRecoveryCodes401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeRegenerateRecoveryCodes401JSONResponse) VisitNativeRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRegenerateRecoveryCodes403JSONResponse Error

func (response NativeRegenerateRecoveryCodes403JSONResponse) VisitNativeRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRegenerateRecoveryCodes503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRegenerateRecoveryCodes503JSONResponse) VisitNativeRegenerateRecoveryCodesResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginStepUpRequestObject struct {
	Body *NativeBeginStepUpJSONRequestBody
}

type NativeBeginStepUpResponseObject interface {
	VisitNativeBeginStepUpResponse(w http.ResponseWriter) error
}

type NativeBeginStepUp200JSONResponse CeremonyResponse

func (response NativeBeginStepUp200JSONResponse) VisitNativeBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginStepUp400JSONResponse Error

func (response NativeBeginStepUp400JSONResponse) VisitNativeBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginStepUp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeBeginStepUp401JSONResponse) VisitNativeBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginStepUp429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeBeginStepUp429JSONResponse) VisitNativeBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeBeginStepUp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeBeginStepUp503JSONResponse) VisitNativeBeginStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishStepUpRequestObject struct {
	Body *NativeFinishStepUpJSONRequestBody
}

type NativeFinishStepUpResponseObject interface {
	VisitNativeFinishStepUpResponse(w http.ResponseWriter) error
}

type NativeFinishStepUp200JSONResponse StepUpResponse

func (response NativeFinishStepUp200JSONResponse) VisitNativeFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishStepUp400JSONResponse Error

func (response NativeFinishStepUp400JSONResponse) VisitNativeFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishStepUp401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeFinishStepUp401JSONResponse) VisitNativeFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishStepUp429JSONResponse struct{ RateLimitedJSONResponse }

func (response NativeFinishStepUp429JSONResponse) VisitNativeFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(429)
	_, err := buf.WriteTo(w)
	return err
}

type NativeFinishStepUp503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeFinishStepUp503JSONResponse) VisitNativeFinishStepUpResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListSessionsRequestObject struct {
}

type NativeListSessionsResponseObject interface {
	VisitNativeListSessionsResponse(w http.ResponseWriter) error
}

type NativeListSessions200JSONResponse SessionList

func (response NativeListSessions200JSONResponse) VisitNativeListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListSessions401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeListSessions401JSONResponse) VisitNativeListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeListSessions503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeListSessions503JSONResponse) VisitNativeListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeSessionRequestObject struct {
	Id string `json:"id"`
}

type NativeRevokeSessionResponseObject interface {
	VisitNativeRevokeSessionResponse(w http.ResponseWriter) error
}

type NativeRevokeSession204Response struct {
}

func (response NativeRevokeSession204Response) VisitNativeRevokeSessionResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeRevokeSession401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeRevokeSession401JSONResponse) VisitNativeRevokeSessionResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRevokeSession503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRevokeSession503JSONResponse) VisitNativeRevokeSessionResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeSignOutRequestObject struct {
	Body *NativeSignOutJSONRequestBody
}

type NativeSignOutResponseObject interface {
	VisitNativeSignOutResponse(w http.ResponseWriter) error
}

type NativeSignOut204Response struct {
}

func (response NativeSignOut204Response) VisitNativeSignOutResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type NativeSignOut400JSONResponse struct{ InvalidRequestJSONResponse }

func (response NativeSignOut400JSONResponse) VisitNativeSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeSignOut401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response NativeSignOut401JSONResponse) VisitNativeSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeSignOut503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeSignOut503JSONResponse) VisitNativeSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRefreshTokenRequestObject struct {
	Body *NativeRefreshTokenJSONRequestBody
}

type NativeRefreshTokenResponseObject interface {
	VisitNativeRefreshTokenResponse(w http.ResponseWriter) error
}

type NativeRefreshToken200JSONResponse NativeRefreshResponse

func (response NativeRefreshToken200JSONResponse) VisitNativeRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRefreshToken400JSONResponse struct{ InvalidRequestJSONResponse }

func (response NativeRefreshToken400JSONResponse) VisitNativeRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRefreshToken401JSONResponse Error

func (response NativeRefreshToken401JSONResponse) VisitNativeRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type NativeRefreshToken503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response NativeRefreshToken503JSONResponse) VisitNativeRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListSessionsRequestObject struct {
}

type BrowserListSessionsResponseObject interface {
	VisitBrowserListSessionsResponse(w http.ResponseWriter) error
}

type BrowserListSessions200JSONResponse SessionList

func (response BrowserListSessions200JSONResponse) VisitBrowserListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListSessions401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserListSessions401JSONResponse) VisitBrowserListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserListSessions503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserListSessions503JSONResponse) VisitBrowserListSessionsResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeSessionRequestObject struct {
	Id string `json:"id"`
}

type BrowserRevokeSessionResponseObject interface {
	VisitBrowserRevokeSessionResponse(w http.ResponseWriter) error
}

type BrowserRevokeSession204Response struct {
}

func (response BrowserRevokeSession204Response) VisitBrowserRevokeSessionResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserRevokeSession401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserRevokeSession401JSONResponse) VisitBrowserRevokeSessionResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeSession403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserRevokeSession403JSONResponse) VisitBrowserRevokeSessionResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRevokeSession503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRevokeSession503JSONResponse) VisitBrowserRevokeSessionResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserSignOutRequestObject struct {
	Body *BrowserSignOutJSONRequestBody
}

type BrowserSignOutResponseObject interface {
	VisitBrowserSignOutResponse(w http.ResponseWriter) error
}

type BrowserSignOut204Response struct {
}

func (response BrowserSignOut204Response) VisitBrowserSignOutResponse(w http.ResponseWriter) error {
	w.WriteHeader(204)
	return nil
}

type BrowserSignOut400JSONResponse struct{ InvalidRequestJSONResponse }

func (response BrowserSignOut400JSONResponse) VisitBrowserSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserSignOut401JSONResponse struct{ UnauthenticatedJSONResponse }

func (response BrowserSignOut401JSONResponse) VisitBrowserSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response.Body); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprint(response.Headers.WWWAuthenticate))
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserSignOut403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserSignOut403JSONResponse) VisitBrowserSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserSignOut503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserSignOut503JSONResponse) VisitBrowserSignOutResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRefreshTokenRequestObject struct {
}

type BrowserRefreshTokenResponseObject interface {
	VisitBrowserRefreshTokenResponse(w http.ResponseWriter) error
}

type BrowserRefreshToken200JSONResponse BrowserRefreshResponse

func (response BrowserRefreshToken200JSONResponse) VisitBrowserRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRefreshToken401JSONResponse Error

func (response BrowserRefreshToken401JSONResponse) VisitBrowserRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRefreshToken403JSONResponse struct{ PermissionDeniedJSONResponse }

func (response BrowserRefreshToken403JSONResponse) VisitBrowserRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)
	_, err := buf.WriteTo(w)
	return err
}

type BrowserRefreshToken503JSONResponse struct {
	TemporarilyUnavailableJSONResponse
}

func (response BrowserRefreshToken503JSONResponse) VisitBrowserRefreshTokenResponse(w http.ResponseWriter) error {

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(response); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(503)
	_, err := buf.WriteTo(w)
	return err
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// GetJWKS Public keys that verify access tokens
	// (GET /.well-known/jwks.json)
	GetJWKS(ctx context.Context, request GetJWKSRequestObject) (GetJWKSResponseObject, error)
	// GetHealthAlive The process serves requests
	// (GET /health/alive)
	GetHealthAlive(ctx context.Context, request GetHealthAliveRequestObject) (GetHealthAliveResponseObject, error)
	// GetHealthReady The service can handle sign-in requests
	// (GET /health/ready)
	GetHealthReady(ctx context.Context, request GetHealthReadyRequestObject) (GetHealthReadyResponseObject, error)
	// BrowserRedeemDeviceSignIn Take the session of an approved request
	// (POST /v1/auth/device/redeem)
	BrowserRedeemDeviceSignIn(ctx context.Context, request BrowserRedeemDeviceSignInRequestObject) (BrowserRedeemDeviceSignInResponseObject, error)
	// BrowserStartDeviceSignIn Ask for a session on this device, to be approved on another
	// (POST /v1/auth/device/start)
	BrowserStartDeviceSignIn(ctx context.Context, request BrowserStartDeviceSignInRequestObject) (BrowserStartDeviceSignInResponseObject, error)
	// BrowserDeviceSignInStatus Ask how the request stands
	// (POST /v1/auth/device/status)
	BrowserDeviceSignInStatus(ctx context.Context, request BrowserDeviceSignInStatusRequestObject) (BrowserDeviceSignInStatusResponseObject, error)
	// BrowserResendEmail Send a new code for the same flow
	// (POST /v1/auth/email/resend)
	BrowserResendEmail(ctx context.Context, request BrowserResendEmailRequestObject) (BrowserResendEmailResponseObject, error)
	// BrowserStartEmail Start an email sign-in flow and queue the code
	// (POST /v1/auth/email/start)
	BrowserStartEmail(ctx context.Context, request BrowserStartEmailRequestObject) (BrowserStartEmailResponseObject, error)
	// BrowserVerifyEmail Prove the code and receive the ticket for the next step
	// (POST /v1/auth/email/verify)
	BrowserVerifyEmail(ctx context.Context, request BrowserVerifyEmailRequestObject) (BrowserVerifyEmailResponseObject, error)
	// BrowserBeginPasskeyLogin Start a passkey assertion
	// (POST /v1/auth/passkey/login/options)
	BrowserBeginPasskeyLogin(ctx context.Context, request BrowserBeginPasskeyLoginRequestObject) (BrowserBeginPasskeyLoginResponseObject, error)
	// BrowserFinishPasskeyLogin Verify the assertion and sign in
	// (POST /v1/auth/passkey/login/verify)
	BrowserFinishPasskeyLogin(ctx context.Context, request BrowserFinishPasskeyLoginRequestObject) (BrowserFinishPasskeyLoginResponseObject, error)
	// BrowserBeginPasskeyRegistration Start registering a passkey
	// (POST /v1/auth/passkey/register/options)
	BrowserBeginPasskeyRegistration(ctx context.Context, request BrowserBeginPasskeyRegistrationRequestObject) (BrowserBeginPasskeyRegistrationResponseObject, error)
	// BrowserFinishPasskeyRegistration Finish registering a passkey and sign in
	// (POST /v1/auth/passkey/register/verify)
	BrowserFinishPasskeyRegistration(ctx context.Context, request BrowserFinishPasskeyRegistrationRequestObject) (BrowserFinishPasskeyRegistrationResponseObject, error)
	// BrowserRedeemRecoveryCode Spend a recovery code in place of a passkey
	// (POST /v1/auth/recovery/verify)
	BrowserRedeemRecoveryCode(ctx context.Context, request BrowserRedeemRecoveryCodeRequestObject) (BrowserRedeemRecoveryCodeResponseObject, error)
	// BrowserGetDeviceRequest See who asks to sign in
	// (GET /v1/device/requests/{request_id})
	BrowserGetDeviceRequest(ctx context.Context, request BrowserGetDeviceRequestRequestObject) (BrowserGetDeviceRequestResponseObject, error)
	// BrowserApproveDeviceRequest Let the device sign in as this user
	// (POST /v1/device/requests/{request_id}/approve)
	BrowserApproveDeviceRequest(ctx context.Context, request BrowserApproveDeviceRequestRequestObject) (BrowserApproveDeviceRequestResponseObject, error)
	// BrowserDenyDeviceRequest Refuse the request
	// (POST /v1/device/requests/{request_id}/deny)
	BrowserDenyDeviceRequest(ctx context.Context, request BrowserDenyDeviceRequestRequestObject) (BrowserDenyDeviceRequestResponseObject, error)
	// BrowserDeleteAccount Permanently delete the signed-in account
	// (DELETE /v1/me)
	BrowserDeleteAccount(ctx context.Context, request BrowserDeleteAccountRequestObject) (BrowserDeleteAccountResponseObject, error)
	// BrowserGetMe The signed-in user and the current session
	// (GET /v1/me)
	BrowserGetMe(ctx context.Context, request BrowserGetMeRequestObject) (BrowserGetMeResponseObject, error)
	// BrowserListApps The applications the user has connected
	// (GET /v1/me/apps)
	BrowserListApps(ctx context.Context, request BrowserListAppsRequestObject) (BrowserListAppsResponseObject, error)
	// BrowserRevokeApp Take every grant of one application back
	// (DELETE /v1/me/apps/clients/{client_id})
	BrowserRevokeApp(ctx context.Context, request BrowserRevokeAppRequestObject) (BrowserRevokeAppResponseObject, error)
	// BrowserRevokeAppGrant Take one grant of an application back
	// (DELETE /v1/me/apps/grants/{id})
	BrowserRevokeAppGrant(ctx context.Context, request BrowserRevokeAppGrantRequestObject) (BrowserRevokeAppGrantResponseObject, error)
	// BrowserStartEmailChange Ask for a code at a new email address
	// (POST /v1/me/email/change)
	BrowserStartEmailChange(ctx context.Context, request BrowserStartEmailChangeRequestObject) (BrowserStartEmailChangeResponseObject, error)
	// BrowserConfirmEmailChange Prove the code from the new address and move the account
	// (POST /v1/me/email/change/confirm)
	BrowserConfirmEmailChange(ctx context.Context, request BrowserConfirmEmailChangeRequestObject) (BrowserConfirmEmailChangeResponseObject, error)
	// BrowserListPasskeys The user's passkeys
	// (GET /v1/me/passkeys)
	BrowserListPasskeys(ctx context.Context, request BrowserListPasskeysRequestObject) (BrowserListPasskeysResponseObject, error)
	// BrowserFinishAddPasskey Finish adding a passkey
	// (POST /v1/me/passkeys)
	BrowserFinishAddPasskey(ctx context.Context, request BrowserFinishAddPasskeyRequestObject) (BrowserFinishAddPasskeyResponseObject, error)
	// BrowserBeginAddPasskey Start adding a passkey
	// (POST /v1/me/passkeys/options)
	BrowserBeginAddPasskey(ctx context.Context, request BrowserBeginAddPasskeyRequestObject) (BrowserBeginAddPasskeyResponseObject, error)
	// BrowserDeletePasskey Delete a passkey
	// (DELETE /v1/me/passkeys/{id})
	BrowserDeletePasskey(ctx context.Context, request BrowserDeletePasskeyRequestObject) (BrowserDeletePasskeyResponseObject, error)
	// BrowserRenamePasskey Rename a passkey
	// (PATCH /v1/me/passkeys/{id})
	BrowserRenamePasskey(ctx context.Context, request BrowserRenamePasskeyRequestObject) (BrowserRenamePasskeyResponseObject, error)
	// BrowserRegenerateRecoveryCodes Replace the recovery codes
	// (POST /v1/me/recovery-codes)
	BrowserRegenerateRecoveryCodes(ctx context.Context, request BrowserRegenerateRecoveryCodesRequestObject) (BrowserRegenerateRecoveryCodesResponseObject, error)
	// BrowserBeginStepUp Start a fresh strong proof for one operation
	// (POST /v1/me/step-up/options)
	BrowserBeginStepUp(ctx context.Context, request BrowserBeginStepUpRequestObject) (BrowserBeginStepUpResponseObject, error)
	// BrowserFinishStepUp Prove the passkey and receive the step-up token
	// (POST /v1/me/step-up/verify)
	BrowserFinishStepUp(ctx context.Context, request BrowserFinishStepUpRequestObject) (BrowserFinishStepUpResponseObject, error)
	// NativeRedeemDeviceSignIn Take the session of an approved request
	// (POST /v1/native/auth/device/redeem)
	NativeRedeemDeviceSignIn(ctx context.Context, request NativeRedeemDeviceSignInRequestObject) (NativeRedeemDeviceSignInResponseObject, error)
	// NativeStartDeviceSignIn Ask for a session on this device, to be approved on another
	// (POST /v1/native/auth/device/start)
	NativeStartDeviceSignIn(ctx context.Context, request NativeStartDeviceSignInRequestObject) (NativeStartDeviceSignInResponseObject, error)
	// NativeDeviceSignInStatus Ask how the request stands
	// (POST /v1/native/auth/device/status)
	NativeDeviceSignInStatus(ctx context.Context, request NativeDeviceSignInStatusRequestObject) (NativeDeviceSignInStatusResponseObject, error)
	// NativeResendEmail Send a new code for the same flow
	// (POST /v1/native/auth/email/resend)
	NativeResendEmail(ctx context.Context, request NativeResendEmailRequestObject) (NativeResendEmailResponseObject, error)
	// NativeStartEmail Start an email sign-in flow and queue the code
	// (POST /v1/native/auth/email/start)
	NativeStartEmail(ctx context.Context, request NativeStartEmailRequestObject) (NativeStartEmailResponseObject, error)
	// NativeVerifyEmail Prove the code and receive the ticket for the next step
	// (POST /v1/native/auth/email/verify)
	NativeVerifyEmail(ctx context.Context, request NativeVerifyEmailRequestObject) (NativeVerifyEmailResponseObject, error)
	// NativeBeginPasskeyLogin Start a passkey assertion
	// (POST /v1/native/auth/passkey/login/options)
	NativeBeginPasskeyLogin(ctx context.Context, request NativeBeginPasskeyLoginRequestObject) (NativeBeginPasskeyLoginResponseObject, error)
	// NativeFinishPasskeyLogin Verify the assertion and sign in
	// (POST /v1/native/auth/passkey/login/verify)
	NativeFinishPasskeyLogin(ctx context.Context, request NativeFinishPasskeyLoginRequestObject) (NativeFinishPasskeyLoginResponseObject, error)
	// NativeBeginPasskeyRegistration Start registering a passkey
	// (POST /v1/native/auth/passkey/register/options)
	NativeBeginPasskeyRegistration(ctx context.Context, request NativeBeginPasskeyRegistrationRequestObject) (NativeBeginPasskeyRegistrationResponseObject, error)
	// NativeFinishPasskeyRegistration Finish registering a passkey and sign in
	// (POST /v1/native/auth/passkey/register/verify)
	NativeFinishPasskeyRegistration(ctx context.Context, request NativeFinishPasskeyRegistrationRequestObject) (NativeFinishPasskeyRegistrationResponseObject, error)
	// NativeRedeemRecoveryCode Spend a recovery code in place of a passkey
	// (POST /v1/native/auth/recovery/verify)
	NativeRedeemRecoveryCode(ctx context.Context, request NativeRedeemRecoveryCodeRequestObject) (NativeRedeemRecoveryCodeResponseObject, error)
	// NativeGetDeviceRequest See who asks to sign in
	// (GET /v1/native/device/requests/{request_id})
	NativeGetDeviceRequest(ctx context.Context, request NativeGetDeviceRequestRequestObject) (NativeGetDeviceRequestResponseObject, error)
	// NativeApproveDeviceRequest Let the device sign in as this user
	// (POST /v1/native/device/requests/{request_id}/approve)
	NativeApproveDeviceRequest(ctx context.Context, request NativeApproveDeviceRequestRequestObject) (NativeApproveDeviceRequestResponseObject, error)
	// NativeDenyDeviceRequest Refuse the request
	// (POST /v1/native/device/requests/{request_id}/deny)
	NativeDenyDeviceRequest(ctx context.Context, request NativeDenyDeviceRequestRequestObject) (NativeDenyDeviceRequestResponseObject, error)
	// NativeDeleteAccount Permanently delete the signed-in account
	// (DELETE /v1/native/me)
	NativeDeleteAccount(ctx context.Context, request NativeDeleteAccountRequestObject) (NativeDeleteAccountResponseObject, error)
	// NativeGetMe The signed-in user and the current session
	// (GET /v1/native/me)
	NativeGetMe(ctx context.Context, request NativeGetMeRequestObject) (NativeGetMeResponseObject, error)
	// NativeListApps The applications the user has connected
	// (GET /v1/native/me/apps)
	NativeListApps(ctx context.Context, request NativeListAppsRequestObject) (NativeListAppsResponseObject, error)
	// NativeRevokeApp Take every grant of one application back
	// (DELETE /v1/native/me/apps/clients/{client_id})
	NativeRevokeApp(ctx context.Context, request NativeRevokeAppRequestObject) (NativeRevokeAppResponseObject, error)
	// NativeRevokeAppGrant Take one grant of an application back
	// (DELETE /v1/native/me/apps/grants/{id})
	NativeRevokeAppGrant(ctx context.Context, request NativeRevokeAppGrantRequestObject) (NativeRevokeAppGrantResponseObject, error)
	// NativeStartEmailChange Ask for a code at a new email address
	// (POST /v1/native/me/email/change)
	NativeStartEmailChange(ctx context.Context, request NativeStartEmailChangeRequestObject) (NativeStartEmailChangeResponseObject, error)
	// NativeConfirmEmailChange Prove the code from the new address and move the account
	// (POST /v1/native/me/email/change/confirm)
	NativeConfirmEmailChange(ctx context.Context, request NativeConfirmEmailChangeRequestObject) (NativeConfirmEmailChangeResponseObject, error)
	// NativeListPasskeys The user's passkeys
	// (GET /v1/native/me/passkeys)
	NativeListPasskeys(ctx context.Context, request NativeListPasskeysRequestObject) (NativeListPasskeysResponseObject, error)
	// NativeFinishAddPasskey Finish adding a passkey
	// (POST /v1/native/me/passkeys)
	NativeFinishAddPasskey(ctx context.Context, request NativeFinishAddPasskeyRequestObject) (NativeFinishAddPasskeyResponseObject, error)
	// NativeBeginAddPasskey Start adding a passkey
	// (POST /v1/native/me/passkeys/options)
	NativeBeginAddPasskey(ctx context.Context, request NativeBeginAddPasskeyRequestObject) (NativeBeginAddPasskeyResponseObject, error)
	// NativeDeletePasskey Delete a passkey
	// (DELETE /v1/native/me/passkeys/{id})
	NativeDeletePasskey(ctx context.Context, request NativeDeletePasskeyRequestObject) (NativeDeletePasskeyResponseObject, error)
	// NativeRenamePasskey Rename a passkey
	// (PATCH /v1/native/me/passkeys/{id})
	NativeRenamePasskey(ctx context.Context, request NativeRenamePasskeyRequestObject) (NativeRenamePasskeyResponseObject, error)
	// NativeRegenerateRecoveryCodes Replace the recovery codes
	// (POST /v1/native/me/recovery-codes)
	NativeRegenerateRecoveryCodes(ctx context.Context, request NativeRegenerateRecoveryCodesRequestObject) (NativeRegenerateRecoveryCodesResponseObject, error)
	// NativeBeginStepUp Start a fresh strong proof for one operation
	// (POST /v1/native/me/step-up/options)
	NativeBeginStepUp(ctx context.Context, request NativeBeginStepUpRequestObject) (NativeBeginStepUpResponseObject, error)
	// NativeFinishStepUp Prove the passkey and receive the step-up token
	// (POST /v1/native/me/step-up/verify)
	NativeFinishStepUp(ctx context.Context, request NativeFinishStepUpRequestObject) (NativeFinishStepUpResponseObject, error)
	// NativeListSessions The user's active sessions
	// (GET /v1/native/sessions)
	NativeListSessions(ctx context.Context, request NativeListSessionsRequestObject) (NativeListSessionsResponseObject, error)
	// NativeRevokeSession End one of the user's sessions
	// (DELETE /v1/native/sessions/{id})
	NativeRevokeSession(ctx context.Context, request NativeRevokeSessionRequestObject) (NativeRevokeSessionResponseObject, error)
	// NativeSignOut End the current session or all sessions
	// (POST /v1/native/signout)
	NativeSignOut(ctx context.Context, request NativeSignOutRequestObject) (NativeSignOutResponseObject, error)
	// NativeRefreshToken Exchange a refresh token for new tokens
	// (POST /v1/native/token/refresh)
	NativeRefreshToken(ctx context.Context, request NativeRefreshTokenRequestObject) (NativeRefreshTokenResponseObject, error)
	// BrowserListSessions The user's active sessions
	// (GET /v1/sessions)
	BrowserListSessions(ctx context.Context, request BrowserListSessionsRequestObject) (BrowserListSessionsResponseObject, error)
	// BrowserRevokeSession End one of the user's sessions
	// (DELETE /v1/sessions/{id})
	BrowserRevokeSession(ctx context.Context, request BrowserRevokeSessionRequestObject) (BrowserRevokeSessionResponseObject, error)
	// BrowserSignOut End the current session or all sessions
	// (POST /v1/signout)
	BrowserSignOut(ctx context.Context, request BrowserSignOutRequestObject) (BrowserSignOutResponseObject, error)
	// BrowserRefreshToken Exchange the refresh cookie for a new access token
	// (POST /v1/token/refresh)
	BrowserRefreshToken(ctx context.Context, request BrowserRefreshTokenRequestObject) (BrowserRefreshTokenResponseObject, error)
}

type StrictHandlerFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error)
type StrictMiddlewareFunc func(f StrictHandlerFunc, operationID string) StrictHandlerFunc

type StrictHTTPServerOptions struct {
	RequestErrorHandlerFunc  func(w http.ResponseWriter, r *http.Request, err error)
	ResponseErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	}}
}

func NewStrictHandlerWithOptions(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc, options StrictHTTPServerOptions) ServerInterface {
	if options.RequestErrorHandlerFunc == nil {
		options.RequestErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	if options.ResponseErrorHandlerFunc == nil {
		options.ResponseErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: options}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
	options     StrictHTTPServerOptions
}

// GetJWKS operation middleware
func (sh *strictHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	var request GetJWKSRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetJWKS(ctx, request.(GetJWKSRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetJWKS")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetJWKSResponseObject); ok {
		if err := validResponse.VisitGetJWKSResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetHealthAlive operation middleware
func (sh *strictHandler) GetHealthAlive(w http.ResponseWriter, r *http.Request) {
	var request GetHealthAliveRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetHealthAlive(ctx, request.(GetHealthAliveRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetHealthAlive")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetHealthAliveResponseObject); ok {
		if err := validResponse.VisitGetHealthAliveResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetHealthReady operation middleware
func (sh *strictHandler) GetHealthReady(w http.ResponseWriter, r *http.Request) {
	var request GetHealthReadyRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetHealthReady(ctx, request.(GetHealthReadyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetHealthReady")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetHealthReadyResponseObject); ok {
		if err := validResponse.VisitGetHealthReadyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRedeemDeviceSignIn operation middleware
func (sh *strictHandler) BrowserRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request) {
	var request BrowserRedeemDeviceSignInRequestObject

	var body BrowserRedeemDeviceSignInJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRedeemDeviceSignIn(ctx, request.(BrowserRedeemDeviceSignInRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRedeemDeviceSignIn")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRedeemDeviceSignInResponseObject); ok {
		if err := validResponse.VisitBrowserRedeemDeviceSignInResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserStartDeviceSignIn operation middleware
func (sh *strictHandler) BrowserStartDeviceSignIn(w http.ResponseWriter, r *http.Request) {
	var request BrowserStartDeviceSignInRequestObject

	var body BrowserStartDeviceSignInJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserStartDeviceSignIn(ctx, request.(BrowserStartDeviceSignInRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserStartDeviceSignIn")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserStartDeviceSignInResponseObject); ok {
		if err := validResponse.VisitBrowserStartDeviceSignInResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserDeviceSignInStatus operation middleware
func (sh *strictHandler) BrowserDeviceSignInStatus(w http.ResponseWriter, r *http.Request) {
	var request BrowserDeviceSignInStatusRequestObject

	var body BrowserDeviceSignInStatusJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserDeviceSignInStatus(ctx, request.(BrowserDeviceSignInStatusRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserDeviceSignInStatus")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserDeviceSignInStatusResponseObject); ok {
		if err := validResponse.VisitBrowserDeviceSignInStatusResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserResendEmail operation middleware
func (sh *strictHandler) BrowserResendEmail(w http.ResponseWriter, r *http.Request) {
	var request BrowserResendEmailRequestObject

	var body BrowserResendEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserResendEmail(ctx, request.(BrowserResendEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserResendEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserResendEmailResponseObject); ok {
		if err := validResponse.VisitBrowserResendEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserStartEmail operation middleware
func (sh *strictHandler) BrowserStartEmail(w http.ResponseWriter, r *http.Request) {
	var request BrowserStartEmailRequestObject

	var body BrowserStartEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserStartEmail(ctx, request.(BrowserStartEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserStartEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserStartEmailResponseObject); ok {
		if err := validResponse.VisitBrowserStartEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserVerifyEmail operation middleware
func (sh *strictHandler) BrowserVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var request BrowserVerifyEmailRequestObject

	var body BrowserVerifyEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserVerifyEmail(ctx, request.(BrowserVerifyEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserVerifyEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserVerifyEmailResponseObject); ok {
		if err := validResponse.VisitBrowserVerifyEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserBeginPasskeyLogin operation middleware
func (sh *strictHandler) BrowserBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var request BrowserBeginPasskeyLoginRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserBeginPasskeyLogin(ctx, request.(BrowserBeginPasskeyLoginRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserBeginPasskeyLogin")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserBeginPasskeyLoginResponseObject); ok {
		if err := validResponse.VisitBrowserBeginPasskeyLoginResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserFinishPasskeyLogin operation middleware
func (sh *strictHandler) BrowserFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var request BrowserFinishPasskeyLoginRequestObject

	var body BrowserFinishPasskeyLoginJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserFinishPasskeyLogin(ctx, request.(BrowserFinishPasskeyLoginRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserFinishPasskeyLogin")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserFinishPasskeyLoginResponseObject); ok {
		if err := validResponse.VisitBrowserFinishPasskeyLoginResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserBeginPasskeyRegistration operation middleware
func (sh *strictHandler) BrowserBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var request BrowserBeginPasskeyRegistrationRequestObject

	var body BrowserBeginPasskeyRegistrationJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserBeginPasskeyRegistration(ctx, request.(BrowserBeginPasskeyRegistrationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserBeginPasskeyRegistration")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserBeginPasskeyRegistrationResponseObject); ok {
		if err := validResponse.VisitBrowserBeginPasskeyRegistrationResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserFinishPasskeyRegistration operation middleware
func (sh *strictHandler) BrowserFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var request BrowserFinishPasskeyRegistrationRequestObject

	var body BrowserFinishPasskeyRegistrationJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserFinishPasskeyRegistration(ctx, request.(BrowserFinishPasskeyRegistrationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserFinishPasskeyRegistration")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserFinishPasskeyRegistrationResponseObject); ok {
		if err := validResponse.VisitBrowserFinishPasskeyRegistrationResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRedeemRecoveryCode operation middleware
func (sh *strictHandler) BrowserRedeemRecoveryCode(w http.ResponseWriter, r *http.Request) {
	var request BrowserRedeemRecoveryCodeRequestObject

	var body BrowserRedeemRecoveryCodeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRedeemRecoveryCode(ctx, request.(BrowserRedeemRecoveryCodeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRedeemRecoveryCode")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRedeemRecoveryCodeResponseObject); ok {
		if err := validResponse.VisitBrowserRedeemRecoveryCodeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserGetDeviceRequest operation middleware
func (sh *strictHandler) BrowserGetDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string) {
	var request BrowserGetDeviceRequestRequestObject

	request.RequestId = requestId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserGetDeviceRequest(ctx, request.(BrowserGetDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserGetDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserGetDeviceRequestResponseObject); ok {
		if err := validResponse.VisitBrowserGetDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserApproveDeviceRequest operation middleware
func (sh *strictHandler) BrowserApproveDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string, params BrowserApproveDeviceRequestParams) {
	var request BrowserApproveDeviceRequestRequestObject

	request.RequestId = requestId
	request.Params = params

	var body BrowserApproveDeviceRequestJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserApproveDeviceRequest(ctx, request.(BrowserApproveDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserApproveDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserApproveDeviceRequestResponseObject); ok {
		if err := validResponse.VisitBrowserApproveDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserDenyDeviceRequest operation middleware
func (sh *strictHandler) BrowserDenyDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string) {
	var request BrowserDenyDeviceRequestRequestObject

	request.RequestId = requestId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserDenyDeviceRequest(ctx, request.(BrowserDenyDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserDenyDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserDenyDeviceRequestResponseObject); ok {
		if err := validResponse.VisitBrowserDenyDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserDeleteAccount operation middleware
func (sh *strictHandler) BrowserDeleteAccount(w http.ResponseWriter, r *http.Request, params BrowserDeleteAccountParams) {
	var request BrowserDeleteAccountRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserDeleteAccount(ctx, request.(BrowserDeleteAccountRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserDeleteAccount")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserDeleteAccountResponseObject); ok {
		if err := validResponse.VisitBrowserDeleteAccountResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserGetMe operation middleware
func (sh *strictHandler) BrowserGetMe(w http.ResponseWriter, r *http.Request) {
	var request BrowserGetMeRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserGetMe(ctx, request.(BrowserGetMeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserGetMe")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserGetMeResponseObject); ok {
		if err := validResponse.VisitBrowserGetMeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserListApps operation middleware
func (sh *strictHandler) BrowserListApps(w http.ResponseWriter, r *http.Request) {
	var request BrowserListAppsRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserListApps(ctx, request.(BrowserListAppsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserListApps")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserListAppsResponseObject); ok {
		if err := validResponse.VisitBrowserListAppsResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRevokeApp operation middleware
func (sh *strictHandler) BrowserRevokeApp(w http.ResponseWriter, r *http.Request, clientId string) {
	var request BrowserRevokeAppRequestObject

	request.ClientId = clientId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRevokeApp(ctx, request.(BrowserRevokeAppRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRevokeApp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRevokeAppResponseObject); ok {
		if err := validResponse.VisitBrowserRevokeAppResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRevokeAppGrant operation middleware
func (sh *strictHandler) BrowserRevokeAppGrant(w http.ResponseWriter, r *http.Request, id string) {
	var request BrowserRevokeAppGrantRequestObject

	request.Id = id

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRevokeAppGrant(ctx, request.(BrowserRevokeAppGrantRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRevokeAppGrant")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRevokeAppGrantResponseObject); ok {
		if err := validResponse.VisitBrowserRevokeAppGrantResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserStartEmailChange operation middleware
func (sh *strictHandler) BrowserStartEmailChange(w http.ResponseWriter, r *http.Request, params BrowserStartEmailChangeParams) {
	var request BrowserStartEmailChangeRequestObject

	request.Params = params

	var body BrowserStartEmailChangeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserStartEmailChange(ctx, request.(BrowserStartEmailChangeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserStartEmailChange")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserStartEmailChangeResponseObject); ok {
		if err := validResponse.VisitBrowserStartEmailChangeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserConfirmEmailChange operation middleware
func (sh *strictHandler) BrowserConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var request BrowserConfirmEmailChangeRequestObject

	var body BrowserConfirmEmailChangeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserConfirmEmailChange(ctx, request.(BrowserConfirmEmailChangeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserConfirmEmailChange")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserConfirmEmailChangeResponseObject); ok {
		if err := validResponse.VisitBrowserConfirmEmailChangeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserListPasskeys operation middleware
func (sh *strictHandler) BrowserListPasskeys(w http.ResponseWriter, r *http.Request) {
	var request BrowserListPasskeysRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserListPasskeys(ctx, request.(BrowserListPasskeysRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserListPasskeys")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserListPasskeysResponseObject); ok {
		if err := validResponse.VisitBrowserListPasskeysResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserFinishAddPasskey operation middleware
func (sh *strictHandler) BrowserFinishAddPasskey(w http.ResponseWriter, r *http.Request, params BrowserFinishAddPasskeyParams) {
	var request BrowserFinishAddPasskeyRequestObject

	request.Params = params

	var body BrowserFinishAddPasskeyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserFinishAddPasskey(ctx, request.(BrowserFinishAddPasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserFinishAddPasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserFinishAddPasskeyResponseObject); ok {
		if err := validResponse.VisitBrowserFinishAddPasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserBeginAddPasskey operation middleware
func (sh *strictHandler) BrowserBeginAddPasskey(w http.ResponseWriter, r *http.Request, params BrowserBeginAddPasskeyParams) {
	var request BrowserBeginAddPasskeyRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserBeginAddPasskey(ctx, request.(BrowserBeginAddPasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserBeginAddPasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserBeginAddPasskeyResponseObject); ok {
		if err := validResponse.VisitBrowserBeginAddPasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserDeletePasskey operation middleware
func (sh *strictHandler) BrowserDeletePasskey(w http.ResponseWriter, r *http.Request, id string, params BrowserDeletePasskeyParams) {
	var request BrowserDeletePasskeyRequestObject

	request.Id = id
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserDeletePasskey(ctx, request.(BrowserDeletePasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserDeletePasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserDeletePasskeyResponseObject); ok {
		if err := validResponse.VisitBrowserDeletePasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRenamePasskey operation middleware
func (sh *strictHandler) BrowserRenamePasskey(w http.ResponseWriter, r *http.Request, id string) {
	var request BrowserRenamePasskeyRequestObject

	request.Id = id

	var body BrowserRenamePasskeyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRenamePasskey(ctx, request.(BrowserRenamePasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRenamePasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRenamePasskeyResponseObject); ok {
		if err := validResponse.VisitBrowserRenamePasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRegenerateRecoveryCodes operation middleware
func (sh *strictHandler) BrowserRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request, params BrowserRegenerateRecoveryCodesParams) {
	var request BrowserRegenerateRecoveryCodesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRegenerateRecoveryCodes(ctx, request.(BrowserRegenerateRecoveryCodesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRegenerateRecoveryCodes")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRegenerateRecoveryCodesResponseObject); ok {
		if err := validResponse.VisitBrowserRegenerateRecoveryCodesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserBeginStepUp operation middleware
func (sh *strictHandler) BrowserBeginStepUp(w http.ResponseWriter, r *http.Request) {
	var request BrowserBeginStepUpRequestObject

	var body BrowserBeginStepUpJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserBeginStepUp(ctx, request.(BrowserBeginStepUpRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserBeginStepUp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserBeginStepUpResponseObject); ok {
		if err := validResponse.VisitBrowserBeginStepUpResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserFinishStepUp operation middleware
func (sh *strictHandler) BrowserFinishStepUp(w http.ResponseWriter, r *http.Request) {
	var request BrowserFinishStepUpRequestObject

	var body BrowserFinishStepUpJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserFinishStepUp(ctx, request.(BrowserFinishStepUpRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserFinishStepUp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserFinishStepUpResponseObject); ok {
		if err := validResponse.VisitBrowserFinishStepUpResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRedeemDeviceSignIn operation middleware
func (sh *strictHandler) NativeRedeemDeviceSignIn(w http.ResponseWriter, r *http.Request) {
	var request NativeRedeemDeviceSignInRequestObject

	var body NativeRedeemDeviceSignInJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRedeemDeviceSignIn(ctx, request.(NativeRedeemDeviceSignInRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRedeemDeviceSignIn")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRedeemDeviceSignInResponseObject); ok {
		if err := validResponse.VisitNativeRedeemDeviceSignInResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeStartDeviceSignIn operation middleware
func (sh *strictHandler) NativeStartDeviceSignIn(w http.ResponseWriter, r *http.Request) {
	var request NativeStartDeviceSignInRequestObject

	var body NativeStartDeviceSignInJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeStartDeviceSignIn(ctx, request.(NativeStartDeviceSignInRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeStartDeviceSignIn")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeStartDeviceSignInResponseObject); ok {
		if err := validResponse.VisitNativeStartDeviceSignInResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeDeviceSignInStatus operation middleware
func (sh *strictHandler) NativeDeviceSignInStatus(w http.ResponseWriter, r *http.Request) {
	var request NativeDeviceSignInStatusRequestObject

	var body NativeDeviceSignInStatusJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeDeviceSignInStatus(ctx, request.(NativeDeviceSignInStatusRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeDeviceSignInStatus")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeDeviceSignInStatusResponseObject); ok {
		if err := validResponse.VisitNativeDeviceSignInStatusResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeResendEmail operation middleware
func (sh *strictHandler) NativeResendEmail(w http.ResponseWriter, r *http.Request) {
	var request NativeResendEmailRequestObject

	var body NativeResendEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeResendEmail(ctx, request.(NativeResendEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeResendEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeResendEmailResponseObject); ok {
		if err := validResponse.VisitNativeResendEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeStartEmail operation middleware
func (sh *strictHandler) NativeStartEmail(w http.ResponseWriter, r *http.Request) {
	var request NativeStartEmailRequestObject

	var body NativeStartEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeStartEmail(ctx, request.(NativeStartEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeStartEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeStartEmailResponseObject); ok {
		if err := validResponse.VisitNativeStartEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeVerifyEmail operation middleware
func (sh *strictHandler) NativeVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var request NativeVerifyEmailRequestObject

	var body NativeVerifyEmailJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeVerifyEmail(ctx, request.(NativeVerifyEmailRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeVerifyEmail")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeVerifyEmailResponseObject); ok {
		if err := validResponse.VisitNativeVerifyEmailResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeBeginPasskeyLogin operation middleware
func (sh *strictHandler) NativeBeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var request NativeBeginPasskeyLoginRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeBeginPasskeyLogin(ctx, request.(NativeBeginPasskeyLoginRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeBeginPasskeyLogin")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeBeginPasskeyLoginResponseObject); ok {
		if err := validResponse.VisitNativeBeginPasskeyLoginResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeFinishPasskeyLogin operation middleware
func (sh *strictHandler) NativeFinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var request NativeFinishPasskeyLoginRequestObject

	var body NativeFinishPasskeyLoginJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeFinishPasskeyLogin(ctx, request.(NativeFinishPasskeyLoginRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeFinishPasskeyLogin")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeFinishPasskeyLoginResponseObject); ok {
		if err := validResponse.VisitNativeFinishPasskeyLoginResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeBeginPasskeyRegistration operation middleware
func (sh *strictHandler) NativeBeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var request NativeBeginPasskeyRegistrationRequestObject

	var body NativeBeginPasskeyRegistrationJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeBeginPasskeyRegistration(ctx, request.(NativeBeginPasskeyRegistrationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeBeginPasskeyRegistration")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeBeginPasskeyRegistrationResponseObject); ok {
		if err := validResponse.VisitNativeBeginPasskeyRegistrationResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeFinishPasskeyRegistration operation middleware
func (sh *strictHandler) NativeFinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	var request NativeFinishPasskeyRegistrationRequestObject

	var body NativeFinishPasskeyRegistrationJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeFinishPasskeyRegistration(ctx, request.(NativeFinishPasskeyRegistrationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeFinishPasskeyRegistration")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeFinishPasskeyRegistrationResponseObject); ok {
		if err := validResponse.VisitNativeFinishPasskeyRegistrationResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRedeemRecoveryCode operation middleware
func (sh *strictHandler) NativeRedeemRecoveryCode(w http.ResponseWriter, r *http.Request) {
	var request NativeRedeemRecoveryCodeRequestObject

	var body NativeRedeemRecoveryCodeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRedeemRecoveryCode(ctx, request.(NativeRedeemRecoveryCodeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRedeemRecoveryCode")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRedeemRecoveryCodeResponseObject); ok {
		if err := validResponse.VisitNativeRedeemRecoveryCodeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeGetDeviceRequest operation middleware
func (sh *strictHandler) NativeGetDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string) {
	var request NativeGetDeviceRequestRequestObject

	request.RequestId = requestId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeGetDeviceRequest(ctx, request.(NativeGetDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeGetDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeGetDeviceRequestResponseObject); ok {
		if err := validResponse.VisitNativeGetDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeApproveDeviceRequest operation middleware
func (sh *strictHandler) NativeApproveDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string, params NativeApproveDeviceRequestParams) {
	var request NativeApproveDeviceRequestRequestObject

	request.RequestId = requestId
	request.Params = params

	var body NativeApproveDeviceRequestJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeApproveDeviceRequest(ctx, request.(NativeApproveDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeApproveDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeApproveDeviceRequestResponseObject); ok {
		if err := validResponse.VisitNativeApproveDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeDenyDeviceRequest operation middleware
func (sh *strictHandler) NativeDenyDeviceRequest(w http.ResponseWriter, r *http.Request, requestId string) {
	var request NativeDenyDeviceRequestRequestObject

	request.RequestId = requestId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeDenyDeviceRequest(ctx, request.(NativeDenyDeviceRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeDenyDeviceRequest")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeDenyDeviceRequestResponseObject); ok {
		if err := validResponse.VisitNativeDenyDeviceRequestResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeDeleteAccount operation middleware
func (sh *strictHandler) NativeDeleteAccount(w http.ResponseWriter, r *http.Request, params NativeDeleteAccountParams) {
	var request NativeDeleteAccountRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeDeleteAccount(ctx, request.(NativeDeleteAccountRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeDeleteAccount")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeDeleteAccountResponseObject); ok {
		if err := validResponse.VisitNativeDeleteAccountResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeGetMe operation middleware
func (sh *strictHandler) NativeGetMe(w http.ResponseWriter, r *http.Request) {
	var request NativeGetMeRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeGetMe(ctx, request.(NativeGetMeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeGetMe")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeGetMeResponseObject); ok {
		if err := validResponse.VisitNativeGetMeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeListApps operation middleware
func (sh *strictHandler) NativeListApps(w http.ResponseWriter, r *http.Request) {
	var request NativeListAppsRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeListApps(ctx, request.(NativeListAppsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeListApps")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeListAppsResponseObject); ok {
		if err := validResponse.VisitNativeListAppsResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRevokeApp operation middleware
func (sh *strictHandler) NativeRevokeApp(w http.ResponseWriter, r *http.Request, clientId string) {
	var request NativeRevokeAppRequestObject

	request.ClientId = clientId

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRevokeApp(ctx, request.(NativeRevokeAppRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRevokeApp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRevokeAppResponseObject); ok {
		if err := validResponse.VisitNativeRevokeAppResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRevokeAppGrant operation middleware
func (sh *strictHandler) NativeRevokeAppGrant(w http.ResponseWriter, r *http.Request, id string) {
	var request NativeRevokeAppGrantRequestObject

	request.Id = id

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRevokeAppGrant(ctx, request.(NativeRevokeAppGrantRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRevokeAppGrant")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRevokeAppGrantResponseObject); ok {
		if err := validResponse.VisitNativeRevokeAppGrantResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeStartEmailChange operation middleware
func (sh *strictHandler) NativeStartEmailChange(w http.ResponseWriter, r *http.Request, params NativeStartEmailChangeParams) {
	var request NativeStartEmailChangeRequestObject

	request.Params = params

	var body NativeStartEmailChangeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeStartEmailChange(ctx, request.(NativeStartEmailChangeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeStartEmailChange")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeStartEmailChangeResponseObject); ok {
		if err := validResponse.VisitNativeStartEmailChangeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeConfirmEmailChange operation middleware
func (sh *strictHandler) NativeConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var request NativeConfirmEmailChangeRequestObject

	var body NativeConfirmEmailChangeJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeConfirmEmailChange(ctx, request.(NativeConfirmEmailChangeRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeConfirmEmailChange")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeConfirmEmailChangeResponseObject); ok {
		if err := validResponse.VisitNativeConfirmEmailChangeResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeListPasskeys operation middleware
func (sh *strictHandler) NativeListPasskeys(w http.ResponseWriter, r *http.Request) {
	var request NativeListPasskeysRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeListPasskeys(ctx, request.(NativeListPasskeysRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeListPasskeys")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeListPasskeysResponseObject); ok {
		if err := validResponse.VisitNativeListPasskeysResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeFinishAddPasskey operation middleware
func (sh *strictHandler) NativeFinishAddPasskey(w http.ResponseWriter, r *http.Request, params NativeFinishAddPasskeyParams) {
	var request NativeFinishAddPasskeyRequestObject

	request.Params = params

	var body NativeFinishAddPasskeyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeFinishAddPasskey(ctx, request.(NativeFinishAddPasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeFinishAddPasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeFinishAddPasskeyResponseObject); ok {
		if err := validResponse.VisitNativeFinishAddPasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeBeginAddPasskey operation middleware
func (sh *strictHandler) NativeBeginAddPasskey(w http.ResponseWriter, r *http.Request, params NativeBeginAddPasskeyParams) {
	var request NativeBeginAddPasskeyRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeBeginAddPasskey(ctx, request.(NativeBeginAddPasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeBeginAddPasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeBeginAddPasskeyResponseObject); ok {
		if err := validResponse.VisitNativeBeginAddPasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeDeletePasskey operation middleware
func (sh *strictHandler) NativeDeletePasskey(w http.ResponseWriter, r *http.Request, id string, params NativeDeletePasskeyParams) {
	var request NativeDeletePasskeyRequestObject

	request.Id = id
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeDeletePasskey(ctx, request.(NativeDeletePasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeDeletePasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeDeletePasskeyResponseObject); ok {
		if err := validResponse.VisitNativeDeletePasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRenamePasskey operation middleware
func (sh *strictHandler) NativeRenamePasskey(w http.ResponseWriter, r *http.Request, id string) {
	var request NativeRenamePasskeyRequestObject

	request.Id = id

	var body NativeRenamePasskeyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRenamePasskey(ctx, request.(NativeRenamePasskeyRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRenamePasskey")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRenamePasskeyResponseObject); ok {
		if err := validResponse.VisitNativeRenamePasskeyResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRegenerateRecoveryCodes operation middleware
func (sh *strictHandler) NativeRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request, params NativeRegenerateRecoveryCodesParams) {
	var request NativeRegenerateRecoveryCodesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRegenerateRecoveryCodes(ctx, request.(NativeRegenerateRecoveryCodesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRegenerateRecoveryCodes")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRegenerateRecoveryCodesResponseObject); ok {
		if err := validResponse.VisitNativeRegenerateRecoveryCodesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeBeginStepUp operation middleware
func (sh *strictHandler) NativeBeginStepUp(w http.ResponseWriter, r *http.Request) {
	var request NativeBeginStepUpRequestObject

	var body NativeBeginStepUpJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeBeginStepUp(ctx, request.(NativeBeginStepUpRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeBeginStepUp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeBeginStepUpResponseObject); ok {
		if err := validResponse.VisitNativeBeginStepUpResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeFinishStepUp operation middleware
func (sh *strictHandler) NativeFinishStepUp(w http.ResponseWriter, r *http.Request) {
	var request NativeFinishStepUpRequestObject

	var body NativeFinishStepUpJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeFinishStepUp(ctx, request.(NativeFinishStepUpRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeFinishStepUp")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeFinishStepUpResponseObject); ok {
		if err := validResponse.VisitNativeFinishStepUpResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeListSessions operation middleware
func (sh *strictHandler) NativeListSessions(w http.ResponseWriter, r *http.Request) {
	var request NativeListSessionsRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeListSessions(ctx, request.(NativeListSessionsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeListSessions")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeListSessionsResponseObject); ok {
		if err := validResponse.VisitNativeListSessionsResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRevokeSession operation middleware
func (sh *strictHandler) NativeRevokeSession(w http.ResponseWriter, r *http.Request, id string) {
	var request NativeRevokeSessionRequestObject

	request.Id = id

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRevokeSession(ctx, request.(NativeRevokeSessionRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRevokeSession")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRevokeSessionResponseObject); ok {
		if err := validResponse.VisitNativeRevokeSessionResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeSignOut operation middleware
func (sh *strictHandler) NativeSignOut(w http.ResponseWriter, r *http.Request) {
	var request NativeSignOutRequestObject

	var body NativeSignOutJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		if !errors.Is(err, io.EOF) {
			sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
			return
		}
	} else {
		request.Body = &body
	}

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeSignOut(ctx, request.(NativeSignOutRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeSignOut")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeSignOutResponseObject); ok {
		if err := validResponse.VisitNativeSignOutResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// NativeRefreshToken operation middleware
func (sh *strictHandler) NativeRefreshToken(w http.ResponseWriter, r *http.Request) {
	var request NativeRefreshTokenRequestObject

	var body NativeRefreshTokenJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
		return
	}
	request.Body = &body

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.NativeRefreshToken(ctx, request.(NativeRefreshTokenRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "NativeRefreshToken")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(NativeRefreshTokenResponseObject); ok {
		if err := validResponse.VisitNativeRefreshTokenResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserListSessions operation middleware
func (sh *strictHandler) BrowserListSessions(w http.ResponseWriter, r *http.Request) {
	var request BrowserListSessionsRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserListSessions(ctx, request.(BrowserListSessionsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserListSessions")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserListSessionsResponseObject); ok {
		if err := validResponse.VisitBrowserListSessionsResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRevokeSession operation middleware
func (sh *strictHandler) BrowserRevokeSession(w http.ResponseWriter, r *http.Request, id string) {
	var request BrowserRevokeSessionRequestObject

	request.Id = id

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRevokeSession(ctx, request.(BrowserRevokeSessionRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRevokeSession")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRevokeSessionResponseObject); ok {
		if err := validResponse.VisitBrowserRevokeSessionResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserSignOut operation middleware
func (sh *strictHandler) BrowserSignOut(w http.ResponseWriter, r *http.Request) {
	var request BrowserSignOutRequestObject

	var body BrowserSignOutJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		if !errors.Is(err, io.EOF) {
			sh.options.RequestErrorHandlerFunc(w, r, fmt.Errorf("can't decode JSON body: %w", err))
			return
		}
	} else {
		request.Body = &body
	}

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserSignOut(ctx, request.(BrowserSignOutRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserSignOut")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserSignOutResponseObject); ok {
		if err := validResponse.VisitBrowserSignOutResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// BrowserRefreshToken operation middleware
func (sh *strictHandler) BrowserRefreshToken(w http.ResponseWriter, r *http.Request) {
	var request BrowserRefreshTokenRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.BrowserRefreshToken(ctx, request.(BrowserRefreshTokenRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "BrowserRefreshToken")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(BrowserRefreshTokenResponseObject); ok {
		if err := validResponse.VisitBrowserRefreshTokenResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}
