package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/adapter/metrics"
	apasskey "go.airlance.org/auth/internal/adapter/passkey"
	"go.airlance.org/auth/internal/application/account"
	"go.airlance.org/auth/internal/application/deviceauth"
	"go.airlance.org/auth/internal/application/emailauth"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

const (
	issuer   = "https://auth.example.test"
	audience = "example"
	// rpID and rpOrigin are the relying party of the tests' passkeys.
	rpID     = "example.test"
	rpOrigin = "https://example.test"
)

var (
	t0      = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
)

// faults wraps the Stores a use case sees, so a test can make one operation fail.
type faults struct {
	inner port.UnitOfWork
	wrap  func(port.Stores) port.Stores
}

func (f *faults) Do(ctx context.Context, fn func(ctx context.Context, s port.Stores) error) error {
	return f.inner.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if f.wrap != nil {
			s = f.wrap(s)
		}

		return fn(ctx, s)
	})
}

type failingOutbox struct{ port.Outbox }

func (failingOutbox) Enqueue(context.Context, port.MailJob) error {
	return errBoom
}

// env is the real handler over the real use cases, crypto and JWT adapters, with the
// in-memory store and a fake clock.
type env struct {
	t        *testing.T
	store    *memory.Store
	faults   *faults
	clock    *testutil.FakeClock
	otp      *crypto.OTP
	ring     *jwt.Ring
	verifier *jwt.Verifier
	metrics  *metrics.Registry
	ready    error
	logs     *bytes.Buffer
	handler  http.Handler
	// auths are the authenticators of the users that registered a passkey, by email.
	auths map[string]*testutil.SoftAuthenticator
}

func newEnv(t *testing.T, opts ...memory.Option) *env {
	t.Helper()
	return newEnvBehind(t, nil, opts...)
}

// newEnvBehind is newEnv with reverse proxies whose forwarding headers are believed.
func newEnvBehind(t *testing.T, proxies []netip.Prefix, opts ...memory.Option) *env {
	t.Helper()
	return newEnvWith(t, func(d *httpapi.Deps) { d.TrustedProxies = proxies }, opts...)
}

// newEnvWith lets a test change the API's dependencies before the handler is built.
func newEnvWith(t *testing.T, configure func(*httpapi.Deps), opts ...memory.Option) *env {
	t.Helper()

	e, err := buildEnv(t, configure, opts...)
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// buildEnv returns the error of assembling the handler instead of failing the test.
func buildEnv(t *testing.T, configure func(*httpapi.Deps), opts ...memory.Option) (*env, error) {
	t.Helper()
	return buildEnvMode(t, identity.RegistrationOpen, configure, opts...)
}

// buildEnvMode is buildEnv with the registration mode of the sign-in use cases.
func buildEnvMode(t *testing.T, mode identity.RegistrationMode, configure func(*httpapi.Deps), opts ...memory.Option) (*env, error) {
	t.Helper()
	e := &env{t: t, store: memory.NewStore(opts...), clock: testutil.NewFakeClock(t0), metrics: metrics.New(), logs: &bytes.Buffer{}, auths: map[string]*testutil.SoftAuthenticator{}}
	e.faults = &faults{inner: e.store}

	otpRing, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	if e.otp, err = crypto.NewOTP(otpRing, nil); err != nil {
		t.Fatal(err)
	}

	keys := testutil.NewSigningKeyPEM(t)
	if e.ring, err = jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)}); err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner(e.ring, e.clock, issuer, audience, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if e.verifier, err = jwt.NewVerifier(e.ring.PublicKeys(), e.clock, issuer, audience, 30*time.Second); err != nil {
		t.Fatal(err)
	}

	flowPolicy, sessionPolicy := authflow.DefaultPolicy(), session.DefaultPolicy()

	start, err := emailauth.NewStart(emailauth.StartDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: crypto.Random{}, OTP: e.otp, Bindings: crypto.Binding{}, Policy: flowPolicy, Registration: mode,
	})
	if err != nil {
		t.Fatal(err)
	}

	resend, err := emailauth.NewResend(emailauth.ResendDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Bindings: crypto.Binding{}, Policy: flowPolicy, Registration: mode,
	})
	if err != nil {
		t.Fatal(err)
	}

	issuerUC, err := appsession.NewIssuer(appsession.IssuerDeps{SessionIDs: id.Generator{}, TokenIDs: id.Generator{}, Secrets: crypto.Refresh{}, Policy: sessionPolicy})
	if err != nil {
		t.Fatal(err)
	}

	verify, err := emailauth.NewVerifyCode(emailauth.VerifyCodeDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Bindings: crypto.Binding{}, UserIDs: id.Generator{},
		RecognizedIDs: id.Generator{}, PasskeyIDs: id.Generator{}, Tickets: crypto.Ticket{}, Policy: flowPolicy, Registration: mode,
	})
	if err != nil {
		t.Fatal(err)
	}

	web, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{rpOrigin}})
	if err != nil {
		t.Fatal(err)
	}

	signedIn := passkey.SessionDeps{Sessions: issuerUC, Signer: signer}

	beginEnroll, err := passkey.NewBeginEnroll(passkey.BeginEnrollDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		t.Fatal(err)
	}

	finishEnroll, err := passkey.NewFinishEnroll(passkey.FinishEnrollDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{},
		PasskeyIDs: id.Generator{}, Recovery: crypto.Recovery{}, SessionDeps: signedIn,
	})
	if err != nil {
		t.Fatal(err)
	}

	beginLogin, err := passkey.NewBeginLogin(passkey.BeginLoginDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, PasskeyIDs: id.Generator{}})
	if err != nil {
		t.Fatal(err)
	}

	finishLogin, err := passkey.NewFinishLogin(passkey.FinishLoginDeps{
		UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, SessionDeps: signedIn,
	})
	if err != nil {
		t.Fatal(err)
	}

	recovery, err := passkey.NewRedeemRecovery(passkey.RedeemRecoveryDeps{
		UnitOfWork: e.faults, Clock: e.clock, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, Recovery: crypto.Recovery{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		t.Fatal(err)
	}

	refresh, err := appsession.NewRefresh(appsession.RefreshDeps{
		UnitOfWork: e.faults, Clock: e.clock, TokenIDs: id.Generator{}, Secrets: crypto.Refresh{},
		Metrics: e.metrics, Signer: signer, Policy: sessionPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	auth, err := appsession.NewAuthenticator(appsession.AuthenticateDeps{UnitOfWork: e.faults, Clock: e.clock, Verifier: e.verifier})
	if err != nil {
		t.Fatal(err)
	}

	reads := appsession.ReadDeps{UnitOfWork: e.faults, Clock: e.clock}

	me, err := appsession.NewMe(reads)
	if err != nil {
		t.Fatal(err)
	}

	list, err := appsession.NewListSessions(reads)
	if err != nil {
		t.Fatal(err)
	}

	revokes := appsession.RevokeDeps{UnitOfWork: e.faults, Clock: e.clock}

	signOut, err := appsession.NewSignOut(revokes)
	if err != nil {
		t.Fatal(err)
	}

	revokeOne, err := appsession.NewRevokeSession(revokes)
	if err != nil {
		t.Fatal(err)
	}

	manage := passkey.ManageDeps{UnitOfWork: e.faults, Clock: e.clock}

	listKeys, err := passkey.NewListCredentials(manage)
	if err != nil {
		t.Fatal(err)
	}

	renameKey, err := passkey.NewRenameCredential(manage)
	if err != nil {
		t.Fatal(err)
	}

	beginStepUp, err := passkey.NewBeginStepUp(passkey.BeginStepUpDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, PasskeyIDs: id.Generator{}})
	if err != nil {
		t.Fatal(err)
	}

	finishStepUp, err := passkey.NewFinishStepUp(passkey.FinishStepUpDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		t.Fatal(err)
	}

	beginAddKey, err := passkey.NewBeginAddPasskey(passkey.BeginAddPasskeyDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		t.Fatal(err)
	}

	finishAddKey, err := passkey.NewFinishAddPasskey(passkey.FinishAddPasskeyDeps{UnitOfWork: e.faults, Clock: e.clock, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		t.Fatal(err)
	}

	deleteKey, err := passkey.NewDeleteCredential(passkey.DeleteCredentialDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}})
	if err != nil {
		t.Fatal(err)
	}

	newCodes, err := passkey.NewRegenerateRecoveryCodes(passkey.RegenerateRecoveryCodesDeps{
		UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}, Recovery: crypto.Recovery{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		t.Fatal(err)
	}

	startChange, err := account.NewStartEmailChange(account.StartEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: crypto.Random{}, OTP: e.otp, Tickets: crypto.Ticket{}, Policy: flowPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	confirmChange, err := account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Policy: flowPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	deleteAccount, err := account.NewDeleteAccount(account.DeleteAccountDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}})
	if err != nil {
		t.Fatal(err)
	}

	startDevice, err := deviceauth.NewStart(deviceauth.StartDeps{
		UnitOfWork: e.faults, Clock: e.clock, Secrets: crypto.Device{}, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{},
	})
	if err != nil {
		t.Fatal(err)
	}

	statusDevice, err := deviceauth.NewStatus(deviceauth.StatusDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{}})
	if err != nil {
		t.Fatal(err)
	}

	deviceApprover, err := deviceauth.NewApprover(deviceauth.ApproveDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}})
	if err != nil {
		t.Fatal(err)
	}

	redeemDevice, err := deviceauth.NewRedeem(deviceauth.RedeemDeps{
		UnitOfWork: e.faults, Clock: e.clock, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{}, SessionDeps: signedIn,
	})
	if err != nil {
		t.Fatal(err)
	}

	apps, err := appoidc.NewApps(appoidc.Apps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}

	deps := httpapi.Deps{
		Start: start, Resend: resend, Verify: verify, Refresh: refresh, JWKS: e.ring,
		BeginEnroll: beginEnroll, FinishEnroll: finishEnroll, BeginLogin: beginLogin, FinishLogin: finishLogin, Recovery: recovery,
		BeginStepUp: beginStepUp, FinishStepUp: finishStepUp, ListKeys: listKeys, RenameKey: renameKey,
		BeginAddKey: beginAddKey, FinishAddKey: finishAddKey, DeleteKey: deleteKey, NewCodes: newCodes,
		StartDevice: startDevice, StatusDevice: statusDevice, DeviceApprover: deviceApprover, RedeemDevice: redeemDevice,
		DeleteAccount: deleteAccount, StartEmailChange: startChange, ConfirmEmailChange: confirmChange,
		Auth: auth, Me: me, List: list, SignOut: signOut, RevokeOne: revokeOne, Apps: apps,
		Ready:   func(context.Context) error { return e.ready },
		Metrics: e.metrics.Handler(),
		Logger:  slog.New(httpapi.RequestIDHandler(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}
	if configure != nil {
		configure(&deps)
	}

	e.handler, err = httpapi.New(deps)

	return e, err
}

func (e *env) do(req *http.Request) *httptest.ResponseRecorder {
	e.t.Helper()

	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	return rec
}

func (e *env) get(path string) *httptest.ResponseRecorder {
	return e.do(httptest.NewRequest(http.MethodGet, path, nil))
}

// postRaw sends body as is, so that malformed JSON can be tested.
func (e *env) postRaw(path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return e.do(req)
}

func (e *env) post(path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}

	return e.postRaw(path, string(data))
}

type startResponse struct {
	FlowID        string    `json:"flow_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	ResendAfter   time.Time `json:"resend_after"`
	ClientBinding string    `json:"client_binding"`
}

type tokenResponse struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
}

type problem struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

const (
	startPath   = "/v1/native/auth/email/start"
	verifyPath  = "/v1/native/auth/email/verify"
	refreshPath = "/v1/native/token/refresh"
)

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder, status int) T {
	t.Helper()

	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}

	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}

	return out
}

// wantProblem checks an error response: status, code and the request ID of the header.
func wantProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	p := decode[problem](t, rec, status)
	if p.Code != code || p.RequestID == "" || p.RequestID != rec.Header().Get(httpapi.RequestIDHeader) {
		t.Errorf("problem = %+v with header %q, want %s and the request id", p, rec.Header().Get(httpapi.RequestIDHeader), code)
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}

func (e *env) start(email, binding string) startResponse {
	e.t.Helper()

	body := map[string]string{"email": email}
	if binding != "" {
		body["client_binding"] = binding
	}

	return decode[startResponse](e.t, e.post(startPath, body), http.StatusAccepted)
}

// code derives the code the email of the flow carries.
func (e *env) code(flowID string) string {
	e.t.Helper()

	id, err := authflow.ParseFlowID(flowID)
	if err != nil {
		e.t.Fatal(err)
	}

	flow, ok := e.store.Flow(id)
	if !ok {
		e.t.Fatalf("flow %s is not stored", flowID)
	}

	code, err := e.otp.Code(flow)
	if err != nil {
		e.t.Fatal(err)
	}

	return code
}

func (e *env) verify(flowID, code, binding string) *httptest.ResponseRecorder {
	return e.post(verifyPath, map[string]string{"flow_id": flowID, "code": code, "client_binding": binding})
}

func (e *env) refresh(token string) *httptest.ResponseRecorder {
	return e.post(refreshPath, map[string]string{"refresh_token": token})
}

type nextStepResponse struct {
	Next      string    `json:"next"`
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ceremonyResponse struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

type registerResponse struct {
	tokenResponse
	RecoveryCodes []string `json:"recovery_codes"`
}

const (
	nativeRegisterOptions = "/v1/native/auth/passkey/register/options"
	nativeRegisterVerify  = "/v1/native/auth/passkey/register/verify"
	nativeLoginOptions    = "/v1/native/auth/passkey/login/options"
	nativeLoginVerify     = "/v1/native/auth/passkey/login/verify"
	nativeRecoveryVerify  = "/v1/native/auth/recovery/verify"
)

// verifyStep runs verify for the flow and returns the next step the client is told about.
func (e *env) verifyStep(flowID, binding string) nextStepResponse {
	e.t.Helper()
	return decode[nextStepResponse](e.t, e.verify(flowID, e.code(flowID), binding), http.StatusOK)
}

// register runs the native registration of a passkey with the ticket and returns the response.
func (e *env) register(auth *testutil.SoftAuthenticator, ticket, binding string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.registerWith(auth, ticket, binding, nil)
}

// registerWith is register with more body fields, such as device_name.
func (e *env) registerWith(auth *testutil.SoftAuthenticator, ticket, binding string, extra map[string]any) *httptest.ResponseRecorder {
	e.t.Helper()
	begun := decode[ceremonyResponse](e.t, e.post(nativeRegisterOptions, map[string]string{"ticket": ticket, "client_binding": binding}), http.StatusOK)

	body := map[string]any{
		"ticket": ticket, "client_binding": binding, "challenge_id": begun.ChallengeID,
		"credential": json.RawMessage(auth.Register(begun.Options)),
	}
	for k, v := range extra {
		body[k] = v
	}

	return e.post(nativeRegisterVerify, body)
}

// assert runs the native passkey login; ticket and binding may be empty.
func (e *env) assert(auth *testutil.SoftAuthenticator, ticket, binding string) *httptest.ResponseRecorder {
	e.t.Helper()
	begun := decode[ceremonyResponse](e.t, e.post(nativeLoginOptions, nil), http.StatusOK)

	body := map[string]any{"challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Assert(begun.Options))}
	if ticket != "" {
		body["ticket"] = ticket
	}

	if binding != "" {
		body["client_binding"] = binding
	}

	return e.post(nativeLoginVerify, body)
}

// signIn runs the whole native sign-in of a new client: the email code, then a passkey. A user
// seen before proves the passkey they registered; a new one registers one.
func (e *env) signIn(email string) (tokenResponse, string) {
	e.t.Helper()
	started := e.start(email, "")

	step := e.verifyStep(started.FlowID, started.ClientBinding)
	if auth, ok := e.auths[email]; ok {
		if step.Next != "second_factor" {
			e.t.Fatalf("a user with a passkey was told %q", step.Next)
		}

		return decode[tokenResponse](e.t, e.assert(auth, step.Ticket, started.ClientBinding), http.StatusOK), started.ClientBinding
	}

	if step.Next != "enroll_passkey" {
		e.t.Fatalf("a new user was told %q", step.Next)
	}

	auth := testutil.NewSoftAuthenticator(e.t, rpID, rpOrigin)
	e.auths[email] = auth

	return decode[registerResponse](e.t, e.register(auth, step.Ticket, started.ClientBinding), http.StatusOK).tokenResponse, started.ClientBinding
}
