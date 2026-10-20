package emailauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

var (
	t0      = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	policy  = authflow.DefaultPolicy()
	errBoom = errors.New("boom")
)

// countingReader yields distinct, reproducible bytes: enough randomness for tests
// that must not depend on the system source.
type countingReader struct{ n byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}

	return len(p), nil
}

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

type env struct {
	t        *testing.T
	store    *memory.Store
	clock    *testutil.FakeClock
	ids      *testutil.SequentialIDs
	otp      *crypto.OTP
	bindings crypto.Binding
	faults   *faults
	start    *emailauth.Start
	resend   *emailauth.Resend
	verify   *emailauth.VerifyCode
	sessions *appsession.Issuer
	signer   port.AccessSigner
	access   port.AccessVerifier
}

type envOption func(*envConfig)

type envConfig struct {
	store []memory.Option
}

func withLimits(send, verify int) envOption {
	return func(c *envConfig) { c.store = append(c.store, memory.WithLimits(send, verify)) }
}

func withQuota(p quota.Profile) envOption {
	return func(c *envConfig) { c.store = append(c.store, memory.WithQuota(p)) }
}

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()

	var cfg envConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	otp, err := crypto.NewOTP(ring, &countingReader{})
	if err != nil {
		t.Fatal(err)
	}

	e := &env{
		t: t, store: memory.NewStore(cfg.store...), clock: testutil.NewFakeClock(t0),
		ids: &testutil.SequentialIDs{}, otp: otp,
	}
	e.faults = &faults{inner: e.store}

	keys := testutil.NewSigningKeyPEM(t)

	ringKeys, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	if err != nil {
		t.Fatal(err)
	}

	e.signer, err = jwt.NewSigner(ringKeys, e.clock, "https://auth.example.test", "example", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	e.access, err = jwt.NewVerifier(ringKeys.PublicKeys(), e.clock, "https://auth.example.test", "example", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	e.sessions, err = appsession.NewIssuer(appsession.IssuerDeps{
		SessionIDs: e.ids, TokenIDs: e.ids, Secrets: crypto.Refresh{}, Policy: session.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}

	e.start, e.resend, e.verify = e.build(otp)

	return e
}

func (e *env) build(otp interface {
	port.OTPGenerations
	port.OTPCodes
}) (*emailauth.Start, *emailauth.Resend, *emailauth.VerifyCode) {
	e.t.Helper()

	start, err := emailauth.NewStart(emailauth.StartDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: e.ids, OTP: otp, Bindings: e.bindings, Policy: policy,
	})
	if err != nil {
		e.t.Fatal(err)
	}

	resend, err := emailauth.NewResend(emailauth.ResendDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: otp, Bindings: e.bindings, Policy: policy,
	})
	if err != nil {
		e.t.Fatal(err)
	}

	verify, err := emailauth.NewVerifyCode(e.verifyDeps(otp))
	if err != nil {
		e.t.Fatal(err)
	}

	return start, resend, verify
}

// begin starts a flow for a new client and returns its ID and binding secret.
func (e *env) begin(email string) (flowID, binding string) {
	e.t.Helper()

	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: email})
	if err != nil || res.Outcome != emailauth.OutcomeOK {
		e.t.Fatalf("start %q = %+v, %v", email, res, err)
	}

	return res.FlowID.String(), res.NewBindingSecret
}

func (e *env) flow(flowID string) *authflow.Flow {
	e.t.Helper()

	id, err := authflow.ParseFlowID(flowID)
	if err != nil {
		e.t.Fatal(err)
	}

	f, ok := e.store.Flow(id)
	if !ok {
		e.t.Fatalf("flow %s is not stored", flowID)
	}

	return f
}

// code is what the mail worker would put in the email for the current generation.
func (e *env) code(flowID string) string {
	e.t.Helper()

	code, err := e.otp.Code(e.flow(flowID))
	if err != nil {
		e.t.Fatalf("derive code: %v", err)
	}

	return code
}

// otherCode returns an eight-digit code different from code.
func otherCode(code string) string {
	if code == "00000000" {
		return "00000001"
	}

	return "00000000"
}

func (e *env) check(flowID, code, binding string) emailauth.VerifyCodeResult {
	e.t.Helper()

	res, err := e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
	if err != nil {
		e.t.Fatalf("verify: %v", err)
	}

	return res
}

func (e *env) email(raw string) identity.Email {
	e.t.Helper()

	email, err := identity.ParseEmail(raw)
	if err != nil {
		e.t.Fatal(err)
	}

	return email
}

// failing stores: each embeds the real store and overrides one operation.

type failingOutbox struct{ port.Outbox }

func (failingOutbox) Enqueue(context.Context, port.MailJob) error {
	return errBoom
}

type failingUsers struct{ port.UserRepository }

func (failingUsers) Ensure(context.Context, *identity.User) (*identity.User, bool, error) {
	return nil, false, errBoom
}

type failingCreate struct{ port.FlowRepository }

func (failingCreate) Create(context.Context, *authflow.Flow) error {
	return errBoom
}

// failingSaveAfter lets the first n Save calls through and then fails.
type failingSaveAfter struct {
	port.FlowRepository
	remaining *int
}

func (f failingSaveAfter) Save(ctx context.Context, fl *authflow.Flow) error {
	if *f.remaining <= 0 {
		return errBoom
	}

	*f.remaining--

	return f.FlowRepository.Save(ctx, fl)
}

type failingFlowIDs struct{}

func (failingFlowIDs) NewFlowID() (authflow.FlowID, error) {
	return authflow.FlowID{}, errBoom
}

type failingGenerations struct{}

func (failingGenerations) NewGeneration() (port.OTPGeneration, error) {
	return port.OTPGeneration{}, errBoom
}

type failingBindings struct{ crypto.Binding }

func (failingBindings) NewBinding() (string, identity.BindingHash, error) {
	return "", identity.BindingHash{}, errBoom
}

// matchesHook runs before the real comparison, to interleave another request
// between the two verify phases.
type matchesHook struct {
	port.OTPCodes
	before func()
}

func (h matchesHook) Matches(f *authflow.Flow, submitted string) (bool, error) {
	h.before()
	return h.OTPCodes.Matches(f, submitted)
}

func (e *env) verifyDeps(otp port.OTPCodes) emailauth.VerifyCodeDeps {
	return emailauth.VerifyCodeDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: otp, Bindings: e.bindings, UserIDs: e.ids,
		RecognizedIDs: e.ids, PasskeyIDs: e.ids, Tickets: crypto.Ticket{}, Policy: policy,
	}
}
