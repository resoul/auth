package emailauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

type failingTickets struct{ port.TicketRepository }

func (failingTickets) Create(context.Context, *passkey.Ticket) error {
	return errBoom
}

type failingCredentials struct{ port.CredentialRepository }

func (failingCredentials) ListByUser(context.Context, identity.UserID) ([]*passkey.Credential, error) {
	return nil, errBoom
}

type failingRecognized struct {
	port.RecognizedClientRepository
}

func (failingRecognized) Register(context.Context, *identity.RecognizedClient) (*identity.RecognizedClient, error) {
	return nil, errBoom
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, port.AuditEvent) error {
	return errBoom
}

// activeRecognized looks the recognized client up like Start does.
func (e *env) activeRecognized(email, bindingSecret string) (*identity.RecognizedClient, error) {
	e.t.Helper()

	hash, err := e.bindings.HashBinding(bindingSecret)
	if err != nil {
		e.t.Fatal(err)
	}

	var rc *identity.RecognizedClient

	err = e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error

		rc, err = st.Recognized.FindActive(ctx, e.email(email), hash, e.clock.Now())

		return err
	})

	return rc, err
}

// ticketOf loads the ticket a verify handed out, by the secret the client received.
func (e *env) ticketOf(secret string) *passkey.Ticket {
	e.t.Helper()

	hash, err := (crypto.Ticket{}).HashTicketSecret(secret)
	if err != nil {
		e.t.Fatalf("ticket secret: %v", err)
	}

	var tk *passkey.Ticket

	err = e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error

		tk, err = st.Tickets.GetByHashForUpdate(ctx, hash)

		return err
	})
	if err != nil {
		e.t.Fatalf("ticket is not stored: %v", err)
	}

	return tk
}

// withPasskey gives the user a registered passkey.
func (e *env) withPasskey(email string) *identity.User {
	e.t.Helper()
	factory := testutil.NewFactory(e.t, e.clock.Now())
	factory.IDs = e.ids
	user := factory.User(testutil.UserSpec{Email: email})

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		return st.Credentials.Create(ctx, factory.Credential(testutil.CredentialSpec{User: user}))
	})
	if err != nil {
		e.t.Fatal(err)
	}

	return user
}

func TestSuccessfulVerifyIssuesATicketAndNoSession(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	e.clock.Advance(time.Minute)

	res := e.check(flowID, e.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK || !res.UserCreated || res.Next != emailauth.NextEnrollPasskey || res.TicketSecret == "" {
		t.Fatalf("result = %+v", res)
	}
	// A proven email is not a session: that needs a passkey.
	if e.store.SessionCount() != 0 || e.store.TokenCount() != 0 {
		t.Fatalf("sessions=%d tokens=%d: verify must not open a session", e.store.SessionCount(), e.store.TokenCount())
	}

	// The ticket is bound to the user and to the binding of the flow, and short-lived.
	tk := e.ticketOf(res.TicketSecret)
	if tk.Kind() != passkey.TicketEnroll || tk.UserID() != res.User.ID() || tk.Binding() != e.flow(flowID).BindingHash() {
		t.Errorf("ticket = kind %s, user %s", tk.Kind(), tk.UserID())
	}

	if want := e.clock.Now().Add(passkey.EnrollTicketTTL); !tk.ExpiresAt().Equal(want) || !res.TicketExpiresAt.Equal(want) {
		t.Errorf("ticket expires %v / reported %v, want %v", tk.ExpiresAt(), res.TicketExpiresAt, want)
	}

	if tk.ConsumedAt() != (time.Time{}) {
		t.Error("the ticket is born used")
	}

	// The client is recognized for this email and binding.
	rc, err := e.activeRecognized("alice@example.test", binding)
	if err != nil || rc.UserID() != res.User.ID() {
		t.Errorf("recognized client = %+v, %v", rc, err)
	}

	// One audit event with codes only, and no secret in it.
	events := e.store.AuditEvents()
	if len(events) != 1 {
		t.Fatalf("%d audit events, want 1", len(events))
	}

	ev := events[0]
	if ev.Type != port.AuditEmailVerified || ev.Result != port.AuditSuccess || ev.UserID != res.User.ID() || !ev.SessionID.IsZero() {
		t.Errorf("event = %+v", ev)
	}

	if ev.Fields["method"] != "otp" || ev.Fields["new_user"] != "true" || ev.Fields["quota_class"] != "unknown" || ev.Fields["next"] != "enroll_passkey" {
		t.Errorf("event fields = %v", ev.Fields)
	}

	for _, v := range ev.Fields {
		if strings.ContainsAny(v, "@. ") && v != "otp" || strings.Contains(v, res.TicketSecret) {
			t.Errorf("audit field value %q looks like personal data or a secret", v)
		}
	}

	if e.flow(flowID).State() != authflow.StateConsumed {
		t.Error("the flow was not consumed")
	}
}

func TestAUserWithAPasskeyGetsASecondFactorTicket(t *testing.T) {
	e := newEnv(t)
	user := e.withPasskey("alice@example.test")
	flowA, bindingA := e.begin("alice@example.test")

	first := e.check(flowA, e.code(flowA), bindingA)
	if first.Outcome != emailauth.OutcomeOK || first.UserCreated || first.User.ID() != user.ID() || first.Next != emailauth.NextSecondFactor {
		t.Fatalf("first = %+v", first)
	}

	if tk := e.ticketOf(first.TicketSecret); tk.Kind() != passkey.TicketSecondFactor || tk.UserID() != user.ID() {
		t.Errorf("ticket = kind %s user %s", tk.Kind(), tk.UserID())
	}

	flowB, bindingB := e.begin("alice@example.test") // another device: its own binding and its own ticket

	second := e.check(flowB, e.code(flowB), bindingB)
	if second.Outcome != emailauth.OutcomeOK || second.TicketSecret == first.TicketSecret {
		t.Fatalf("second = %+v", second)
	}

	if e.store.TicketCount() != 2 || e.store.SessionCount() != 0 {
		t.Errorf("tickets=%d sessions=%d", e.store.TicketCount(), e.store.SessionCount())
	}

	if got := e.store.AuditEvents()[1].Fields["new_user"]; got != "false" {
		t.Errorf("second event new_user = %q", got)
	}

	if got := e.store.AuditEvents()[1].Fields["next"]; got != "second_factor" {
		t.Errorf("second event next = %q", got)
	}
}

func TestFailedProofIssuesNoTicketAndNoSuccessEvent(t *testing.T) {
	e := newEnv(t)

	flowID, binding := e.begin("alice@example.test")
	for i := 0; i < policy.MaxAttempts; i++ {
		e.check(flowID, otherCode("12345678"), binding)
	}

	if e.store.TicketCount() != 0 || e.store.UserCount() != 0 || len(e.store.AuditEvents()) != 0 {
		t.Errorf("tickets=%d users=%d events=%d after only failed proofs",
			e.store.TicketCount(), e.store.UserCount(), len(e.store.AuditEvents()))
	}

	if _, err := e.activeRecognized("alice@example.test", binding); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("a client that never proved anything is recognized: %v", err)
	}
}

func TestAnyFailureInTheResultTransactionRollsBackTheWholeVerify(t *testing.T) {
	stages := map[string]func(port.Stores) port.Stores{
		"ticket insert":     func(s port.Stores) port.Stores { s.Tickets = failingTickets{s.Tickets}; return s },
		"credential list":   func(s port.Stores) port.Stores { s.Credentials = failingCredentials{s.Credentials}; return s },
		"recognized client": func(s port.Stores) port.Stores { s.Recognized = failingRecognized{s.Recognized}; return s },
		"audit event":       func(s port.Stores) port.Stores { s.Audit = failingAudit{}; return s },
		"user":              func(s port.Stores) port.Stores { s.Users = failingUsers{s.Users}; return s },
	}
	for name, wrap := range stages {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			flowID, binding := e.begin("alice@example.test")
			code := e.code(flowID)
			e.faults.wrap = wrap

			_, err := e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
			if !errors.Is(err, errBoom) {
				t.Fatalf("error = %v, want boom", err)
			}

			assertLoginRolledBack(t, e, flowID, binding)

			// The retry reserves a new attempt and then succeeds.
			e.faults.wrap = nil
			if res := e.check(flowID, code, binding); res.Outcome != emailauth.OutcomeOK {
				t.Fatalf("retry = %+v", res)
			}
		})
	}
}

func assertLoginRolledBack(t *testing.T, e *env, flowID, binding string) {
	t.Helper()

	if e.store.UserCount() != 0 || e.store.TicketCount() != 0 || len(e.store.AuditEvents()) != 0 {
		t.Errorf("users=%d tickets=%d events=%d: a failed verify left data behind",
			e.store.UserCount(), e.store.TicketCount(), len(e.store.AuditEvents()))
	}

	if _, err := e.activeRecognized("alice@example.test", binding); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("a recognized client survived the rollback: %v", err)
	}

	flow := e.flow(flowID)
	if flow.State() != authflow.StatePending || flow.Attempts() != 1 {
		t.Errorf("flow state=%s attempts=%d: the flow stays pending and the reserved attempt stays spent", flow.State(), flow.Attempts())
	}
}

func TestStartChoosesTheQuotaClassFromTheRecognizedClient(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	login := e.check(flowID, e.code(flowID), binding)

	rc, err := e.activeRecognized("alice@example.test", binding)
	if err != nil {
		t.Fatal(err)
	}

	start := func(email, secret string) *authflow.Flow {
		t.Helper()

		res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: email, BindingSecret: secret})
		if err != nil || res.Outcome != emailauth.OutcomeOK {
			t.Fatalf("start = %+v, %v", res, err)
		}

		return e.flow(res.FlowID.String())
	}

	if f := start("alice@example.test", binding); f.QuotaClass() != authflow.QuotaRecognized || f.RecognizedClientID() != rc.ID() {
		t.Errorf("recognized client: class=%s client=%s, want recognized/%s", f.QuotaClass(), f.RecognizedClientID(), rc.ID())
	}

	if f := start("alice@example.test", ""); f.QuotaClass() != authflow.QuotaUnknown || !f.RecognizedClientID().IsZero() {
		t.Error("a client without a binding must be unknown")
	}

	otherBinding, _, err := e.bindings.NewBinding()
	if err != nil {
		t.Fatal(err)
	}

	if f := start("alice@example.test", otherBinding); f.QuotaClass() != authflow.QuotaUnknown {
		t.Error("an unknown binding must be unknown")
	}
	// The recognition is for one email: the same binding asking for another address earns nothing.
	if f := start("bob@example.test", binding); f.QuotaClass() != authflow.QuotaUnknown {
		t.Error("recognition leaked to another email")
	}

	_ = login
}

func TestRecognitionEndsWithRevocationOrExpiry(t *testing.T) {
	for name, end := range map[string]func(*env, *identity.RecognizedClient){
		"revoked": func(e *env, rc *identity.RecognizedClient) {
			err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
				return st.Recognized.RevokeAll(ctx, rc.UserID(), e.clock.Now())
			})
			if err != nil {
				e.t.Fatal(err)
			}
		},
		"expired": func(e *env, rc *identity.RecognizedClient) { e.clock.Set(rc.ExpiresAt()) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			flowID, binding := e.begin("alice@example.test")
			e.check(flowID, e.code(flowID), binding)

			rc, err := e.activeRecognized("alice@example.test", binding)
			if err != nil {
				t.Fatal(err)
			}

			end(e, rc)

			res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test", BindingSecret: binding})
			if err != nil || res.Outcome != emailauth.OutcomeOK {
				t.Fatalf("start = %+v, %v", res, err)
			}

			if f := e.flow(res.FlowID.String()); f.QuotaClass() != authflow.QuotaUnknown {
				t.Errorf("class = %s, want unknown after the recognition ended", f.QuotaClass())
			}
		})
	}
}

func TestVerifyRenewsTheRecognitionWithoutDuplicatingIt(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	e.check(flowID, e.code(flowID), binding)

	first, err := e.activeRecognized("alice@example.test", binding)
	if err != nil {
		t.Fatal(err)
	}

	e.clock.Advance(10 * 24 * time.Hour)

	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test", BindingSecret: binding})
	if err != nil {
		t.Fatal(err)
	}

	second := e.check(res.FlowID.String(), e.code(res.FlowID.String()), binding)
	if second.Outcome != emailauth.OutcomeOK {
		t.Fatalf("second login = %+v", second)
	}

	renewed, err := e.activeRecognized("alice@example.test", binding)
	if err != nil || renewed.ID() != first.ID() || !renewed.ExpiresAt().After(first.ExpiresAt()) {
		t.Errorf("renewed = %+v, %v; want the same record with a later expiry", renewed, err)
	}
}

// After a change of address the client signs in with the new one: its recognition moves there, and the old address,
// which may now be someone else's, earns nothing through it.
func TestRecognitionFollowsTheNewAddress(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	login := e.check(flowID, e.code(flowID), binding)

	before, err := e.activeRecognized("alice@example.test", binding)
	if err != nil {
		t.Fatal(err)
	}

	// What a confirmed change of address does to the account and its recognition.
	e.clock.Advance(time.Hour)

	err = e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		user := login.User
		if err := user.ChangeEmail(e.email("alice.new@example.test"), e.clock.Now()); err != nil {
			return err
		}

		if err := st.Users.ChangeEmail(ctx, user); err != nil {
			return err
		}

		return st.Recognized.RevokeAll(ctx, user.ID(), e.clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}

	// The same client proves the new address.
	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice.new@example.test", BindingSecret: binding})
	if err != nil || res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("start with the new address = %+v, %v", res, err)
	}

	if got := e.check(res.FlowID.String(), e.code(res.FlowID.String()), binding); got.Outcome != emailauth.OutcomeOK {
		t.Fatalf("verify the new address = %+v", got)
	}

	after, err := e.activeRecognized("alice.new@example.test", binding)
	if err != nil || after.ID() != before.ID() {
		t.Errorf("recognized for the new address = %+v, %v; want the same record %s", after, err, before.ID())
	}

	if got, err := e.activeRecognized("alice@example.test", binding); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("recognized for the old address = %+v, %v; want ErrNotFound", got, err)
	}

	old, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test", BindingSecret: binding})
	if err != nil || old.Outcome != emailauth.OutcomeOK {
		t.Fatalf("start with the old address = %+v, %v", old, err)
	}

	if f := e.flow(old.FlowID.String()); f.QuotaClass() != authflow.QuotaUnknown {
		t.Errorf("the old address gets quota class %s through the moved record, want unknown", f.QuotaClass())
	}
}
