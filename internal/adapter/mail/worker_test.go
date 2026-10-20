package mail_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/mail"
	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

var errBoom = errors.New("boom")

type recordedMetric struct {
	class     authflow.QuotaClass
	outcome   port.MailOutcome
	queueWait time.Duration
	sendTime  time.Duration
}

type recordingMetrics struct {
	mu     sync.Mutex
	mails  []recordedMetric
	reuses int
}

func (m *recordingMetrics) MailProcessed(class authflow.QuotaClass, outcome port.MailOutcome, wait, send time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mails = append(m.mails, recordedMetric{class, outcome, wait, send})
}

func (m *recordingMetrics) RefreshReuseDetected() { m.reuses++ }

func (m *recordingMetrics) outcomes() []port.MailOutcome {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []port.MailOutcome
	for _, r := range m.mails {
		out = append(out, r.outcome)
	}

	return out
}

// scriptedSender records what it is asked to send and answers from a script.
type scriptedSender struct {
	mu      sync.Mutex
	sent    []port.Mail
	results []error // consumed one per call; nil when exhausted
	block   chan struct{}
	started chan struct{}
}

func (s *scriptedSender) Send(ctx context.Context, m port.Mail) error {
	s.mu.Lock()
	s.sent = append(s.sent, m)

	var result error
	if len(s.results) > 0 {
		result, s.results = s.results[0], s.results[1:]
	}

	block, started := s.block, s.started
	s.mu.Unlock()

	if started != nil {
		close(started)
	}

	if block != nil {
		<-block
	}

	return result
}

func (s *scriptedSender) mails() []port.Mail {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]port.Mail(nil), s.sent...)
}

// syncBuffer is a log sink that the worker goroutine and the test can use together.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

type workerEnv struct {
	t       *testing.T
	store   *memory.Store
	clock   *testutil.FakeClock
	f       *testutil.Factory
	otp     *crypto.OTP
	sender  *scriptedSender
	metrics *recordingMetrics
	logs    *syncBuffer
	faults  *faultyUoW
	policy  mail.DeliveryPolicy
	worker  *mail.Worker
	// invitationURL is the link of invitation mail; the tests of other mail leave it unset.
	invitationURL string
}

type faultyUoW struct {
	inner port.UnitOfWork
	wrap  func(port.Stores) port.Stores
}

func (f *faultyUoW) Do(ctx context.Context, fn func(ctx context.Context, s port.Stores) error) error {
	return f.inner.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if f.wrap != nil {
			s = f.wrap(s)
		}

		return fn(ctx, s)
	})
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	f := testutil.NewFactory(t, now)
	store := memory.NewStore()

	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		t.Fatal(err)
	}

	e := &workerEnv{
		t: t, store: store, clock: f.Clock, f: f, otp: otp, sender: &scriptedSender{}, metrics: &recordingMetrics{},
		logs: &syncBuffer{}, faults: &faultyUoW{inner: store}, policy: mail.DefaultDeliveryPolicy(),
	}
	e.policy.PollInterval = 10 * time.Millisecond
	e.rebuild(otp)

	return e
}

func (e *workerEnv) rebuild(otp port.OTPCodes) {
	e.t.Helper()

	w, err := mail.NewWorker(mail.WorkerDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: otp, Sender: e.sender, Metrics: e.metrics,
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)), Policy: e.policy, InvitationURL: e.invitationURL,
	})
	if err != nil {
		e.t.Fatal(err)
	}

	e.worker = w
}

// queue stores a flow (its key is otp-a) and queues the mail of generation 1.
func (e *workerEnv) queue(emailAddr string, class authflow.QuotaClass) *authflow.Flow {
	e.t.Helper()

	spec := testutil.FlowSpec{Email: emailAddr, KeyID: "otp-a"}
	if class == authflow.QuotaRecognized {
		user := e.f.User(testutil.UserSpec{Email: emailAddr})
		client := e.f.RecognizedClient(testutil.RecognizedSpec{User: user})

		err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
			if _, _, err := st.Users.Ensure(ctx, user); err != nil {
				return err
			}

			stored, err := st.Recognized.Register(ctx, client)
			spec.RecognizedClientID = stored.ID()

			return err
		})
		if err != nil {
			e.t.Fatal(err)
		}

		spec.QuotaClass = authflow.QuotaRecognized
	}

	flow := e.f.Flow(spec)

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if err := st.Flows.Create(ctx, flow); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: class, AvailableAt: e.clock.Now()})
	})
	if err != nil {
		e.t.Fatal(err)
	}

	return flow
}

// change loads the flow, applies fn and saves it, like a request would.
func (e *workerEnv) change(flow *authflow.Flow, fn func(*authflow.Flow, port.Stores, context.Context) error) {
	e.t.Helper()

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		loaded, err := st.Flows.GetForUpdate(ctx, flow.ID())
		if err != nil {
			return err
		}

		if err := fn(loaded, st, ctx); err != nil {
			return err
		}

		return st.Flows.Save(ctx, loaded)
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *workerEnv) resend(flow *authflow.Flow) {
	e.t.Helper()
	e.change(flow, func(f *authflow.Flow, st port.Stores, ctx context.Context) error {
		if err := f.Resend(e.clock.Now(), authflow.PurposeLogin, testutil.BindingHash(testutil.DefaultBindingSecret), e.f.Salt(), "otp-a", authflow.DefaultPolicy()); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{FlowID: f.ID(), Generation: f.Generation(), QuotaClass: f.QuotaClass(), AvailableAt: e.clock.Now()})
	})
}

func (e *workerEnv) codeOf(flow *authflow.Flow) string {
	e.t.Helper()

	var stored *authflow.Flow

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error

		stored, err = st.Flows.Get(ctx, flow.ID())

		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}

	code, err := e.otp.Code(stored)
	if err != nil {
		e.t.Fatal(err)
	}

	return code
}

func (e *workerEnv) process() bool {
	e.t.Helper()

	processed, err := e.worker.ProcessNext(context.Background())
	if err != nil {
		e.t.Fatalf("ProcessNext: %v", err)
	}

	return processed
}

func (e *workerEnv) statuses() []memory.MailStatus { return e.store.OutboxStatuses() }

func TestWorkerSendsTheCodeOfTheStoredFlow(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.queue("alice@example.test", authflow.QuotaUnknown)
	e.clock.Advance(7 * time.Second)

	if !e.process() {
		t.Fatal("no job was processed")
	}

	mails := e.sender.mails()
	if len(mails) != 1 {
		t.Fatalf("%d mails sent, want 1", len(mails))
	}

	if mails[0].To.String() != "alice@example.test" || mails[0].Code != e.codeOf(flow) || !mails[0].ExpiresAt.Equal(flow.ExpiresAt()) {
		t.Errorf("mail = %+v", mails[0])
	}

	if st := e.statuses()[0]; st.Status != "sent" || st.Leased || st.LastError != "" {
		t.Errorf("job = %+v", st)
	}

	if got := e.metrics.mails; len(got) != 1 || got[0].outcome != port.MailSent || got[0].queueWait != 7*time.Second || got[0].class != authflow.QuotaUnknown {
		t.Errorf("metrics = %+v", got)
	}

	if e.process() {
		t.Error("the finished job was processed again")
	}

	if len(e.sender.mails()) != 1 {
		t.Error("a sent mail was sent again")
	}
}

func TestWorkerSkipsJobsThatNoLongerMatter(t *testing.T) {
	t.Run("an older generation after resend", func(t *testing.T) {
		e := newWorkerEnv(t)
		flow := e.queue("alice@example.test", authflow.QuotaUnknown)
		e.clock.Advance(authflow.DefaultPolicy().ResendPause)
		e.resend(flow)
		current := e.codeOf(flow)

		for e.process() {
		}

		mails := e.sender.mails()
		if len(mails) != 1 || mails[0].Code != current {
			t.Fatalf("mails = %+v; only the current generation's code may go out", mails)
		}

		st := e.statuses()
		if st[0].Status != "dead" || st[0].LastError != "flow_obsolete" || st[1].Status != "sent" {
			t.Errorf("jobs = %+v", st)
		}

		if got := e.metrics.outcomes(); len(got) != 2 || got[0] != port.MailObsolete || got[1] != port.MailSent {
			t.Errorf("outcomes = %v", got)
		}
	})

	t.Run("a flow that was already used", func(t *testing.T) {
		e := newWorkerEnv(t)
		flow := e.queue("alice@example.test", authflow.QuotaUnknown)
		e.change(flow, func(f *authflow.Flow, _ port.Stores, _ context.Context) error {
			attempt, err := f.Reserve(e.clock.Now(), authflow.PurposeLogin, testutil.BindingHash(testutil.DefaultBindingSecret), authflow.DefaultPolicy())
			if err != nil {
				return err
			}

			return f.Accept(attempt, e.clock.Now())
		})
		e.process()

		if len(e.sender.mails()) != 0 {
			t.Error("a mail was sent for a consumed flow")
		}

		if st := e.statuses()[0]; st.Status != "dead" || st.LastError != "flow_obsolete" {
			t.Errorf("job = %+v", st)
		}
	})

	t.Run("an expired flow", func(t *testing.T) {
		e := newWorkerEnv(t)
		e.queue("alice@example.test", authflow.QuotaUnknown)
		e.clock.Advance(authflow.DefaultPolicy().TTL)
		e.process()

		if len(e.sender.mails()) != 0 {
			t.Error("a mail was sent for an expired flow")
		}

		if got := e.metrics.outcomes(); len(got) != 1 || got[0] != port.MailObsolete {
			t.Errorf("outcomes = %v", got)
		}
	})

	t.Run("a flow that is gone", func(t *testing.T) {
		e := newWorkerEnv(t)
		e.queue("alice@example.test", authflow.QuotaUnknown)
		e.faults.wrap = func(s port.Stores) port.Stores { s.Flows = missingFlows{s.Flows}; return s }
		e.process()

		if len(e.sender.mails()) != 0 {
			t.Error("a mail was sent for a missing flow")
		}

		if st := e.statuses()[0]; st.Status != "dead" || st.LastError != "flow_missing" {
			t.Errorf("job = %+v", st)
		}
	})
}

type missingFlows struct{ port.FlowRepository }

func (missingFlows) Get(context.Context, authflow.FlowID) (*authflow.Flow, error) {
	return nil, port.ErrNotFound
}

func TestWorkerRetriesTemporaryFailuresWithGrowingDelays(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)

	temporary := fmt.Errorf("%w: smtp code 451", port.ErrMailTemporary)
	e.sender.results = []error{temporary, temporary, temporary, nil}

	delays := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}
	for i, delay := range delays {
		if !e.process() {
			t.Fatalf("attempt %d: nothing to process", i+1)
		}

		st := e.statuses()[0]
		if st.Status != "queued" || st.Attempts != i+1 || st.LastError != "smtp_temporary" || st.Leased {
			t.Fatalf("after attempt %d: %+v", i+1, st)
		}
		// Not before the delay has passed.
		e.clock.Advance(delay - time.Second)

		if e.process() {
			t.Fatalf("attempt %d: the job was retried %v early", i+1, time.Second)
		}

		e.clock.Advance(time.Second)
	}

	if !e.process() {
		t.Fatal("the fourth attempt did not run")
	}

	if st := e.statuses()[0]; st.Status != "sent" || st.Attempts != 4 {
		t.Errorf("job = %+v", st)
	}

	if got := e.metrics.outcomes(); fmt.Sprint(got) != "[retried retried retried sent]" {
		t.Errorf("outcomes = %v", got)
	}
}

func TestWorkerGivesUpAfterTheMaximumNumberOfAttempts(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)

	temporary := fmt.Errorf("%w: smtp code 451", port.ErrMailTemporary)
	e.sender.results = []error{temporary, temporary, temporary, temporary, temporary, temporary}

	// Advance exactly by each backoff, so that the flow (10 minutes) is still alive at the last attempt.
	delays := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 0}

	for i := 1; i <= e.policy.MaxAttempts; i++ {
		if !e.process() {
			t.Fatalf("attempt %d: nothing to process", i)
		}

		e.clock.Advance(delays[i-1])
	}

	e.clock.Advance(time.Hour) // far later: an abandoned job must stay abandoned

	st := e.statuses()[0]
	if st.Status != "dead" || st.LastError != "attempts_exhausted" || st.Attempts != e.policy.MaxAttempts {
		t.Errorf("job = %+v", st)
	}

	if e.process() {
		t.Error("an exhausted job was processed again")
	}

	if got := len(e.sender.mails()); got != e.policy.MaxAttempts {
		t.Errorf("%d sends, want %d", got, e.policy.MaxAttempts)
	}

	outcomes := e.metrics.outcomes()
	if outcomes[len(outcomes)-1] != port.MailExhausted {
		t.Errorf("last outcome = %v, want exhausted", outcomes[len(outcomes)-1])
	}
}

func TestWorkerAbandonsRejectedMailAtOnce(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)
	e.sender.results = []error{fmt.Errorf("%w: smtp code 550", port.ErrMailRejected)}

	e.process()

	if st := e.statuses()[0]; st.Status != "dead" || st.LastError != "smtp_rejected" || st.Attempts != 1 {
		t.Errorf("job = %+v", st)
	}

	e.clock.Advance(time.Hour)

	if e.process() || len(e.sender.mails()) != 1 {
		t.Error("a rejected mail was tried again")
	}

	if got := e.metrics.outcomes(); fmt.Sprint(got) != "[rejected]" {
		t.Errorf("outcomes = %v", got)
	}
}

func TestWorkerTreatsUnclassifiedSenderErrorsAsTemporary(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)
	e.sender.results = []error{errBoom}
	e.process()

	if st := e.statuses()[0]; st.Status != "queued" || st.LastError != "smtp_temporary" {
		t.Errorf("job = %+v", st)
	}
}

func TestACrashedWorkersJobIsTakenOverAfterTheLease(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)

	// A worker claims the job and dies: nothing is sent and nothing is recorded.
	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Outbox.Claim(ctx, e.clock.Now(), e.policy.Lease)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if e.process() {
		t.Fatal("a leased job was processed by a second worker")
	}

	e.clock.Advance(e.policy.Lease)

	if !e.process() {
		t.Fatal("the job was not taken over after the lease expired")
	}

	if len(e.sender.mails()) != 1 || e.statuses()[0].Status != "sent" || e.statuses()[0].Attempts != 2 {
		t.Errorf("mails=%d job=%+v", len(e.sender.mails()), e.statuses()[0])
	}
}

func TestWorkerWaitsWhileTheOTPKeyIsMissingAndSendsOnceItIsBack(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.queue("alice@example.test", authflow.QuotaUnknown)

	otherRing, err := crypto.NewOTPKeyring("otp-z", map[string][]byte{"otp-z": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	withoutKey, err := crypto.NewOTP(otherRing, nil)
	if err != nil {
		t.Fatal(err)
	}

	e.rebuild(withoutKey)

	e.process()

	if len(e.sender.mails()) != 0 {
		t.Error("a mail was sent without the OTP key")
	}

	if st := e.statuses()[0]; st.Status != "queued" || st.LastError != "otp_key_unavailable" {
		t.Errorf("job = %+v", st)
	}

	e.rebuild(e.otp) // the keyring is fixed
	e.clock.Advance(time.Minute)
	e.process()

	if mails := e.sender.mails(); len(mails) != 1 || mails[0].Code != e.codeOf(flow) {
		t.Errorf("mails = %+v", mails)
	}

	if got := e.metrics.outcomes(); fmt.Sprint(got) != "[key_unavailable sent]" {
		t.Errorf("outcomes = %v", got)
	}
}

func TestRecognizedClientsAreServedFirst(t *testing.T) {
	e := newWorkerEnv(t)
	for i := 0; i < 3; i++ {
		e.queue(fmt.Sprintf("unknown%d@example.test", i), authflow.QuotaUnknown)
		e.clock.Advance(time.Second)
	}

	e.queue("regular@example.test", authflow.QuotaRecognized)
	e.clock.Advance(time.Second)

	e.process()

	if mails := e.sender.mails(); len(mails) != 1 || mails[0].To.String() != "regular@example.test" {
		t.Errorf("first mail = %+v; the recognized client must not wait behind the queue", mails)
	}
}

func TestLogsNeverContainTheCodeTheAddressOrTheFlow(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.queue("alice@example.test", authflow.QuotaUnknown)
	code := e.codeOf(flow)
	e.sender.results = []error{fmt.Errorf("%w: smtp code 451", port.ErrMailTemporary)}
	e.process()
	e.clock.Advance(time.Minute)
	e.process()

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("the worker logged nothing")
	}

	for _, secret := range []string{code, code[:4], "alice", "example.test", flow.ID().String()} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains %q:\n%s", secret, logs)
		}
	}
}

func TestRunDrainsTheQueueAndStopsOnCancel(t *testing.T) {
	e := newWorkerEnv(t)
	for i := 0; i < 3; i++ {
		e.queue(fmt.Sprintf("user%d@example.test", i), authflow.QuotaUnknown)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- e.worker.Run(ctx) }()

	waitFor(t, func() bool { return len(e.sender.mails()) == 3 })

	// A job queued later is picked up by polling.
	e.queue("late@example.test", authflow.QuotaUnknown)
	waitFor(t, func() bool { return len(e.sender.mails()) == 4 })

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func TestShutdownDuringASendStillRecordsTheResult(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)
	e.sender.block = make(chan struct{})
	e.sender.started = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- e.worker.Run(ctx) }()

	<-e.sender.started
	cancel() // shutdown begins while the SMTP delivery is in flight

	select {
	case <-done:
		t.Fatal("Run returned before the claimed job was finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(e.sender.block)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after the send finished")
	}

	if st := e.statuses()[0]; st.Status != "sent" {
		t.Errorf("job = %+v: the result of the in-flight send must be recorded", st)
	}

	if len(e.sender.mails()) != 1 {
		t.Errorf("%d sends: shutdown must not cause a second delivery", len(e.sender.mails()))
	}
}

type failingClaim struct {
	port.Outbox
	failures *int
}

func (f failingClaim) Claim(ctx context.Context, now time.Time, lease time.Duration) (port.ClaimedMail, error) {
	if *f.failures > 0 {
		*f.failures--
		return port.ClaimedMail{}, errBoom
	}

	return f.Outbox.Claim(ctx, now, lease)
}

func TestRunSurvivesDatabaseErrors(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)

	failures := 3
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingClaim{s.Outbox, &failures}; return s }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = e.worker.Run(ctx) }()

	waitFor(t, func() bool { return len(e.sender.mails()) == 1 })

	if !strings.Contains(e.logs.String(), "failed to process") {
		t.Error("the database errors were not logged")
	}
}

type failingComplete struct{ port.Outbox }

func (failingComplete) Complete(context.Context, port.MailJobID) error { return errBoom }

func TestAFailedCompletionLeavesTheJobToBeRetriedAfterTheLease(t *testing.T) {
	e := newWorkerEnv(t)
	e.queue("alice@example.test", authflow.QuotaUnknown)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingComplete{s.Outbox}; return s }

	if _, err := e.worker.ProcessNext(context.Background()); err == nil {
		t.Fatal("ProcessNext hid the failure to record the result")
	}

	if len(e.sender.mails()) != 1 {
		t.Fatal("the mail was not sent")
	}
	// The record is lost, so after the lease the job is delivered again: the documented
	// at-least-once behaviour.
	e.faults.wrap = nil
	e.clock.Advance(e.policy.Lease)
	e.process()

	if len(e.sender.mails()) != 2 || e.statuses()[0].Status != "sent" {
		t.Errorf("mails=%d job=%+v", len(e.sender.mails()), e.statuses()[0])
	}
}

func TestNewWorkerValidatesItsInputs(t *testing.T) {
	e := newWorkerEnv(t)

	good := mail.WorkerDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Sender: e.sender, Metrics: e.metrics,
		Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), Policy: mail.DefaultDeliveryPolicy(),
	}
	for name, mutate := range map[string]func(*mail.WorkerDeps){
		"unit of work": func(d *mail.WorkerDeps) { d.UnitOfWork = nil },
		"clock":        func(d *mail.WorkerDeps) { d.Clock = nil },
		"otp":          func(d *mail.WorkerDeps) { d.OTP = nil },
		"sender":       func(d *mail.WorkerDeps) { d.Sender = nil },
		"metrics":      func(d *mail.WorkerDeps) { d.Metrics = nil },
		"logger":       func(d *mail.WorkerDeps) { d.Logger = nil },
	} {
		d := good
		mutate(&d)

		if _, err := mail.NewWorker(d); err == nil {
			t.Errorf("NewWorker accepted a missing %s", name)
		}
	}

	for name, mutate := range map[string]func(*mail.DeliveryPolicy){
		"no attempts":          func(p *mail.DeliveryPolicy) { p.MaxAttempts = 0 },
		"no base delay":        func(p *mail.DeliveryPolicy) { p.BaseDelay = 0 },
		"max below base":       func(p *mail.DeliveryPolicy) { p.MaxDelay = p.BaseDelay - 1 },
		"no send timeout":      func(p *mail.DeliveryPolicy) { p.SendTimeout = 0 },
		"lease not above send": func(p *mail.DeliveryPolicy) { p.Lease = p.SendTimeout },
		"no poll interval":     func(p *mail.DeliveryPolicy) { p.PollInterval = 0 },
	} {
		d := good
		mutate(&d.Policy)

		if _, err := mail.NewWorker(d); err == nil {
			t.Errorf("NewWorker accepted a policy with %s", name)
		}
	}
}

// changeFlow stores a change_email flow for a new user and queues its code.
func (e *workerEnv) changeFlow(newAddress string) *authflow.Flow {
	e.t.Helper()
	user := e.f.User(testutil.UserSpec{})
	flow := e.f.Flow(testutil.FlowSpec{Email: newAddress, KeyID: "otp-a", Purpose: authflow.PurposeChangeEmail, UserID: user.ID()})

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		if err := st.Flows.Create(ctx, flow); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: flow.QuotaClass(), AvailableAt: e.clock.Now()})
	})
	if err != nil {
		e.t.Fatal(err)
	}

	return flow
}

func TestWorkerSendsTheConfirmationOfAnEmailChangeToTheNewAddress(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.changeFlow("new@example.test")

	if !e.process() {
		t.Fatal("no job was processed")
	}

	mails := e.sender.mails()
	if len(mails) != 1 || mails[0].Kind != port.MailConfirmEmail || mails[0].To.String() != "new@example.test" ||
		mails[0].Code != e.codeOf(flow) || !mails[0].ExpiresAt.Equal(flow.ExpiresAt()) {
		t.Fatalf("mails = %+v, want the confirmation code for the new address", mails)
	}

	if st := e.statuses()[0]; st.Status != "sent" {
		t.Errorf("job = %+v", st)
	}
}

func TestWorkerSendsTheNoticeOfAChangedEmailToTheOldAddressOnly(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.changeFlow("new@example.test")

	old, err := identity.ParseEmail("old@example.test")
	if err != nil {
		t.Fatal(err)
	}
	// The change happened: the flow is consumed, and the notice is queued next to the code job.
	e.change(flow, func(f *authflow.Flow, st port.Stores, ctx context.Context) error {
		attempt, err := f.Reserve(e.clock.Now(), authflow.PurposeChangeEmail, testutil.BindingHash(testutil.DefaultBindingSecret), authflow.DefaultPolicy())
		if err != nil {
			return err
		}

		if err := f.Accept(attempt, e.clock.Now()); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{
			Kind: port.JobEmailChanged, FlowID: f.ID(), Generation: f.Generation(), QuotaClass: f.QuotaClass(),
			AvailableAt: e.clock.Now(), Recipient: old,
		})
	})

	for e.process() {
	}

	mails := e.sender.mails()
	if len(mails) != 1 || mails[0].Kind != port.MailEmailChanged || mails[0].To != old || mails[0].Code != "" || !mails[0].ExpiresAt.IsZero() {
		t.Fatalf("mails = %+v; only the notice goes out, to the old address, and the consumed flow's code does not", mails)
	}

	st := e.statuses()
	if st[0].Status != "dead" || st[0].LastError != "flow_obsolete" || st[1].Status != "sent" {
		t.Errorf("jobs = %+v, want the stale code dead and the notice sent", st)
	}
}

func TestWorkerRetriesAFailedNoticeLikeAnyOtherMail(t *testing.T) {
	e := newWorkerEnv(t)
	flow := e.changeFlow("new@example.test")
	old, _ := identity.ParseEmail("old@example.test")

	e.change(flow, func(f *authflow.Flow, st port.Stores, ctx context.Context) error {
		return st.Outbox.Enqueue(ctx, port.MailJob{
			Kind: port.JobEmailChanged, FlowID: f.ID(), Generation: f.Generation(), QuotaClass: f.QuotaClass(),
			AvailableAt: e.clock.Now().Add(time.Hour), Recipient: old,
		})
	})
	e.process() // the code job, so only the notice is left
	e.clock.Advance(time.Hour)
	e.sender.results = []error{fmt.Errorf("%w: busy", port.ErrMailTemporary)}

	e.process()

	if st := e.statuses()[1]; st.Status != "queued" || st.LastError != "smtp_temporary" || st.Attempts != 1 {
		t.Fatalf("notice after a temporary failure = %+v", st)
	}

	e.clock.Advance(e.policy.BaseDelay)
	e.process()

	if st := e.statuses()[1]; st.Status != "sent" || st.Attempts != 2 {
		t.Errorf("notice after the retry = %+v", st)
	}
}

// deleteAfterClaim models deletion after leasing a notice but before preparing its message.
type deleteAfterClaim struct {
	port.Outbox
	users  port.UserRepository
	userID identity.UserID
}

func (o deleteAfterClaim) Claim(ctx context.Context, now time.Time, lease time.Duration) (port.ClaimedMail, error) {
	job, err := o.Outbox.Claim(ctx, now, lease)
	if err != nil {
		return job, err
	}

	return job, o.users.Delete(ctx, o.userID)
}

func TestWorkerDoesNotSendAClaimedNoticeAfterAccountDeletion(t *testing.T) {
	e := newWorkerEnv(t)
	user := e.f.User(testutil.UserSpec{Email: "new@example.test"})
	flow := e.f.Flow(testutil.FlowSpec{Email: "new@example.test", KeyID: "otp-a"})

	err := e.store.Do(t.Context(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		if err := st.Flows.Create(ctx, flow); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{Kind: port.JobEmailChanged, FlowID: flow.ID(), Generation: flow.Generation(), QuotaClass: flow.QuotaClass(), AvailableAt: e.clock.Now(), Recipient: user.Email()})
	})
	if err != nil {
		t.Fatal(err)
	}

	e.faults.wrap = func(st port.Stores) port.Stores {
		st.Outbox = deleteAfterClaim{st.Outbox, st.Users, user.ID()}
		return st
	}
	if !e.process() {
		t.Fatal("no job was claimed")
	}

	if len(e.sender.mails()) != 0 || len(e.store.OutboxJobs()) != 0 {
		t.Error("deleted account's notice was sent or kept")
	}
}

// invitation saves an invitation of the address and queues its mail.
func (e *workerEnv) invitation(raw string, ttl time.Duration) identity.Email {
	e.t.Helper()

	to, err := identity.ParseEmail(raw)
	if err != nil {
		e.t.Fatal(err)
	}

	inv, err := identity.NewInvitation(to, e.clock.Now(), ttl)
	if err != nil {
		e.t.Fatal(err)
	}

	err = e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if err := st.Invitations.Save(ctx, inv); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{Kind: port.JobInvitation, Recipient: to, QuotaClass: authflow.QuotaUnknown, AvailableAt: e.clock.Now()})
	})
	if err != nil {
		e.t.Fatal(err)
	}

	return to
}

func (e *workerEnv) dropInvitation(to identity.Email) {
	e.t.Helper()

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Invitations.Delete(ctx, to)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestWorkerSendsTheInvitationWithTheLinkAndTheEnd(t *testing.T) {
	e := newWorkerEnv(t)
	e.invitationURL = "https://app.example.test/login"
	e.rebuild(e.otp)
	to := e.invitation("guest@example.test", 3*24*time.Hour)
	e.clock.Advance(5 * time.Second)

	if !e.process() {
		t.Fatal("no job was processed")
	}

	mails := e.sender.mails()
	if len(mails) != 1 || mails[0].Kind != port.MailInvitation || mails[0].To != to || mails[0].Link != "https://app.example.test/login" ||
		mails[0].Code != "" || !mails[0].ExpiresAt.Equal(now.Add(3*24*time.Hour)) {
		t.Fatalf("mails = %+v", mails)
	}

	if st := e.statuses()[0]; st.Status != "sent" {
		t.Errorf("job = %+v", st)
	}

	if got := e.metrics.outcomes(); len(got) != 1 || got[0] != port.MailSent {
		t.Errorf("outcomes = %v", got)
	}
}

func TestWorkerDoesNotAnnounceAnInvitationThatIsGone(t *testing.T) {
	for name, gone := range map[string]func(e *workerEnv, to identity.Email){
		"revoked": func(e *workerEnv, to identity.Email) { e.dropInvitation(to) },
		"expired": func(e *workerEnv, _ identity.Email) { e.clock.Advance(2 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newWorkerEnv(t)
			e.invitationURL = "https://app.example.test/login"
			e.rebuild(e.otp)
			to := e.invitation("guest@example.test", time.Hour)
			gone(e, to)

			e.process()

			if len(e.sender.mails()) != 0 {
				t.Error("a mail went out for an invitation that is gone")
			}

			if st := e.statuses()[0]; st.Status != "dead" || st.LastError != "invitation_gone" {
				t.Errorf("job = %+v", st)
			}

			if got := e.metrics.outcomes(); len(got) != 1 || got[0] != port.MailObsolete {
				t.Errorf("outcomes = %v", got)
			}
		})
	}
}

func TestWorkerGivesUpAnInvitationItHasNoLinkFor(t *testing.T) {
	e := newWorkerEnv(t) // no invitation URL
	e.invitation("guest@example.test", time.Hour)

	e.process()

	if len(e.sender.mails()) != 0 {
		t.Error("an invitation went out without a link")
	}

	if st := e.statuses()[0]; st.Status != "dead" || st.LastError != "no_invitation_url" {
		t.Errorf("job = %+v", st)
	}
}

func TestWorkerRetriesAnInvitationLikeAnyOtherMail(t *testing.T) {
	e := newWorkerEnv(t)
	e.invitationURL = "https://app.example.test/login"
	e.rebuild(e.otp)
	e.invitation("guest@example.test", 24*time.Hour)
	e.sender.results = []error{fmt.Errorf("%w: busy", port.ErrMailTemporary)}

	e.process()

	if st := e.statuses()[0]; st.Status != "queued" || st.LastError != "smtp_temporary" {
		t.Fatalf("after a temporary failure = %+v", st)
	}

	e.clock.Advance(e.policy.BaseDelay)
	e.process()

	if st := e.statuses()[0]; st.Status != "sent" || st.Attempts != 2 {
		t.Errorf("after the retry = %+v", st)
	}
}
