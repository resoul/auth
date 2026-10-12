//go:build integration

package bootstrap_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/bootstrap"
	"airlance.org/auth/internal/config"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/testutil"
)

var otpKey = make([]byte, 32)

// schemaDSN gives a migrated, isolated schema and returns its DSN.
func schemaDSN(t *testing.T) string {
	t.Helper()
	base := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("AIRLANCE_AUTH_TEST_DATABASE_URL is not set; run `make up` and `make test-int`")
	}
	admin, err := postgres.OpenMigrationDB(base)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("boot_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, err := postgres.OpenMigrationDB(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := postgres.MigrateUp(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return u.String()
}

type service struct {
	t       *testing.T
	dsn     string
	db      *sql.DB
	store   *postgres.Store
	keyFile string
	factory *testutil.Factory
}

func newService(t *testing.T) *service {
	t.Helper()
	dsn := schemaDSN(t)
	db, err := postgres.OpenMigrationDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := postgres.Open(context.Background(), dsn, id.Generator{}, postgres.WithMaxConns(4))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	keyFile := testutil.WriteFile(t, "otp-a", []byte(base64.StdEncoding.EncodeToString(otpKey)))
	return &service{t: t, dsn: dsn, db: db, store: store, keyFile: keyFile, factory: testutil.NewFactory(t, time.Now().UTC().Truncate(time.Microsecond))}
}

func (s *service) config(smtpAddr string) config.Config {
	host, portText, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		s.t.Fatal(err)
	}
	var smtpPort int
	if _, err := fmt.Sscanf(portText, "%d", &smtpPort); err != nil {
		s.t.Fatal(err)
	}
	return config.Config{
		Log:             config.LogConfig{Format: config.LogFormatText},
		ShutdownTimeout: 5 * time.Second,
		Database:        config.DatabaseConfig{URL: config.NewSecret(s.dsn), MaxConns: 4},
		SMTP:            config.SMTPConfig{Host: host, Port: smtpPort, TLS: config.SMTPTLSNone, From: "no-reply@auth.example.test"},
		Keyring: &config.Keyring{
			FormatVersion: config.KeyringFormatVersion,
			OTPHMAC:       &config.KeySet{ActiveKID: "otp-a", Keys: map[string]config.KeyRef{"otp-a": {KeyFile: s.keyFile}}},
		},
	}
}

// queue stores a flow of the current time and queues its first mail.
func (s *service) queue(emailAddr string) *authflow.Flow {
	s.t.Helper()
	flow := s.factory.Flow(testutil.FlowSpec{Email: emailAddr, KeyID: "otp-a"})
	err := s.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if err := st.Flows.Create(ctx, flow); err != nil {
			return err
		}
		return st.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1, QuotaClass: authflow.QuotaUnknown, AvailableAt: flow.CreatedAt()})
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return flow
}

func (s *service) expectedCode(flow *authflow.Flow) string {
	s.t.Helper()
	ring, err := crypto.NewOTPKeyring("otp-a", map[string][]byte{"otp-a": otpKey})
	if err != nil {
		s.t.Fatal(err)
	}
	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	code, err := otp.Code(flow)
	if err != nil {
		s.t.Fatal(err)
	}
	return code
}

func (s *service) jobState() (status string, attempts int) {
	s.t.Helper()
	if err := s.db.QueryRow(`SELECT status, attempts FROM outbox`).Scan(&status, &attempts); err != nil {
		s.t.Fatal(err)
	}
	return status, attempts
}

// start runs the service and returns a stop function that waits for a clean exit.
func (s *service) start(cfg config.Config) (stop func()) {
	s.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bootstrap.Run(ctx, cfg, bootstrap.NewLogger(io.Discard, cfg.Log)) }()
	return func() {
		// A connection the client opened but never used is not idle for the server until it is
		// five seconds old, and Shutdown waits for it: close the client's connections first.
		http.DefaultClient.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				s.t.Errorf("Run = %v, want a clean stop", err)
			}
		case <-time.After(10 * time.Second):
			s.t.Fatal("the service did not stop")
		}
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func addrOf(smtp *testutil.FakeSMTP) string {
	host, p := smtp.Addr()
	return fmt.Sprintf("%s:%d", host, p)
}

func TestServiceDeliversQueuedMailAndStopsCleanly(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	flow := s.queue("alice@example.test")
	stop := s.start(s.config(addrOf(smtp)))

	waitUntil(t, "the mail", func() bool { return len(smtp.Messages()) == 1 })
	stop()

	msg := smtp.Messages()[0]
	if len(msg.To) != 1 || msg.To[0] != "alice@example.test" || !strings.Contains(msg.Data, s.expectedCode(flow)[:4]) {
		t.Errorf("message = %+v", msg)
	}
	if status, attempts := s.jobState(); status != "sent" || attempts != 1 {
		t.Errorf("job = %s after %d attempts", status, attempts)
	}
}

func TestRestartDoesNotLoseTheQueue(t *testing.T) {
	s := newService(t)
	flow := s.queue("alice@example.test")

	// The first process cannot reach the SMTP server: the job stays queued and is retried later.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := closed.Addr().String()
	_ = closed.Close()
	stop := s.start(s.config(deadAddr))
	waitUntil(t, "a failed attempt", func() bool { _, attempts := s.jobState(); return attempts >= 1 })
	stop()
	if status, _ := s.jobState(); status != "queued" {
		t.Fatalf("job = %s, want queued after a temporary failure", status)
	}

	// The retry time is in the future; fast-forward it, then start a new process with a working server.
	if _, err := s.db.Exec(`UPDATE outbox SET available_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	smtp := testutil.NewFakeSMTP(t)
	stop = s.start(s.config(addrOf(smtp)))
	waitUntil(t, "the mail after the restart", func() bool { return len(smtp.Messages()) == 1 })
	stop()

	if !strings.Contains(smtp.Messages()[0].Data, s.expectedCode(flow)[:4]) {
		t.Error("the delivered mail does not carry the code of the flow")
	}
	if status, attempts := s.jobState(); status != "sent" || attempts != 2 {
		t.Errorf("job = %s after %d attempts, want sent after 2", status, attempts)
	}
}

func TestAJobLeasedByADeadWorkerIsTakenOverWhenTheLeaseEnds(t *testing.T) {
	s := newService(t)
	s.queue("alice@example.test")

	// A worker that died: it claimed the job and never reported back.
	err := s.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Outbox.Claim(ctx, time.Now(), 2*time.Minute)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	smtp := testutil.NewFakeSMTP(t)
	stop := s.start(s.config(addrOf(smtp)))

	time.Sleep(500 * time.Millisecond)
	if len(smtp.Messages()) != 0 {
		t.Fatal("a job under a live lease was taken by another worker")
	}
	if _, err := s.db.Exec(`UPDATE outbox SET lease_until = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the takeover", func() bool { return len(smtp.Messages()) == 1 })
	stop()
	if status, attempts := s.jobState(); status != "sent" || attempts != 2 {
		t.Errorf("job = %s after %d attempts", status, attempts)
	}
}

func TestTwoServicesNeverSendTheSameMailTwice(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	const mails = 10
	for i := 0; i < mails; i++ {
		s.queue(fmt.Sprintf("user%d@example.test", i))
	}
	cfg := s.config(addrOf(smtp))
	stopA, stopB := s.start(cfg), s.start(cfg)

	waitUntil(t, "all mails", func() bool { return len(smtp.Messages()) >= mails })
	time.Sleep(300 * time.Millisecond) // a duplicate would show up by now
	stopA()
	stopB()

	seen := map[string]int{}
	for _, m := range smtp.Messages() {
		seen[m.To[0]]++
	}
	if len(seen) != mails || len(smtp.Messages()) != mails {
		t.Errorf("%d messages to %d recipients, want %d of each", len(smtp.Messages()), len(seen), mails)
	}
	var sent int
	if err := s.db.QueryRow(`SELECT count(*) FROM outbox WHERE status = 'sent'`).Scan(&sent); err != nil || sent != mails {
		t.Errorf("sent = %d, %v", sent, err)
	}
}

func TestServiceRefusesToStartWhenTheDatabaseIsUnreachable(t *testing.T) {
	cfg := config.Config{
		Log: config.LogConfig{Format: config.LogFormatText}, ShutdownTimeout: time.Second,
		Database: config.DatabaseConfig{URL: config.NewSecret("postgres://airlance_auth:hunter2@127.0.0.1:1/airlance_auth?sslmode=disable&connect_timeout=1")},
		SMTP:     config.SMTPConfig{Host: "127.0.0.1", Port: 1025, TLS: config.SMTPTLSNone, From: "no-reply@example.test"},
		Keyring: &config.Keyring{
			FormatVersion: config.KeyringFormatVersion,
			OTPHMAC: &config.KeySet{ActiveKID: "otp-a", Keys: map[string]config.KeyRef{
				"otp-a": {KeyFile: testutil.WriteFile(t, "otp-a", []byte(base64.StdEncoding.EncodeToString(otpKey)))},
			}},
		},
	}
	err := bootstrap.Run(t.Context(), cfg, bootstrap.NewLogger(io.Discard, cfg.Log))
	if err == nil {
		t.Fatal("Run succeeded without a database")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q leaks the database password", err)
	}
}
