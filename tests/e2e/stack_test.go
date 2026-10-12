//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"airlance.org/auth/internal/testutil"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "airlance_auth-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "airlance-auth")
	build := exec.Command("go", "build", "-o", binary, "airlance.org/auth/cmd/airlance-auth")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build the binary:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	baseDSN     = env("AIRLANCE_AUTH_TEST_DATABASE_URL", "postgres://airlance_auth:airlance_auth@127.0.0.1:5432/airlance_auth?sslmode=disable")
	mailpitURL  = env("AIRLANCE_AUTH_E2E_MAILPIT", "http://127.0.0.1:8025")
	mailpitSMTP = env("AIRLANCE_AUTH_E2E_SMTP", "127.0.0.1:1025")
)

// stack is one service process with its own schema, keys and address.
type stack struct {
	t     *testing.T
	dir   string
	dsn   string
	addr  string
	base  string
	env   []string
	cmd   *exec.Cmd
	logs  *syncBuffer
	done  chan error
	db    *sql.DB
	seen  []string // every secret a test saw, to check the logs against
	seenM sync.Mutex
	// auths are the software authenticators of the users that registered a passkey, by email.
	auths map[string]*testutil.SoftAuthenticator
}

// The relying party of the e2e service. The software authenticators claim this origin, as a
// page of that domain would.
const (
	e2eRPID     = "e2e.test"
	e2eRPOrigin = "https://e2e.test"
)

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

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func newStack(t *testing.T, extra ...string) *stack {
	t.Helper()
	if _, err := http.Get(mailpitURL + "/api/v1/info"); err != nil {
		t.Fatalf("Mailpit is not reachable at %s: run `make up` (%v)", mailpitURL, err)
	}
	s := &stack{t: t, dir: t.TempDir(), logs: &syncBuffer{}, auths: map[string]*testutil.SoftAuthenticator{}}

	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("e2e_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema (is PostgreSQL up?): %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s.dsn = u.String()
	if s.db, err = sql.Open("pgx", s.dsn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.db.Close() })

	otp := filepath.Join(s.dir, "otp-a")
	if err := os.WriteFile(otp, []byte(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))), 0o600); err != nil {
		t.Fatal(err)
	}
	sign := filepath.Join(s.dir, "sign-a.pem")
	if err := os.WriteFile(sign, testutil.NewSigningKeyPEM(t).Private, 0o600); err != nil {
		t.Fatal(err)
	}
	ring := filepath.Join(s.dir, "keyring.json")
	body := fmt.Sprintf(`{"format_version": 1,
		"otp_hmac": {"active_kid": "otp-a", "keys": {"otp-a": {"key_file": %q}}},
		"jwt_signing": {"active_kid": "sign-a", "keys": {"sign-a": {"key_file": %q}}}}`, otp, sign)
	if err := os.WriteFile(ring, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s.addr = freeAddr(t)
	s.base = "http://" + s.addr
	s.env = append(os.Environ(),
		"AIRLANCE_AUTH_DATABASE_URL="+s.dsn,
		"AIRLANCE_AUTH_DATABASE_MAX_CONNS=4",
		"AIRLANCE_AUTH_KEYRING_FILE="+ring,
		"AIRLANCE_AUTH_JWT_ISSUER="+s.base,
		"AIRLANCE_AUTH_JWT_AUDIENCE=e2e",
		"AIRLANCE_AUTH_SMTP_ADDR="+mailpitSMTP,
		"AIRLANCE_AUTH_SMTP_TLS=none",
		"AIRLANCE_AUTH_MAIL_FROM=no-reply@auth.example.test",
		"AIRLANCE_AUTH_LOG_FORMAT=json",
		"AIRLANCE_AUTH_LOG_LEVEL=debug",
		"AIRLANCE_AUTH_HTTP_ADDR="+s.addr,
		"AIRLANCE_AUTH_WEBAUTHN_RP_ID="+e2eRPID,
		"AIRLANCE_AUTH_WEBAUTHN_ORIGINS="+e2eRPOrigin,
	)
	s.env = append(s.env, extra...)

	migrate := exec.Command(binary, "migrate", "up")
	migrate.Env = s.env
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate up: %v\n%s", err, out)
	}
	s.start()
	t.Cleanup(func() {
		s.stop()
		if t.Failed() {
			t.Logf("server logs:\n%s", s.logs)
		}
	})
	return s
}

func (s *stack) start() {
	s.t.Helper()
	s.cmd = exec.Command(binary, "serve")
	s.cmd.Env = s.env
	s.cmd.Stdout, s.cmd.Stderr = s.logs, s.logs
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.done = make(chan error, 1)
	go func() { s.done <- s.cmd.Wait() }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(s.base + "/health/ready")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case err := <-s.done:
			s.t.Fatalf("the server exited at start: %v\n%s", err, s.logs)
		default:
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("the server is not ready:\n%s", s.logs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop asks the server to stop as an operator does (SIGTERM) and requires a clean exit.
func (s *stack) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-s.done:
		if err != nil {
			s.t.Errorf("the server did not stop cleanly: %v", err)
		}
	case <-time.After(15 * time.Second):
		_ = s.cmd.Process.Kill()
		s.t.Error("the server did not stop within 15 seconds of SIGTERM")
	}
	s.cmd = nil
}

func (s *stack) restart() {
	s.t.Helper()
	s.stop()
	s.start()
}

func (s *stack) secret(values ...string) {
	s.seenM.Lock()
	defer s.seenM.Unlock()
	s.seen = append(s.seen, values...)
}

// checkLogs fails if a secret a test handled appears in the server logs.
func (s *stack) checkLogs() {
	s.t.Helper()
	s.seenM.Lock()
	defer s.seenM.Unlock()
	logs := s.logs.String()
	for _, secret := range s.seen {
		if len(secret) >= 8 && strings.Contains(logs, secret) {
			s.t.Errorf("the server logs contain a secret (%s…)", secret[:8])
		}
	}
	for _, forbidden := range []string{"Authorization", "Set-Cookie"} {
		if strings.Contains(logs, forbidden) {
			s.t.Errorf("the server logs mention %s", forbidden)
		}
	}
}

func (s *stack) count(table, where string) int {
	s.t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table + ` WHERE ` + where).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

// uniqueEmail keeps tests apart in the shared Mailpit.
func uniqueEmail(t *testing.T, label string) string {
	return fmt.Sprintf("%s-%d@e2e.example.test", label, time.Now().UnixNano())
}

var codeInMail = regexp.MustCompile(`(\d{4}) (\d{4})`)

// code reads the newest code mailed to the address, waiting for the worker to deliver it.
// after is the number of mails the address had before the request.
func code(t *testing.T, email string, after int) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		ids := mailIDs(t, email)
		if len(ids) > after {
			var msg struct{ Text string }
			getJSON(t, mailpitURL+"/api/v1/message/"+ids[0], &msg)
			if m := codeInMail.FindStringSubmatch(msg.Text); m != nil {
				return m[1] + m[2]
			}
			t.Fatalf("the mail carries no code: %q", msg.Text)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no mail for %s after %d seconds", email, 15)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// newDeviceSubject is the subject of the notice a sign-in of a new client sends.
const newDeviceSubject = "New sign-in to your account"

// mailIDs returns the Mailpit message ids addressed to email, newest first, without the notices of new devices:
// a notice is queued with a sign-in and may arrive while a test already waits for a code, so counting it would
// make the code of the next flow look delivered. noticeIDs returns the notices.
func mailIDs(t *testing.T, email string) []string { return messageIDs(t, email, false) }

// noticeIDs returns the ids of the new device notices addressed to email, newest first.
func noticeIDs(t *testing.T, email string) []string { return messageIDs(t, email, true) }

func messageIDs(t *testing.T, email string, notices bool) []string {
	t.Helper()
	var res struct {
		Messages []struct{ ID, Subject string } `json:"messages"`
	}
	getJSON(t, mailpitURL+"/api/v1/search?query="+url.QueryEscape("to:"+email), &res)
	ids := make([]string, 0, len(res.Messages))
	for _, m := range res.Messages {
		if (m.Subject == newDeviceSubject) == notices {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// waitForNotices waits until the address has n new device notices and returns the text of the newest.
func waitForNotices(t *testing.T, email string, n int) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for len(noticeIDs(t, email)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s has %d new device notices, want %d", email, len(noticeIDs(t, email)), n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var msg struct{ Text string }
	getJSON(t, mailpitURL+"/api/v1/message/"+noticeIDs(t, email)[0], &msg)
	return msg.Text
}

func getJSON(t *testing.T, target string, into any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s: %v: %s", target, err, data)
	}
}
