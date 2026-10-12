//go:build integration

package mail_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/mail"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/testutil"
)

// mailpit returns the SMTP host and port and the API base URL of the development Mailpit
// (deploy/compose.yaml); AIRLANCE_AUTH_TEST_MAILPIT_* override the defaults.
func mailpit(t *testing.T) (smtpHost string, smtpPort int, api string) {
	t.Helper()
	smtpAddr := envOr("AIRLANCE_AUTH_TEST_MAILPIT_SMTP", "127.0.0.1:1025")
	api = envOr("AIRLANCE_AUTH_TEST_MAILPIT_API", "http://127.0.0.1:8025")
	smtpHost, portText, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		t.Fatal(err)
	}
	smtpPort, err = strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(api + "/api/v1/info")
	if err != nil {
		t.Fatalf("Mailpit is not reachable at %s (run `make up`): %v", api, err)
	}
	_ = resp.Body.Close()

	clear := func() {
		req, _ := http.NewRequest(http.MethodDelete, api+"/api/v1/messages", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}
	clear()
	t.Cleanup(clear)
	return smtpHost, smtpPort, api
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type mailpitMessage struct {
	ID      string
	Subject string
	To      []struct{ Address string }
	From    struct{ Address, Name string }
	Text    string
	HTML    string
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func TestMailpitReceivesTheSignInEmail(t *testing.T) {
	smtpHost, smtpPort, api := mailpit(t)
	sender, err := mail.NewSMTPSender(mail.SMTPConfig{
		Host: smtpHost, Port: smtpPort, TLS: mail.TLSNone,
		FromAddress: "no-reply@auth.example.test", FromName: "Example Auth", Timeout: 5 * time.Second,
	}, testutil.NewFakeClock(now))
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(context.Background(), port.Mail{To: email(t, "alice@example.test"), Code: "30999009", ExpiresAt: now.Add(10 * time.Minute)})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	var list struct {
		Messages []struct{ ID string }
	}
	getJSON(t, api+"/api/v1/messages", &list)
	if len(list.Messages) != 1 {
		t.Fatalf("Mailpit holds %d messages, want 1", len(list.Messages))
	}
	var msg mailpitMessage
	getJSON(t, fmt.Sprintf("%s/api/v1/message/%s", api, list.Messages[0].ID), &msg)

	if msg.Subject != "Your sign-in code" || len(msg.To) != 1 || msg.To[0].Address != "alice@example.test" ||
		msg.From.Address != "no-reply@auth.example.test" || msg.From.Name != "Example Auth" {
		t.Errorf("message = %+v", msg)
	}
	for name, body := range map[string]string{"text": msg.Text, "html": msg.HTML} {
		if !strings.Contains(body, "3099 9009") {
			t.Errorf("the %s part does not show the code: %q", name, body)
		}
	}
	if strings.Contains(msg.Subject, "3099") {
		t.Error("the subject carries the code")
	}
}
