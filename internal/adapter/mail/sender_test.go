package mail_test

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/mail"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func newSender(t *testing.T, smtp *testutil.FakeSMTP, mutate ...func(*mail.SMTPConfig)) *mail.SMTPSender {
	t.Helper()
	host, p := smtp.Addr()
	cfg := mail.SMTPConfig{
		Host: host, Port: p, TLS: mail.TLSNone, FromAddress: "no-reply@auth.example.test", FromName: "Example Auth", Timeout: 2 * time.Second,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	sender, err := mail.NewSMTPSender(cfg, testutil.NewFakeClock(now))
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	return sender
}

func email(t *testing.T, raw string) identity.Email {
	t.Helper()
	e, err := identity.ParseEmail(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func loginMail(t *testing.T) port.Mail {
	return port.Mail{To: email(t, "alice@example.test"), Code: "30999009", ExpiresAt: now.Add(10 * time.Minute)}
}

// bodies returns the decoded text and HTML parts of a received message.
func bodies(t *testing.T, raw string) (header netmail.Header, text, html string) {
	t.Helper()
	msg, err := netmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("content type = %q, %v; want multipart/alternative", mediaType, err)
	}
	reader := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var body io.Reader = part
		if part.Header.Get("Content-Transfer-Encoding") == "quoted-printable" {
			body = quotedprintable.NewReader(part)
		}
		data, err := io.ReadAll(body)
		if err != nil {
			t.Fatal(err)
		}
		switch ct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type")); ct {
		case "text/plain":
			text = string(data)
		case "text/html":
			html = string(data)
		}
	}
	return msg.Header, text, html
}

func TestSendDeliversTheCodeToTheRecipientOnly(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	sender := newSender(t, smtp)

	if err := sender.Send(context.Background(), loginMail(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	messages := smtp.Messages()
	if len(messages) != 1 {
		t.Fatalf("%d messages, want 1", len(messages))
	}
	msg := messages[0]
	if msg.From != "no-reply@auth.example.test" || len(msg.To) != 1 || msg.To[0] != "alice@example.test" {
		t.Errorf("envelope = %q -> %v", msg.From, msg.To)
	}

	header, text, html := bodies(t, msg.Data)
	if got := header.Get("Subject"); got != "Your sign-in code" {
		t.Errorf("subject = %q: it must not carry the code", got)
	}
	from, err := netmail.ParseAddress(header.Get("From"))
	if err != nil || from.Address != "no-reply@auth.example.test" || from.Name != "Example Auth" {
		t.Errorf("From = %q, %v", header.Get("From"), err)
	}
	if header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("Auto-Submitted = %q", header.Get("Auto-Submitted"))
	}
	for name, body := range map[string]string{"text": text, "html": html} {
		if !strings.Contains(body, "3099 9009") || !strings.Contains(body, "10 minutes") {
			t.Errorf("%s body lacks the grouped code or the lifetime: %q", name, body)
		}
		if strings.Contains(body, "30999009") {
			t.Errorf("%s body shows the code ungrouped", name)
		}
	}
	for key, values := range header {
		for _, v := range values {
			if strings.Contains(v, "30999009") || strings.Contains(v, "3099 9009") {
				t.Errorf("header %s carries the code", key)
			}
		}
	}
}

func TestSendRoundsTheLifetimeUp(t *testing.T) {
	for in, want := range map[time.Duration]string{10 * time.Minute: "10 minutes", 90 * time.Second: "2 minutes", 30 * time.Second: "1 minute", -time.Minute: "1 minute"} {
		smtp := testutil.NewFakeSMTP(t)
		m := loginMail(t)
		m.ExpiresAt = now.Add(in)
		if err := newSender(t, smtp).Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
		_, text, _ := bodies(t, smtp.Messages()[0].Data)
		if !strings.Contains(text, "expires in about "+want) {
			t.Errorf("lifetime %v: text = %q, want %q", in, text, want)
		}
	}
}

func TestSendClassifiesServerRefusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testutil.FakeSMTP)
		want  error
	}{
		{"recipient refused for good", func(s *testutil.FakeSMTP) { s.Reply("rcpt", "550 5.1.1 alice@example.test user unknown") }, port.ErrMailRejected},
		{"message refused for good", func(s *testutil.FakeSMTP) { s.Reply("data", "554 5.6.0 content rejected") }, port.ErrMailRejected},
		{"recipient deferred", func(s *testutil.FakeSMTP) { s.Reply("rcpt", "451 4.2.1 mailbox busy") }, port.ErrMailTemporary},
		{"server busy at greeting", func(s *testutil.FakeSMTP) { s.Reply("greeting", "421 4.3.2 shutting down") }, port.ErrMailTemporary},
		{"delivery deferred after the content", func(s *testutil.FakeSMTP) { s.Reply("data", "452 4.3.1 insufficient storage") }, port.ErrMailTemporary},
		// A refused sender is our configuration, not this mail: it must be retried.
		{"sender refused", func(s *testutil.FakeSMTP) { s.Reply("mail", "550 5.7.1 sender not allowed") }, port.ErrMailTemporary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smtp := testutil.NewFakeSMTP(t)
			tt.setup(smtp)
			err := newSender(t, smtp).Send(context.Background(), loginMail(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			other := port.ErrMailTemporary
			if errors.Is(tt.want, port.ErrMailTemporary) {
				other = port.ErrMailRejected
			}
			if errors.Is(err, other) {
				t.Errorf("error %v matches both classes", err)
			}
			for _, secret := range []string{"alice", "example.test", "30999009", "3099"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q contains %q", err, secret)
				}
			}
			if len(smtp.Messages()) != 0 {
				t.Error("a refused message was recorded as delivered")
			}
		})
	}
}

func TestSendTreatsUnreachableAndSlowServersAsTemporary(t *testing.T) {
	t.Run("nothing is listening", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().(*net.TCPAddr)
		_ = ln.Close() // the port is now closed
		sender, err := mail.NewSMTPSender(mail.SMTPConfig{
			Host: "127.0.0.1", Port: addr.Port, TLS: mail.TLSNone, FromAddress: "no-reply@auth.example.test", Timeout: time.Second,
		}, testutil.NewFakeClock(now))
		if err != nil {
			t.Fatal(err)
		}
		if err := sender.Send(context.Background(), loginMail(t)); !errors.Is(err, port.ErrMailTemporary) {
			t.Errorf("error = %v, want temporary", err)
		}
	})

	t.Run("the server stays silent", func(t *testing.T) {
		smtp := testutil.NewFakeSMTP(t)
		smtp.Hang()
		sender := newSender(t, smtp, func(c *mail.SMTPConfig) { c.Timeout = 300 * time.Millisecond })
		started := time.Now()
		err := sender.Send(context.Background(), loginMail(t))
		if !errors.Is(err, port.ErrMailTemporary) {
			t.Errorf("error = %v, want temporary", err)
		}
		if took := time.Since(started); took > 3*time.Second {
			t.Errorf("Send took %v: the timeout did not bound it", took)
		}
	})

	t.Run("the context is cancelled", func(t *testing.T) {
		smtp := testutil.NewFakeSMTP(t)
		smtp.Hang()
		sender := newSender(t, smtp, func(c *mail.SMTPConfig) { c.Timeout = 30 * time.Second })
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		started := time.Now()
		if err := sender.Send(ctx, loginMail(t)); !errors.Is(err, port.ErrMailTemporary) {
			t.Errorf("error = %v, want temporary", err)
		}
		if took := time.Since(started); took > 3*time.Second {
			t.Errorf("Send took %v: the context did not bound it", took)
		}
	})
}

func TestMandatoryTLSRefusesAServerWithoutIt(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t) // does not offer STARTTLS
	sender := newSender(t, smtp, func(c *mail.SMTPConfig) { c.TLS = mail.TLSStartTLS })
	err := sender.Send(context.Background(), loginMail(t))
	if !errors.Is(err, port.ErrMailTemporary) {
		t.Errorf("error = %v, want temporary", err)
	}
	if len(smtp.Messages()) != 0 {
		t.Error("the code was sent over an unprotected connection although TLS is mandatory")
	}
}

func TestNewSMTPSenderValidatesTheConfiguration(t *testing.T) {
	good := mail.SMTPConfig{Host: "smtp.example.test", Port: 587, TLS: mail.TLSStartTLS, FromAddress: "no-reply@example.test", Timeout: time.Second}
	clock := testutil.NewFakeClock(now)
	if _, err := mail.NewSMTPSender(good, clock); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}
	for name, mutate := range map[string]func(*mail.SMTPConfig){
		"no host":             func(c *mail.SMTPConfig) { c.Host = "" },
		"no port":             func(c *mail.SMTPConfig) { c.Port = 0 },
		"port too large":      func(c *mail.SMTPConfig) { c.Port = 70000 },
		"no sender":           func(c *mail.SMTPConfig) { c.FromAddress = "" },
		"unknown tls mode":    func(c *mail.SMTPConfig) { c.TLS = "ssl" },
		"no timeout":          func(c *mail.SMTPConfig) { c.Timeout = 0 },
		"username only":       func(c *mail.SMTPConfig) { c.Username = "u" },
		"password only":       func(c *mail.SMTPConfig) { c.Password = "p" },
		"credentials, no TLS": func(c *mail.SMTPConfig) { c.Username, c.Password, c.TLS = "u", "p", mail.TLSNone },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := mail.NewSMTPSender(cfg, clock); err == nil {
			t.Errorf("%s: NewSMTPSender accepted the configuration", name)
		}
	}
	if _, err := mail.NewSMTPSender(good, nil); err == nil {
		t.Error("NewSMTPSender accepted a nil clock")
	}
	withAuth := good
	withAuth.Username, withAuth.Password = "u", "p"
	if _, err := mail.NewSMTPSender(withAuth, clock); err != nil {
		t.Errorf("credentials with STARTTLS were rejected: %v", err)
	}
}

func TestSendRejectsACodeOfTheWrongShape(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	m := loginMail(t)
	m.Code = "123"
	if err := newSender(t, smtp).Send(context.Background(), m); err == nil {
		t.Error("Send accepted a short code")
	}
	if smtp.Connections() != 0 {
		t.Error("the server was contacted although the mail could not be rendered")
	}
}

func TestSendRendersEachKindWithItsOwnSubjectAndNeverPutsACodeInIt(t *testing.T) {
	cases := map[string]struct {
		kind    port.MailKind
		code    string
		subject string
		phrases []string
	}{
		"sign-in":       {port.MailSignIn, "30999009", "Your sign-in code", []string{"3099 9009", "sign-in code"}},
		"confirm email": {port.MailConfirmEmail, "30999009", "Confirm your new email address", []string{"3099 9009", "confirm this email address", "stays as it was"}},
		"notice":        {port.MailEmailChanged, "", "The email address of your account changed", []string{"was changed", "recovery codes"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			smtp := testutil.NewFakeSMTP(t)
			m := port.Mail{Kind: tc.kind, To: email(t, "alice@example.test"), Code: tc.code}
			if tc.code != "" {
				m.ExpiresAt = now.Add(10 * time.Minute)
			}
			if err := newSender(t, smtp).Send(context.Background(), m); err != nil {
				t.Fatalf("Send: %v", err)
			}
			header, text, html := bodies(t, smtp.Messages()[0].Data)
			if got := header.Get("Subject"); got != tc.subject {
				t.Errorf("subject = %q, want %q", got, tc.subject)
			}
			for key, values := range header {
				for _, v := range values {
					if tc.code != "" && strings.Contains(v, tc.code[:4]) && strings.Contains(v, tc.code[4:]) {
						t.Errorf("header %s carries the code", key)
					}
				}
			}
			for label, body := range map[string]string{"text": text, "html": html} {
				for _, phrase := range tc.phrases {
					if !strings.Contains(body, phrase) {
						t.Errorf("%s body lacks %q: %q", label, phrase, body)
					}
				}
				if tc.code == "" && (strings.Contains(body, "minute") || strings.Contains(body, "@")) {
					t.Errorf("the notice names a lifetime or an address: %q", body)
				}
			}
		})
	}
}

func TestSendRefusesAMailItCannotRender(t *testing.T) {
	to := email(t, "alice@example.test")
	for name, m := range map[string]port.Mail{
		"a notice with a code":     {Kind: port.MailEmailChanged, To: to, Code: "30999009"},
		"a code that is too short": {Kind: port.MailConfirmEmail, To: to, Code: "1234", ExpiresAt: now.Add(time.Minute)},
		"an unknown kind":          {Kind: "newsletter", To: to, Code: "30999009", ExpiresAt: now.Add(time.Minute)},
		"a sign-in without a code": {To: to, ExpiresAt: now.Add(time.Minute)},
	} {
		smtp := testutil.NewFakeSMTP(t)
		if err := newSender(t, smtp).Send(context.Background(), m); err == nil {
			t.Errorf("%s: Send accepted it", name)
		}
		if len(smtp.Messages()) != 0 {
			t.Errorf("%s: a message went out", name)
		}
	}
}
