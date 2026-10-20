package mail_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/testutil"
)

func invitationMail(t *testing.T) port.Mail {
	return port.Mail{Kind: port.MailInvitation, To: email(t, "guest@example.test"), Link: "https://app.example.test/login", ExpiresAt: now.Add(7 * 24 * time.Hour)}
}

func TestAnInvitationCarriesTheLinkAndTheEndAndNoCode(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	if err := newSender(t, smtp).Send(context.Background(), invitationMail(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg := smtp.Messages()[0]
	if len(msg.To) != 1 || msg.To[0] != "guest@example.test" {
		t.Errorf("recipients = %v", msg.To)
	}

	header, text, html := bodies(t, msg.Data)
	if got := header.Get("Subject"); got != "You have been invited" {
		t.Errorf("subject = %q", got)
	}

	for label, body := range map[string]string{"text": text, "html": html} {
		for _, want := range []string{"https://app.example.test/login", "2026-10-09 12:00 UTC", "invited"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s body lacks %q: %q", label, want, body)
			}
		}

		if strings.Contains(body, "sign-in code is") {
			t.Errorf("%s body talks about a code that is not there", label)
		}
	}

	if !strings.Contains(html, `href="https://app.example.test/login"`) {
		t.Errorf("the html link is not a link: %q", html)
	}

	if header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("Auto-Submitted = %q", header.Get("Auto-Submitted"))
	}
}

func TestAnInvitationNeedsAnAddressItMayPointTo(t *testing.T) {
	to := email(t, "guest@example.test")

	end := now.Add(time.Hour)
	for name, m := range map[string]port.Mail{
		"no link":             {Kind: port.MailInvitation, To: to, ExpiresAt: end},
		"plain http":          {Kind: port.MailInvitation, To: to, Link: "http://app.example.test/login", ExpiresAt: end},
		"another scheme":      {Kind: port.MailInvitation, To: to, Link: "javascript:alert(1)", ExpiresAt: end},
		"credentials in it":   {Kind: port.MailInvitation, To: to, Link: "https://user:pass@app.example.test/", ExpiresAt: end},
		"a fragment":          {Kind: port.MailInvitation, To: to, Link: "https://app.example.test/#x", ExpiresAt: end},
		"no host":             {Kind: port.MailInvitation, To: to, Link: "https:///login", ExpiresAt: end},
		"no end":              {Kind: port.MailInvitation, To: to, Link: "https://app.example.test/login"},
		"a code on an invite": {Kind: port.MailInvitation, To: to, Link: "https://app.example.test/login", ExpiresAt: end, Code: "30999009"},
	} {
		smtp := testutil.NewFakeSMTP(t)
		if err := newSender(t, smtp).Send(context.Background(), m); err == nil {
			t.Errorf("%s: Send accepted it", name)
		}

		if len(smtp.Messages()) != 0 {
			t.Errorf("%s: a message went out", name)
		}
	}
	// A local address over http is fine in development.
	smtp := testutil.NewFakeSMTP(t)

	local := port.Mail{Kind: port.MailInvitation, To: to, Link: "http://localhost:5173/", ExpiresAt: end}
	if err := newSender(t, smtp).Send(context.Background(), local); err != nil {
		t.Errorf("a localhost link: %v", err)
	}
}

func TestTheLinkOfAnInvitationCannotInjectMarkup(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	m := invitationMail(t)

	m.Link = "https://app.example.test/login?next=\"><script>alert(1)</script>"
	if err := newSender(t, smtp).Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	_, _, html := bodies(t, smtp.Messages()[0].Data)
	if strings.Contains(html, "<script>") {
		t.Errorf("the link broke out of the markup: %q", html)
	}
}
