package mail_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

var clientAddr = netip.MustParseAddr("203.0.113.7")

func newDeviceMail(t *testing.T) port.Mail {
	return port.Mail{Kind: port.MailNewDevice, To: email(t, "owner@example.test"), DeviceName: "Office laptop", ClientIP: clientAddr, At: now}
}

func TestANewDeviceNoticeShowsTheDeviceTheAddressAndTheTimeAndNoCode(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	if err := newSender(t, smtp).Send(context.Background(), newDeviceMail(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg := smtp.Messages()[0]
	if len(msg.To) != 1 || msg.To[0] != "owner@example.test" {
		t.Errorf("recipients = %v", msg.To)
	}

	header, text, html := bodies(t, msg.Data)
	if got := header.Get("Subject"); got != "New sign-in to your account" {
		t.Errorf("subject = %q", got)
	}

	for label, body := range map[string]string{"text": text, "html": html} {
		for _, want := range []string{"Office laptop", "203.0.113.7", "2026-10-02 12:00 UTC", "If it was not you"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s body lacks %q: %q", label, want, body)
			}
		}
	}
}

func TestANewDeviceNoticeSaysWhenTheNameOrTheAddressIsUnknownAndCannotInjectMarkup(t *testing.T) {
	smtp := testutil.NewFakeSMTP(t)
	m := newDeviceMail(t)

	m.DeviceName, m.ClientIP = "", netip.Addr{}
	if err := newSender(t, smtp).Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	_, text, _ := bodies(t, smtp.Messages()[0].Data)
	if !strings.Contains(text, "Device: not named") || !strings.Contains(text, "Address: unknown") {
		t.Errorf("text = %q", text)
	}

	smtp = testutil.NewFakeSMTP(t)
	m = newDeviceMail(t)

	m.DeviceName = `<script>alert(1)</script>`
	if err := newSender(t, smtp).Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}

	_, _, html := bodies(t, smtp.Messages()[0].Data)
	if strings.Contains(html, "<script>") {
		t.Errorf("the name broke out of the markup: %q", html)
	}
}

func TestANewDeviceNoticeNeedsATimeACleanNameAndNoCode(t *testing.T) {
	for name, edit := range map[string]func(*port.Mail){
		"no time":      func(m *port.Mail) { m.At = time.Time{} },
		"a line break": func(m *port.Mail) { m.DeviceName = "a\nBcc: x@example.test" },
		"a code":       func(m *port.Mail) { m.Code = "30999009" },
	} {
		smtp := testutil.NewFakeSMTP(t)
		m := newDeviceMail(t)
		edit(&m)

		if err := newSender(t, smtp).Send(context.Background(), m); err == nil {
			t.Errorf("%s: Send accepted it", name)
		}

		if len(smtp.Messages()) != 0 {
			t.Errorf("%s: a message went out", name)
		}
	}
}

// newDeviceJob stores a user and queues the notice of a new device for them.
func (e *workerEnv) newDeviceJob() *identity.User {
	e.t.Helper()
	user := e.f.User(testutil.UserSpec{Email: "owner@example.test"})

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		return st.Outbox.Enqueue(ctx, port.MailJob{
			Kind: port.JobNewDevice, QuotaClass: authflow.QuotaRecognized, AvailableAt: e.clock.Now(),
			UserID: user.ID(), DeviceName: "Office laptop", ClientIP: clientAddr, EventAt: e.clock.Now(),
		})
	})
	if err != nil {
		e.t.Fatal(err)
	}

	return user
}

func TestWorkerSendsTheNewDeviceNoticeToTheAddressOfTheUserAndForgetsTheClientAddress(t *testing.T) {
	e := newWorkerEnv(t)
	user := e.newDeviceJob()
	e.clock.Advance(5 * time.Second)

	if !e.process() {
		t.Fatal("no job was processed")
	}

	mails := e.sender.mails()
	if len(mails) != 1 || mails[0].Kind != port.MailNewDevice || mails[0].To != user.Email() || mails[0].DeviceName != "Office laptop" ||
		mails[0].ClientIP != clientAddr || !mails[0].At.Equal(now) || mails[0].Code != "" {
		t.Fatalf("mails = %+v", mails)
	}

	st := e.statuses()[0]
	if st.Status != "sent" {
		t.Errorf("job = %+v", st)
	}

	if st.Job.ClientIP.IsValid() {
		t.Error("the client address stayed in the job after the mail went out")
	}

	if got := e.metrics.outcomes(); len(got) != 1 || got[0] != port.MailSent {
		t.Errorf("outcomes = %v", got)
	}
}

func TestWorkerDoesNotSendTheNewDeviceNoticeToAClosedAccount(t *testing.T) {
	for name, closeAccount := range map[string]func(e *workerEnv, user *identity.User){
		"blocked": func(e *workerEnv, user *identity.User) {
			if err := user.Block(e.clock.Now()); err != nil {
				e.t.Fatal(err)
			}

			err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error { return st.Users.SetBlocked(ctx, user) })
			if err != nil {
				e.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWorkerEnv(t)
			user := e.newDeviceJob()
			closeAccount(e, user)

			e.process()

			if len(e.sender.mails()) != 0 {
				t.Error("a notice went out to a closed account")
			}

			st := e.statuses()[0]
			if st.Status != "dead" || st.LastError != "user_gone" || st.Job.ClientIP.IsValid() {
				t.Errorf("job = %+v", st)
			}

			if got := e.metrics.outcomes(); len(got) != 1 || got[0] != port.MailObsolete {
				t.Errorf("outcomes = %v", got)
			}
		})
	}
}
