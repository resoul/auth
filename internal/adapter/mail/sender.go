package mail

import (
	"context"
	"errors"
	"fmt"
	"time"

	gomail "github.com/wneessen/go-mail"

	"airlance.org/auth/internal/application/port"
)

var _ port.MailSender = (*SMTPSender)(nil)

// TLSMode says how the connection to the SMTP server is protected.
type TLSMode string

// TLS modes.
const (
	// TLSNone is plain SMTP. It is for local development only (Mailpit).
	TLSNone TLSMode = "none"
	// TLSStartTLS upgrades the connection with STARTTLS and refuses to continue without it.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit wraps the whole connection in TLS (SMTPS, usually port 465).
	TLSImplicit TLSMode = "tls"
)

// SMTPConfig describes the SMTP server and the sender address.
type SMTPConfig struct {
	Host string
	Port int
	TLS  TLSMode
	// Username and Password enable authentication; both or neither. They are never
	// sent over an unprotected connection.
	Username string
	Password string
	// FromAddress is the envelope and header sender; FromName is optional.
	FromAddress string
	FromName    string
	// Timeout bounds connecting and each SMTP command.
	Timeout time.Duration
}

// SMTPSender delivers sign-in code emails. It opens a connection per message, which is
// enough for the volume of one installation and keeps failures independent.
type SMTPSender struct {
	cfg   SMTPConfig
	clock port.Clock
}

// NewSMTPSender checks the configuration once, at assembly time.
func NewSMTPSender(cfg SMTPConfig, clock port.Clock) (*SMTPSender, error) {
	if clock == nil {
		return nil, errors.New("new smtp sender: a clock is required")
	}
	if cfg.Host == "" || cfg.Port <= 0 || cfg.Port > 65535 || cfg.FromAddress == "" {
		return nil, errors.New("new smtp sender: host, port and from address are required")
	}
	switch cfg.TLS {
	case TLSNone, TLSStartTLS, TLSImplicit:
	default:
		return nil, fmt.Errorf("new smtp sender: unknown tls mode %q", cfg.TLS)
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("new smtp sender: username and password go together")
	}
	if cfg.Username != "" && cfg.TLS == TLSNone {
		return nil, errors.New("new smtp sender: credentials are not sent without TLS")
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("new smtp sender: a positive timeout is required")
	}
	return &SMTPSender{cfg: cfg, clock: clock}, nil
}

// Send renders and delivers one email of any kind. Errors never contain the address or the code.
func (s *SMTPSender) Send(ctx context.Context, m port.Mail) error {
	subject, text, html, err := render(m, s.clock.Now())
	if err != nil {
		return err
	}

	msg := gomail.NewMsg()
	if s.cfg.FromName != "" {
		err = msg.FromFormat(s.cfg.FromName, s.cfg.FromAddress)
	} else {
		err = msg.From(s.cfg.FromAddress)
	}
	if err != nil {
		return fmt.Errorf("build mail: sender address: %w", err)
	}
	if err := msg.To(m.To.String()); err != nil {
		return fmt.Errorf("build mail: recipient address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(gomail.TypeTextPlain, text)
	msg.AddAlternativeString(gomail.TypeTextHTML, html)
	// Marks the email as machine generated, so that auto-repliers stay quiet.
	msg.SetGenHeader("Auto-Submitted", "auto-generated")

	// The library blocks on the network without watching the context, so the client
	// timeout is capped by the context deadline, and a cancellation returns at once
	// (the abandoned attempt ends by its own timeout).
	timeout := s.cfg.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return fmt.Errorf("%w: no time left to send", port.ErrMailTemporary)
	}
	opts := []gomail.Option{gomail.WithPort(s.cfg.Port), gomail.WithTimeout(timeout)}
	switch s.cfg.TLS {
	case TLSNone:
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	case TLSStartTLS:
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	case TLSImplicit:
		opts = append(opts, gomail.WithSSL())
	}
	if s.cfg.Username != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(s.cfg.Username), gomail.WithPassword(s.cfg.Password))
	}
	client, err := gomail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("%w: create smtp client", port.ErrMailTemporary)
	}
	done := make(chan error, 1)
	go func() { done <- client.DialAndSendWithContext(ctx, msg) }()
	select {
	case err := <-done:
		if err != nil {
			return classify(err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", port.ErrMailTemporary, context.Cause(ctx))
	}
}

// classify turns a go-mail error into one of ours, keeping only the stage and the SMTP
// code: the library's text can contain the recipient address.
func classify(err error) error {
	var sendErr *gomail.SendError
	if !errors.As(err, &sendErr) {
		// Connection, TLS, authentication, timeout or cancellation: worth retrying.
		return fmt.Errorf("%w: connection or protocol error", port.ErrMailTemporary)
	}
	code := sendErr.ErrorCode()
	if sendErr.IsTemp() {
		return fmt.Errorf("%w: smtp code %d", port.ErrMailTemporary, code)
	}
	switch sendErr.Reason {
	case gomail.ErrSMTPRcptTo, gomail.ErrSMTPData, gomail.ErrSMTPDataClose:
		// The server looked at this recipient or message and said no for good.
		return fmt.Errorf("%w: smtp code %d", port.ErrMailRejected, code)
	}
	// A refused sender or another stage points at our configuration, not at this mail:
	// retry, so that fixing the configuration saves the pending jobs.
	return fmt.Errorf("%w: smtp code %d", port.ErrMailTemporary, code)
}
