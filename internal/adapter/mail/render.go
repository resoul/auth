package mail

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"math"
	"net/url"
	texttemplate "text/template"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/session"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// message is one kind of email: its subject and its plain text and HTML templates. No subject
// contains a code.
type message struct {
	subject string
	text    *texttemplate.Template
	html    *htmltemplate.Template
}

func newMessage(subject, name string) message {
	return message{
		subject: subject,
		text:    texttemplate.Must(texttemplate.ParseFS(templateFS, "templates/"+name+".txt.tmpl")),
		html:    htmltemplate.Must(htmltemplate.ParseFS(templateFS, "templates/"+name+".html.tmpl")),
	}
}

var (
	signInMessage       = newMessage("Your sign-in code", "login_code")
	confirmEmailMessage = newMessage("Confirm your new email address", "confirm_email")
	emailChangedMessage = newMessage("The email address of your account changed", "email_changed")
	invitationMessage   = newMessage("You have been invited", "invitation")
	newDeviceMessage    = newMessage("New sign-in to your account", "new_device")
)

type loginData struct {
	Code    string
	Minutes int
	Link    string
	Until   string
	Device  string
	Address string
	When    string
}

// validLink accepts the place an invitation points to: an https address, or http on the local machine for
// development, with no credentials in it.
func validLink(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
		return false
	}

	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}

	return false
}

// render returns the subject and the plain text and HTML bodies of a mail. The kinds with a
// code need an eight-digit one; the notice has none and must not be given one.
func render(m port.Mail, now time.Time) (subject, text, html string, err error) {
	var msg message

	switch m.Kind {
	case port.MailSignIn:
		msg = signInMessage
	case port.MailConfirmEmail:
		msg = confirmEmailMessage
	case port.MailEmailChanged:
		msg = emailChangedMessage
	case port.MailInvitation:
		msg = invitationMessage
	case port.MailNewDevice:
		msg = newDeviceMessage
	default:
		return "", "", "", fmt.Errorf("render mail: unknown kind %q", m.Kind)
	}

	data := loginData{}

	switch m.Kind {
	case port.MailEmailChanged:
		if m.Code != "" {
			return "", "", "", errors.New("render mail: a notice carries no code")
		}
	case port.MailInvitation:
		if m.Code != "" {
			return "", "", "", errors.New("render mail: an invitation carries no code")
		}

		if !validLink(m.Link) || m.ExpiresAt.IsZero() {
			return "", "", "", errors.New("render mail: an invitation needs a valid link and an end")
		}

		data = loginData{Link: m.Link, Until: m.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")}
	case port.MailNewDevice:
		if m.Code != "" {
			return "", "", "", errors.New("render mail: a notice carries no code")
		}

		if m.At.IsZero() || !session.ValidDeviceName(m.DeviceName) {
			return "", "", "", errors.New("render mail: a new device notice needs a time and a valid device name")
		}

		data = loginData{Device: m.DeviceName, Address: "unknown", When: m.At.UTC().Format("2006-01-02 15:04 UTC")}
		if data.Device == "" {
			data.Device = "not named"
		}

		if m.ClientIP.IsValid() {
			data.Address = m.ClientIP.Unmap().String()
		}
	default:
		if len(m.Code) != 8 {
			return "", "", "", errors.New("render mail: code must have 8 digits")
		}

		minutes := max(int(math.Ceil(m.ExpiresAt.Sub(now).Minutes())), 1)
		data = loginData{Code: m.Code[:4] + " " + m.Code[4:], Minutes: minutes}
	}

	var t, h bytes.Buffer
	if err := msg.text.Execute(&t, data); err != nil {
		return "", "", "", fmt.Errorf("render mail text: %w", err)
	}

	if err := msg.html.Execute(&h, data); err != nil {
		return "", "", "", fmt.Errorf("render mail html: %w", err)
	}

	return msg.subject, t.String(), h.String(), nil
}
