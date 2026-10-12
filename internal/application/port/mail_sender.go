package port

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// Errors a MailSender returns; anything else is treated as temporary.
var (
	// ErrMailTemporary means delivery failed for a reason that may pass: the server is
	// unreachable, busy or slow.
	ErrMailTemporary = errors.New("mail delivery failed temporarily")
	// ErrMailRejected means the server refused this message for good, for example an
	// unknown recipient. Retrying cannot help.
	ErrMailRejected = errors.New("mail was rejected")
)

// MailKind picks the message. The zero value is the sign-in code.
type MailKind string

// Mail kinds.
const (
	// MailSignIn carries the code that proves an address for signing in.
	MailSignIn MailKind = ""
	// MailConfirmEmail carries the code that proves a new address for an existing account.
	MailConfirmEmail MailKind = "confirm_email"
	// MailEmailChanged tells the old address that the account moved. It has no code.
	MailEmailChanged MailKind = "email_changed"
	// MailInvitation tells an address that it may register, with a link to the place to do it.
	MailInvitation MailKind = "invitation"
	// MailNewDevice tells the user that a device or an app they had not used before signed in. It has no code.
	MailNewDevice MailKind = "new_device"
)

// Mail is an email the service sends. Code and the address are personal data and secrets:
// implementations must not log them. Code is set for every kind but MailEmailChanged.
type Mail struct {
	Kind      MailKind
	To        identity.Email
	Code      string
	ExpiresAt time.Time
	// Link is where an invited address goes to sign in; set for MailInvitation only. ExpiresAt is then
	// the end of the invitation.
	Link string
	// DeviceName, ClientIP and At describe the sign-in of MailNewDevice: the label the client gave, the address it
	// came from (the zero value is unknown) and when. At is in any zone; the message shows UTC.
	DeviceName string
	ClientIP   netip.Addr
	At         time.Time
}

// MailSender delivers one email over SMTP, outside any database transaction.
type MailSender interface {
	// Send returns nil when the server accepted the message, or an error wrapping
	// ErrMailTemporary or ErrMailRejected.
	Send(ctx context.Context, m Mail) error
}
