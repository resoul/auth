package quota

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

// MaxWindow is the longest window a profile may hold, so counters never outlive a day.
const MaxWindow = 24 * time.Hour

// Kind is the quota being spent.
type Kind string

// Quota kinds.
const (
	KindSend   Kind = "send"
	KindVerify Kind = "verify"
	// KindPasskey is the start of a passkey ceremony: it writes a challenge row for a caller
	// who has not proven anything yet.
	KindPasskey Kind = "passkey"
	// KindAdmin is a step of an operator's ceremony on the admin listener; it has its own budget so
	// that guessing there never shares a limit with the public passkey endpoints.
	KindAdmin Kind = "admin"
	// KindDevice is the start of a device sign-in: it writes a request row for a caller who has proven nothing.
	KindDevice Kind = "device"
	// KindOIDC is the start of a sign-in through the OpenID Provider: it writes a request row for a browser that
	// has proven nothing yet.
	KindOIDC Kind = "oidc"
)

// Spend identifies one quota expenditure. Now is the time of the request; the window
// arithmetic uses it, not a clock of the storage.
type Spend struct {
	Kind               Kind
	Email              identity.Email
	Class              authflow.QuotaClass
	RecognizedClientID identity.RecognizedClientID
	Binding            identity.BindingHash
	// IP is the client address behind trusted proxies. The zero value means unknown;
	// the email-send IP budgets then do not apply, and a passkey spend draws from one shared
	// budget of unknown addresses.
	IP netip.Addr
	// Ref names the object a passkey spend is about, such as the ticket whose registration is
	// being started; it keeps one ticket from filling the table.
	Ref string
	Now time.Time
}

// Scope names one budget.
type Scope string

// Scopes. An email-wide scope is shared by every unknown client of the address; the
// recognized scopes belong to one recognition record.
const (
	UnknownSendEmail       Scope = "unknown_send_email"
	UnknownVerifyEmail     Scope = "unknown_verify_email"
	UnknownSendPair        Scope = "unknown_send_pair"
	UnknownVerifyPair      Scope = "unknown_verify_pair"
	UnknownSendIP          Scope = "unknown_send_ip"
	RecognizedSendClient   Scope = "recognized_send_client"
	RecognizedVerifyClient Scope = "recognized_verify_client"
	RecognizedSendIP       Scope = "recognized_send_ip"
	// PasskeyIP bounds the ceremonies one address may start; PasskeyRef bounds one ticket's.
	PasskeyIP  Scope = "passkey_ip"
	PasskeyRef Scope = "passkey_ref"
	// AdminIP bounds the ceremony steps one address may take on the admin listener.
	AdminIP Scope = "admin_ip"
	// DeviceIP bounds the device sign-in requests one address may start.
	DeviceIP Scope = "device_ip"
	// OIDCAuthorizeIP bounds the sign-ins one address may start through the OpenID Provider.
	OIDCAuthorizeIP Scope = "oidc_authorize_ip"
)

// Window allows Limit spends in any period of length Per.
type Window struct {
	Limit int
	Per   time.Duration
}

// Profile maps each scope to the windows that all apply at once. A scope without
// windows is unlimited.
type Profile struct {
	windows map[Scope][]Window
}

// NewProfile validates and copies the windows.
func NewProfile(windows map[Scope][]Window) (Profile, error) {
	p := Profile{windows: make(map[Scope][]Window, len(windows))}
	for scope, ws := range windows {
		if !knownScope(scope) {
			return Profile{}, fmt.Errorf("quota profile: unknown scope %q", scope)
		}

		for _, w := range ws {
			if w.Limit < 0 || w.Per <= 0 || w.Per > MaxWindow {
				return Profile{}, fmt.Errorf("quota profile: %s: window %d per %v is out of range (0 < per <= %v)", scope, w.Limit, w.Per, MaxWindow)
			}
		}

		p.windows[scope] = append([]Window(nil), ws...)
	}

	return p, nil
}

// Unlimited is the profile without any budget, for tests and tools.
func Unlimited() Profile { return Profile{} }

// DefaultProfile is the working profile. Pair and IP budgets are provisional values
// that only narrow the address-wide budgets.
func DefaultProfile() Profile {
	p, err := NewProfile(map[Scope][]Window{
		UnknownSendEmail:       {{10, 24 * time.Hour}},
		UnknownVerifyEmail:     {{50, 24 * time.Hour}},
		UnknownSendPair:        {{5, time.Hour}},
		UnknownVerifyPair:      {{20, 24 * time.Hour}},
		UnknownSendIP:          {{20, time.Hour}},
		RecognizedSendClient:   {{5, time.Hour}, {20, 24 * time.Hour}},
		RecognizedVerifyClient: {{20, 24 * time.Hour}},
		RecognizedSendIP:       {{100, time.Hour}},
		PasskeyIP:              {{60, time.Hour}},
		PasskeyRef:             {{10, time.Hour}},
		AdminIP:                {{30, time.Hour}},
		DeviceIP:               {{30, time.Hour}},
		// An office behind one address signs many people in at the start of a day; a flood still ends.
		OIDCAuthorizeIP: {{60, time.Minute}, {600, time.Hour}},
	})
	if err != nil {
		panic(err)
	}

	return p
}

func knownScope(s Scope) bool {
	switch s {
	case UnknownSendEmail, UnknownVerifyEmail, UnknownSendPair, UnknownVerifyPair, UnknownSendIP,
		RecognizedSendClient, RecognizedVerifyClient, RecognizedSendIP, PasskeyIP, PasskeyRef, AdminIP, DeviceIP, OIDCAuthorizeIP:
		return true
	}

	return false
}

// Windows returns the windows of a scope.
func (p Profile) Windows(s Scope) []Window { return p.windows[s] }

// Limit is one budget a spend draws from: the windows of Scope applied to Key.
type Limit struct {
	Scope   Scope
	Key     string
	Windows []Window
}

// Limits lists the budgets a spend draws from. Every one must have room, and then all
// are charged together. Unknown clients draw from the shared address budget, so a new
// binding, flow or IP never opens a new one; a recognized client draws from its own.
func (p Profile) Limits(s Spend) ([]Limit, error) {
	if s.Kind != KindSend && s.Kind != KindVerify && s.Kind != KindPasskey && s.Kind != KindAdmin && s.Kind != KindDevice && s.Kind != KindOIDC {
		return nil, fmt.Errorf("quota: unknown spend kind %q", s.Kind)
	}

	if s.Now.IsZero() {
		return nil, errors.New("quota: the time of the spend is required")
	}

	ip := ""
	if s.IP.IsValid() {
		ip = ipKey(s.IP)
	}

	var limits []Limit

	add := func(scope Scope, key string) {
		if ws := p.windows[scope]; len(ws) > 0 {
			limits = append(limits, Limit{Scope: scope, Key: key, Windows: ws})
		}
	}

	if s.Kind == KindOIDC {
		if ip == "" {
			ip = "unknown"
		}

		add(OIDCAuthorizeIP, ip)

		return limits, nil
	}

	if s.Kind == KindDevice {
		if ip == "" {
			ip = "unknown"
		}

		add(DeviceIP, ip)

		return limits, nil
	}

	if s.Kind == KindAdmin {
		if ip == "" {
			ip = "unknown"
		}

		add(AdminIP, ip)

		return limits, nil
	}

	if s.Kind == KindPasskey {
		// Every caller is unknown here: no email is known yet. An unknown address shares one budget
		// rather than escaping the limit.
		if ip == "" {
			ip = "unknown"
		}

		add(PasskeyIP, ip)

		if s.Ref != "" {
			add(PasskeyRef, s.Ref)
		}

		return limits, nil
	}

	switch s.Class {
	case authflow.QuotaUnknown:
		pair := s.Email.String() + "\x00" + hex.EncodeToString(s.Binding.Bytes())
		if s.Kind == KindSend {
			add(UnknownSendEmail, s.Email.String())
			add(UnknownSendPair, pair)

			if ip != "" {
				add(UnknownSendIP, ip)
			}
		} else {
			add(UnknownVerifyEmail, s.Email.String())
			add(UnknownVerifyPair, pair)
		}
	case authflow.QuotaRecognized:
		if s.RecognizedClientID.IsZero() {
			return nil, errors.New("quota: a recognized spend needs the recognition record")
		}

		client := s.Email.String() + "\x00" + s.RecognizedClientID.String()
		if s.Kind == KindSend {
			add(RecognizedSendClient, client)

			if ip != "" {
				add(RecognizedSendIP, ip)
			}
		} else {
			add(RecognizedVerifyClient, client)
		}
	default:
		return nil, fmt.Errorf("quota: unknown class %q", s.Class)
	}

	return limits, nil
}

// ipKey groups IPv6 by /64, the smallest block a subscriber normally owns, so that
// rotating inside one cannot mint new budgets. IPv4-mapped addresses count as IPv4.
func ipKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}

	return a.String()
}
