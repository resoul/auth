package passkey_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func mustID(t *testing.T, s string) passkey.ID {
	t.Helper()

	id, err := passkey.ParseID(s)
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func user(t *testing.T) identity.UserID {
	t.Helper()

	id, err := identity.ParseUserID("6ba7b810-9dad-41d1-80b4-00c04fd430c8")
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func sessionID(t *testing.T) session.ID {
	t.Helper()

	id, err := session.ParseID("0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7b")
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func binding(t *testing.T, fill byte) identity.BindingHash {
	t.Helper()

	b, err := identity.NewBindingHash([]byte(strings.Repeat(string(rune(fill)), 32)))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func secret(t *testing.T) passkey.SecretHash {
	t.Helper()

	h, err := passkey.NewSecretHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	return h
}

const idText = "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"

func TestParseIDAcceptsOnlyCanonicalUUIDv7(t *testing.T) {
	if _, err := passkey.ParseID(idText); err != nil {
		t.Errorf("valid id: %v", err)
	}

	for _, bad := range []string{"", "x", strings.ToUpper(idText), "6ba7b810-9dad-41d1-80b4-00c04fd430c8", idText + "0"} {
		if _, err := passkey.ParseID(bad); !errors.Is(err, passkey.ErrInvalidID) {
			t.Errorf("ParseID(%q) = %v, want ErrInvalidID", bad, err)
		}
	}
}

func newCredential(t *testing.T, mutate func(*passkey.NewCredentialParams)) (*passkey.Credential, error) {
	t.Helper()

	p := passkey.NewCredentialParams{
		ID: mustID(t, idText), UserID: user(t), CredentialID: []byte("cred-1"), PublicKey: []byte("key"),
		Transports: []string{"internal", "hybrid", "bogus", "internal"}, Name: "  Laptop  ", Now: t0,
		BackupEligible: true,
	}
	if mutate != nil {
		mutate(&p)
	}

	return passkey.NewCredential(p)
}

func TestNewCredentialNormalizesAndValidates(t *testing.T) {
	c, err := newCredential(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	if c.Name() != "Laptop" {
		t.Errorf("name = %q", c.Name())
	}

	if got := strings.Join(c.Transports(), ","); got != "hybrid,internal" {
		t.Errorf("transports = %q, want the known ones once, in stable order", got)
	}

	for name, mutate := range map[string]func(*passkey.NewCredentialParams){
		"no credential id":           func(p *passkey.NewCredentialParams) { p.CredentialID = nil },
		"credential id too long":     func(p *passkey.NewCredentialParams) { p.CredentialID = make([]byte, passkey.MaxCredentialIDLength+1) },
		"no public key":              func(p *passkey.NewCredentialParams) { p.PublicKey = nil },
		"bad aaguid":                 func(p *passkey.NewCredentialParams) { p.AAGUID = []byte{1} },
		"empty name":                 func(p *passkey.NewCredentialParams) { p.Name = "   " },
		"long name":                  func(p *passkey.NewCredentialParams) { p.Name = strings.Repeat("я", passkey.MaxNameLength+1) },
		"control in name":            func(p *passkey.NewCredentialParams) { p.Name = "a\nb" },
		"backup without eligibility": func(p *passkey.NewCredentialParams) { p.BackupEligible, p.BackupState = false, true },
		"no user":                    func(p *passkey.NewCredentialParams) { p.UserID = identity.UserID{} },
	} {
		if _, err := newCredential(t, mutate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := newCredential(t, func(p *passkey.NewCredentialParams) { p.Name = strings.Repeat("я", passkey.MaxNameLength) }); err != nil {
		t.Errorf("a name of exactly the limit in characters: %v", err)
	}
}

func TestCredentialSignCount(t *testing.T) {
	use := func(stored, next uint32) error {
		c, err := newCredential(t, func(p *passkey.NewCredentialParams) { p.SignCount = stored })
		if err != nil {
			t.Fatal(err)
		}

		return c.RecordUse(t0.Add(time.Hour), next, false)
	}
	for name, tc := range map[string]struct {
		stored, next uint32
		wantClone    bool
	}{
		"synced key reports zero": {0, 0, false},
		"counter starts":          {0, 1, false},
		"counter grows":           {5, 6, false},
		"counter repeats":         {5, 5, true},
		"counter goes back":       {5, 4, true},
		"counter drops to zero":   {5, 0, true},
	} {
		err := use(tc.stored, tc.next)
		if tc.wantClone != errors.Is(err, passkey.ErrCloneSuspected) {
			t.Errorf("%s: err = %v, wantClone = %v", name, err, tc.wantClone)
		}
	}
}

func TestCredentialRecordUseChangesNothingOnRefusal(t *testing.T) {
	c, _ := newCredential(t, func(p *passkey.NewCredentialParams) { p.SignCount = 5 })

	before := c.Record()
	if err := c.RecordUse(t0.Add(time.Hour), 5, true); !errors.Is(err, passkey.ErrCloneSuspected) {
		t.Fatalf("err = %v", err)
	}

	if after := c.Record(); after.SignCount != before.SignCount || after.BackupState != before.BackupState || !after.LastUsedAt.IsZero() {
		t.Errorf("a refused use changed the credential: %+v", after)
	}

	if err := c.RecordUse(t0.Add(time.Hour), 6, true); err != nil || !c.LastUsedAt().Equal(t0.Add(time.Hour)) || !c.BackupState() {
		t.Errorf("use = %v, last used %v, backed up %v", err, c.LastUsedAt(), c.BackupState())
	}
}

func TestCredentialBackupStateNeedsEligibility(t *testing.T) {
	c, _ := newCredential(t, func(p *passkey.NewCredentialParams) { p.BackupEligible = false })
	if err := c.RecordUse(t0, 1, true); err == nil {
		t.Error("a credential that cannot be backed up reported a backup")
	}
}

func TestCredentialRestoreRoundTripAndAccessorsCopy(t *testing.T) {
	c, _ := newCredential(t, nil)

	back, err := passkey.RestoreCredential(c.Record())
	if err != nil || back.Name() != c.Name() || string(back.CredentialID()) != "cred-1" {
		t.Fatalf("restore = %+v, %v", back, err)
	}

	c.CredentialID()[0] = 'X'

	c.PublicKey()[0] = 'X'
	if string(c.CredentialID()) != "cred-1" || string(c.PublicKey()) != "key" {
		t.Error("accessors expose internal slices")
	}

	rec := c.Record()

	rec.PublicKey = nil
	if _, err := passkey.RestoreCredential(rec); err == nil {
		t.Error("restored a credential without a public key")
	}

	if err := c.Rename(" "); !errors.Is(err, passkey.ErrInvalidName) {
		t.Errorf("rename to blank = %v", err)
	}

	if err := c.Rename("Phone"); err != nil || c.Name() != "Phone" {
		t.Errorf("rename = %v, name %q", err, c.Name())
	}
}

func newChallenge(t *testing.T, purpose passkey.ChallengePurpose, uid identity.UserID) (*passkey.Challenge, error) {
	t.Helper()

	return passkey.NewChallenge(passkey.NewChallengeParams{
		ID: mustID(t, idText), Purpose: purpose, UserID: uid, Data: []byte(`{"challenge":"x"}`), Now: t0,
	})
}

func TestChallengeIsSingleUseAndExpires(t *testing.T) {
	c, err := newChallenge(t, passkey.ChallengeRegistration, user(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Consume(t0.Add(time.Second), passkey.ChallengeLogin); !errors.Is(err, passkey.ErrChallengePurpose) {
		t.Errorf("wrong purpose = %v", err)
	}

	if !c.ConsumedAt().IsZero() {
		t.Error("a refused consume used the challenge")
	}

	if err := c.Consume(t0.Add(passkey.ChallengeTTL), passkey.ChallengeRegistration); !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Errorf("at the expiry instant = %v", err)
	}

	if err := c.Consume(t0.Add(passkey.ChallengeTTL-time.Nanosecond), passkey.ChallengeRegistration); err != nil {
		t.Errorf("just before the expiry = %v", err)
	}

	if err := c.Consume(t0.Add(time.Minute), passkey.ChallengeRegistration); !errors.Is(err, passkey.ErrChallengeUsed) {
		t.Errorf("second use = %v", err)
	}
}

func TestChallengeValidation(t *testing.T) {
	if _, err := newChallenge(t, passkey.ChallengeLogin, identity.UserID{}); err != nil {
		t.Errorf("a discoverable login names no user: %v", err)
	}

	for _, purpose := range []passkey.ChallengePurpose{passkey.ChallengeRegistration, passkey.ChallengeStepUp} {
		if _, err := newChallenge(t, purpose, identity.UserID{}); err == nil {
			t.Errorf("%s without a user accepted", purpose)
		}
	}

	if _, err := newChallenge(t, "other", user(t)); err == nil {
		t.Error("unknown purpose accepted")
	}

	if _, err := passkey.NewChallenge(passkey.NewChallengeParams{ID: mustID(t, idText), Purpose: passkey.ChallengeLogin, Now: t0}); err == nil {
		t.Error("a challenge without ceremony data accepted")
	}

	c, _ := newChallenge(t, passkey.ChallengeRegistration, user(t))

	back, err := passkey.RestoreChallenge(c.Record())
	if err != nil || string(back.Data()) != `{"challenge":"x"}` {
		t.Errorf("restore = %v, %v", back, err)
	}
}

func TestStepUpChallengeNamesItsSessionAndOperation(t *testing.T) {
	p := passkey.NewChallengeParams{
		ID: mustID(t, idText), Purpose: passkey.ChallengeStepUp, UserID: user(t), Data: []byte("x"), Now: t0,
		SessionID: sessionID(t), Operation: passkey.OperationDeletePasskey,
	}

	c, err := passkey.NewChallenge(p)
	if err != nil || c.SessionID() != sessionID(t) || c.Operation() != passkey.OperationDeletePasskey {
		t.Fatalf("challenge = %+v, %v", c, err)
	}

	back, err := passkey.RestoreChallenge(c.Record())
	if err != nil || back.Operation() != passkey.OperationDeletePasskey {
		t.Errorf("restore = %v, %v", back, err)
	}

	for name, mutate := range map[string]func(*passkey.NewChallengeParams){
		"no session":        func(p *passkey.NewChallengeParams) { p.SessionID = session.ID{} },
		"no operation":      func(p *passkey.NewChallengeParams) { p.Operation = "" },
		"unknown operation": func(p *passkey.NewChallengeParams) { p.Operation = "wipe" },
		"a login with an operation": func(p *passkey.NewChallengeParams) {
			p.Purpose, p.UserID, p.SessionID = passkey.ChallengeLogin, identity.UserID{}, session.ID{}
		},
		"a registration with a session": func(p *passkey.NewChallengeParams) {
			p.Purpose, p.Operation = passkey.ChallengeRegistration, ""
		},
	} {
		q := p
		mutate(&q)

		if _, err := passkey.NewChallenge(q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func newTicket(t *testing.T, kind passkey.TicketKind) *passkey.Ticket {
	t.Helper()

	p := passkey.NewTicketParams{ID: mustID(t, idText), Kind: kind, UserID: user(t), SecretHash: secret(t), Now: t0}
	if kind == passkey.TicketStepUp {
		p.SessionID, p.Operation = sessionID(t), passkey.OperationDeletePasskey
	} else {
		p.Binding = binding(t, 'a')
	}

	tk, err := passkey.NewTicket(p)
	if err != nil {
		t.Fatal(err)
	}

	return tk
}

func TestTicketLifetimes(t *testing.T) {
	for kind, ttl := range map[passkey.TicketKind]time.Duration{
		passkey.TicketEnroll: passkey.EnrollTicketTTL, passkey.TicketSecondFactor: passkey.SecondFactorTicketTTL,
		passkey.TicketRecoveryEnroll: passkey.EnrollTicketTTL, passkey.TicketStepUp: passkey.StepUpTicketTTL,
	} {
		if got := newTicket(t, kind).ExpiresAt().Sub(t0); got != ttl {
			t.Errorf("%s lives %v, want %v", kind, got, ttl)
		}
	}

	if passkey.StepUpTicketTTL != 5*time.Minute {
		t.Error("step-up window must be 5 minutes")
	}
}

func TestTicketUseIsBoundAndSingleUse(t *testing.T) {
	enroll := passkey.Presented{Kind: passkey.TicketEnroll, Binding: binding(t, 'a')}
	tk := newTicket(t, passkey.TicketEnroll)

	for name, p := range map[string]passkey.Presented{
		"other kind":    {Kind: passkey.TicketSecondFactor, Binding: binding(t, 'a')},
		"other binding": {Kind: passkey.TicketEnroll, Binding: binding(t, 'b')},
		"no binding":    {Kind: passkey.TicketEnroll},
	} {
		if err := tk.Use(t0.Add(time.Minute), p); !errors.Is(err, passkey.ErrTicketMismatch) {
			t.Errorf("%s: err = %v, want a mismatch", name, err)
		}
	}

	if !tk.ConsumedAt().IsZero() {
		t.Fatal("a refused use consumed the ticket")
	}

	if err := tk.Check(t0.Add(time.Minute), enroll); err != nil || !tk.ConsumedAt().IsZero() {
		t.Errorf("check = %v, consumed %v", err, tk.ConsumedAt())
	}

	if err := tk.Use(t0.Add(time.Minute), enroll); err != nil {
		t.Fatal(err)
	}

	if err := tk.Use(t0.Add(2*time.Minute), enroll); !errors.Is(err, passkey.ErrTicketUsed) {
		t.Errorf("second use = %v", err)
	}

	late := newTicket(t, passkey.TicketEnroll)
	if err := late.Use(t0.Add(passkey.EnrollTicketTTL), enroll); !errors.Is(err, passkey.ErrTicketExpired) {
		t.Errorf("at the expiry instant = %v", err)
	}
}

func TestStepUpTicketIsBoundToSessionAndOperation(t *testing.T) {
	tk := newTicket(t, passkey.TicketStepUp)
	other, _ := session.ParseID("0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7d")
	good := passkey.Presented{Kind: passkey.TicketStepUp, SessionID: sessionID(t), Operation: passkey.OperationDeletePasskey}

	for name, p := range map[string]passkey.Presented{
		"other session":   {Kind: passkey.TicketStepUp, SessionID: other, Operation: passkey.OperationDeletePasskey},
		"other operation": {Kind: passkey.TicketStepUp, SessionID: sessionID(t), Operation: passkey.OperationChangeEmail},
		"no operation":    {Kind: passkey.TicketStepUp, SessionID: sessionID(t)},
	} {
		if err := tk.Use(t0.Add(time.Minute), p); !errors.Is(err, passkey.ErrTicketMismatch) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	if err := tk.Use(t0.Add(time.Minute), good); err != nil {
		t.Errorf("matching use = %v", err)
	}
}

func TestTicketValidation(t *testing.T) {
	base := passkey.NewTicketParams{ID: mustID(t, idText), Kind: passkey.TicketEnroll, UserID: user(t), SecretHash: secret(t), Binding: binding(t, 'a'), Now: t0}
	for name, mutate := range map[string]func(*passkey.NewTicketParams){
		"unknown kind":           func(p *passkey.NewTicketParams) { p.Kind = "other" },
		"no user":                func(p *passkey.NewTicketParams) { p.UserID = identity.UserID{} },
		"no secret":              func(p *passkey.NewTicketParams) { p.SecretHash = passkey.SecretHash{} },
		"enroll without binding": func(p *passkey.NewTicketParams) { p.Binding = identity.BindingHash{} },
		"enroll with a session":  func(p *passkey.NewTicketParams) { p.SessionID = sessionID(t) },
		"step-up without session": func(p *passkey.NewTicketParams) {
			p.Kind, p.Operation = passkey.TicketStepUp, passkey.OperationAddPasskey
		},
		"step-up with unknown operation": func(p *passkey.NewTicketParams) {
			p.Kind, p.SessionID, p.Operation, p.Binding = passkey.TicketStepUp, sessionID(t), "wipe", identity.BindingHash{}
		},
	} {
		p := base
		mutate(&p)

		if _, err := passkey.NewTicket(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	tk := newTicket(t, passkey.TicketStepUp)
	if back, err := passkey.RestoreTicket(tk.Record()); err != nil || back.Operation() != passkey.OperationDeletePasskey {
		t.Errorf("restore = %v, %v", back, err)
	}

	if _, err := passkey.NewSecretHash([]byte("short")); err == nil {
		t.Error("a short hash accepted")
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	const canonical = "ABCDEFGHJKLMNPQR"
	for in, want := range map[string]string{
		canonical:               canonical,
		"abcd-efgh-jklm-npqr":   canonical,
		" ABCD EFGH JKLM NPQR ": canonical,
		"abcdefghjklmnpqr":      canonical,
	} {
		if got, ok := passkey.NormalizeRecoveryCode(in); !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v", in, got, ok)
		}
	}

	for _, bad := range []string{"", "ABCD", canonical + "A", "ABCDEFGH1JKLMNPQ", "ABCDEFGHJKLMNPQ!", "ABCDEFGHJKLMNPQЯ"} {
		if got, ok := passkey.NormalizeRecoveryCode(bad); ok {
			t.Errorf("Normalize(%q) = %q, want a refusal", bad, got)
		}
	}

	if got := passkey.FormatRecoveryCode(canonical); got != "ABCD-EFGH-JKLM-NPQR" {
		t.Errorf("format = %q", got)
	}

	if got, _ := passkey.NormalizeRecoveryCode(passkey.FormatRecoveryCode(canonical)); got != canonical {
		t.Error("format and normalize do not round-trip")
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	c, err := passkey.NewRecoveryCode(mustID(t, idText), user(t), secret(t), t0)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Use(t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := c.Use(t0.Add(2 * time.Hour)); !errors.Is(err, passkey.ErrRecoveryCodeUsed) {
		t.Errorf("second use = %v", err)
	}

	if !c.UsedAt().Equal(t0.Add(time.Hour)) {
		t.Errorf("used at %v: a refused use must keep the first time", c.UsedAt())
	}

	if _, err := passkey.RestoreRecoveryCode(c.Record()); err != nil {
		t.Errorf("restore: %v", err)
	}

	if _, err := passkey.NewRecoveryCode(passkey.ID{}, user(t), secret(t), t0); err == nil {
		t.Error("a code without an id accepted")
	}
}
