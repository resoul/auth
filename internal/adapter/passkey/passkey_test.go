package passkey_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	apasskey "airlance.org/auth/internal/adapter/passkey"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

const (
	rpID   = "example.test"
	origin = "https://example.test"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func service(t *testing.T) *apasskey.Service {
	t.Helper()
	s, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func subject(t *testing.T, creds ...*passkey.Credential) (port.Subject, *identity.User) {
	t.Helper()
	f := testutil.NewFactory(t, now)
	u := f.User(testutil.UserSpec{})
	return port.Subject{ID: u.ID(), Email: u.Email(), Credentials: creds}, u
}

// register runs a whole registration and returns the stored form of the new credential.
func register(t *testing.T, s *apasskey.Service, sub port.Subject, auth *testutil.SoftAuthenticator) port.RegisteredCredential {
	t.Helper()
	c, err := s.BeginRegistration(sub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.FinishRegistration(sub, c.State, auth.Register(c.Options))
	if err != nil {
		t.Fatalf("registration refused: %v", err)
	}
	return got
}

func stored(t *testing.T, sub port.Subject, r port.RegisteredCredential) *passkey.Credential {
	t.Helper()
	f := testutil.NewFactory(t, now)
	id, _ := f.IDs.NewPasskeyID()
	c, err := passkey.NewCredential(passkey.NewCredentialParams{
		ID: id, UserID: sub.ID, CredentialID: r.CredentialID, PublicKey: r.PublicKey, AAGUID: r.AAGUID,
		Transports: r.Transports, SignCount: r.SignCount, BackupEligible: r.BackupEligible, BackupState: r.BackupState,
		Name: "Test", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func lookupOf(c *passkey.Credential) port.CredentialLookup {
	return func(id []byte, handle port.UserHandle) (*passkey.Credential, error) {
		if string(id) != string(c.CredentialID()) || string(handle) != string(passkey.UserHandle(c.UserID())) {
			return nil, port.ErrNotFound
		}
		return c, nil
	}
}

func TestRegistrationOptionsDemandAResidentKeyAndUserVerification(t *testing.T) {
	s := service(t)
	existing, _ := subject(t)
	existing.Credentials = nil
	c, err := s.BeginRegistration(existing)
	if err != nil {
		t.Fatal(err)
	}
	var opts struct {
		PublicKey struct {
			RP struct {
				ID string `json:"id"`
			} `json:"rp"`
			Selection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			Attestation string `json:"attestation"`
			Params      []struct {
				Alg int `json:"alg"`
			} `json:"pubKeyCredParams"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(c.Options, &opts); err != nil {
		t.Fatal(err)
	}
	pk := opts.PublicKey
	if pk.RP.ID != rpID || pk.Selection.ResidentKey != "required" || pk.Selection.UserVerification != "required" || pk.Attestation != "none" {
		t.Errorf("options = %+v", pk)
	}
	if len(pk.Params) != 2 || pk.Params[0].Alg != -7 || pk.Params[1].Alg != -257 {
		t.Errorf("algorithms = %+v, want ES256 and RS256", pk.Params)
	}
}

func TestRegistrationAndLoginRoundTrip(t *testing.T) {
	s := service(t)
	sub, user := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)

	reg := register(t, s, sub, auth)
	if string(reg.CredentialID) != string(auth.CredentialID) || len(reg.PublicKey) == 0 {
		t.Fatalf("registered = %+v", reg)
	}
	if string(auth.UserHandle) != string(passkey.UserHandle(user.ID())) {
		t.Error("the authenticator did not receive the user handle derived from the user id")
	}
	cred := stored(t, sub, reg)

	c, err := s.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.FinishLogin(c.State, auth.Assert(c.Options), lookupOf(cred))
	if err != nil {
		t.Fatalf("login refused: %v", err)
	}
	if string(got.CredentialID) != string(auth.CredentialID) || got.SignCount != 1 || string(got.UserHandle) != string(auth.UserHandle) {
		t.Errorf("assertion = %+v", got)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	s := service(t)
	for name, mutate := range map[string]func(*testutil.SoftAuthenticator){
		"another origin":        func(a *testutil.SoftAuthenticator) { a.Origin = "https://evil.test" },
		"another relying party": func(a *testutil.SoftAuthenticator) { a.RPID = "evil.test" },
		"no user verification":  func(a *testutil.SoftAuthenticator) { a.SkipUserVerification = true },
		"http instead of https": func(a *testutil.SoftAuthenticator) { a.Origin = "http://example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			sub, _ := subject(t)
			auth := testutil.NewSoftAuthenticator(t, rpID, origin)
			mutate(auth)
			c, err := s.BeginRegistration(sub)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.FinishRegistration(sub, c.State, auth.Register(c.Options)); !errors.Is(err, port.ErrCeremonyFailed) {
				t.Errorf("err = %v, want ErrCeremonyFailed", err)
			}
		})
	}

	t.Run("a response to another challenge", func(t *testing.T) {
		sub, _ := subject(t)
		auth := testutil.NewSoftAuthenticator(t, rpID, origin)
		first, _ := s.BeginRegistration(sub)
		second, _ := s.BeginRegistration(sub)
		if _, err := s.FinishRegistration(sub, second.State, auth.Register(first.Options)); !errors.Is(err, port.ErrCeremonyFailed) {
			t.Errorf("err = %v, want ErrCeremonyFailed", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		sub, _ := subject(t)
		c, _ := s.BeginRegistration(sub)
		for _, body := range []string{"", "{}", "not json", `{"id":"x"}`} {
			if _, err := s.FinishRegistration(sub, c.State, []byte(body)); !errors.Is(err, port.ErrCeremonyFailed) {
				t.Errorf("body %q: err = %v", body, err)
			}
		}
	})
}

func TestRegistrationExcludesTheSubjectsCredentials(t *testing.T) {
	s := service(t)
	sub, _ := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	cred := stored(t, sub, register(t, s, sub, auth))
	sub.Credentials = []*passkey.Credential{cred}

	c, err := s.BeginRegistration(sub)
	if err != nil {
		t.Fatal(err)
	}
	var opts struct {
		PublicKey struct {
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(c.Options, &opts); err != nil || len(opts.PublicKey.Exclude) != 1 {
		t.Fatalf("exclude list = %+v, %v; the authenticator must be told not to register a second time", opts, err)
	}
}

func TestLoginRefusals(t *testing.T) {
	s := service(t)
	sub, _ := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	cred := stored(t, sub, register(t, s, sub, auth))

	for name, mutate := range map[string]func(*testutil.SoftAuthenticator){
		"another origin":        func(a *testutil.SoftAuthenticator) { a.Origin = "https://evil.test" },
		"another relying party": func(a *testutil.SoftAuthenticator) { a.RPID = "evil.test" },
		"no user verification":  func(a *testutil.SoftAuthenticator) { a.SkipUserVerification = true },
		"another user handle":   func(a *testutil.SoftAuthenticator) { a.UserHandle = []byte("someone else....") },
		"backup flag appears":   func(a *testutil.SoftAuthenticator) { a.BackupState = true },
	} {
		t.Run(name, func(t *testing.T) {
			attacker := *auth
			mutate(&attacker)
			c, _ := s.BeginLogin()
			if _, err := s.FinishLogin(c.State, attacker.Assert(c.Options), lookupOf(cred)); !errors.Is(err, port.ErrCeremonyFailed) {
				t.Errorf("err = %v, want ErrCeremonyFailed", err)
			}
		})
	}

	t.Run("a signature by another key", func(t *testing.T) {
		other := testutil.NewSoftAuthenticator(t, rpID, origin)
		other.CredentialID = auth.CredentialID
		other.UserHandle = auth.UserHandle
		c, _ := s.BeginLogin()
		if _, err := s.FinishLogin(c.State, other.Assert(c.Options), lookupOf(cred)); !errors.Is(err, port.ErrCeremonyFailed) {
			t.Errorf("err = %v, want ErrCeremonyFailed", err)
		}
	})

	t.Run("an assertion replayed against a new challenge", func(t *testing.T) {
		first, _ := s.BeginLogin()
		replayed := auth.Assert(first.Options)
		second, _ := s.BeginLogin()
		if _, err := s.FinishLogin(second.State, replayed, lookupOf(cred)); !errors.Is(err, port.ErrCeremonyFailed) {
			t.Errorf("err = %v, want ErrCeremonyFailed", err)
		}
	})

	t.Run("an unknown credential", func(t *testing.T) {
		stranger := testutil.NewSoftAuthenticator(t, rpID, origin)
		stranger.UserHandle = auth.UserHandle
		c, _ := s.BeginLogin()
		if _, err := s.FinishLogin(c.State, stranger.Assert(c.Options), lookupOf(cred)); !errors.Is(err, port.ErrCeremonyFailed) {
			t.Errorf("err = %v, want ErrCeremonyFailed", err)
		}
	})

	t.Run("a registration state cannot finish a login", func(t *testing.T) {
		reg, _ := s.BeginRegistration(sub)
		c, _ := s.BeginLogin()
		if _, err := s.FinishLogin(reg.State, auth.Assert(c.Options), lookupOf(cred)); !errors.Is(err, port.ErrCeremonyFailed) {
			t.Errorf("err = %v, want ErrCeremonyFailed", err)
		}
	})
}

func TestSignCountIsReportedForTheApplicationToJudge(t *testing.T) {
	s := service(t)
	sub, _ := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	cred := stored(t, sub, register(t, s, sub, auth))

	// The library does not refuse a counter that did not grow: that decision is the
	// credential's (passkey.ErrCloneSuspected), so a use that must be refused is reported.
	auth.SignCount = 0
	c, _ := s.BeginLogin()
	got, err := s.FinishLogin(c.State, auth.Assert(c.Options), lookupOf(cred))
	if err != nil || got.SignCount != 1 {
		t.Fatalf("first use = %+v, %v", got, err)
	}
	if err := cred.RecordUse(now, got.SignCount, got.BackupState); err != nil {
		t.Fatal(err)
	}
	auth.SignCount = 0 // the counter resets: a clone, or a broken device
	c, _ = s.BeginLogin()
	got, err = s.FinishLogin(c.State, auth.Assert(c.Options), lookupOf(cred))
	if err != nil {
		t.Fatalf("second use = %v: the application, not the adapter, decides about the counter", err)
	}
	if err := cred.RecordUse(now, got.SignCount, got.BackupState); !errors.Is(err, passkey.ErrCloneSuspected) {
		t.Errorf("RecordUse with counter %d after 1 = %v, want ErrCloneSuspected", got.SignCount, err)
	}
}

func TestSyncedPasskeysReportZeroCounters(t *testing.T) {
	s := service(t)
	sub, _ := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	auth.Synced, auth.BackupEligible, auth.BackupState = true, true, true
	reg := register(t, s, sub, auth)
	if !reg.BackupEligible || !reg.BackupState {
		t.Errorf("registered flags = %+v", reg)
	}
	cred := stored(t, sub, reg)
	for range 2 {
		c, _ := s.BeginLogin()
		got, err := s.FinishLogin(c.State, auth.Assert(c.Options), lookupOf(cred))
		if err != nil || got.SignCount != 0 {
			t.Fatalf("login = %+v, %v", got, err)
		}
		if err := cred.RecordUse(now, got.SignCount, got.BackupState); err != nil {
			t.Errorf("a synced key with counter zero was refused: %v", err)
		}
	}
}

func TestNativeAppOriginsAreAccepted(t *testing.T) {
	const android = "android:apk-key-hash:abc123_-xyz"
	s, err := apasskey.New(apasskey.Config{RPID: rpID, Origins: []string{origin, android}})
	if err != nil {
		t.Fatalf("an Android app origin was refused: %v", err)
	}
	sub, _ := subject(t)
	auth := testutil.NewSoftAuthenticator(t, rpID, android)
	register(t, s, sub, auth)
}

func TestNewRefusesAnIncompleteRelyingParty(t *testing.T) {
	for name, cfg := range map[string]apasskey.Config{
		"no origins":     {RPID: rpID},
		"bad RP ID":      {RPID: "not a domain!", Origins: []string{origin}},
		"unknown opaque": {RPID: rpID, Origins: []string{origin, "ftp:thing"}},
	} {
		if _, err := apasskey.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
