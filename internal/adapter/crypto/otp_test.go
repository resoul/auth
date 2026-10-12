package crypto_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

// Vectors were produced by an independent implementation of the derivation formula.
var (
	vectorKey   = seq(0, 32)                     // 000102…1f
	vectorSalt  = seq(16, 16)                    // 101112…1f
	vectorFlow  = [16]byte(seq(0, 16))           // flow id AAECAwQFBgcICQoLDA0ODw
	vectorOther = bytes.Repeat([]byte{0xff}, 32) // second key
	t0          = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
)

func seq(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(from + i)
	}
	return b
}

type vector struct {
	name       string
	key        []byte
	purpose    authflow.Purpose
	generation uint64
	salt       []byte
	want       string
}

var vectors = []vector{
	{"login", vectorKey, authflow.PurposeLogin, 1, vectorSalt, "74747300"},
	{"step_up with leading zero", vectorKey, authflow.PurposeStepUp, 1, vectorSalt, "95089668"},
	{"change_email", vectorKey, authflow.PurposeChangeEmail, 1, vectorSalt, "53145064"},
	{"generation 2", vectorKey, authflow.PurposeLogin, 2, vectorSalt, "51894861"},
	{"generation above 32 bits", vectorKey, authflow.PurposeLogin, 1<<32 + 1, vectorSalt, "27085356"},
	{"zero salt", vectorKey, authflow.PurposeLogin, 1, make([]byte, 16), "60114303"},
	{"other key", vectorOther, authflow.PurposeLogin, 1, vectorSalt, "68388518"},
	{"two leading zeros", vectorKey, authflow.PurposeLogin, 297, vectorSalt, "74136578"},
	{"three leading zeros", vectorKey, authflow.PurposeLogin, 1321, vectorSalt, "68968100"},
}

func newOTP(t *testing.T, active string, keys map[string][]byte) *crypto.OTP {
	t.Helper()
	ring, err := crypto.NewOTPKeyring(active, keys)
	if err != nil {
		t.Fatalf("NewOTPKeyring: %v", err)
	}
	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		t.Fatalf("NewOTP: %v", err)
	}
	return otp
}

func flow(t *testing.T, purpose authflow.Purpose, generation uint64, salt []byte, keyID string) *authflow.Flow {
	t.Helper()
	email, err := identity.ParseEmail("alice@example.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := authflow.Record{
		ID: authflow.NewFlowID(vectorFlow), Email: email, Purpose: purpose, Generation: generation,
		Salt: salt, KeyID: keyID, BindingHash: testutil.BindingHash("b"), State: authflow.StatePending,
		CreatedAt: t0, ExpiresAt: t0.Add(time.Minute), ResendAfter: t0, QuotaClass: authflow.QuotaUnknown,
	}
	if purpose == authflow.PurposeChangeEmail {
		rec.UserID, err = identity.ParseUserID("3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f")
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := authflow.Restore(rec)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	return f
}

func TestCodeKnownValues(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			otp := newOTP(t, "k", map[string][]byte{"k": v.key})
			got, err := otp.Code(flow(t, v.purpose, v.generation, v.salt, "k"))
			if err != nil {
				t.Fatalf("Code: %v", err)
			}
			if got != v.want {
				t.Errorf("Code = %q, want %q", got, v.want)
			}
		})
	}
}

func TestCodeKeepsLeadingZerosAndEightDigits(t *testing.T) {
	otp := newOTP(t, "k", map[string][]byte{"k": vectorKey})
	for _, v := range vectors {
		got, _ := otp.Code(flow(t, v.purpose, v.generation, v.salt, "k"))
		if len(got) != 8 || strings.Trim(got, "0123456789") != "" {
			t.Errorf("%s: code %q is not eight digits", v.name, got)
		}
	}
	got, _ := otp.Code(flow(t, authflow.PurposeLogin, 1321, vectorSalt, "k"))
	if got != "68968100" {
		t.Errorf("leading zeros lost: %q", got)
	}
}

func TestCodeDependsOnEveryInput(t *testing.T) {
	base := flow(t, authflow.PurposeLogin, 1, vectorSalt, "a")
	otp := newOTP(t, "a", map[string][]byte{"a": vectorKey, "b": vectorOther})
	want, err := otp.Code(base)
	if err != nil {
		t.Fatal(err)
	}

	otherSalt := append([]byte(nil), vectorSalt...)
	otherSalt[15] ^= 1
	otherFlow := vectorFlow
	otherFlow[15] ^= 1
	record := base.Record()
	record.ID = authflow.NewFlowID(otherFlow)
	flowOther, err := authflow.Restore(record)
	if err != nil {
		t.Fatal(err)
	}

	for name, f := range map[string]*authflow.Flow{
		"salt":       flow(t, authflow.PurposeLogin, 1, otherSalt, "a"),
		"generation": flow(t, authflow.PurposeLogin, 2, vectorSalt, "a"),
		"purpose":    flow(t, authflow.PurposeStepUp, 1, vectorSalt, "a"),
		"key":        flow(t, authflow.PurposeLogin, 1, vectorSalt, "b"),
		"flow id":    flowOther,
	} {
		got, err := otp.Code(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == want {
			t.Errorf("changing %s kept the code %q", name, got)
		}
	}
}

func TestCodeIsStableAcrossProviders(t *testing.T) {
	f := flow(t, authflow.PurposeLogin, 1, vectorSalt, "k")
	a, _ := newOTP(t, "k", map[string][]byte{"k": vectorKey}).Code(f)
	b, _ := newOTP(t, "k", map[string][]byte{"k": vectorKey, "z": vectorOther}).Code(f)
	if a != b {
		t.Errorf("worker and verifier derived different codes: %q vs %q", a, b)
	}
}

func TestRotationUsesTheKeyRecordedInTheFlow(t *testing.T) {
	old := flow(t, authflow.PurposeLogin, 1, vectorSalt, "old")
	before := newOTP(t, "old", map[string][]byte{"old": vectorKey})
	want, _ := before.Code(old)

	after := newOTP(t, "new", map[string][]byte{"old": vectorKey, "new": vectorOther})
	got, err := after.Code(old)
	if err != nil || got != want {
		t.Errorf("Code with rotated active key = %q, %v; want %q", got, err, want)
	}
	if gen, err := after.NewGeneration(); err != nil || gen.KeyID != "new" {
		t.Errorf("NewGeneration = %+v, %v; want active key new", gen, err)
	}
}

func TestUnknownKeyIDIsAnErrorWithoutFallback(t *testing.T) {
	otp := newOTP(t, "active", map[string][]byte{"active": vectorKey})

	_, err := otp.Code(flow(t, authflow.PurposeLogin, 1, vectorSalt, "removed"))
	if !errors.Is(err, crypto.ErrUnknownOTPKey) {
		t.Fatalf("Code error = %v, want ErrUnknownOTPKey", err)
	}
	ok, err := otp.Matches(flow(t, authflow.PurposeLogin, 1, vectorSalt, "removed"), "74747300")
	if ok || !errors.Is(err, crypto.ErrUnknownOTPKey) {
		t.Errorf("Matches = %v, %v; want false and ErrUnknownOTPKey", ok, err)
	}
}

func TestClosedFlowHasNoCode(t *testing.T) {
	f := testutil.NewFactory(t, t0).Flow(testutil.FlowSpec{KeyID: "k"})
	attempt, err := f.Reserve(t0, authflow.PurposeLogin, testutil.BindingHash(testutil.DefaultBindingSecret), authflow.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Accept(attempt, t0); err != nil {
		t.Fatal(err)
	}

	otp := newOTP(t, "k", map[string][]byte{"k": vectorKey})
	if _, err := otp.Code(f); !errors.Is(err, crypto.ErrNoOTPSalt) {
		t.Errorf("Code error = %v, want ErrNoOTPSalt", err)
	}
	if ok, err := otp.Matches(f, "74747300"); ok || !errors.Is(err, crypto.ErrNoOTPSalt) {
		t.Errorf("Matches = %v, %v; want false and ErrNoOTPSalt", ok, err)
	}
}

func TestMatches(t *testing.T) {
	otp := newOTP(t, "k", map[string][]byte{"k": vectorKey})
	f := flow(t, authflow.PurposeStepUp, 1, vectorSalt, "k") // code 05821141

	tests := []struct {
		name, submitted string
		want            bool
	}{
		{"correct", "95089668", true},
		{"wrong", "95089669", false},
		{"leading zero dropped", "5089668", false},
		{"extra leading zero", "095089668", false},
		{"grouped with space", "9508 9668", false},
		{"surrounding space", " 95089668", false},
		{"trailing newline", "95089668\n", false},
		{"empty", "", false},
		{"letters", "9508966a", false},
		{"fullwidth digits", "９５０８９６６８", false},
		{"arabic indic digits", "٩٥٠٨٩٦٦٨", false},
		{"sign", "+5089668", false},
		{"too long", "950896689", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := otp.Matches(f, tt.submitted)
			if err != nil {
				t.Fatalf("Matches: %v", err)
			}
			if got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.submitted, got, tt.want)
			}
		})
	}
}

func TestMatchesOnlyForTheCurrentGeneration(t *testing.T) {
	otp := newOTP(t, "k", map[string][]byte{"k": vectorKey})
	gen1 := flow(t, authflow.PurposeLogin, 1, vectorSalt, "k")
	gen2 := flow(t, authflow.PurposeLogin, 2, vectorSalt, "k")

	oldCode, _ := otp.Code(gen1)
	if ok, err := otp.Matches(gen2, oldCode); err != nil || ok {
		t.Errorf("code of generation 1 matched generation 2: %v, %v", ok, err)
	}
}

func TestNewGenerationDrawsFreshSaltAndActiveKey(t *testing.T) {
	otp := newOTP(t, "active", map[string][]byte{"active": vectorKey, "old": vectorOther})
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		gen, err := otp.NewGeneration()
		if err != nil {
			t.Fatalf("NewGeneration: %v", err)
		}
		if len(gen.Salt) != authflow.SaltLength || gen.KeyID != "active" {
			t.Fatalf("generation = %+v", gen)
		}
		if seen[string(gen.Salt)] {
			t.Fatal("salt repeated")
		}
		seen[string(gen.Salt)] = true
	}
}

func TestNewGenerationFailsWithoutRandomBytes(t *testing.T) {
	ring, _ := crypto.NewOTPKeyring("k", map[string][]byte{"k": vectorKey})
	boom := errors.New("entropy unavailable")
	for name, source := range map[string]interface{ Read([]byte) (int, error) }{
		"error": failingReader{err: boom}, "short": bytes.NewReader(make([]byte, 15)),
	} {
		t.Run(name, func(t *testing.T) {
			otp, err := crypto.NewOTP(ring, source)
			if err != nil {
				t.Fatal(err)
			}
			gen, err := otp.NewGeneration()
			if err == nil || gen.Salt != nil || gen.KeyID != "" {
				t.Fatalf("NewGeneration = %+v, %v; want error and no material", gen, err)
			}
		})
	}
}

func TestNewOTPRequiresKeyring(t *testing.T) {
	if _, err := crypto.NewOTP(nil, nil); err == nil {
		t.Error("NewOTP accepted nil keyring")
	}
}

func TestSaltAndKeyStayOutOfErrorsAndFormatting(t *testing.T) {
	otp := newOTP(t, "k", map[string][]byte{"k": vectorKey})
	_, err := otp.Code(flow(t, authflow.PurposeLogin, 1, vectorSalt, "missing"))
	if err == nil {
		t.Fatal("expected error")
	}
	secrets := []string{
		string(vectorSalt), fmt.Sprintf("%x", vectorSalt), base64.StdEncoding.EncodeToString(vectorSalt),
		string(vectorKey), fmt.Sprintf("%x", vectorKey), base64.StdEncoding.EncodeToString(vectorKey),
	}
	ring, _ := crypto.NewOTPKeyring("k", map[string][]byte{"k": vectorKey})
	outputs := []string{err.Error(), fmt.Sprintf("%v", ring), fmt.Sprintf("%+v", ring), fmt.Sprintf("%#v", ring), fmt.Sprintf("%v", otp)}
	for _, out := range outputs {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("output %q leaks secret material", out)
			}
		}
	}
}
