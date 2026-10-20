package authflow_test

import (
	"reflect"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

func TestRecordRoundTripKeepsEveryState(t *testing.T) {
	f := testutil.NewFactory(t, start)

	pending := f.Flow(testutil.FlowSpec{})

	consumed := f.Flow(testutil.FlowSpec{})

	attempt, _ := consumed.Reserve(start, authflow.PurposeLogin, binding(), policy)
	if err := consumed.Accept(attempt, start); err != nil {
		t.Fatal(err)
	}

	locked := f.Flow(testutil.FlowSpec{})
	for i := 0; i < policy.MaxAttempts; i++ {
		attempt, _ := locked.Reserve(start, authflow.PurposeLogin, binding(), policy)
		if err := locked.Reject(attempt, start, policy); err != nil {
			t.Fatal(err)
		}
	}

	expired := f.Flow(testutil.FlowSpec{})
	expired.ExpireIfDue(start.Add(policy.TTL))

	clientID, _ := f.IDs.NewRecognizedClientID()
	recognized := f.Flow(testutil.FlowSpec{QuotaClass: authflow.QuotaRecognized, RecognizedClientID: clientID})

	for name, flow := range map[string]*authflow.Flow{
		"pending": pending, "consumed": consumed, "locked": locked, "expired": expired, "recognized": recognized,
	} {
		t.Run(name, func(t *testing.T) {
			restored, err := authflow.Restore(flow.Record())
			if err != nil {
				t.Fatalf("Restore: %v", err)
			}

			if !reflect.DeepEqual(restored.Record(), flow.Record()) {
				t.Errorf("round trip changed record:\n got %+v\nwant %+v", restored.Record(), flow.Record())
			}
		})
	}
}

func TestRestoreRejectsImpossibleRecords(t *testing.T) {
	f := testutil.NewFactory(t, start)
	clientID, _ := f.IDs.NewRecognizedClientID()
	good := f.Flow(testutil.FlowSpec{}).Record()

	tests := []struct {
		name   string
		mutate func(*authflow.Record)
	}{
		{"zero id", func(r *authflow.Record) { r.ID = authflow.FlowID{} }},
		{"zero email", func(r *authflow.Record) { r.Email = identity.Email{} }},
		{"unknown purpose", func(r *authflow.Record) { r.Purpose = "other" }},
		{"zero generation", func(r *authflow.Record) { r.Generation = 0 }},
		{"no key id", func(r *authflow.Record) { r.KeyID = "" }},
		{"zero binding", func(r *authflow.Record) { r.BindingHash = identity.BindingHash{} }},
		{"unknown state", func(r *authflow.Record) { r.State = "done" }},
		{"zero created", func(r *authflow.Record) { r.CreatedAt = time.Time{} }},
		{"expires before created", func(r *authflow.Record) { r.ExpiresAt = r.CreatedAt }},
		{"zero resend", func(r *authflow.Record) { r.ResendAfter = time.Time{} }},
		{"negative attempts", func(r *authflow.Record) { r.Attempts = -1 }},
		{"unknown quota class", func(r *authflow.Record) { r.QuotaClass = "vip" }},
		{"recognized without client", func(r *authflow.Record) { r.QuotaClass = authflow.QuotaRecognized }},
		{"unknown with client", func(r *authflow.Record) { r.RecognizedClientID = clientID }},
		{"pending without salt", func(r *authflow.Record) { r.Salt = nil }},
		{"pending short salt", func(r *authflow.Record) { r.Salt = r.Salt[:4] }},
		{"consumed keeps salt", func(r *authflow.Record) { r.State = authflow.StateConsumed }},
		{"locked keeps salt", func(r *authflow.Record) { r.State = authflow.StateLocked }},
		{"expired keeps salt", func(r *authflow.Record) { r.State = authflow.StateExpired }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			r.Salt = append([]byte(nil), good.Salt...)
			tt.mutate(&r)

			if _, err := authflow.Restore(r); err == nil {
				t.Error("Restore accepted an impossible record")
			}
		})
	}
}

func TestParseFlowID(t *testing.T) {
	id, err := (&testutil.SequentialIDs{}).NewFlowID()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := authflow.ParseFlowID(id.String())
	if err != nil || parsed != id {
		t.Fatalf("ParseFlowID(%q) = %q, %v", id, parsed, err)
	}

	if len(id.String()) != 22 {
		t.Errorf("flow id %q has %d chars, want 22", id, len(id.String()))
	}

	for _, in := range []string{
		"", "short", id.String() + "A", id.String() + "=", "AAAAAAAAAAAAAAAAAAAAA+", "AAAAAAAAAAAAAAAAAAAAAB", // extra/padding/not url alphabet/non-canonical tail
		"AAECAwQFBgcICQoLDA0ODw\n", "AAECAwQFBgc\nICQoLDA0ODw", "AAECAwQFBgcICQoLDA0ODw\r\n", // the decoder would skip line breaks
	} {
		if _, err := authflow.ParseFlowID(in); err == nil {
			t.Errorf("ParseFlowID(%q) succeeded", in)
		}
	}
}

func TestNewBindingHashRequiresSHA256Length(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := identity.NewBindingHash(make([]byte, n)); err == nil {
			t.Errorf("NewBindingHash accepted %d bytes", n)
		}
	}

	hash, err := identity.NewBindingHash(make([]byte, identity.BindingHashLength))
	if err != nil || hash.IsZero() || len(hash.Bytes()) != identity.BindingHashLength {
		t.Errorf("NewBindingHash(32 bytes) = %+v, %v", hash, err)
	}
}
