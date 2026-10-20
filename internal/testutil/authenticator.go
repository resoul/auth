package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// SoftAuthenticator is a software WebAuthn authenticator with one ES256 credential. It
// builds the JSON a browser would send after navigator.credentials.create and .get, so
// tests run the real ceremonies without a browser. The exported fields are the knobs of
// negative tests: change one and the next response is wrong in exactly that way.
type SoftAuthenticator struct {
	t   testing.TB
	key *ecdsa.PrivateKey
	// CredentialID is the ID the authenticator registers under.
	CredentialID []byte
	// RPID and Origin are what the authenticator believes it talks to.
	RPID   string
	Origin string
	// UserHandle is learned at registration from the options.
	UserHandle []byte
	// SignCount is the counter reported by the next assertion; Assert increments it first.
	// Set Synced to report zero, as synced passkeys do.
	SignCount uint32
	Synced    bool
	// SkipUserVerification clears the UV flag, as an authenticator that could not verify the user.
	SkipUserVerification bool
	// BackupEligible and BackupState are the BE and BS flags.
	BackupEligible, BackupState bool
}

// NewSoftAuthenticator returns an authenticator for a relying party.
func NewSoftAuthenticator(t testing.TB, rpID, origin string) *SoftAuthenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}

	return &SoftAuthenticator{t: t, key: key, CredentialID: id, RPID: rpID, Origin: origin}
}

var b64 = base64.RawURLEncoding

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

// Register answers the registration options with an attestation of format none.
func (a *SoftAuthenticator) Register(options []byte) []byte {
	a.t.Helper()

	var opts creationOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		a.t.Fatalf("registration options: %v", err)
	}

	handle, err := b64.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		a.t.Fatalf("user handle: %v", err)
	}

	a.UserHandle = handle

	pub, err := a.key.PublicKey.ECDH()
	if err != nil {
		a.t.Fatal(err)
	}

	raw := pub.Bytes() // 0x04 || X || Y

	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		a.t.Fatal(err)
	}

	authData := a.authData(a.flags()|0x40, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID: all zeros, as for a platform authenticator without attestation
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.CredentialID)))
	authData = append(authData, a.CredentialID...)
	authData = append(authData, cose...)

	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		a.t.Fatal(err)
	}

	return a.encode(map[string]any{
		"id": b64.EncodeToString(a.CredentialID), "rawId": b64.EncodeToString(a.CredentialID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", opts.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attestation),
			"transports":        []string{"internal"},
		},
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
	})
}

// Assert answers the request options with a signed assertion.
func (a *SoftAuthenticator) Assert(options []byte) []byte {
	a.t.Helper()

	var opts requestOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		a.t.Fatalf("request options: %v", err)
	}

	a.SignCount++

	counter := a.SignCount
	if a.Synced {
		counter = 0
	}

	authData := a.authData(a.flags(), counter)
	clientData := a.clientData("webauthn.get", opts.PublicKey.Challenge)
	hash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte(nil), authData...), hash[:]...))

	sig, err := ecdsa.SignASN1(rand.Reader, a.key, signed[:])
	if err != nil {
		a.t.Fatal(err)
	}

	return a.encode(map[string]any{
		"id": b64.EncodeToString(a.CredentialID), "rawId": b64.EncodeToString(a.CredentialID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.UserHandle),
		},
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
	})
}

func (a *SoftAuthenticator) flags() byte {
	flags := byte(0x01) // user present
	if !a.SkipUserVerification {
		flags |= 0x04
	}

	if a.BackupEligible {
		flags |= 0x08
	}

	if a.BackupState {
		flags |= 0x10
	}

	return flags
}

func (a *SoftAuthenticator) authData(flags byte, counter uint32) []byte {
	hash := sha256.Sum256([]byte(a.RPID))
	out := append([]byte(nil), hash[:]...)
	out = append(out, flags)

	return binary.BigEndian.AppendUint32(out, counter)
}

func (a *SoftAuthenticator) clientData(kind, challenge string) []byte {
	data, err := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	if err != nil {
		a.t.Fatal(err)
	}

	return data
}

func (a *SoftAuthenticator) encode(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		a.t.Fatal(err)
	}

	return data
}
