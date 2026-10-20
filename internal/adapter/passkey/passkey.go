package passkey

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"go.airlance.org/auth/internal/application/port"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

var _ port.WebAuthn = (*Service)(nil)

// Config is the relying party.
type Config struct {
	// RPID is the registrable domain the credentials are bound to, such as example.com or localhost.
	RPID string
	// RPName is the display name shown by the authenticator.
	RPName string
	// Origins are the exact origins that may run a ceremony: https origins of web pages, http
	// only for localhost, and the opaque origins of native apps such as android:apk-key-hash:...
	Origins []string
}

// Service runs WebAuthn ceremonies for one relying party.
type Service struct {
	wa *webauthn.WebAuthn
}

// New validates the relying party and builds the service.
func New(cfg Config) (*Service, error) {
	var origins, opaque []string

	for _, o := range cfg.Origins {
		if protocol.IsOpaqueOrigin(o) {
			opaque = append(opaque, o)
		} else {
			origins = append(origins, o)
		}
	}

	name := cfg.RPName
	if name == "" {
		name = cfg.RPID
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: name, RPOrigins: origins, RPOpaqueOrigins: opaque,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: new(true),
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: dpasskey.ChallengeTTL, TimeoutUVD: dpasskey.ChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: dpasskey.ChallengeTTL, TimeoutUVD: dpasskey.ChallengeTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new webauthn: %w", err)
	}

	return &Service{wa: wa}, nil
}

// credentialParams are the algorithms a new credential may use: ES256 and RS256.
var credentialParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

type user struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return u.id }
func (u user) WebAuthnName() string                       { return u.name }
func (u user) WebAuthnDisplayName() string                { return u.name }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func subjectUser(s port.Subject) user {
	u := user{id: dpasskey.UserHandle(s.ID), name: s.Email.String()}
	for _, c := range s.Credentials {
		u.credentials = append(u.credentials, libraryCredential(c))
	}

	return u
}

// libraryCredential rebuilds what the library needs to verify an assertion.
func libraryCredential(c *dpasskey.Credential) webauthn.Credential {
	flags := protocol.FlagUserPresent | protocol.FlagUserVerified
	if c.BackupEligible() {
		flags |= protocol.FlagBackupEligible
	}

	if c.BackupState() {
		flags |= protocol.FlagBackupState
	}

	var transports []protocol.AuthenticatorTransport
	for _, t := range c.Transports() {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}

	return webauthn.Credential{
		ID: c.CredentialID(), PublicKey: c.PublicKey(), Transport: transports,
		Flags:         webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID(), SignCount: c.SignCount()},
	}
}

func descriptors(creds []*dpasskey.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		d := protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.CredentialID()}
		for _, t := range c.Transports() {
			d.Transport = append(d.Transport, protocol.AuthenticatorTransport(t))
		}

		out = append(out, d)
	}

	return out
}

// BeginRegistration prepares a registration that needs a resident key and user verification.
func (s *Service) BeginRegistration(subject port.Subject) (port.Ceremony, error) {
	creation, state, err := s.wa.BeginRegistration(subjectUser(subject),
		webauthn.WithCredentialParameters(credentialParams),
		webauthn.WithExclusions(descriptors(subject.Credentials)),
	)
	if err != nil {
		return port.Ceremony{}, fmt.Errorf("begin registration: %w", err)
	}

	return ceremony(creation, state)
}

// FinishRegistration verifies the client's attestation. Any refusal is port.ErrCeremonyFailed.
func (s *Service) FinishRegistration(subject port.Subject, state, response []byte) (port.RegisteredCredential, error) {
	session, err := decodeState(state)
	if err != nil {
		return port.RegisteredCredential{}, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return port.RegisteredCredential{}, fmt.Errorf("%w: parse: %w", port.ErrCeremonyFailed, err)
	}

	cred, err := s.wa.CreateCredential(subjectUser(subject), session, parsed)
	if err != nil {
		return port.RegisteredCredential{}, fmt.Errorf("%w: %w", port.ErrCeremonyFailed, err)
	}

	if !cred.Flags.UserVerified {
		return port.RegisteredCredential{}, fmt.Errorf("%w: user verification is required", port.ErrCeremonyFailed)
	}

	var transports []string
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	return port.RegisteredCredential{
		CredentialID: cred.ID, PublicKey: cred.PublicKey, AAGUID: cred.Authenticator.AAGUID, Transports: transports,
		SignCount: cred.Authenticator.SignCount, BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
	}, nil
}

// BeginLogin prepares a discoverable assertion that needs user verification.
func (s *Service) BeginLogin() (port.Ceremony, error) {
	assertion, state, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return port.Ceremony{}, fmt.Errorf("begin login: %w", err)
	}

	return ceremony(assertion, state)
}

// FinishLogin verifies the client's assertion. Any refusal is port.ErrCeremonyFailed.
func (s *Service) FinishLogin(state, response []byte, lookup port.CredentialLookup) (port.VerifiedAssertion, error) {
	session, err := decodeState(state)
	if err != nil {
		return port.VerifiedAssertion{}, err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return port.VerifiedAssertion{}, fmt.Errorf("%w: parse: %w", port.ErrCeremonyFailed, err)
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		stored, err := lookup(rawID, userHandle)
		if err != nil {
			return nil, err
		}

		return user{id: slices.Clone(userHandle), credentials: []webauthn.Credential{libraryCredential(stored)}}, nil
	}

	_, cred, err := s.wa.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return port.VerifiedAssertion{}, fmt.Errorf("%w: %w", port.ErrCeremonyFailed, err)
	}

	return port.VerifiedAssertion{
		CredentialID: cred.ID, UserHandle: parsed.Response.UserHandle,
		SignCount: cred.Authenticator.SignCount, BackupState: cred.Flags.BackupState,
	}, nil
}

func ceremony(options any, state *webauthn.SessionData) (port.Ceremony, error) {
	opts, err := json.Marshal(options)
	if err != nil {
		return port.Ceremony{}, fmt.Errorf("encode options: %w", err)
	}

	st, err := json.Marshal(state)
	if err != nil {
		return port.Ceremony{}, fmt.Errorf("encode ceremony state: %w", err)
	}

	return port.Ceremony{Options: opts, State: st}, nil
}

// decodeState reads the stored state. The library compares its own expiry to the system
// clock; the application expires a challenge by its injected clock, so the library's check is
// switched off here.
func decodeState(state []byte) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return webauthn.SessionData{}, fmt.Errorf("decode ceremony state: %w", err)
	}

	session.Expires = time.Time{}

	return session, nil
}
