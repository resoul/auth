package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// KeyringFormatVersion is the only keyring format this build understands.
const KeyringFormatVersion = 1

// Keyring is the parsed key configuration: file references and key IDs only.
// Key material is loaded by the adapters that use it, never by this package.
type Keyring struct {
	FormatVersion int     `json:"format_version"`
	OTPHMAC       *KeySet `json:"otp_hmac"`
	JWTSigning    *KeySet `json:"jwt_signing"`
	// OIDCSigning holds the RS256 keys of the OpenID Provider. It is separate from JWTSigning: the ES256 keys of the
	// /v1 API and these publish in different key sets, so enabling OIDC changes nothing for existing verifiers.
	OIDCSigning *KeySet `json:"oidc_signing"`
}

// KeySet lists the keys of one purpose and the key used for new operations.
type KeySet struct {
	ActiveKID string            `json:"active_kid"`
	Keys      map[string]KeyRef `json:"keys"`
}

// KeyRef points at the secret file that holds one key.
type KeyRef struct {
	KeyFile string `json:"key_file"`
}

// LoadKeyring reads and validates the keyring schema from path.
func LoadKeyring(path string) (*Keyring, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's own setting, not request input
	if err != nil {
		return nil, fmt.Errorf("read keyring file: %w", err)
	}

	ring, err := ParseKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("keyring file %s: %w", path, err)
	}

	return ring, nil
}

// ParseKeyring validates the keyring schema: known format version, no unknown
// fields, no duplicate JSON keys or kids, and an active kid present in every
// declared purpose. Errors never include file contents.
func ParseKeyring(data []byte) (*Keyring, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var ring Keyring
	if err := dec.Decode(&ring); err != nil {
		return nil, fmt.Errorf("decode keyring: %s", describeDecodeError(err))
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode keyring: unexpected data after top-level object")
	}

	if err := ring.validate(); err != nil {
		return nil, err
	}

	return &ring, nil
}

// validate checks the schema only. Presence of key files, base64/PEM content and
// key types is verified by the adapter that needs the purpose.
func (k *Keyring) validate() error {
	if k.FormatVersion != KeyringFormatVersion {
		return fmt.Errorf("unsupported format_version %d, want %d", k.FormatVersion, KeyringFormatVersion)
	}

	return errors.Join(
		validateKeySet("otp_hmac", k.OTPHMAC),
		validateKeySet("jwt_signing", k.JWTSigning),
		validateKeySet("oidc_signing", k.OIDCSigning),
	)
}

func validateKeySet(purpose string, set *KeySet) error {
	if set == nil {
		return nil
	}

	if len(set.Keys) == 0 {
		return fmt.Errorf("%s: keys must not be empty", purpose)
	}

	var errs []error

	for kid, ref := range set.Keys {
		if kid == "" {
			errs = append(errs, fmt.Errorf("%s: empty kid", purpose))
		}

		if ref.KeyFile == "" {
			errs = append(errs, fmt.Errorf("%s: kid %q has no key_file", purpose, kid))
		}
	}

	if _, ok := set.Keys[set.ActiveKID]; !ok {
		errs = append(errs, fmt.Errorf("%s: active_kid %q is not in keys", purpose, set.ActiveKID))
	}

	return errors.Join(errs...)
}

// rejectDuplicateKeys fails on a repeated key inside any JSON object, which
// encoding/json would silently resolve to the last value.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSON(dec); err != nil {
		return fmt.Errorf("decode keyring: %s", describeDecodeError(err))
	}

	return nil
}

func walkJSON(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})

		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}

			key, _ := keyTok.(string)
			if _, dup := seen[key]; dup {
				return fmt.Errorf("duplicate key %q", key)
			}

			seen[key] = struct{}{}

			if err := walkJSON(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec); err != nil {
				return err
			}
		}
	}

	_, err = dec.Token() // closing delimiter

	return err
}

// describeDecodeError reduces a JSON error to its position and kind so that the
// message cannot echo file contents.
func describeDecodeError(err error) string {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Sprintf("invalid JSON at offset %d", syntaxErr.Offset)
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Sprintf("field %q has an invalid type", typeErr.Field)
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected end of JSON"
	}

	return err.Error()
}
