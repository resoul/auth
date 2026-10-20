package config

import "log/slog"

// Secret holds a value that must not appear in logs or error messages. Printing it
// with any fmt verb or logging it yields a placeholder; Reveal returns the value.
type Secret struct {
	value string
}

// NewSecret wraps v.
func NewSecret(v string) Secret {
	return Secret{value: v}
}

// Reveal returns the wrapped value for the one place that needs it.
func (s Secret) Reveal() string {
	return s.value
}

// IsSet reports whether a value was provided.
func (s Secret) IsSet() bool {
	return s.value != ""
}

// String implements fmt.Stringer.
func (s Secret) String() string {
	return "[redacted]"
}

// GoString implements fmt.GoStringer.
func (s Secret) GoString() string {
	return "config.Secret{[redacted]}"
}

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// MarshalText implements encoding.TextMarshaler so encoders cannot leak the value.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte("[redacted]"), nil
}
