package http

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type noMetrics struct{}

func (noMetrics) RequestServed(string, int, time.Duration) {}
func (noMetrics) AuthDenied(string, string)                {}

func TestRefusalsThatSuggestAStolenSecretAreWarnings(t *testing.T) {
	cases := map[string]slog.Level{
		"token_reused":    slog.LevelWarn,
		"clone_suspected": slog.LevelWarn,
		"bad_code":        slog.LevelDebug,
		"rate_limited":    slog.LevelDebug,
		"blocked":         slog.LevelDebug,
	}
	for reason, want := range cases {
		var out bytes.Buffer

		logger := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
		a := &API{logger: logger, requests: noMetrics{}}
		a.denied(context.Background(), "refresh", reason)

		if !strings.Contains(out.String(), "level="+want.String()) || !strings.Contains(out.String(), "reason="+reason) {
			t.Errorf("%s logged %q, want level %s", reason, strings.TrimSpace(out.String()), want)
		}
	}

	// At the default level the routine ones are silent and the warnings are not.
	var out bytes.Buffer

	a := &API{logger: slog.New(slog.NewTextHandler(&out, nil)), requests: noMetrics{}}
	a.denied(context.Background(), "verify", "bad_code")

	if out.Len() != 0 {
		t.Errorf("a routine refusal was logged at the default level: %q", out.String())
	}

	a.denied(context.Background(), "refresh", "token_reused")

	if !strings.Contains(out.String(), "token_reused") {
		t.Errorf("a reused token was not logged at the default level: %q", out.String())
	}
}
