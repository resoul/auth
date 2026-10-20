package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/config"
)

func TestSecretNeverPrintsItsValue(t *testing.T) {
	const value = "hunter2"

	s := config.NewSecret(value)
	cfg := config.Config{Database: config.DatabaseConfig{URL: s}}

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("loaded", "secret", s, "database", cfg.Database, "config", cfg)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("loaded", "secret", s, "config", cfg)
	encoded, _ := json.Marshal(cfg)

	outputs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%s|%q", s, s),
		fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg),
		logs.String(), string(encoded),
	}
	for _, out := range outputs {
		if strings.Contains(out, value) {
			t.Errorf("output %q leaks the secret", out)
		}
	}

	if s.Reveal() != value || !s.IsSet() {
		t.Error("Reveal/IsSet broken")
	}

	if config.NewSecret("").IsSet() {
		t.Error("empty secret reports set")
	}
}
