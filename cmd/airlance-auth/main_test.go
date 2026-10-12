package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	old := buildVersion
	buildVersion = "v1.2.3"
	t.Cleanup(func() { buildVersion = old })

	var out bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "v1.2.3" {
		t.Errorf("output = %q, want v1.2.3", got)
	}
}

func TestServeRejectsInvalidConfig(t *testing.T) {
	t.Setenv("AIRLANCE_AUTH_LOG_LEVEL", "loud")

	cmd := newRootCommand()
	cmd.SetArgs([]string{"serve"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "AIRLANCE_AUTH_LOG_LEVEL") {
		t.Fatalf("Execute error = %v, want AIRLANCE_AUTH_LOG_LEVEL", err)
	}
}

func TestServeRejectsArguments(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"serve", "extra"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute succeeded with extra argument")
	}
}

func TestMigrateNeedsADatabase(t *testing.T) {
	t.Setenv("AIRLANCE_AUTH_DATABASE_URL", "")
	for _, action := range []string{"up", "down", "status"} {
		cmd := newRootCommand()
		cmd.SetArgs([]string{"migrate", action})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "AIRLANCE_AUTH_DATABASE_URL") {
			t.Errorf("migrate %s error = %v, want a request for AIRLANCE_AUTH_DATABASE_URL", action, err)
		}
	}
}
