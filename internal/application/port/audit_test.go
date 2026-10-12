package port_test

import (
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
)

var at = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestAuditEventValidation(t *testing.T) {
	valid := port.AuditEvent{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at,
		Fields: map[string]string{"method": "otp", "new_user": "true", "quota_class": "unknown", "reason": "token_reused"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid event was rejected: %v", err)
	}
	if err := (port.AuditEvent{Type: port.AuditSessionRevoked, Result: port.AuditDenied, At: at}).Validate(); err != nil {
		t.Errorf("an event without fields was rejected: %v", err)
	}

	tests := map[string]port.AuditEvent{
		"unknown type":     {Type: "login", Result: port.AuditSuccess, At: at},
		"no type":          {Result: port.AuditSuccess, At: at},
		"unknown result":   {Type: port.AuditLoginSucceeded, Result: "ok", At: at},
		"no time":          {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess},
		"email as a field": {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": "alice@example.test"}},
		"ip as a field":    {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": "203.0.113.7"}},
		"free text":        {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": "wrong code for Alice"}},
		"upper case":       {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": "Token"}},
		"empty value":      {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": ""}},
		"long value":       {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"reason": strings.Repeat("a", 65)}},
		"unlisted key":     {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"email": "x"}},
		"user agent key":   {Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: at, Fields: map[string]string{"user_agent": "curl"}},
	}
	for name, e := range tests {
		if err := e.Validate(); err == nil {
			t.Errorf("%s: Validate accepted the event", name)
		}
	}
}
