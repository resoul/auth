package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"airlance.org/auth/internal/bootstrap"
	"airlance.org/auth/internal/config"
	httpapi "airlance.org/auth/internal/transport/http"
)

func TestEveryRecordOfARequestCarriesItsRequestID(t *testing.T) {
	for _, format := range []string{config.LogFormatJSON, config.LogFormatText} {
		var out bytes.Buffer
		logger := bootstrap.NewLogger(&out, config.LogConfig{Level: slog.LevelDebug, Format: format})

		var header string
		handler := httpapi.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A record logged deep below the handler, with only the context: no one passed the id.
			logger.WarnContext(r.Context(), "something happened", "route", "x")
			header = w.Header().Get(httpapi.RequestIDHeader)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

		if header == "" || !strings.Contains(out.String(), header) {
			t.Errorf("%s: the record %q does not carry the request id %q", format, out.String(), header)
		}
		if format == config.LogFormatJSON {
			var rec map[string]any
			if err := json.Unmarshal(out.Bytes(), &rec); err != nil || rec["request_id"] != header {
				t.Errorf("json record = %v, %v; want request_id %q", rec, err, header)
			}
		}
	}
}

func TestRecordsOutsideARequestHaveNoRequestID(t *testing.T) {
	var out bytes.Buffer
	logger := bootstrap.NewLogger(&out, config.LogConfig{Level: slog.LevelInfo, Format: config.LogFormatJSON})
	logger.InfoContext(context.Background(), "service started")
	if strings.Contains(out.String(), "request_id") {
		t.Errorf("a startup record carries a request id: %s", out.String())
	}
}

func TestLoggerKeepsItsAttributesAndGroups(t *testing.T) {
	var out bytes.Buffer
	logger := bootstrap.NewLogger(&out, config.LogConfig{Level: slog.LevelInfo, Format: config.LogFormatJSON}).With("version", "1.2.3")
	logger.Info("hello")
	if !strings.Contains(out.String(), `"version":"1.2.3"`) {
		t.Errorf("With lost its attribute: %s", out.String())
	}
}
