package bootstrap

import (
	"io"
	"log/slog"

	"go.airlance.org/auth/internal/config"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

// NewLogger builds the process logger. Handlers log only the attributes passed
// to them; callers must keep secrets out of attributes. A record logged with the
// context of a request carries its request_id without the caller passing it.
func NewLogger(w io.Writer, cfg config.LogConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.Level}

	var inner slog.Handler = slog.NewJSONHandler(w, opts)
	if cfg.Format == config.LogFormatText {
		inner = slog.NewTextHandler(w, opts)
	}

	return slog.New(httpapi.RequestIDHandler(inner))
}
