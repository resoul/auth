package http

import (
	"context"
	"log/slog"
)

// RequestIDHandler wraps a log handler so that every record logged with the context of a request carries its
// request_id, without the caller passing it. A line written anywhere below a handler can then be matched to the
// access line and to the id the client got in its error body. Records outside a request are left as they are.
func RequestIDHandler(inner slog.Handler) slog.Handler { return requestIDHandler{inner} }

type requestIDHandler struct{ slog.Handler }

func (h requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := requestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return requestIDHandler{h.Handler.WithAttrs(attrs)}
}

func (h requestIDHandler) WithGroup(name string) slog.Handler {
	return requestIDHandler{h.Handler.WithGroup(name)}
}
