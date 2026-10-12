package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"airlance.org/auth/internal/adapter/metrics"
	httpapi "airlance.org/auth/internal/transport/http"
)

// newMetricsServer serves GET /metrics on its own listener, so the route is not reachable through the port
// a reverse proxy publishes for the API. The listener has no authentication: bind it to the loopback or keep
// it inside the cluster or the compose network.
func newMetricsServer(addr string, logger *slog.Logger, registry *metrics.Registry) (component, net.Addr, error) {
	ln, err := listen(addr)
	if err != nil {
		return component{}, nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", registry.Handler())
	srv := httpapi.NewServer(mux, logger)
	return component{
		name: "metrics",
		run: func(context.Context) error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
		stop: srv.Shutdown,
	}, ln.Addr(), nil
}
