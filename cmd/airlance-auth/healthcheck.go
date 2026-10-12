package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// newHealthcheckCommand asks the service on this machine whether it is ready, for a container
// health check: the image has no shell and no curl. It reads the same AIRLANCE_AUTH_HTTP_ADDR as serve
// and talks to that address, or to the loopback when it listens on every interface.
func newHealthcheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 when the service on AIRLANCE_AUTH_HTTP_ADDR is ready",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return checkReady(cmd.Context(), os.Getenv("AIRLANCE_AUTH_HTTP_ADDR"), 3*time.Second)
		},
	}
}

func checkReady(ctx context.Context, addr string, timeout time.Duration) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return errors.New("healthcheck: AIRLANCE_AUTH_HTTP_ADDR must be a host:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("healthcheck: AIRLANCE_AUTH_HTTP_ADDR must be an IP address with a port")
	}
	if ip.IsUnspecified() {
		// 0.0.0.0 and [::] accept connections on every interface, this one included.
		host = "127.0.0.1"
		if ip.To4() == nil {
			host = "::1"
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/health/ready", nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return errors.New("healthcheck: the service is not reachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: the service answered %d", resp.StatusCode)
	}
	return nil
}
