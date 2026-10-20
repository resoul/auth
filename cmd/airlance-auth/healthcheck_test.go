package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serveReadiness(t *testing.T, status int) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

func TestHealthcheckSucceedsOnlyOnAReadyService(t *testing.T) {
	if err := checkReady(context.Background(), serveReadiness(t, http.StatusOK), time.Second); err != nil {
		t.Errorf("ready service: %v", err)
	}

	for _, status := range []int{http.StatusServiceUnavailable, http.StatusFound, http.StatusInternalServerError} {
		if err := checkReady(context.Background(), serveReadiness(t, status), time.Second); err == nil {
			t.Errorf("status %d was accepted", status)
		}
	}
}

func TestHealthcheckRefusesAddressesThatAreNotAnIPAndPort(t *testing.T) {
	for _, addr := range []string{"", "8080", ":8080", "example.com:8080", "localhost:8080"} {
		if err := checkReady(context.Background(), addr, time.Second); err == nil {
			t.Errorf("%q was accepted", addr)
		}
	}
}

func TestHealthcheckReachesAServiceListeningOnEveryInterfaceThroughTheLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("no IPv4 wildcard listener: %v", err)
	}

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
	go func() { _ = srv.Serve(ln) }()

	defer func() { _ = srv.Close() }()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := checkReady(context.Background(), "0.0.0.0:"+port, time.Second); err != nil {
		t.Errorf("0.0.0.0:%s: %v", port, err)
	}
}

func TestHealthcheckFailsWhenNothingListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := ln.Addr().String()
	_ = ln.Close()

	if err := checkReady(context.Background(), addr, time.Second); err == nil {
		t.Error("a closed port was ready")
	}
}

func TestHealthcheckGivesUpOnASlowService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	began := time.Now()

	if err := checkReady(context.Background(), strings.TrimPrefix(srv.URL, "http://"), 200*time.Millisecond); err == nil {
		t.Error("a hanging service was ready")
	}

	if time.Since(began) > 2*time.Second {
		t.Errorf("gave up after %v", time.Since(began))
	}
}

func TestHealthcheckCommandReadsTheServiceAddress(t *testing.T) {
	t.Setenv("AIRLANCE_AUTH_HTTP_ADDR", serveReadiness(t, http.StatusOK))

	cmd := newRootCommand()
	cmd.SetArgs([]string{"healthcheck"})

	if err := cmd.Execute(); err != nil {
		t.Errorf("healthcheck: %v", err)
	}

	t.Setenv("AIRLANCE_AUTH_HTTP_ADDR", "")

	cmd = newRootCommand()
	cmd.SetArgs([]string{"healthcheck"})

	if err := cmd.Execute(); err == nil {
		t.Error("healthcheck without an address succeeded")
	}
}
