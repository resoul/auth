package main

import (
	"context"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/resoul/api/cmd"
	"github.com/sirupsen/logrus"
)

var cleanupWaitGroup sync.WaitGroup

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func main() {
	execCtx, execCancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGINT,
	)
	defer execCancel()

	go func() {
		<-execCtx.Done()
		logrus.Info("received graceful shutdown signal")
	}()

	if err := cmd.RootCommand(&cleanupWaitGroup).ExecuteContext(execCtx); err != nil {
		logrus.WithError(err).Fatal("application crash")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	cleanupDone := make(chan struct{})

	go func() {
		cleanupWaitGroup.Wait()
		close(cleanupDone)
	}()

	select {
	case <-shutdownCtx.Done():
		logrus.Error("cleanup timed out: some resources might not have closed properly")
		return

	case <-cleanupDone:
		logrus.Info("all resources closed, graceful shutdown complete")
		return
	}
}
