// Package main is the thin entry point for eth-deposit-tx (orchestration moved per M2.3-5 thin-main convention; see run.go etc).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	defer stop()

	if err := newTxApp().RunContext(ctx, os.Args); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(ExitCodeFor(err))
	}
}
