// Package main is the thin entry point for eth-deposit-gen (orchestration in internal/cli per M2.3-5 thin-main; mains ≤~30 LOC, no orchestration).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ucli "github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/rootwarp/eth-utils/go/internal/cli"
)

// version, commit, and date are set at build time via -ldflags.
// Default values are used for local/dev builds.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	defer stop()

	app := cli.NewApp(cli.Run)
	app.Version = version
	ucli.VersionPrinter = func(cmd *ucli.Command) {
		fmt.Fprintf(cmd.Writer, "%s version %s (commit=%s, built=%s)\n",
			cmd.Name, cmd.Version, commit, date)
	}
	if err := app.Run(ctx, os.Args); err != nil {
		os.Exit(exitCodeFor(err))
	}
}
