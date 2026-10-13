// Command wg-agent is the device side of the WireGuard ZTNA tunnel.
//
//	wg-agent init --dir D --uid U   prepare the identity directory (init container, root)
//	wg-agent run                    run the agent (configured by environment)
//	wg-agent version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/teknoir/wg-tunnel/pkg/agent"
	"github.com/teknoir/wg-tunnel/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: wg-agent init --dir DIR --uid UID | run | version")
		return 2
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintln(stdout, version.Version)
		return 0
	case "init":
		return runInit(args[1:], stderr)
	case "run":
		return runAgent(ctx, getenv, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "wg-agent: unknown command %q (want init, run or version)\n", args[0])
		return 2
	}
}

func runInit(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "identity directory (absolute path)")
	uid := fs.Int("uid", -1, "numeric owner uid (and gid) of the directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *uid < 0 || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: wg-agent init --dir DIR --uid UID")
		return 2
	}
	if err := agent.InitDir(*dir, *uid); err != nil {
		_, _ = fmt.Fprintln(stderr, "wg-agent:", err)
		return 1
	}
	return 0
}

func runAgent(ctx context.Context, getenv func(string) string, stderr io.Writer) int {
	level, err := agent.ParseLogLevel(getenv("LOG_LEVEL"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "wg-agent:", err)
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	cfg, err := agent.ConfigFromEnv(getenv)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return 2
	}
	cfg.Logger = log
	a, err := agent.New(cfg)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return 2
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("wg-agent failed", "error", err.Error())
		return 1
	}
	return 0
}
