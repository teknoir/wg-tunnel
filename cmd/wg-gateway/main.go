// Command wg-gateway is the web gateway of a device: the second container of
// the per-device wgt- pod. It publishes the device's web services to browsers
// through the ingress, over the ZTNA tunnel. See package gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/gateway"
	"github.com/teknoir/wg-tunnel/pkg/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version.Version)
		return
	}
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("wg-gateway failed", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("wg-gateway", flag.ContinueOnError)
	var (
		hubURL    = fs.String("hub-url", "", "hub internal session API, e.g. http://wg-hub.teknoir-ztna.svc.cluster.local:8081")
		namespace = fs.String("namespace", "", "teamspace of the device")
		device    = fs.String("device", "", "name of the device")
		tokenFile = fs.String("sa-token-file", "/var/run/ztna/token", "projected service account token (audience teknoir-ztna)")
		listen    = fs.String("listen", ":8090", "address to serve on")
		idle      = fs.Duration("idle-timeout", 15*time.Minute, "close a service's hub session after this long without requests")
		strip     = fs.String("strip-cookies", os.Getenv("STRIP_COOKIES"), "comma-separated extra cookie names never forwarded to the device (env STRIP_COOKIES); platform login cookies are always stripped")
		level     = fs.String("log-level", "info", "debug, info, warn or error")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*level)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	g, err := gateway.New(gateway.Config{
		HubURL: *hubURL, Namespace: *namespace, Device: *device, TokenFile: *tokenFile,
		IdleTimeout: *idle, Logger: log, StripCookies: splitList(*strip),
	})
	if err != nil {
		return err
	}
	defer g.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    256 << 10,
		// No read or write timeout: downloads, long polls and WebSockets
		// legitimately run for hours.
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("wg-gateway starting", "version", version.Version, "namespace", *namespace, "device", *device, "listen", *listen)
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
