package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/hub"
	"github.com/teknoir/wg-tunnel/pkg/version"
)

// runFlagsWatcher runs `wg-hub flags-watcher`: it mirrors the ztna annotations
// of every Device (metadata only) into flags ConfigMaps in HUB_NAMESPACE. It has
// no ingress and is the only ztna component with access to Device objects.
func runFlagsWatcher() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(env("LOG_LEVEL", "info"))}))
	slog.SetDefault(log)
	hubNS := env("HUB_NAMESPACE", api.HubNamespace)

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	mc, err := metadata.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	w, err := hub.NewFlagsWatcher(cs, mc, hub.FlagsWatcherConfig{Namespace: hubNS, Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := hub.NewHTTPServer(env("METRICS_ADDR", ":9090"), w.Handler())
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	go func() { errc <- w.Run(ctx) }()
	log.Info("wg-hub flags-watcher starting", "version", version.Version, "namespace", hubNS)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	stop()
	shutdown(srv)
	return runErr
}
