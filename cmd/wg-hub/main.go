// Command wg-hub is the session broker and WireGuard gateway of the ZTNA
// tunnel. See package hub.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/hub"
	"github.com/teknoir/wg-tunnel/pkg/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version.Version)
			return
		case "help", "--help", "-h":
			fmt.Println("wg-hub: WireGuard ZTNA session broker and gateway (" + version.Version + ").\n" +
				"It takes no arguments; configuration is by environment (POD_IP, DOMAIN, TURN_URLS, KEYCLOAK_ISSUER, ...).\n" +
				"Usage: wg-hub [version|--help]")
			return
		}
		fmt.Fprintf(os.Stderr, "wg-hub: unexpected argument %q (try --help)\n", os.Args[1])
		os.Exit(2)
	}
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("wg-hub failed", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func logLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(env("LOG_LEVEL", "info"))}))
	slog.SetDefault(log)

	domain := env("DOMAIN", "")
	hubNS := env("HUB_NAMESPACE", api.HubNamespace)
	podIP := env("POD_IP", "")
	if podIP == "" {
		return errors.New("POD_IP is required (downward API)")
	}
	turnURLs := hub.SplitList(env("TURN_URLS", ""))
	if len(turnURLs) == 0 && domain != "" {
		turnURLs = []string{fmt.Sprintf("turn:%s.%s:%d?transport=udp", api.TURNHostPrefix, domain, api.TURNPort)}
	}
	if len(turnURLs) == 0 {
		return errors.New("TURN_URLS or DOMAIN is required")
	}
	issuer := env("KEYCLOAK_ISSUER", "")
	if issuer == "" && domain != "" {
		issuer = "https://auth." + domain + "/auth/realms/master"
	}
	jwks := env("KEYCLOAK_JWKS_URL", "")
	if jwks == "" && issuer != "" {
		jwks = issuer + "/protocol/openid-connect/certs"
	}
	if issuer == "" {
		return errors.New("KEYCLOAK_ISSUER or DOMAIN is required")
	}
	azp := hub.SplitList(env("ALLOWED_AZP", api.KeycloakAllowedAZP))

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	mc, err := metadata.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	policy, err := hub.NewK8sPolicySource(cs, hubNS, log)
	if err != nil {
		return err
	}
	flags, err := hub.NewK8sDeviceFlags(mc)
	if err != nil {
		return err
	}
	policy.Start(ctx)
	flags.Start(ctx)

	users, err := hub.NewKeycloakVerifier(hub.KeycloakConfig{Issuer: issuer, JWKSURL: jwks, AllowedAZP: azp})
	if err != nil {
		return err
	}
	secrets, err := hub.NewK8sSecretSource(cs, env("TURN_SECRET_REF", "stunner-system/stunner-auth-secret"), 30*time.Second)
	if err != nil {
		return err
	}
	flushGrace, err := time.ParseDuration(env("FLUSH_GRACE", "300ms"))
	if err != nil || flushGrace < 0 {
		return fmt.Errorf("FLUSH_GRACE must be a non-negative duration such as 300ms: %v", err)
	}
	h, err := hub.New(hub.Config{
		FlushGrace:     flushGrace,
		Namespace:      hubNS,
		PodIP:          podIP,
		WGListenPort:   api.HubWGPort,
		ClientIPHeader: env("CLIENT_IP_HEADER", ""),
		Logger:         log,
	}, hub.Deps{
		Policy:   policy,
		Flags:    flags,
		Identity: hub.NewK8sIdentityStore(cs, hubNS),
		Users:    users,
		SA:       hub.NewK8sSADelegation(cs, hubNS),
		Authz:    hub.NewCachedAuthorizer(hub.NewK8sAuthorizer(cs), 5*time.Second, 1024),
		TURN:     hub.NewTURNMinter(secrets.Secret, turnURLs, 30*time.Minute, nil),
	})
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	log.Info("wg-hub starting", "version", version.Version, "namespace", hubNS, "wgPort", h.WGPort(), "endpoint", h.Endpoint())

	httpSrv := hub.NewHTTPServer(env("HTTP_ADDR", fmt.Sprintf(":%d", api.HubHTTPPort)), h.Handler())
	metricsSrv := hub.NewHTTPServer(env("METRICS_ADDR", ":9090"), metricsMux(h))

	errc := make(chan error, 3)
	go func() { errc <- httpSrv.ListenAndServe() }()
	go func() { errc <- metricsSrv.ListenAndServe() }()
	go func() { errc <- h.ServeTunnel(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "err", err)
			stop()
			shutdown(httpSrv, metricsSrv)
			return err
		}
	}
	shutdown(httpSrv, metricsSrv)
	return nil
}

func metricsMux(h *hub.Hub) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", h.MetricsHandler())
	return mux
}

func shutdown(srvs ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range srvs {
		_ = s.Shutdown(ctx)
	}
}
