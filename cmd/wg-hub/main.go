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
				"Without arguments it runs the hub; configuration is by environment (POD_IP, DOMAIN, TURN_URLS, KEYCLOAK_ISSUER, ...).\n" +
				"'wg-hub flags-watcher' runs the Device flags mirror (HUB_NAMESPACE, LOG_LEVEL, METRICS_ADDR); it is the only\n" +
				"component that reads Devices.\n" +
				"Usage: wg-hub [flags-watcher|version|--help]")
			return
		case "flags-watcher":
			if len(os.Args) > 2 {
				fmt.Fprintf(os.Stderr, "wg-hub flags-watcher: unexpected argument %q\n", os.Args[2])
				os.Exit(2)
			}
			if err := runFlagsWatcher(); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("wg-hub flags-watcher failed", "err", err)
				os.Exit(1)
			}
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	policy, err := hub.NewK8sPolicySource(cs, hubNS, log)
	if err != nil {
		return err
	}
	flags, err := hub.NewK8sFlagsSource(cs, hubNS, log)
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
	// The status listener (live status and admin actions for the Backstage
	// backend) is off unless STATUS_ADDR is set; it then needs BACKSTAGE_SA, the
	// full username of the Backstage service account.
	statusAddr := env("STATUS_ADDR", "")
	backstageSA := env("BACKSTAGE_SA", "")
	if statusAddr != "" && backstageSA == "" {
		return errors.New("STATUS_ADDR needs BACKSTAGE_SA (system:serviceaccount:<namespace>:<name>)")
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
		BackstageSA:    backstageSA,
		Logger:         log,
	}, hub.Deps{
		Policy:   policy,
		Flags:    flags,
		Identity: hub.NewK8sIdentityStore(cs, hubNS),
		Users:    users,
		SA:       hub.NewK8sSADelegation(cs, hubNS),
		Authz:    hub.NewCachedAuthorizer(hub.NewK8sAuthorizer(cs), 5*time.Second, 1024),
		TURN:     hub.NewTURNMinter(secrets.Secret, turnURLs, 30*time.Minute, nil),
		Status:   hub.NewK8sStatusAuth(cs, env("STATUS_AUDIENCE", api.StatusTokenAudience)),
	})
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	log.Info("wg-hub starting", "version", version.Version, "namespace", hubNS, "wgPort", h.WGPort(), "endpoint", h.Endpoint())

	// The outside API (users and devices through the ingress gateways) and the
	// internal API (service-account delegation and direct sessions from pods
	// in the hub namespace; no VirtualService routes to it).
	httpSrv := hub.NewHTTPServer(env("HTTP_ADDR", fmt.Sprintf(":%d", api.HubHTTPPort)), h.Handler())
	internalSrv := hub.NewHTTPServer(env("INTERNAL_HTTP_ADDR", fmt.Sprintf(":%d", api.HubInternalPort)), h.InternalHandler())
	metricsSrv := hub.NewHTTPServer(env("METRICS_ADDR", ":9090"), metricsMux(h))

	srvs := []*http.Server{httpSrv, internalSrv, metricsSrv}
	errc := make(chan error, 5)
	if statusAddr != "" {
		statusSrv := hub.NewHTTPServer(statusAddr, h.StatusHandler())
		srvs = append(srvs, statusSrv)
		go func() { errc <- statusSrv.ListenAndServe() }()
	}
	go func() { errc <- httpSrv.ListenAndServe() }()
	go func() { errc <- internalSrv.ListenAndServe() }()
	go func() { errc <- metricsSrv.ListenAndServe() }()
	go func() { errc <- h.ServeTunnel(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "err", err)
			stop()
			shutdown(srvs...)
			return err
		}
	}
	shutdown(srvs...)
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
