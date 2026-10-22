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

// envDuration reads a duration; an invalid or negative value is an error (a
// hub that silently ignored a typo in a timing would elect on the wrong clock).
func envDuration(key, def string) (time.Duration, error) {
	d, err := time.ParseDuration(env(key, def))
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s must be a non-negative duration such as %s: %v", key, def, err)
	}
	return d, nil
}

// handoverBudget bounds the notices of the planned handover: lease release and
// the wait for the successor (HANDOVER_WAIT, 10 s) and the settle pause (2 s)
// come on top, and everything stays within the 30 s termination grace period.
const handoverBudget = 8 * time.Second

// errLostLease is the exit reason of a replica that lost the leader lease: it
// exits non-zero and the container restarts as a standby.
var errLostLease = errors.New("lost the leader lease")

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

	orgMode, err := hub.ParseOrgGateMode(env("ORG_GATE_MODE", ""))
	if err != nil {
		return err
	}

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	// The hub keeps working (policy updates, the in-tunnel API and the open
	// streams) until the handover is over, so its components run on runCtx,
	// which ends after the planned handover; ctx is only the signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runCtx, runStop := context.WithCancel(context.Background())
	defer runStop()

	policy, err := hub.NewK8sPolicySource(cs, hubNS, log)
	if err != nil {
		return err
	}
	flags, err := hub.NewK8sFlagsSource(cs, hubNS, log)
	if err != nil {
		return err
	}
	org, err := hub.NewK8sOrgSource(cs, hubNS, log)
	if err != nil {
		return err
	}
	policy.Start(runCtx)
	flags.Start(runCtx)
	org.Start(runCtx)

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
	// Leader election (more than one replica): off unless LEADER_ELECTION names
	// the Lease. See pkg/hub/leader.go.
	leaseName := env("LEADER_ELECTION", "")
	podName := env("POD_NAME", "")
	var timings hub.ElectionTimings
	var handoverWait, handoverSettle time.Duration
	if timings.LeaseDuration, err = envDuration("LEASE_DURATION", "60s"); err != nil {
		return err
	}
	if timings.RenewDeadline, err = envDuration("RENEW_DEADLINE", "45s"); err != nil {
		return err
	}
	if timings.RetryPeriod, err = envDuration("RETRY_PERIOD", "2s"); err != nil {
		return err
	}
	if handoverWait, err = envDuration("HANDOVER_WAIT", "10s"); err != nil {
		return err
	}
	if handoverSettle, err = envDuration("HANDOVER_SETTLE", "2s"); err != nil {
		return err
	}
	var elector *hub.K8sElector
	if leaseName != "" {
		if podName == "" {
			return errors.New("LEADER_ELECTION needs POD_NAME (downward API)")
		}
		if elector, err = hub.NewK8sElector(cs, hubNS, leaseName, podName, timings, log); err != nil {
			return err
		}
	}
	h, err := hub.New(hub.Config{
		OrgGateMode:    orgMode,
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
		Org:      org,
		Authz:    hub.NewCachedAuthorizer(hub.NewK8sAuthorizer(cs), 5*time.Second, 1024),
		TURN:     hub.NewTURNMinter(secrets.Secret, turnURLs, 30*time.Minute, nil),
		Status:   hub.NewK8sStatusAuth(cs, env("STATUS_AUDIENCE", api.StatusTokenAudience)),
	})
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	log.Info("wg-hub starting", "version", version.Version, "namespace", hubNS, "orgGate", orgMode, "wgPort", h.WGPort(), "endpoint", h.Endpoint(),
		"leaderElection", leaseName != "", "pod", podName)
	// A replica is a standby (it answers 503) from here until it wins the lease.
	var leader *hub.Leader
	if elector != nil {
		leader = hub.NewLeader(h, hub.LeaderConfig{
			Elector: elector, Patcher: hub.NewK8sRolePatcher(cs, hubNS, podName),
			HandoverWait: handoverWait, HandoverSettle: handoverSettle, Logger: log,
		})
	}

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
	go func() { errc <- h.ServeTunnel(runCtx) }()
	var lost <-chan struct{} // nil (never ready) without leader election
	if leader != nil {
		leader.Start(runCtx)
		lost = leader.Lost()
	}

	var exitErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case <-lost:
		log.Error("the leader lease was lost; handing over and exiting")
		exitErr = errLostLease
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "err", err)
			exitErr = err
		}
	}
	// Planned handover: the servers stay up (the standby gate answers 503)
	// while the lease moves and the devices are told to reconnect.
	if leader != nil {
		hctx, cancel := context.WithTimeout(context.Background(), handoverWait+handoverSettle+handoverBudget)
		if err := leader.Shutdown(hctx); err != nil {
			log.Error("handover failed", "err", err)
		}
		cancel()
	}
	runStop()
	shutdown(srvs...)
	return exitErr
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
