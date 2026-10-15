package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// k3s Service discovery (api.CapK3sDiscovery). The hub asks on demand, when an
// administrator opens "Add service" in the console, which Services the device's
// k3s cluster has. The agent answers from the Kubernetes API of the cluster it
// runs in, with its own ServiceAccount (get/list on Services only, shipped by
// device-controller), and returns metadata only: no annotations, labels,
// selectors or Endpoints. The API client is plain net/http, in-cluster
// configuration only.

// In-cluster configuration (the standard ServiceAccount mount).
const (
	k3sTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k3sCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	k3sListTimeout = 5 * time.Second
	k3sCacheTTL    = 10 * time.Second
	// maxK3sAPIBody bounds what is read from the API server: 500 Services with
	// full metadata (managedFields, annotations) stay far below it.
	maxK3sAPIBody = 32 << 20
)

// Plain-English answers in K3sServiceList.Error.
const (
	k3sErrNoPermission = "the agent has no permission to list Services yet"
	k3sErrNoCluster    = "the agent is not running inside a Kubernetes cluster"
	k3sErrUnreachable  = "the agent could not reach the Kubernetes API of the device"
	k3sErrBadAnswer    = "the Kubernetes API of the device gave an answer the agent could not read"
)

// k3sConfig points the lister at the Kubernetes API.
type k3sConfig struct {
	// APIURL is https://host:port of the API server ("" when the agent does
	// not run in a cluster).
	APIURL    string
	TokenFile string
	CAFile    string
	Timeout   time.Duration
	CacheTTL  time.Duration
	Now       func() time.Time
}

// k3sConfigFromEnv is the in-cluster configuration.
func k3sConfigFromEnv(getenv func(string) string) k3sConfig {
	c := k3sConfig{TokenFile: k3sTokenFile, CAFile: k3sCAFile}
	if host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
		c.APIURL = "https://" + net.JoinHostPort(host, port)
	}
	return c
}

// k3sLister lists the Services of the cluster, with a short cache so that a
// busy console cannot load the API server of a small device.
type k3sLister struct {
	cfg k3sConfig

	mu      sync.Mutex // also serializes the fetch: concurrent callers share one
	cached  api.K3sServiceList
	cacheAt time.Time
	have    bool
}

func newK3sLister(cfg k3sConfig) *k3sLister {
	if cfg.Timeout <= 0 {
		cfg.Timeout = k3sListTimeout
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = k3sCacheTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &k3sLister{cfg: cfg}
}

// List returns the cached list or fetches a fresh one. A failure is an answer
// (K3sServiceList.Error), never an error, so the hub can show the reason.
func (l *k3sLister) List(ctx context.Context) api.K3sServiceList {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	if l.have && now.Sub(l.cacheAt) < l.cfg.CacheTTL && now.Sub(l.cacheAt) >= 0 {
		return l.cached
	}
	ctx, cancel := context.WithTimeout(ctx, l.cfg.Timeout)
	defer cancel()
	out := l.fetch(ctx)
	out.ObservedAt = now.UTC()
	l.cached, l.cacheAt, l.have = out, now, true
	return out
}

func k3sFailed(msg string) api.K3sServiceList {
	return api.K3sServiceList{Services: []api.K3sService{}, Error: msg}
}

// k3sAPIList is the part of a Kubernetes ServiceList the agent reads. Unknown
// fields (labels, annotations, selectors, managed fields) are dropped by the
// decoder.
type k3sAPIList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Type      string `json:"type"`
			ClusterIP string `json:"clusterIP"`
			Ports     []struct {
				Name        string `json:"name"`
				Protocol    string `json:"protocol"`
				AppProtocol string `json:"appProtocol"`
				Port        int    `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	} `json:"items"`
}

func (l *k3sLister) fetch(ctx context.Context) api.K3sServiceList {
	if l.cfg.APIURL == "" {
		return k3sFailed(k3sErrNoCluster)
	}
	// The token is projected and rotated by the kubelet: read it on every call.
	tok, err := os.ReadFile(l.cfg.TokenFile)
	if err != nil || len(strings.TrimSpace(string(tok))) == 0 {
		return k3sFailed(k3sErrNoPermission)
	}
	pool := x509.NewCertPool()
	if ca, err := os.ReadFile(l.cfg.CAFile); err != nil || !pool.AppendCertsFromPEM(ca) {
		return k3sFailed(k3sErrUnreachable)
	}
	cl := &http.Client{
		Timeout: l.cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			Proxy:             nil, // the API server is never reached through a proxy
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/services?limit=%d", l.cfg.APIURL, api.MaxK3sServices), nil)
	if err != nil {
		return k3sFailed(k3sErrUnreachable)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return k3sFailed(k3sErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return k3sFailed(k3sErrNoPermission)
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return k3sFailed(fmt.Sprintf("the Kubernetes API of the device answered %d", resp.StatusCode))
	}
	var list k3sAPIList
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxK3sAPIBody)).Decode(&list); err != nil {
		return k3sFailed(k3sErrBadAnswer)
	}
	return mapK3sServices(list)
}

// mapK3sServices turns the API's list into the contract type: sorted by
// namespace and name, at most api.MaxK3sServices Services of at most
// api.MaxK3sServicePorts ports.
func mapK3sServices(list k3sAPIList) api.K3sServiceList {
	out := api.K3sServiceList{Services: make([]api.K3sService, 0, len(list.Items))}
	out.Truncated = list.Metadata.Continue != "" || len(list.Items) > api.MaxK3sServices
	for _, it := range list.Items {
		if len(out.Services) >= api.MaxK3sServices {
			break
		}
		if it.Metadata.Namespace == "" || it.Metadata.Name == "" {
			continue
		}
		s := api.K3sService{
			Namespace: it.Metadata.Namespace, Name: it.Metadata.Name,
			Type: it.Spec.Type, ClusterIP: it.Spec.ClusterIP,
		}
		if s.Type == "" {
			s.Type = "ClusterIP"
		}
		for _, p := range it.Spec.Ports {
			if len(s.Ports) >= api.MaxK3sServicePorts {
				break
			}
			s.Ports = append(s.Ports, api.K3sServicePort{Name: p.Name, Port: p.Port, Protocol: p.Protocol, AppProtocol: p.AppProtocol})
		}
		out.Services = append(out.Services, s)
	}
	slices.SortFunc(out.Services, func(a, b api.K3sService) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// registerK3s adds the discovery route to the control mux.
func (c *controlServer) registerK3s(mux *http.ServeMux) {
	mux.HandleFunc(api.ControlK3sServicesPath, c.k3sHandler(newK3sLister(k3sConfigFromEnv(os.Getenv))))
}

// k3sHandler serves GET api.ControlK3sServicesPath. It has the access check of
// the other control handlers (only the hub's overlay address), but reads, so
// GET instead of POST.
func (c *controlServer) k3sHandler(l *k3sLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || ap.Addr().Unmap() != c.hubAddr {
			writeControlJSON(w, http.StatusForbidden, &api.Error{Reason: api.ReasonForbidden, Message: "only the hub may call this"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeControlJSON(w, http.StatusMethodNotAllowed, &api.Error{Reason: api.ReasonBadRequest, Message: "GET required"})
			return
		}
		res := l.List(r.Context())
		if res.Error != "" {
			c.log.Info("k3s Services not listed", "why", res.Error)
		}
		writeControlJSON(w, http.StatusOK, res)
	}
}
