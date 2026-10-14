package e2erig

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/gateway"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// WebGateway is a running web gateway of the rig's device.
type WebGateway struct {
	*gateway.Gateway
	// URL is where the gateway listens (the rig's "ingress" talks to it).
	URL  string
	Logs *LogBuf
}

// GatewayHost is the host name browsers use in the rig.
const GatewayHost = "web.vdev-1.e2e.test"

// StartWebGateway runs the real gateway (pkg/gateway) against the hub's
// internal API with the rig's gateway service account token; it is stopped at
// test end.
func (r *Rig) StartWebGateway(idle time.Duration) *WebGateway {
	r.T.Helper()
	tokenFile := filepath.Join(r.T.TempDir(), "token")
	must(r.T, os.WriteFile(tokenFile, []byte(GatewayToken+"\n"), 0o600))
	logs := &LogBuf{}
	g, err := gateway.New(gateway.Config{
		HubURL: r.InternalURL, Namespace: NS, Device: DeviceName, TokenFile: tokenFile,
		IdleTimeout: idle, Logger: logger(logs), ConnMaxAge: 200 * time.Millisecond, SweepInterval: 100 * time.Millisecond,
		WGOptions: func(o *wgclient.Options) {
			o.HandshakeTimeout = 20 * time.Second
			o.RenewRetry = 500 * time.Millisecond
			o.RenewTimeout = 3 * time.Second
			o.DeadAfter = r.Opts.DeadAfter
		},
	})
	must(r.T, err)
	srv := httptest.NewServer(g)
	r.T.Cleanup(func() { srv.Close(); g.Close() })
	return &WebGateway{Gateway: g, URL: srv.URL, Logs: logs}
}

// Do sends a browser-like request through the gateway as the ingress would
// have forwarded it: oauth2-proxy has authenticated user (empty: nobody) and
// the VirtualService of the service has set the service header.
func (g *WebGateway) Do(method, path, user, service string, hdr http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, g.URL+path, body)
	if err != nil {
		return nil, err
	}
	req.Host = GatewayHost
	for k, v := range hdr {
		req.Header[k] = v
	}
	if user != "" {
		req.Header.Set(gateway.HeaderEmail, user)
	}
	if service != "" {
		req.Header.Set(gateway.HeaderService, service)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 30 * time.Second}
	return cl.Do(req)
}
