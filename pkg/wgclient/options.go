// Package wgclient creates and maintains one WireGuard tunnel session to the
// wg-hub, for devices (wg-agent) and users (wg-connect, tnctl).
//
// A session is ephemeral: Create generates a fresh WireGuard key, asks the hub
// for a session over HTTPS, brings up a userspace WireGuard device on a gVisor
// netstack (no TUN device, no privileges), and keeps the session alive by
// renewing it inside the tunnel with a fresh credential. The transport is a
// TURN relay (STUNner) that is re-allocated when it goes stale or the hub
// rotates its credentials. Any denial by the hub ends the session: Done is
// closed, every connection made through it is closed, and Err says why.
//
// Nothing in this package logs bearer tokens, TURN passwords, Authorization
// headers or request and response bodies.
package wgclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Credential returns a FRESH bearer credential for one create or renew call.
// wgPublicKey is the session's WireGuard public key (base64); device identity
// tokens bind it in their wgk claim. The returned value is never logged.
type Credential func(ctx context.Context, wgPublicKey string) (string, error)

// Options configures Create.
type Options struct {
	// HubURL is the session API base, e.g. https://wg.teknoir.cloud,
	// https://wg-device.teknoir.cloud:8084 or http://wg-hub.teknoir-ztna.svc:8081.
	// Plain http is accepted only for in-cluster service names (*.svc,
	// *.svc.cluster.local), localhost and loopback addresses: bearer
	// credentials would otherwise cross the network in the clear.
	HubURL string
	// Kind is api.KindDevice or api.KindClient.
	Kind string
	// Credential is called for every create and renew call.
	Credential Credential
	// DeviceRequest (Kind device) or ClientRequest (Kind client) is the request
	// template; WGPublicKey is filled in per session.
	DeviceRequest *api.DeviceSessionRequest
	ClientRequest *api.ClientSessionRequest
	// Direct sends WireGuard straight to the hub endpoint over UDP instead of
	// through TURN. Only for clients inside the cluster; the request asks the
	// hub not to mint TURN credentials.
	Direct bool
	// TURNServerOverride ("host:port", or just a host) replaces the TURN
	// server taken from the credential URLs, for LAN tests.
	TURNServerOverride string
	// HTTPClient talks to HubURL (custom CAs). Default: a client with a 20 s timeout.
	// Redirects are never followed, so credentials cannot be forwarded elsewhere.
	HTTPClient *http.Client
	// Logger receives one line per decision. Default: discard.
	Logger *slog.Logger
	// Realm is the TURN realm hint (default relay.DefaultRealm).
	Realm string
	// StaleAfter is how long the relay may receive nothing before it is
	// re-allocated (default 75 s; renewals every 60 s keep it fresh).
	StaleAfter time.Duration
	// HandshakeTimeout bounds the wait for the first WireGuard handshake (default 15 s).
	HandshakeTimeout time.Duration
	// RenewRetry is the delay before retrying a failed renewal (default 5 s).
	RenewRetry time.Duration
	// RenewTimeout bounds one renewal attempt (default 15 s).
	RenewTimeout time.Duration
	// DeadAfter is how long nothing may arrive through WireGuard before a
	// transport-level renewal failure ends the session (default
	// 2 * api.PersistentKeepalive seconds).
	DeadAfter time.Duration
}

const (
	defaultHTTPTimeout      = 20 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	defaultRenewRetry       = 5 * time.Second
	defaultRenewTimeout     = 15 * time.Second
)

// Validate checks the options without any side effects.
func (o Options) Validate() error {
	u, err := parseHubURL(o.HubURL)
	if err != nil {
		return err
	}
	_ = u
	if o.Credential == nil {
		return errors.New("wgclient: Credential is required")
	}
	switch o.Kind {
	case api.KindDevice:
		if o.DeviceRequest == nil {
			return errors.New("wgclient: DeviceRequest is required for a device session")
		}
		if o.ClientRequest != nil {
			return errors.New("wgclient: ClientRequest set on a device session")
		}
	case api.KindClient:
		r := o.ClientRequest
		if r == nil {
			return errors.New("wgclient: ClientRequest is required for a client session")
		}
		if o.DeviceRequest != nil {
			return errors.New("wgclient: DeviceRequest set on a client session")
		}
		if r.Namespace == "" || r.Device == "" {
			return errors.New("wgclient: ClientRequest needs a namespace and a device")
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("wgclient: ClientRequest port %d out of range", r.Port)
		}
	default:
		return fmt.Errorf("wgclient: unknown session kind %q", o.Kind)
	}
	if o.TURNServerOverride != "" {
		if _, err := withDefaultPort(o.TURNServerOverride); err != nil {
			return fmt.Errorf("wgclient: TURNServerOverride: %w", err)
		}
	}
	return nil
}

func parseHubURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("wgclient: HubURL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("wgclient: HubURL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("wgclient: HubURL must be http or https")
	}
	if u.Scheme == "http" && !plainHTTPAllowed(u.Hostname()) {
		return nil, errors.New("wgclient: HubURL must use https (plain http is accepted only for in-cluster *.svc names, localhost and loopback addresses)")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("wgclient: HubURL must be scheme://host[:port][/path] without credentials, query or fragment")
	}
	return u, nil
}

// plainHTTPAllowed reports whether bearer credentials may travel over plain
// http to host: in-cluster service names and loopback only.
func plainHTTPAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case host == "localhost", strings.HasSuffix(host, ".localhost"):
		return true
	case strings.HasSuffix(host, ".svc"), strings.HasSuffix(host, ".svc.cluster.local"):
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// hubEndpoint joins the base URL and an API path.
func hubEndpoint(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

func (o Options) httpClient() *http.Client {
	var c http.Client
	if o.HTTPClient != nil {
		c = *o.HTTPClient
	} else {
		c.Timeout = defaultHTTPTimeout
	}
	if c.CheckRedirect == nil {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &c
}

func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (o Options) handshakeTimeout() time.Duration {
	if o.HandshakeTimeout > 0 {
		return o.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (o Options) renewRetry() time.Duration {
	if o.RenewRetry > 0 {
		return o.RenewRetry
	}
	return defaultRenewRetry
}

func (o Options) renewTimeout() time.Duration {
	if o.RenewTimeout > 0 {
		return o.RenewTimeout
	}
	return defaultRenewTimeout
}

func (o Options) deadAfter() time.Duration {
	if o.DeadAfter > 0 {
		return o.DeadAfter
	}
	return 2 * api.PersistentKeepalive * time.Second
}
