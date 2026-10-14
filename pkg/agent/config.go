// Package agent is the device side of the WireGuard ZTNA tunnel (wg-agent).
//
// The agent owns an Ed25519 identity key that never leaves the device. It
// enrolls that key with the hub (trust on first use inside an admin-opened
// window, proven with the legacy RSA device key), then repeatedly creates a
// WireGuard session over TURN, exposes the allowed ports on its overlay
// address and forwards every accepted connection to the local host. Whatever
// ends the session (revocation, expiry, hub restart), it backs off and starts
// over; it never gives up.
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Defaults for the environment variables of wg-agent run.
const (
	DefaultRSAKey       = "/etc/teknoir/rsa_private.pem"
	DefaultIdentityDir  = "/var/lib/teknoir/wg-agent"
	DefaultHostKeysGlob = "/etc/ssh/ssh_host_*_key.pub"
	DefaultForwardHost  = "127.0.0.1"
	DefaultExtraCAFile  = "/etc/teknoir/roots.pem"

	DefaultMaxConns    = 32
	DefaultDialTimeout = 5 * time.Second
	// DefaultMaxConnsPerService caps concurrent connections of one service.
	DefaultMaxConnsPerService = 16
)

// Backoff bounds the delay between session attempts: exponential from Min to
// Max with jitter. Stable is how long a session must last before the next
// failure starts from Min again.
type Backoff struct {
	Min, Max, Stable time.Duration
}

// DefaultBackoff is 2 s doubling up to 5 min.
var DefaultBackoff = Backoff{Min: 2 * time.Second, Max: 5 * time.Minute, Stable: time.Minute}

// Config configures the agent.
type Config struct {
	DeviceID  string
	Namespace string
	// Domain is only used to derive HubURL when that is empty.
	Domain string
	HubURL string

	RSAKeyPath      string
	IdentityDir     string
	SSHHostKeysGlob string
	ForwardHost     string
	// TURNServer ("host:port") overrides the TURN server in the hub's credentials.
	TURNServer string
	// AttestExchange is the directory shared with the attestor sidecar
	// (ATTEST_EXCHANGE). Empty: no host-key attestation (phase-1 behaviour).
	AttestExchange string
	// AttestTimeout is how long to wait for the attestor (default 15 s).
	AttestTimeout time.Duration

	HTTPClient *http.Client
	Logger     *slog.Logger
	Backoff    Backoff
	// MaxConns caps concurrent forwarded connections (default 32); it applies
	// to the legacy per-port listeners and, separately, to the connect listener.
	MaxConns    int
	DialTimeout time.Duration

	// Services (phase 2). See TargetPolicy for the rules they select.
	//
	// ServiceCIDRs are the cluster's service networks (default 10.43.0.0/16,
	// the k3s default); ClusterDomain the cluster DNS domain (default
	// cluster.local); SSHPort the sshd port of the implicit ssh service
	// (default 22; the host is ForwardHost).
	ServiceCIDRs  []netip.Prefix
	ClusterDomain string
	SSHPort       int
	// MaxConnsPerService caps concurrent connections of one service (default 16).
	MaxConnsPerService int
	// Resolver and NodeIPs replace the system resolver and the interface
	// addresses (tests).
	Resolver Resolver
	NodeIPs  func() []netip.Addr
	// AllowTarget is a TEST HOOK that lifts the loopback refusal for the
	// targets it approves (see TargetPolicy.AllowTarget). Never set by
	// ConfigFromEnv.
	AllowTarget func(netip.AddrPort) bool

	// P2P (phase 2) enables plane B, the direct WireGuard path to clients:
	// the agent advertises api.CapP2P and serves granted clients on its own
	// UDP socket (P2PPort, 0 = any). P2PSTUN ("host:port") overrides the STUN
	// server, which is otherwise the host of the session's TURN URL.
	P2P     bool
	P2PPort int
	P2PSTUN string
	// Test hooks of plane B: a pre-opened socket, a wrapper around the socket
	// (a lossy conn), a fake interface listing, loopback host candidates and
	// the probe interval. ConfigFromEnv never sets them.
	P2PConn            func() (net.PacketConn, error)
	P2PWrapConn        func(net.PacketConn) net.PacketConn
	P2PInterfaces      func() ([]netip.Addr, error)
	P2PIncludeLoopback bool
	P2PProbeInterval   time.Duration

	// Passed through to wgclient (zero: its defaults).
	StaleAfter       time.Duration
	HandshakeTimeout time.Duration
	RenewRetry       time.Duration
	RenewTimeout     time.Duration
	DeadAfter        time.Duration
}

// ConfigFromEnv reads the environment of wg-agent run:
//
//	DEVICE_ID, NAMESPACE       required
//	DOMAIN                     required unless HUB_URL is set
//	HUB_URL                    default https://wg-device.<DOMAIN>:8084
//	RSA_KEY                    default /etc/teknoir/rsa_private.pem
//	IDENTITY_DIR               default /var/lib/teknoir/wg-agent
//	SSH_HOST_KEYS_GLOB         default /etc/ssh/ssh_host_*_key.pub
//	FORWARD_HOST               default 127.0.0.1
//	SERVICE_CIDR               comma-separated k3s service networks, default 10.43.0.0/16
//	CLUSTER_DOMAIN             cluster DNS domain, default cluster.local
//	SSH_PORT                   sshd port of the ssh service, default 22
//	TURN_SERVER                optional host:port override
//	P2P                        on (default) or off: direct WireGuard to clients
//	P2P_PORT                   UDP port of the direct socket, default 0 (any)
//	P2P_STUN                   host:port of a STUN server (default: the TURN host)
//	ATTEST_EXCHANGE            directory shared with the attestor sidecar
//	                           (e.g. /run/wg-attest); empty: no attestation
//	CA_FILE                    extra CA bundle added to the system roots
//	                           (default: /etc/teknoir/roots.pem if present)
//	LOG_LEVEL                  debug, info (default), warn, error
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		DeviceID:        getenv("DEVICE_ID"),
		Namespace:       getenv("NAMESPACE"),
		Domain:          getenv("DOMAIN"),
		HubURL:          getenv("HUB_URL"),
		RSAKeyPath:      getenv("RSA_KEY"),
		IdentityDir:     getenv("IDENTITY_DIR"),
		SSHHostKeysGlob: getenv("SSH_HOST_KEYS_GLOB"),
		ForwardHost:     getenv("FORWARD_HOST"),
		TURNServer:      getenv("TURN_SERVER"),
		AttestExchange:  getenv("ATTEST_EXCHANGE"),
		ClusterDomain:   getenv("CLUSTER_DOMAIN"),
	}
	if v := getenv("SERVICE_CIDR"); v != "" {
		cidrs, err := ParseServiceCIDRs(v)
		if err != nil {
			return Config{}, fmt.Errorf("agent: SERVICE_CIDR: %w", err)
		}
		c.ServiceCIDRs = cidrs
	}
	if v := getenv("SSH_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return Config{}, fmt.Errorf("agent: SSH_PORT %q is not a port", v)
		}
		c.SSHPort = port
	}
	switch strings.ToLower(strings.TrimSpace(getenv("P2P"))) {
	case "", "on", "true", "1", "yes":
		c.P2P = true
	case "off", "false", "0", "no":
	default:
		return Config{}, fmt.Errorf("agent: P2P %q is not on or off", getenv("P2P"))
	}
	if v := getenv("P2P_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 0 || port > 65535 {
			return Config{}, fmt.Errorf("agent: P2P_PORT %q is not a port", v)
		}
		c.P2PPort = port
	}
	c.P2PSTUN = getenv("P2P_STUN")
	if c.P2PSTUN != "" {
		if _, _, err := net.SplitHostPort(c.P2PSTUN); err != nil {
			return Config{}, fmt.Errorf("agent: P2P_STUN must be host:port: %w", err)
		}
	}
	caFile, explicit := getenv("CA_FILE"), true
	if caFile == "" {
		caFile, explicit = DefaultExtraCAFile, false
	}
	hc, err := HTTPClient(caFile, explicit)
	if err != nil {
		return Config{}, err
	}
	c.HTTPClient = hc
	if err := c.applyDefaults(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// ParseLogLevel maps LOG_LEVEL values to slog levels (default info).
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("agent: unknown LOG_LEVEL %q (want debug, info, warn or error)", s)
}

func (c *Config) applyDefaults() error {
	if c.DeviceID == "" || c.Namespace == "" {
		return errors.New("agent: DEVICE_ID and NAMESPACE are required")
	}
	if strings.ContainsAny(c.DeviceID+c.Namespace, "/ \t\r\n") {
		return errors.New("agent: DEVICE_ID and NAMESPACE must not contain '/' or whitespace")
	}
	if c.HubURL == "" {
		if c.Domain == "" {
			return errors.New("agent: DOMAIN is required when HUB_URL is not set")
		}
		c.HubURL = "https://" + net.JoinHostPort(api.DeviceHostPrefix+"."+c.Domain, strconv.Itoa(api.DevicePort))
	}
	c.RSAKeyPath = orDefault(c.RSAKeyPath, DefaultRSAKey)
	c.IdentityDir = orDefault(c.IdentityDir, DefaultIdentityDir)
	c.SSHHostKeysGlob = orDefault(c.SSHHostKeysGlob, DefaultHostKeysGlob)
	c.ForwardHost = orDefault(c.ForwardHost, DefaultForwardHost)
	if c.TURNServer != "" {
		if _, _, err := net.SplitHostPort(c.TURNServer); err != nil {
			return fmt.Errorf("agent: TURN_SERVER must be host:port: %w", err)
		}
	}
	if c.AttestExchange != "" && !filepath.IsAbs(c.AttestExchange) {
		return errors.New("agent: ATTEST_EXCHANGE must be an absolute path")
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Backoff.Min <= 0 {
		c.Backoff.Min = DefaultBackoff.Min
	}
	if c.Backoff.Max < c.Backoff.Min {
		c.Backoff.Max = max(DefaultBackoff.Max, c.Backoff.Min)
	}
	if c.Backoff.Stable <= 0 {
		c.Backoff.Stable = DefaultBackoff.Stable
	}
	if c.MaxConns <= 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.MaxConnsPerService <= 0 {
		c.MaxConnsPerService = DefaultMaxConnsPerService
	}
	if c.SSHPort < 0 || c.SSHPort > 65535 {
		return errors.New("agent: SSHPort out of range")
	}
	if c.HTTPClient == nil {
		hc, err := HTTPClient("", false)
		if err != nil {
			return err
		}
		c.HTTPClient = hc
	}
	return nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// HTTPClient builds the client for the hub's public endpoint: system roots
// plus the PEM bundle at caFile. A missing file is fine unless explicit.
func HTTPClient(caFile string, explicit bool) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		switch {
		case err == nil:
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("agent: %s contains no usable PEM certificates", caFile)
			}
		case explicit || !errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("agent: reading CA file: %w", err)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}
