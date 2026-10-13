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
	"os"
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

	HTTPClient *http.Client
	Logger     *slog.Logger
	Backoff    Backoff
	// MaxConns caps concurrent forwarded connections (default 32).
	MaxConns    int
	DialTimeout time.Duration

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
//	TURN_SERVER                optional host:port override
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
