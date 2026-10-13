// Command wg-connect is an ssh ProxyCommand that reaches a device through the
// WireGuard ZTNA hub:
//
//	ssh -o ProxyCommand='wg-connect --hub-url ... --namespace NS --device DEV \
//	    --sa-token-file F --on-behalf-of EMAIL --known-hosts-file K' \
//	    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=K \
//	    -o HostKeyAlias=DEV.NS.ztna.teknoir dev
//
// It creates a client session, writes the device's SSH host keys to the
// known_hosts file BEFORE it relays a single byte, then copies stdin/stdout to
// the tunnel. Credentials come from files that are re-read for every session
// create and renewal (projected service account tokens rotate), never from
// argv or the environment. On denial it prints one line to stderr and exits 1.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/knownhosts"
	"github.com/teknoir/wg-tunnel/pkg/version"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2

	maxTokenFile = 16 << 10
	createTimout = 40 * time.Second
	dialTimeout  = 15 * time.Second
	drainGrace   = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type options struct {
	hubURL, namespace, device string
	port                      int
	direct                    bool
	saTokenFile               string
	keycloakTokenFile         string
	onBehalfOf                string
	knownHostsFile            string
	turnServer                string
	caFile                    string
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

func parseArgs(args []string, stderr io.Writer) (*options, error) {
	var o options
	fs := flag.NewFlagSet("wg-connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.hubURL, "hub-url", "", "session API base URL of the hub")
	fs.StringVar(&o.namespace, "namespace", "", "teamspace (namespace) of the device")
	fs.StringVar(&o.device, "device", "", "device name")
	fs.IntVar(&o.port, "port", 22, "device TCP port")
	fs.BoolVar(&o.direct, "direct", false, "send WireGuard straight to the hub over UDP (in-cluster only)")
	fs.StringVar(&o.saTokenFile, "sa-token-file", "", "file with a projected service account token (re-read for every call)")
	fs.StringVar(&o.keycloakTokenFile, "keycloak-token-file", "", "file with a Keycloak access token (re-read for every call)")
	fs.StringVar(&o.onBehalfOf, "on-behalf-of", "", "end-user email (with --sa-token-file)")
	fs.StringVar(&o.knownHostsFile, "known-hosts-file", "", "known_hosts file to write the device SSH host keys to")
	fs.StringVar(&o.turnServer, "turn-server", "", "TURN server host:port overriding the hub's (LAN tests)")
	fs.StringVar(&o.caFile, "ca-file", "", "extra CA bundle for the hub's TLS certificate")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return &o, o.validate()
}

func (o *options) validate() error {
	switch {
	case o.hubURL == "":
		return errors.New("--hub-url is required")
	case !nameRE.MatchString(o.namespace):
		return errors.New("--namespace is required and must be a DNS-style name")
	case !nameRE.MatchString(o.device):
		return errors.New("--device is required and must be a DNS-style name")
	case o.port < 1 || o.port > 65535:
		return errors.New("--port must be between 1 and 65535")
	case o.knownHostsFile == "":
		return errors.New("--known-hosts-file is required")
	case o.saTokenFile == "" && o.keycloakTokenFile == "":
		return errors.New("one of --sa-token-file or --keycloak-token-file is required")
	case o.saTokenFile != "" && o.keycloakTokenFile != "":
		return errors.New("--sa-token-file and --keycloak-token-file are mutually exclusive")
	case o.saTokenFile != "" && o.onBehalfOf == "":
		return errors.New("--on-behalf-of is required with --sa-token-file")
	case o.saTokenFile == "" && o.onBehalfOf != "":
		return errors.New("--on-behalf-of is only valid with --sa-token-file")
	case o.direct && o.turnServer != "":
		return errors.New("--direct and --turn-server are mutually exclusive")
	}
	if o.onBehalfOf != "" && (len(o.onBehalfOf) > 254 || !strings.Contains(o.onBehalfOf, "@") || strings.ContainsFunc(o.onBehalfOf, func(r rune) bool { return r <= ' ' || r == 0x7f })) {
		return errors.New("--on-behalf-of must be an email address")
	}
	if err := knownhosts.ValidAlias(api.KnownHostsAlias(o.namespace, o.device)); err != nil {
		return err
	}
	return nil
}

func (o *options) tokenFile() string {
	if o.saTokenFile != "" {
		return o.saTokenFile
	}
	return o.keycloakTokenFile
}

// readToken reads a bearer from a file (fresh on every call). Errors never
// contain the file's contents.
func readToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read token file: %s", osReason(err))
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", errors.New("cannot read token file")
	}
	if len(b) > maxTokenFile {
		return "", errors.New("token file is too large")
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("token file is empty")
	}
	return tok, nil
}

// osReason is the OS error without the file name.
func osReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "unreadable"
}

func httpClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read CA file: %s", osReason(err))
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA file contains no usable certificates")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}

func fail(stderr io.Writer, code int, format string, a ...any) int {
	_, _ = fmt.Fprintf(stderr, "wg-connect: "+format+"\n", a...)
	return code
}

// describe turns an error into the single stderr line's text.
func describe(err error) string {
	var he *wgclient.Error
	if errors.As(err, &he) {
		if he.Message != "" {
			return fmt.Sprintf("access denied: %s (%s)", orUnknown(he.Reason), he.Message)
		}
		return fmt.Sprintf("access denied: %s", orUnknown(he.Reason))
	}
	return oneLine(err.Error())
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return fail(stderr, exitUsage, "%v", err)
	}
	hc, err := httpClient(o.caFile)
	if err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}

	software := "tnctl"
	if o.saTokenFile != "" {
		software = "web-terminal"
	}
	tokenPath := o.tokenFile()
	host, _ := os.Hostname()
	opts := wgclient.Options{
		HubURL: o.hubURL,
		Kind:   api.KindClient,
		Credential: func(context.Context, string) (string, error) {
			return readToken(tokenPath)
		},
		ClientRequest: &api.ClientSessionRequest{
			Namespace: o.namespace, Device: o.device, Port: o.port, OnBehalfOf: o.onBehalfOf,
			Posture: api.Posture{Software: software, Version: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: host},
		},
		Direct:             o.direct,
		TURNServerOverride: o.turnServer,
		HTTPClient:         hc,
	}
	if err := opts.Validate(); err != nil {
		return fail(stderr, exitUsage, "%v", err)
	}

	cctx, cancel := context.WithTimeout(ctx, createTimout)
	sess, err := wgclient.Create(cctx, opts)
	cancel()
	if err != nil {
		return fail(stderr, exitFail, "%s", describe(err))
	}
	defer func() { _ = sess.Close() }()

	// Host keys first: ssh must be able to verify the device before any byte flows.
	resp := sess.Response()
	if err := knownhosts.Write(o.knownHostsFile, api.KnownHostsAlias(o.namespace, o.device), resp.SSHHostKeys); err != nil {
		return fail(stderr, exitFail, "cannot record the device SSH host keys: %s", oneLine(err.Error()))
	}

	dctx, dcancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := sess.Dial(dctx)
	dcancel()
	if err != nil {
		return fail(stderr, exitFail, "cannot reach the hub inside the tunnel: %s", oneLine(err.Error()))
	}
	defer func() { _ = conn.Close() }()
	return relayStdio(ctx, sess, conn, stdin, stdout, stderr)
}

// relayStdio copies stdin to conn and conn to stdout until either side ends,
// the session is torn down, or ctx is cancelled.
func relayStdio(ctx context.Context, sess *wgclient.Session, conn net.Conn, stdin io.Reader, stdout, stderr io.Writer) int {
	connDone := make(chan error, 1) // conn -> stdout finished
	stdinDone := make(chan struct{})
	go func() {
		_, err := io.Copy(stdout, conn)
		connDone <- err
	}()
	go func() {
		_, _ = io.Copy(conn, stdin)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // stdin EOF: tell the device we are done sending
		}
		close(stdinDone)
	}()

	sessionEnded := func() int {
		if err := sess.Err(); err != nil {
			return fail(stderr, exitFail, "session ended: %s", describe(err))
		}
		return exitOK
	}
	select {
	case err := <-connDone:
		select { // a revoked session closes the conn; report why if the hub said so
		case <-sess.Done():
			return sessionEnded()
		case <-time.After(100 * time.Millisecond):
		}
		if err != nil {
			return fail(stderr, exitFail, "connection lost: %s", oneLine(err.Error()))
		}
		return exitOK
	case <-stdinDone:
		// ssh closed its end: let the device finish, but not forever.
		select {
		case <-connDone:
		case <-sess.Done():
		case <-time.After(drainGrace):
		case <-ctx.Done():
		}
		return exitOK
	case <-sess.Done():
		return sessionEnded()
	case <-ctx.Done():
		return exitOK
	}
}
