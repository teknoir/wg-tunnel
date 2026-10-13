package wgclient

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// turnServer picks the TURN server "host:port" (UDP) from the URLs of the
// credentials, e.g. "turn:turn.teknoir.cloud:3478?transport=udp". override, if
// set, replaces the host (and the port if it carries one): it is for LAN tests
// where the public name does not resolve.
func turnServer(urls []string, override string) (string, error) {
	if len(urls) == 0 {
		return "", errors.New("hub returned no TURN URLs")
	}
	var lastErr error
	for _, u := range urls {
		hostport, err := parseTURNURL(u)
		if err != nil {
			lastErr = err
			continue
		}
		if override != "" {
			return applyOverride(hostport, override)
		}
		return hostport, nil
	}
	return "", fmt.Errorf("no usable TURN URL: %w", lastErr)
}

func parseTURNURL(raw string) (string, error) {
	rest, ok := strings.CutPrefix(raw, "turn:")
	if !ok {
		return "", fmt.Errorf("unsupported TURN URL scheme (want turn: over UDP)")
	}
	rest = strings.TrimPrefix(rest, "//")
	rest, query, _ := strings.Cut(rest, "?")
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return "", fmt.Errorf("bad TURN URL query: %w", err)
		}
		if tr := q.Get("transport"); tr != "" && tr != "udp" {
			return "", fmt.Errorf("unsupported TURN transport %q (want udp)", tr)
		}
	}
	return withDefaultPort(rest)
}

func withDefaultPort(hostport string) (string, error) {
	if hostport == "" {
		return "", errors.New("empty TURN host")
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.Trim(hostport, "[]"), strconv.Itoa(api.TURNPort)
	}
	if host == "" || strings.ContainsAny(host, "/@ \t") {
		return "", errors.New("bad TURN host")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", errors.New("bad TURN port")
	}
	return net.JoinHostPort(host, port), nil
}

func applyOverride(urlHostPort, override string) (string, error) {
	_, urlPort, err := net.SplitHostPort(urlHostPort)
	if err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(override)
	if err != nil {
		host, port = strings.Trim(override, "[]"), urlPort
	}
	return withDefaultPort(net.JoinHostPort(host, port))
}
