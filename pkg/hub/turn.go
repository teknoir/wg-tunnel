package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/turncred"
)

// SecretFunc returns the TURN shared secret.
type SecretFunc func() (string, error)

type turnMinter struct {
	secret SecretFunc
	urls   []string
	ttl    time.Duration
	now    func() time.Time
}

// NewTURNMinter mints TURN-REST credentials (see pkg/turncred) valid for ttl.
func NewTURNMinter(secret SecretFunc, urls []string, ttl time.Duration, now func() time.Time) TURNMinter {
	if now == nil {
		now = time.Now
	}
	return &turnMinter{secret: secret, urls: urls, ttl: ttl, now: now}
}

// Mint implements TURNMinter. The TURN user is "<ns>/<sessionId>".
func (m *turnMinter) Mint(ns, sessionID string) (*api.TURNCredentials, error) {
	userID := ns + "/" + sessionID
	if err := turncred.ValidUserID(userID); err != nil {
		return nil, err
	}
	secret, err := m.secret()
	if err != nil {
		return nil, err
	}
	user, pass, exp := turncred.Generate(secret, userID, m.ttl, m.now())
	return &api.TURNCredentials{URLs: append([]string(nil), m.urls...), Username: user, Password: pass, ExpiresAt: exp}, nil
}

// SplitList parses a comma-separated TURN_URLS value.
func SplitList(s string) []string {
	var out []string
	for u := range strings.SplitSeq(s, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// secretRetryAfterFailure spaces re-reads of the TURN secret after a failure
// when no value is cached yet.
const secretRetryAfterFailure = 2 * time.Second

// K8sSecretSource reads the TURN shared secret (key "secret") from a Secret,
// re-reading it every refresh interval so a rotated secret is picked up. If a
// re-read fails, the last known value keeps being served and the next attempt
// waits for the refresh interval again. The mutex is never held across the API
// call, and concurrent callers share one read.
type K8sSecretSource struct {
	cs      kubernetes.Interface
	ns      string
	name    string
	refresh time.Duration
	now     func() time.Time

	mu          sync.Mutex
	value       string
	fetched     time.Time // last success
	lastAttempt time.Time // last read, successful or not
	lastErr     error
	flight      *secretFlight
}

type secretFlight struct {
	done chan struct{}
	val  string
	err  error
}

// NewK8sSecretSource parses ref ("namespace/name") and returns the source.
func NewK8sSecretSource(cs kubernetes.Interface, ref string, refresh time.Duration) (*K8sSecretSource, error) {
	ns, name, ok := strings.Cut(ref, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("hub: TURN secret reference %q must be namespace/name", ref)
	}
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &K8sSecretSource{cs: cs, ns: ns, name: name, refresh: refresh, now: time.Now}, nil
}

// Secret implements SecretFunc.
func (s *K8sSecretSource) Secret() (string, error) {
	s.mu.Lock()
	now := s.now()
	if s.value != "" && now.Sub(s.fetched) < s.refresh {
		v := s.value
		s.mu.Unlock()
		return v, nil
	}
	// Stale or empty. Do not hammer the API server: after an attempt, wait for
	// the refresh interval (or a short retry delay if we have nothing yet).
	wait := s.refresh
	if s.value == "" {
		wait = min(secretRetryAfterFailure, s.refresh)
	}
	if !s.lastAttempt.IsZero() && now.Sub(s.lastAttempt) < wait && s.flight == nil {
		v, err := s.value, s.lastErr
		s.mu.Unlock()
		if v != "" {
			return v, nil
		}
		return "", err
	}
	if f := s.flight; f != nil {
		v := s.value
		s.mu.Unlock()
		if v != "" {
			return v, nil // serve the stale value while another caller refreshes
		}
		<-f.done
		return f.val, f.err
	}
	f := &secretFlight{done: make(chan struct{})}
	s.flight, s.lastAttempt = f, now
	stale := s.value
	s.mu.Unlock()

	v, err := s.read()

	s.mu.Lock()
	if err == nil {
		s.value, s.fetched, s.lastErr = v, s.now(), nil
	} else {
		s.lastErr = err
		if stale != "" {
			v, err = stale, nil
		}
	}
	s.flight = nil
	s.mu.Unlock()
	f.val, f.err = v, err
	close(f.done)
	return v, err
}

func (s *K8sSecretSource) read() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("hub: reading TURN secret: %w", err)
	}
	v := string(sec.Data["secret"])
	if v == "" {
		return "", errors.New("hub: TURN secret has no \"secret\" key")
	}
	return v, nil
}
