package hub

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	keycloakSkew       = 30 * time.Second
	maxJWKSBytes       = 1 << 20
	maxBearerTokenSize = 12 << 10
	minJWKSRSABits     = 2048
)

// KeycloakConfig configures the Keycloak access-token verifier.
type KeycloakConfig struct {
	// Issuer must equal the token's iss exactly.
	Issuer string
	// JWKSURL is where the realm signing keys are fetched.
	JWKSURL string
	// AllowedAZP lists the accepted authorized parties (default: api.KeycloakAllowedAZP).
	AllowedAZP []string
	HTTPClient *http.Client
	// CacheTTL is how long a fetched key set is trusted (default 10m).
	CacheTTL time.Duration
	// MinRefresh is the minimum time between fetches triggered by an unknown
	// kid (default 5s), so garbage tokens cannot make the hub hammer Keycloak.
	MinRefresh time.Duration
	// StaleWait bounds how long a request for a KNOWN key whose cache expired
	// waits for the refresh (default 1.5s): long enough to pick up a rotation
	// from a healthy Keycloak, short enough that an outage never blocks logins.
	StaleWait time.Duration
	Now       func() time.Time
}

// KeycloakVerifier implements UserAuthenticator.
type KeycloakVerifier struct {
	cfg KeycloakConfig

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time // last SUCCESSFUL fetch
	// lastAttempt is the start of the last fetch, successful or not;
	// failures counts consecutive failed fetches (backoff).
	lastAttempt time.Time
	failures    int
	// flight is the fetch in progress, shared by every caller (singleflight).
	flight *jwksFlight
}

type jwksFlight struct {
	done chan struct{}
	err  error
}

// maxJWKSBackoff bounds the delay between failed JWKS fetches.
const maxJWKSBackoff = time.Minute

var _ UserAuthenticator = (*KeycloakVerifier)(nil)

// NewKeycloakVerifier validates cfg and returns a verifier. Keys are fetched
// lazily on first use.
func NewKeycloakVerifier(cfg KeycloakConfig) (*KeycloakVerifier, error) {
	if cfg.Issuer == "" || cfg.JWKSURL == "" {
		return nil, errors.New("hub: keycloak issuer and JWKS URL are required")
	}
	if len(cfg.AllowedAZP) == 0 {
		cfg.AllowedAZP = []string{"teknoir-cli"}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Minute
	}
	if cfg.MinRefresh <= 0 {
		cfg.MinRefresh = 5 * time.Second
	}
	if cfg.StaleWait <= 0 {
		cfg.StaleWait = 1500 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &KeycloakVerifier{cfg: cfg, keys: map[string]*rsa.PublicKey{}}, nil
}

// Authenticate verifies an access token: RS256 only, signature by a key of the
// realm JWKS, iss, azp, exp/nbf (30s skew), a lowercase email, email_verified.
func (v *KeycloakVerifier) Authenticate(ctx context.Context, token string) (UserIdentity, error) {
	if token == "" || len(token) > maxBearerTokenSize {
		return UserIdentity{}, fmt.Errorf("%w: bad token length", ErrUnauthenticated)
	}
	claims := jwt.MapClaims{}
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(keycloakSkew),
		jwt.WithTimeFunc(v.cfg.Now),
		jwt.WithExpirationRequired(),
	)
	_, err := p.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.key(ctx, kid)
	})
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return UserIdentity{}, err
		}
		return UserIdentity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	bad := func(what string) (UserIdentity, error) {
		return UserIdentity{}, fmt.Errorf("%w: %s", ErrUnauthenticated, what)
	}
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return bad("issuer")
	}
	if azp, _ := claims["azp"].(string); azp == "" || !slices.Contains(v.cfg.AllowedAZP, azp) {
		return bad("authorized party")
	}
	if ev, ok := claims["email_verified"].(bool); !ok || !ev {
		return bad("email not verified")
	}
	email, _ := claims["email"].(string)
	if !ValidEmail(email) {
		return bad("email")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return bad("exp")
	}
	id := UserIdentity{Email: email, ExpiresAt: exp.Time}
	id.TokenID, _ = claims["jti"].(string)
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		id.IssuedAt = iat.Time
	}
	return id, nil
}

// key returns the signing key for kid.
//
//   - A cached key within CacheTTL is returned at once.
//   - A KNOWN key whose cache is stale is returned at once too, while a refresh
//     runs in the background: a slow or black-holed Keycloak never blocks
//     authentication of keys we already trust (a rotated-away key disappears
//     with the next successful fetch).
//   - An unknown kid (or an empty cache) waits for a fetch, but fetches are
//     shared (one at a time, with a context of their own, not the caller's),
//     spaced by MinRefresh after a success and by an exponential backoff after
//     failures, so garbage tokens cannot make the hub hammer Keycloak.
func (v *KeycloakVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := v.cfg.Now()
	v.mu.Lock()
	k, known := v.keys[kid]
	fresh := !v.fetched.IsZero() && now.Sub(v.fetched) < v.cfg.CacheTTL
	if known && fresh {
		v.mu.Unlock()
		return k, nil
	}
	flight := v.flight
	if flight == nil && v.attemptAllowedLocked(now) {
		flight = v.startFetchLocked(now)
	}
	if known { // stale but trusted: never wait long for the refresh
		v.mu.Unlock()
		if sk := v.staleKey(ctx, kid, k, flight); sk != nil {
			return sk, nil
		}
		return nil, errors.New("unknown signing key")
	}
	lastErr := v.failures > 0
	v.mu.Unlock()

	if flight == nil {
		// Too soon after the last attempt to ask again.
		if lastErr {
			return nil, fmt.Errorf("%w: JWKS endpoint is failing", ErrUnavailable)
		}
		return nil, errors.New("unknown signing key")
	}
	select {
	case <-flight.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: waiting for JWKS: %v", ErrUnavailable, ctx.Err())
	}
	if flight.err != nil {
		return nil, fmt.Errorf("%w: fetching JWKS: %v", ErrUnavailable, flight.err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}

// staleKey answers a request for a known key whose cache expired: it waits up
// to StaleWait for the running refresh (so a rotation is picked up promptly)
// and otherwise serves the key it has. A refresh that succeeded without the key
// means the key was rotated away: it is gone.
func (v *KeycloakVerifier) staleKey(ctx context.Context, kid string, k *rsa.PublicKey, flight *jwksFlight) *rsa.PublicKey {
	if flight == nil {
		return k
	}
	t := time.NewTimer(v.cfg.StaleWait)
	defer t.Stop()
	select {
	case <-flight.done:
		if flight.err != nil {
			return k
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		return v.keys[kid] // nil when the key was removed
	case <-t.C:
	case <-ctx.Done():
	}
	return k
}

// attemptAllowedLocked reports whether a new fetch may start now.
func (v *KeycloakVerifier) attemptAllowedLocked(now time.Time) bool {
	if v.lastAttempt.IsZero() {
		return true
	}
	wait := v.cfg.MinRefresh
	for i := 0; i < v.failures && wait < maxJWKSBackoff; i++ {
		wait *= 2
	}
	return now.Sub(v.lastAttempt) >= min(wait, max(maxJWKSBackoff, v.cfg.MinRefresh))
}

// startFetchLocked starts a shared fetch with its own context.
func (v *KeycloakVerifier) startFetchLocked(now time.Time) *jwksFlight {
	f := &jwksFlight{done: make(chan struct{})}
	v.flight = f
	v.lastAttempt = now
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), v.fetchTimeout())
		defer cancel()
		keys, err := v.fetch(ctx)
		v.mu.Lock()
		if err != nil {
			v.failures++
		} else {
			v.keys, v.fetched, v.failures = keys, v.cfg.Now(), 0
		}
		v.flight = nil
		v.mu.Unlock()
		f.err = err
		close(f.done)
	}()
	return f
}

func (v *KeycloakVerifier) fetchTimeout() time.Duration {
	if t := v.cfg.HTTPClient.Timeout; t > 0 {
		return t
	}
	return 10 * time.Second
}

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *KeycloakVerifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		n := new(big.Int).SetBytes(nb)
		if n.BitLen() < minJWKSRSABits {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable RSA signing keys")
	}
	return keys, nil
}

// bearer extracts the token of an "Authorization: Bearer <token>" header value.
func bearer(h string) string {
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	tok = strings.TrimSpace(tok)
	if len(tok) > maxBearerTokenSize || strings.ContainsAny(tok, " \t\r\n") {
		return ""
	}
	return tok
}
