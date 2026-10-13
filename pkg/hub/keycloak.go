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
	Now        func() time.Time
}

// KeycloakVerifier implements UserAuthenticator.
type KeycloakVerifier struct {
	cfg KeycloakConfig

	fetchMu sync.Mutex // serialises fetches

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

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
	return UserIdentity{Email: email, ExpiresAt: exp.Time}, nil
}

func (v *KeycloakVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := v.cfg.Now()
	v.mu.RLock()
	k, ok := v.keys[kid]
	fresh := now.Sub(v.fetched) < v.cfg.CacheTTL
	v.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}

	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	// Another goroutine may have refreshed meanwhile.
	now = v.cfg.Now()
	v.mu.RLock()
	k, ok = v.keys[kid]
	age := now.Sub(v.fetched)
	v.mu.RUnlock()
	if ok && age < v.cfg.CacheTTL {
		return k, nil
	}
	if age >= v.cfg.MinRefresh || v.fetched.IsZero() {
		if err := v.fetch(ctx); err != nil {
			if ok { // stale but known key: keep serving while Keycloak is unreachable
				return k, nil
			}
			return nil, fmt.Errorf("%w: fetching JWKS: %v", ErrUnavailable, err)
		}
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
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

func (v *KeycloakVerifier) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return fmt.Errorf("decoding: %w", err)
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
		return errors.New("no usable RSA signing keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = v.cfg.Now()
	v.mu.Unlock()
	return nil
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
