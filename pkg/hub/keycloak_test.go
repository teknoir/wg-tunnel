package hub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const kcIssuer = "https://auth.example.com/auth/realms/master"

type kcKey struct {
	kid string
	key *rsa.PrivateKey
}

func newKCKey(t *testing.T, kid string) kcKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return kcKey{kid: kid, key: k}
}

// jwksServer serves a mutable key set.
type jwksServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	keys  []kcKey
	hits  atomic.Int32
	fails atomic.Bool
}

func newJWKSServer(t *testing.T, keys ...kcKey) *jwksServer {
	t.Helper()
	j := &jwksServer{keys: keys}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.hits.Add(1)
		if j.fails.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		j.mu.Lock()
		defer j.mu.Unlock()
		var doc struct {
			Keys []map[string]string `json:"keys"`
		}
		for _, k := range j.keys {
			doc.Keys = append(doc.Keys, map[string]string{
				"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(k.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) setKeys(keys ...kcKey) {
	j.mu.Lock()
	j.keys = keys
	j.mu.Unlock()
}

func kcToken(t *testing.T, k kcKey, mutate func(jwt.MapClaims), now time.Time) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": kcIssuer, "azp": "teknoir-cli", "email": "alice@example.com", "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "sub": "u-1",
		"aud": []string{"teknoir-cli", "teknoir-ztna", "account"},
	}
	if mutate != nil {
		mutate(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKCVerifier(t *testing.T, j *jwksServer, clock *fakeClock, azp ...string) *KeycloakVerifier {
	t.Helper()
	v, err := NewKeycloakVerifier(KeycloakConfig{
		Issuer: kcIssuer, JWKSURL: j.srv.URL, AllowedAZP: azp, Now: clock.Now, MinRefresh: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestKeycloakVerifier(t *testing.T) {
	key := newKCKey(t, "k1")
	other := newKCKey(t, "k1") // same kid, different key: signature must fail
	j := newJWKSServer(t, key)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	ctx := context.Background()
	now := clock.Now()

	hs256 := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": kcIssuer, "azp": "teknoir-cli", "email": "alice@example.com", "email_verified": true, "exp": now.Add(time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString([]byte("secret"))
		return s
	}
	none := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"iss": kcIssuer, "azp": "teknoir-cli", "email": "alice@example.com", "email_verified": true, "exp": now.Add(time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		return s
	}

	tests := []struct {
		name   string
		token  string
		wantOK bool
	}{
		{"valid", kcToken(t, key, nil, now), true},
		{"browser token azp teknoir is rejected", kcToken(t, key, func(c jwt.MapClaims) { c["azp"] = "teknoir" }, now), false},
		{"missing azp", kcToken(t, key, func(c jwt.MapClaims) { delete(c, "azp") }, now), false},
		{"wrong issuer", kcToken(t, key, func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" }, now), false},
		{"expired", kcToken(t, key, func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Minute).Unix() }, now), false},
		{"expired within skew is accepted", kcToken(t, key, func(c jwt.MapClaims) { c["exp"] = now.Add(-20 * time.Second).Unix() }, now), true},
		{"expired beyond skew", kcToken(t, key, func(c jwt.MapClaims) { c["exp"] = now.Add(-40 * time.Second).Unix() }, now), false},
		{"no exp", kcToken(t, key, func(c jwt.MapClaims) { delete(c, "exp") }, now), false},
		{"nbf in the future", kcToken(t, key, func(c jwt.MapClaims) { c["nbf"] = now.Add(5 * time.Minute).Unix() }, now), false},
		{"nbf within skew", kcToken(t, key, func(c jwt.MapClaims) { c["nbf"] = now.Add(20 * time.Second).Unix() }, now), true},
		{"email missing", kcToken(t, key, func(c jwt.MapClaims) { delete(c, "email") }, now), false},
		{"email uppercase", kcToken(t, key, func(c jwt.MapClaims) { c["email"] = "Alice@example.com" }, now), false},
		{"email malformed", kcToken(t, key, func(c jwt.MapClaims) { c["email"] = "not-an-email" }, now), false},
		{"email with display name", kcToken(t, key, func(c jwt.MapClaims) { c["email"] = "alice <alice@example.com>" }, now), false},
		{"email not verified", kcToken(t, key, func(c jwt.MapClaims) { c["email_verified"] = false }, now), false},
		{"email_verified missing", kcToken(t, key, func(c jwt.MapClaims) { delete(c, "email_verified") }, now), false},
		{"email_verified as string", kcToken(t, key, func(c jwt.MapClaims) { c["email_verified"] = "true" }, now), false},
		{"wrong signing key", kcToken(t, other, nil, now), false},
		{"unknown kid", kcToken(t, kcKey{kid: "zzz", key: key.key}, nil, now), false},
		{"HS256", hs256(), false},
		{"alg none", none(), false},
		{"garbage", "a.b.c", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Authenticate(ctx, tc.token)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				if id.Email != "alice@example.com" || id.ExpiresAt.IsZero() {
					t.Fatalf("bad identity %+v", id)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("want ErrUnauthenticated, got %v", err)
			}
		})
	}
}

func TestKeycloakAllowedAZPConfigurable(t *testing.T) {
	key := newKCKey(t, "k1")
	j := newJWKSServer(t, key)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock, "teknoir-cli", "teknoir-ztna")
	for azp, want := range map[string]bool{"teknoir-cli": true, "teknoir-ztna": true, "teknoir": false} {
		_, err := v.Authenticate(context.Background(), kcToken(t, key, func(c jwt.MapClaims) { c["azp"] = azp }, clock.Now()))
		if (err == nil) != want {
			t.Fatalf("azp %q: err=%v, want ok=%v", azp, err, want)
		}
	}
}

func TestKeycloakJWKSCachingAndRefresh(t *testing.T) {
	k1, k2 := newKCKey(t, "k1"), newKCKey(t, "k2")
	j := newJWKSServer(t, k1)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	ctx := context.Background()

	for range 5 {
		if _, err := v.Authenticate(ctx, kcToken(t, k1, nil, clock.Now())); err != nil {
			t.Fatal(err)
		}
	}
	if j.hits.Load() != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 (cached)", j.hits.Load())
	}

	// Key rotation: a token with an unknown kid triggers a refresh.
	j.setKeys(k1, k2)
	clock.Advance(2 * time.Second) // beyond MinRefresh
	if _, err := v.Authenticate(ctx, kcToken(t, k2, nil, clock.Now())); err != nil {
		t.Fatalf("token with rotated-in kid rejected: %v", err)
	}
	if j.hits.Load() != 2 {
		t.Fatalf("expected one refresh, hits=%d", j.hits.Load())
	}

	// Garbage kids cannot make the hub hammer Keycloak.
	for range 20 {
		_, _ = v.Authenticate(ctx, kcToken(t, kcKey{kid: "nope", key: k1.key}, nil, clock.Now()))
	}
	if j.hits.Load() > 3 {
		t.Fatalf("unknown kids caused %d fetches", j.hits.Load())
	}

	// A removed key stops verifying after the next refresh.
	j.setKeys(k2)
	clock.Advance(11 * time.Minute) // cache TTL
	if _, err := v.Authenticate(ctx, kcToken(t, k1, nil, clock.Now())); err == nil {
		t.Fatal("token signed by a removed key must be rejected after refresh")
	}
}

func TestKeycloakJWKSUnavailable(t *testing.T) {
	k1 := newKCKey(t, "k1")
	j := newJWKSServer(t, k1)
	j.fails.Store(true)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	_, err := v.Authenticate(context.Background(), kcToken(t, k1, nil, clock.Now()))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}

	// Once fetched, an outage does not break verification of known keys.
	j.fails.Store(false)
	clock.Advance(2 * time.Second)
	if _, err := v.Authenticate(context.Background(), kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatal(err)
	}
	j.fails.Store(true)
	clock.Advance(11 * time.Minute)
	if _, err := v.Authenticate(context.Background(), kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatalf("known key must keep working during an outage: %v", err)
	}
}

func TestValidEmail(t *testing.T) {
	for _, ok := range []string{"a@b.co", "first.last+tag@example.com", "x@y"} {
		if !ValidEmail(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "A@b.co", "a b@c.d", "a@b@c", "@b.c", "a@", "<a@b.c>", "n <a@b.c>", "a@b.c\n", "\"a b\"@c.d", "a,b@c.d", "a@b.c;x"} {
		if ValidEmail(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

// ---- JWKS outage behaviour ----

// blackHole is a JWKS endpoint that accepts connections and never answers
// until released.
type blackHole struct {
	srv     *httptest.Server
	hits    atomic.Int32
	release chan struct{}
	doc     http.Handler
}

func newBlackHole(t *testing.T, good http.Handler) *blackHole {
	t.Helper()
	b := &blackHole{release: make(chan struct{}), doc: good}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		select {
		case <-b.release:
			b.doc.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(b.release); b.srv.Close() })
	return b
}

func TestKeycloakBlackholedJWKSDoesNotSerialiseAuthentication(t *testing.T) {
	k1 := newKCKey(t, "k1")
	j := newJWKSServer(t, k1)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	ctx := context.Background()
	if _, err := v.Authenticate(ctx, kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatal(err)
	}

	// Keycloak now hangs; the cache is stale.
	bh := newBlackHole(t, http.NotFoundHandler())
	v.cfg.JWKSURL = bh.srv.URL
	v.cfg.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	v.cfg.StaleWait = 150 * time.Millisecond
	clock.Advance(11 * time.Minute)

	const callers = 12
	tokens := make([]string, callers)
	for i := range tokens {
		tokens[i] = kcToken(t, k1, nil, clock.Now())
	}
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := v.Authenticate(ctx, tokens[i])
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a known key must keep working while Keycloak hangs: %v", err)
		}
	}
	// In parallel, each waiting at most StaleWait: nowhere near callers * timeout.
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("%d callers took %v; authentication was serialised behind the hung fetch", callers, took)
	}
	if n := bh.hits.Load(); n != 1 {
		t.Fatalf("%d concurrent fetches; callers must share one", n)
	}
	// Later calls do not wait for the hung fetch at all, nor start another.
	start = time.Now()
	if _, err := v.Authenticate(ctx, kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("took %v with a fetch in flight", took)
	}
	if n := bh.hits.Load(); n != 1 {
		t.Fatalf("%d fetches", n)
	}
}

func TestKeycloakFailedFetchesBackOff(t *testing.T) {
	k1 := newKCKey(t, "k1")
	j := newJWKSServer(t, k1)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	ctx := context.Background()
	if _, err := v.Authenticate(ctx, kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatal(err)
	}
	j.fails.Store(true)
	clock.Advance(11 * time.Minute) // stale

	call := func(kid kcKey) error {
		_, err := v.Authenticate(ctx, kcToken(t, kid, nil, clock.Now()))
		return err
	}
	hits0 := j.hits.Load()
	if err := call(k1); err != nil {
		t.Fatalf("stale known key: %v", err)
	}
	waitFor(t, "failed fetch", func() bool { return j.hits.Load() > hits0 })
	hits1 := j.hits.Load()
	// Unknown kids and stale keys in a burst: no new fetch within the backoff.
	unknown := kcKey{kid: "nope", key: k1.key}
	for range 20 {
		_ = call(k1)
		if err := call(unknown); !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("unknown kid during an outage: %v", err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := j.hits.Load(); n != hits1 {
		t.Fatalf("%d fetches during the backoff; failures must be throttled like successes", n-hits1)
	}
	// After the backoff (MinRefresh * 2) one more attempt is made, and when
	// Keycloak is back the new key set is used.
	j.fails.Store(false)
	clock.Advance(3 * time.Second)
	if err := call(k1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "recovery fetch", func() bool { return j.hits.Load() > hits1 })
}

func TestKeycloakFetchIgnoresTheCallersContext(t *testing.T) {
	k1 := newKCKey(t, "k1")
	j := newJWKSServer(t, k1)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)

	// The first caller's request is cancelled at once; the fetch it started
	// must still finish, so the next caller finds the keys.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = v.Authenticate(cctx, kcToken(t, k1, nil, clock.Now()))
	waitFor(t, "keys cached", func() bool {
		v.mu.Lock()
		defer v.mu.Unlock()
		return len(v.keys) == 1
	})
	if _, err := v.Authenticate(context.Background(), kcToken(t, k1, nil, clock.Now())); err != nil {
		t.Fatalf("a cancelled first caller poisoned the cache: %v", err)
	}
}

func TestKeycloakTokenIdentity(t *testing.T) {
	key := newKCKey(t, "k1")
	j := newJWKSServer(t, key)
	clock := newFakeClock()
	v := newKCVerifier(t, j, clock)
	now := clock.Now()
	id, err := v.Authenticate(context.Background(), kcToken(t, key, func(c jwt.MapClaims) { c["jti"] = "jti-1" }, now))
	if err != nil {
		t.Fatal(err)
	}
	if id.TokenID != "jti-1" || !id.IssuedAt.Equal(now) {
		t.Fatalf("identity %+v", id)
	}
}

func newKCVerifierMode(t *testing.T, j *jwksServer, clock *fakeClock, mode string) (*KeycloakVerifier, error) {
	t.Helper()
	return NewKeycloakVerifier(KeycloakConfig{
		Issuer: kcIssuer, JWKSURL: j.srv.URL, Now: clock.Now, MinRefresh: time.Second, AudienceMode: mode,
	})
}

func TestKeycloakAudience(t *testing.T) {
	key := newKCKey(t, "k1")
	j := newJWKSServer(t, key)
	clock := newFakeClock()
	now := clock.Now()
	ctx := context.Background()

	enforce, err := newKCVerifierMode(t, j, clock, "") // the default mode is enforce
	if err != nil {
		t.Fatal(err)
	}
	transition, err := newKCVerifierMode(t, j, clock, "transition")
	if err != nil {
		t.Fatal(err)
	}
	withAud := func(aud any) func(jwt.MapClaims) {
		return func(c jwt.MapClaims) {
			if aud == nil {
				delete(c, "aud")
				return
			}
			c["aud"] = aud
		}
	}
	tests := []struct {
		name        string
		mutate      func(jwt.MapClaims)
		wantEnforce bool // accepted in enforce mode
	}{
		{"array with the audience", withAud([]string{"teknoir-cli", "teknoir-ztna", "account"}), true},
		{"string audience", withAud("teknoir-ztna"), true},
		{"main token (cli only)", withAud([]string{"teknoir-cli", "master-realm", "account"}), false},
		{"string without the audience", withAud("teknoir-cli"), false},
		{"no aud claim", withAud(nil), false},
		{"empty array", withAud([]string{}), false},
		{"prefix of the audience is not it", withAud([]string{"teknoir-ztna-status"}), false},
		{"non-string aud", withAud(42), false},
		{"azp teknoir with the audience", func(c jwt.MapClaims) { c["azp"] = "teknoir"; c["aud"] = "teknoir-ztna" }, false},
	}
	for _, tc := range tests {
		tok := kcToken(t, key, tc.mutate, now)
		t.Run("enforce/"+tc.name, func(t *testing.T) {
			id, err := enforce.Authenticate(ctx, tok)
			if tc.wantEnforce {
				if err != nil || id.LegacyAudience {
					t.Fatalf("err=%v legacy=%v", err, id.LegacyAudience)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("want ErrUnauthenticated, got %v", err)
			}
		})
		t.Run("transition/"+tc.name, func(t *testing.T) {
			id, err := transition.Authenticate(ctx, tok)
			azpWrong := tc.name == "azp teknoir with the audience"
			switch {
			case azpWrong:
				if err == nil {
					t.Fatal("azp teknoir accepted in transition mode")
				}
			case err != nil:
				t.Fatalf("rejected: %v", err)
			case id.LegacyAudience == tc.wantEnforce:
				t.Fatalf("legacy=%v for a token that %s", id.LegacyAudience, tc.name)
			}
		})
	}

	// The enforce error satisfies both sentinels, so asDenial answers 401.
	_, err = enforce.Authenticate(ctx, kcToken(t, key, withAud("teknoir-cli"), now))
	if !errors.Is(err, ErrMissingAudience) || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("got %v", err)
	}
	if d := asDenial(err); d.status != http.StatusUnauthorized || d.reason != "unauthenticated" {
		t.Fatalf("denial %+v", d)
	}
}

func TestKeycloakAudienceConfigurable(t *testing.T) {
	key := newKCKey(t, "k1")
	j := newJWKSServer(t, key)
	clock := newFakeClock()
	v, err := NewKeycloakVerifier(KeycloakConfig{Issuer: kcIssuer, JWKSURL: j.srv.URL, Now: clock.Now, Audience: "hub-x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(context.Background(), kcToken(t, key, func(c jwt.MapClaims) { c["aud"] = "teknoir-ztna" }, clock.Now())); !errors.Is(err, ErrMissingAudience) {
		t.Fatalf("default audience accepted for a verifier configured for hub-x: %v", err)
	}
	if _, err := v.Authenticate(context.Background(), kcToken(t, key, func(c jwt.MapClaims) { c["aud"] = []string{"hub-x"} }, clock.Now())); err != nil {
		t.Fatal(err)
	}
}

func TestKeycloakBadAudienceModeRejected(t *testing.T) {
	for _, mode := range []string{"off", "audit", "Enforce", "true"} {
		if _, err := NewKeycloakVerifier(KeycloakConfig{Issuer: kcIssuer, JWKSURL: "http://x", AudienceMode: mode}); err == nil {
			t.Errorf("mode %q accepted", mode)
		}
	}
}
