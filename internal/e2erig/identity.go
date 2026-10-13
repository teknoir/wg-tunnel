package e2erig

import (
	"crypto/ed25519"
	"testing"

	"github.com/teknoir/wg-tunnel/pkg/identity"
)

// LoadFingerprint returns the fingerprint of the identity key in dir.
func LoadFingerprint(t testing.TB, dir string) string {
	t.Helper()
	priv, err := identity.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("loading identity: %v", err)
	}
	return identity.Fingerprint(priv.Public().(ed25519.PublicKey))
}
