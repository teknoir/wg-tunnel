package e2erig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/devicekey"
)

// DeliverDeviceKey plays device-controller's MQTT delivery: it generates a
// device key, seals it to the device's bootstrap RSA key and writes the
// envelope where the kubelet would project the ConfigMap api.DeviceKeyConfigMap
// (atomically). It returns the key's fingerprint; TrustDeviceKey makes it the
// activation anchor. The key itself is a secret of the rig.
func (r *Rig) DeliverDeviceKey(serial string) string {
	r.T.Helper()
	priv, err := devicekey.Generate()
	must(r.T, err)
	env, err := devicekey.Seal([]byte(rsaCert), NS, DeviceName, serial, priv)
	must(r.T, err)
	b, err := json.Marshal(env)
	must(r.T, err)
	must(r.T, os.MkdirAll(filepath.Dir(r.DeviceKeyEnvelope), 0o755))
	tmp := r.DeviceKeyEnvelope + ".tmp"
	must(r.T, os.WriteFile(tmp, b, 0o644))
	must(r.T, os.Rename(tmp, r.DeviceKeyEnvelope))
	r.AddSecret(base64.StdEncoding.EncodeToString(priv.Seed()))
	r.AddSecret(env.Ciphertext)
	return env.Fingerprint
}

// RemoveEnvelope takes the envelope away, as device-controller does once the
// hub confirmed the key.
func (r *Rig) RemoveEnvelope() {
	r.T.Helper()
	must(r.T, os.Remove(r.DeviceKeyEnvelope))
}

// InstallBootstrapDeviceKey plays the trusted bootstrap: it writes a device
// key where the agent looks for api.DeviceKeyFile (mode 0440) and returns its
// fingerprint.
func (r *Rig) InstallBootstrapDeviceKey() string {
	r.T.Helper()
	priv, err := devicekey.Generate()
	must(r.T, err)
	pemBytes, err := devicekey.MarshalOpenSSH(priv)
	must(r.T, err)
	_ = os.Remove(r.DeviceKeyFile) // read-only
	must(r.T, os.WriteFile(r.DeviceKeyFile, pemBytes, 0o440))
	r.AddSecret(base64.StdEncoding.EncodeToString(priv.Seed()))
	fp, err := devicekey.Fingerprint(priv.Public().(ed25519.PublicKey))
	must(r.T, err)
	return fp
}

// TrustDeviceKey plays device-controller's policy: the fingerprint of the
// device key becomes PolicyEntry.TrustedHostKey (source mqtt).
func (r *Rig) TrustDeviceKey(fp string) {
	r.T.Helper()
	r.Policy.Update(NS, DeviceName, func(e *api.PolicyEntry) {
		e.TrustedHostKey, e.TrustedKeySource = fp, api.DeviceKeySourceMQTT
	})
}

// CloseEnrollmentWindow ends the TOFU window of the current generation, as
// time does on a device that was bootstrapped long ago.
func (r *Rig) CloseEnrollmentWindow() {
	r.T.Helper()
	r.Policy.Update(NS, DeviceName, func(e *api.PolicyEntry) { e.EnrollUntil = time.Now().Add(-time.Minute) })
}
