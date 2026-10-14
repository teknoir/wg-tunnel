package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/version"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

// identityTokenTTL is the lifetime of the identity JWTs sent with session and
// renewal requests (the contract caps it at 60 s; one is minted per call).
const identityTokenTTL = 30 * time.Second

// Agent runs the device session loop.
type Agent struct {
	cfg Config
	log *slog.Logger
	sub string

	// Replaceable in tests.
	sleep func(context.Context, time.Duration)
	rnd   func() float64

	mu       sync.Mutex
	loggedFP string
}

// New validates cfg (applying defaults) and returns an Agent.
func New(cfg Config) (*Agent, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	return &Agent{
		cfg: cfg, log: cfg.Logger, sub: api.DeviceSubject(cfg.Namespace, cfg.DeviceID),
		sleep: sleepCtx, rnd: randFloat,
	}, nil
}

func (a *Agent) posture() api.Posture {
	host, _ := os.Hostname()
	return api.Posture{Software: "wg-agent", Version: version.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: host}
}

// Run keeps a device session up until ctx is cancelled, then closes it and
// returns nil. It returns an error only for failures that retrying cannot
// fix (an unusable identity directory).
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("wg-agent starting", "device", a.cfg.DeviceID, "namespace", a.cfg.Namespace, "hub", a.cfg.HubURL, "version", version.Version)
	failures := 0
	for ctx.Err() == nil {
		up, err := a.attempt(ctx)
		if ctx.Err() != nil {
			a.log.Info("wg-agent stopping")
			return nil
		}
		var fatal *fatalError
		if errors.As(err, &fatal) {
			return fatal.err
		}
		if up >= a.cfg.Backoff.Stable {
			failures = 0
		}
		d := a.cfg.Backoff.delay(failures, a.rnd)
		failures++
		a.logFailure(err, d)
		a.sleep(ctx, d)
	}
	a.log.Info("wg-agent stopping")
	return nil
}

type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }

// hint maps a hub denial to what the operator should do about it.
var hints = map[string]string{
	api.ReasonEnrollClosed:    "the enrollment window is closed; an admin must reset enrollment for this device in the Teknoir UI",
	api.ReasonEnrollConflict:  "a different identity is already pinned for this device; an admin must reset enrollment if this is the same device",
	api.ReasonDeviceRevoked:   "the device is flagged compromised or failed its health check; waiting for an admin to clear the flag",
	api.ReasonDeviceDisabled:  "WireGuard is not enabled for this device",
	api.ReasonForbidden:       "the hub refused this device",
	api.ReasonDeviceUnknown:   "the hub has no policy for this device yet",
	api.ReasonReplay:          "the hub saw a replayed device token",
	api.ReasonSessionLimit:    "the hub's session limit is reached",
	api.ReasonPosture:         "the hub rejected this agent's version",
	api.ReasonPendingApproval: "an admin must approve this device identity (fingerprint above) in the Teknoir UI",
}

func (a *Agent) logFailure(err error, wait time.Duration) {
	if err == nil {
		err = errors.New("session ended")
	}
	if wgclient.ReasonOf(err) == api.ReasonPendingApproval {
		// Stay enrolled and keep asking: the admin compares this fingerprint
		// with the one the UI shows for the pinned identity, then approves it.
		a.mu.Lock()
		fp := a.loggedFP
		a.mu.Unlock()
		a.log.Warn("waiting for admin approval of this device identity",
			"fingerprint", fp, "retry_in", wait.Round(time.Millisecond).String(),
			"hint", hints[api.ReasonPendingApproval])
		return
	}
	attrs := []any{"retry_in", wait.Round(time.Millisecond).String(), "error", err.Error()}
	if reason := wgclient.ReasonOf(err); reason != "" {
		attrs = append(attrs, "reason", reason)
		if h, ok := hints[reason]; ok {
			attrs = append(attrs, "hint", h)
		}
	}
	a.log.Warn("no session", attrs...)
}

// attempt runs one pass: ensure an identity, create a session (enrolling or
// re-enrolling when the hub asks), serve it until it ends. up is how long the
// session lasted (0 if none was established).
func (a *Agent) attempt(ctx context.Context) (up time.Duration, err error) {
	priv, err := identity.LoadOrCreate(a.cfg.IdentityDir)
	if err != nil {
		return 0, &fatalError{fmt.Errorf("identity key unusable: %w", err)}
	}
	a.logFingerprint(priv)
	if err := a.publishIdentityPub(priv); err != nil {
		return 0, err
	}
	hostKeys := ReadHostKeys(a.cfg.SSHHostKeysGlob, a.log)
	if len(hostKeys) == 0 {
		a.log.Warn("no SSH host keys found; clients will not be able to verify this device", "glob", a.cfg.SSHHostKeysGlob)
	}

	enrolled := false
	for {
		sess, cerr := a.create(ctx, priv, hostKeys)
		if cerr == nil {
			return a.serve(ctx, sess)
		}
		switch wgclient.ReasonOf(cerr) {
		case api.ReasonNotEnrolled:
			a.log.Info("device identity is not enrolled; enrolling")
		case api.ReasonUnauthenticated:
			// The hub shows strangers nothing but "unauthenticated", also for a
			// device whose pin belongs to another key (a rotated or lost
			// identity file, or an enrollment window that was reset while this
			// key never got enrolled). Enrolling is idempotent for the pinned
			// key and refused with a precise reason for any other.
			a.log.Info("the hub did not accept the device identity; trying to enroll it")
		case api.ReasonReenroll:
			if enrolled {
				return 0, fmt.Errorf("hub asked to re-enroll right after enrollment: %w", cerr)
			}
			a.log.Info("enrollment was reset; generating a new identity")
			rotated, rerr := identity.Rotate(a.cfg.IdentityDir)
			if rerr != nil {
				return 0, &fatalError{fmt.Errorf("rotating identity key: %w", rerr)}
			}
			priv = rotated
			a.logFingerprint(priv)
			if err := a.publishIdentityPub(priv); err != nil {
				return 0, err
			}
		default:
			return 0, cerr
		}
		if enrolled {
			return 0, fmt.Errorf("still not enrolled after enrollment: %w", cerr)
		}
		if eerr := a.enroll(ctx, priv); eerr != nil {
			return 0, eerr
		}
		enrolled = true
	}
}

func (a *Agent) logFingerprint(priv ed25519.PrivateKey) {
	fp := identity.Fingerprint(priv.Public().(ed25519.PublicKey))
	a.mu.Lock()
	changed := fp != a.loggedFP
	a.loggedFP = fp
	a.mu.Unlock()
	if changed {
		a.log.Info("device identity", "fingerprint", fp)
	}
}

// create asks the hub for a device session. The credential is a fresh identity
// JWT bound to the session's WireGuard key, minted for every create and renew.
func (a *Agent) create(ctx context.Context, priv ed25519.PrivateKey, hostKeys []string) (*wgclient.Session, error) {
	return wgclient.Create(ctx, wgclient.Options{
		HubURL: a.cfg.HubURL,
		Kind:   api.KindDevice,
		Credential: func(_ context.Context, wgPub string) (string, error) {
			tok, _, err := identity.MintIdentityJWT(priv, a.sub, wgPub, identityTokenTTL)
			return tok, err
		},
		DeviceRequest:      &api.DeviceSessionRequest{Posture: a.posture(), SSHHostKeys: hostKeys, Capabilities: a.capabilities()},
		TURNServerOverride: a.cfg.TURNServer,
		HTTPClient:         a.cfg.HTTPClient,
		Logger:             a.log,
		StaleAfter:         a.cfg.StaleAfter,
		HandshakeTimeout:   a.cfg.HandshakeTimeout,
		RenewRetry:         a.cfg.RenewRetry,
		RenewTimeout:       a.cfg.RenewTimeout,
		DeadAfter:          a.cfg.DeadAfter,
	})
}

// enroll pins the identity key at the hub, proving possession of the legacy
// RSA device key (admission) and of the identity key (proof of possession).
func (a *Agent) enroll(ctx context.Context, priv ed25519.PrivateKey) error {
	rsaPEM, err := os.ReadFile(a.cfg.RSAKeyPath)
	if err != nil {
		return fmt.Errorf("reading device RSA key for enrollment: %w", err)
	}
	pub := identity.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	var attestations []api.HostKeyAttestation
	if a.attesting() {
		if attestations, err = a.attest(ctx, rsaPEM, priv, pub); err != nil {
			return fmt.Errorf("host-key attestation: %w", err)
		}
	}
	token, jti, err := identity.MintEnrollJWT(rsaPEM, a.sub, pub, identityTokenTTL)
	if err != nil {
		return fmt.Errorf("minting enrollment token: %w", err)
	}
	req := api.EnrollRequest{
		IdentityPublicKey: pub,
		Proof:             identity.ProveEnroll(priv, a.sub, jti),
		Posture:           a.posture(),
	}
	if len(attestations) > 0 {
		// Advertised only together with a valid attestation: an agent that
		// could not obtain one enrolls like a phase-1 agent (admin approval).
		req.Capabilities, req.HostKeyAttestations = []string{api.CapAttest}, attestations
	}
	resp, err := wgclient.Enroll(ctx, a.cfg.HubURL, a.cfg.HTTPClient, token, req)
	if err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	a.log.Info("device identity enrolled", "fingerprint", resp.Fingerprint, "generation", resp.EnrollmentGeneration)
	return nil
}
