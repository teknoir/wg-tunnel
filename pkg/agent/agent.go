package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/version"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// identityTokenTTL is the lifetime of the identity JWTs sent with session and
// renewal requests (the contract caps it at 60 s; one is minted per call).
const identityTokenTTL = 30 * time.Second

// Agent runs the device session loop.
type Agent struct {
	cfg Config
	log *slog.Logger
	sub string
	// target decides where services may connect (re-validated on every dial).
	target *TargetPolicy

	// Replaceable in tests.
	sleep func(context.Context, time.Duration)
	rnd   func() float64

	mu       sync.Mutex
	loggedFP string
	// attestedSet identifies the keys (attestSetOf, or legacyAttestSet) this
	// process delivered attestations for with an enrollment of the current
	// identity, "" when it delivered none. triedSet and lastReattest are the
	// set of the last try to attest again and when that was.
	attestedSet  string
	triedSet     string
	lastReattest time.Time
	// curID is the identity key of the current attempt (the key watcher
	// attests it again when the device keys change).
	curID atomic.Pointer[ed25519.PrivateKey]
	// wake ends the wait between two attempts early.
	wake chan struct{}
	// lastImmediate is when the last hub notice skipped the back-off (guarded
	// by mu): a hub that keeps ending sessions cannot make the agent spin.
	lastImmediate time.Time

	// dkMu guards the device key files and dkWarned.
	dkMu     sync.Mutex
	dkWarned map[string]struct{}

	// pb is the plane B of the current device session (nil: none).
	pb atomic.Pointer[planeB]
	// grants is the grant store of the current device session.
	grants atomic.Pointer[GrantStore]
}

// New validates cfg (applying defaults) and returns an Agent.
func New(cfg Config) (*Agent, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	sshHost, err := netip.ParseAddr(cfg.ForwardHost)
	if err != nil {
		sshHost = netip.MustParseAddr(DefaultForwardHost) // a host name cannot be vetted: fall back to loopback
	}
	target := &TargetPolicy{
		ServiceCIDRs: cfg.ServiceCIDRs, ClusterCIDRs: cfg.ClusterCIDRs, ClusterDomain: cfg.ClusterDomain,
		SSHHost: sshHost.Unmap(), SSHPort: cfg.SSHPort,
		Resolver: cfg.Resolver, NodeIPs: cfg.NodeIPs, AllowTarget: cfg.AllowTarget,
	}
	target.applyDefaults()
	return &Agent{
		cfg: cfg, log: cfg.Logger, sub: api.DeviceSubject(cfg.Namespace, cfg.DeviceID),
		sleep: sleepCtx, rnd: randFloat, target: target, wake: make(chan struct{}, 1),
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
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		a.watchDeviceKeys(ctx)
	}()
	defer func() { <-watcherDone }()
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
		if a.skipBackoff(ctx, err) {
			continue
		}
		d := a.cfg.Backoff.delay(failures, a.rnd)
		failures++
		a.logFailure(err, d)
		a.sleepUnlessWoken(ctx, d)
	}
	a.log.Info("wg-agent stopping")
	return nil
}

// noticeError is why a session ended on the hub's RevokeNotice: err is the
// denial the notice carried, so wgclient.ReasonOf sees the notice's reason.
type noticeError struct{ err *wgclient.Error }

func (e *noticeError) Error() string { return "the hub ended the session: " + e.err.Error() }
func (e *noticeError) Unwrap() error { return e.err }

// noticeCooldown is how long after a notice that skipped the back-off the next
// one may skip it again. Notices are rare (an admin resets enrollment), so the
// limit only matters for a hub that misbehaves.
const noticeCooldown = 10 * time.Second

// skipBackoff reports whether the session ended on a notice that enrollment
// was reset, in which case the agent starts the next attempt at once: after a
// minimal jitter, without counting a failure and without a back-off. At most
// one attempt per notice and per noticeCooldown skips the back-off; whatever
// that attempt does goes through the normal back-off.
func (a *Agent) skipBackoff(ctx context.Context, err error) bool {
	var ne *noticeError
	if !errors.As(err, &ne) || ne.err.Reason != api.ReasonReenroll {
		return false
	}
	a.mu.Lock()
	ok := a.lastImmediate.IsZero() || time.Since(a.lastImmediate) >= noticeCooldown
	if ok {
		a.lastImmediate = time.Now()
	}
	a.mu.Unlock()
	if !ok {
		return false
	}
	// 100-300 ms: enough to spread a fleet reset together, still "at once".
	d := 100*time.Millisecond + time.Duration(a.rnd()*float64(200*time.Millisecond))
	a.log.Info("the hub reset this device's enrollment; enrolling again", "in", d.Round(time.Millisecond).String())
	a.sleepUnlessWoken(ctx, d)
	return true
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
	api.ReasonHubHandover:     "the hub hands over to another replica; connecting to it",
	api.ReasonAttestRequired:  "a device key is trusted for this device and this agent holds none it can attest with; an admin can rotate the device key in the Teknoir UI to deliver one",
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
	a.curID.Store(&priv)
	if err := a.publishIdentityPub(priv); err != nil {
		return 0, err
	}
	hostKeys := ReadHostKeys(a.cfg.SSHHostKeysGlob, a.log)
	if len(hostKeys) == 0 {
		a.log.Warn("no SSH host keys found; clients will not be able to verify this device", "glob", a.cfg.SSHHostKeysGlob)
	}

	enrolled := false
	for {
		// Plane B: a fresh WireGuard key for every device session, never stored.
		var p2pPriv *wgkey.PrivateKey
		if a.cfg.P2P {
			if k, _, err := wgkey.Generate(); err == nil {
				p2pPriv = &k
			}
		}
		holder := &grantHolder{log: a.log}
		sess, cerr := a.create(ctx, priv, hostKeys, p2pPriv, holder)
		if cerr == nil {
			up, err := a.serve(ctx, sess, p2pPriv, holder)
			if p2pPriv != nil {
				p2pPriv.Zero()
			}
			return up, err
		}
		if p2pPriv != nil {
			p2pPriv.Zero()
		}
		switch wgclient.ReasonOf(cerr) {
		case api.ReasonNotEnrolled:
			a.log.Info("device identity is not enrolled; enrolling")
		case api.ReasonPendingApproval:
			// The pin exists but is not usable. If it was enrolled without an
			// attestation by the keys held now (a new process, a device key
			// that came later, an attestor that could not sign yet), try again
			// to attest it: the hub accepts the same identity idempotently,
			// records the attestation, and activates the pin when the device
			// key is the one the policy trusts. Slow timer unless the keys
			// changed; no-op without a device key or attestor.
			if enrolled || !a.shouldReattest(true) {
				return 0, cerr
			}
			a.log.Info("the identity is waiting for approval; attesting it again")
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
			if priv, err = a.rotateIdentity(); err != nil {
				return 0, err
			}
		default:
			return 0, cerr
		}
		if enrolled {
			return 0, fmt.Errorf("still not enrolled after enrollment: %w", cerr)
		}
		eerr := a.enroll(ctx, priv)
		if wgclient.ReasonOf(eerr) == api.ReasonReenroll {
			// The hub voided this identity (a replacement of the device's pin
			// while it was offline, a flag) and, because the enrollment was
			// attested by the trusted device key, tells the device itself to
			// start over with a new identity.
			a.log.Info("the hub voided this device identity; generating a new one")
			if priv, err = a.rotateIdentity(); err != nil {
				return 0, err
			}
			eerr = a.enroll(ctx, priv)
		}
		if eerr != nil {
			return 0, eerr
		}
		enrolled = true
	}
}

// rotateIdentity replaces the identity key with a new one and makes it the
// identity of the current attempt.
func (a *Agent) rotateIdentity() (ed25519.PrivateKey, error) {
	priv, err := identity.Rotate(a.cfg.IdentityDir)
	if err != nil {
		return nil, &fatalError{fmt.Errorf("rotating identity key: %w", err)}
	}
	a.curID.Store(&priv)
	a.logFingerprint(priv)
	if err := a.publishIdentityPub(priv); err != nil {
		return nil, err
	}
	return priv, nil
}

// shouldReattest reports whether the identity should be attested again now:
// there are keys to attest with and this process has not delivered an
// attestation made with exactly this set of keys. A changed set is attested at
// once. An unchanged one is attested only while the hub still holds the
// identity back (pending: the hub records one attestation per pin, and the key
// it preferred then may not be the one it trusts now), at most every
// Config.ReattestInterval.
func (a *Agent) shouldReattest(pending bool) bool {
	set := a.currentAttestSet()
	if set == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if (a.attestedSet == set && !pending) || (set == a.triedSet && time.Since(a.lastReattest) < a.cfg.ReattestInterval) {
		return false
	}
	a.triedSet, a.lastReattest = set, time.Now()
	return true
}

// watchDeviceKeys notices a device key that appeared or changed (the bootstrap
// file, or an envelope device-controller delivered) and attests the current
// identity again, whatever state the session is in: a pending pin activates, an
// active one records the key. It returns when ctx ends.
func (a *Agent) watchDeviceKeys(ctx context.Context) {
	poll := a.cfg.DeviceKeyPoll
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		priv := a.curID.Load()
		if priv == nil || len(a.deviceKeys()) == 0 || !a.shouldReattest(false) {
			continue
		}
		a.log.Info("the device keys changed; attesting the device identity again")
		if err := a.enroll(ctx, *priv); err != nil {
			if ctx.Err() == nil {
				a.log.Warn("attesting the device identity again failed", "error", err.Error())
			}
			if wgclient.ReasonOf(err) == api.ReasonReenroll { // the session loop rotates the identity
				select {
				case a.wake <- struct{}{}:
				default:
				}
			}
			continue
		}
		select { // the session attempt may be waiting for exactly this
		case a.wake <- struct{}{}:
		default:
		}
	}
}

// sleepUnlessWoken waits d between two attempts, or less when the key watcher
// attested the identity meanwhile.
func (a *Agent) sleepUnlessWoken(ctx context.Context, d time.Duration) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-a.wake:
			cancel()
		case <-wctx.Done():
		}
	}()
	a.sleep(wctx, d)
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
func (a *Agent) create(ctx context.Context, priv ed25519.PrivateKey, hostKeys []string, p2pPriv *wgkey.PrivateKey, holder *grantHolder) (*wgclient.Session, error) {
	req := &api.DeviceSessionRequest{Posture: a.posture(), SSHHostKeys: hostKeys, Capabilities: a.capabilities()}
	if p2pPriv != nil {
		if pub, err := p2pPriv.Public(); err == nil {
			req.P2PWGPublicKey = pub.Base64()
		}
	}
	return wgclient.Create(ctx, wgclient.Options{
		OnRenew: func(rr *api.RenewResponse) {
			if rr.Grants != nil {
				holder.applyBackstop(*rr.Grants)
			}
		},
		HubURL: a.cfg.HubURL,
		Kind:   api.KindDevice,
		Credential: func(_ context.Context, wgPub string) (string, error) {
			tok, _, err := identity.MintIdentityJWT(priv, a.sub, wgPub, identityTokenTTL)
			return tok, err
		},
		DeviceRequest:      req,
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
// RSA device key (admission) and of the identity key (proof of possession),
// and attests it with the device keys. Enrolling the pinned identity again is
// how a changed set of device keys reaches the hub.
func (a *Agent) enroll(ctx context.Context, priv ed25519.PrivateKey) error {
	rsaPEM, err := os.ReadFile(a.cfg.RSAKeyPath)
	if err != nil {
		return fmt.Errorf("reading device RSA key for enrollment: %w", err)
	}
	pub := identity.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	var (
		attestations []api.HostKeyAttestation
		caps         []string
		set          string
	)
	switch keys := a.deviceKeys(); {
	case len(keys) > 0:
		if attestations, err = a.attestDeviceKeys(ctx, rsaPEM, priv, pub, keys); err != nil {
			return fmt.Errorf("device key attestation: %w", err)
		}
		caps, set = []string{api.CapAttest, api.CapDeviceKey}, attestSetOf(keys)
	case a.legacyAttesting(keys):
		if attestations, err = a.attest(ctx, rsaPEM, priv, pub); err != nil {
			return fmt.Errorf("host-key attestation: %w", err)
		}
		caps, set = []string{api.CapAttest}, legacyAttestSet
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
		req.Capabilities, req.HostKeyAttestations = caps, attestations
	} else {
		set = ""
	}
	resp, err := wgclient.Enroll(ctx, a.cfg.HubURL, a.cfg.HTTPClient, token, req)
	if err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	a.mu.Lock()
	a.attestedSet = set
	a.mu.Unlock()
	a.log.Info("device identity enrolled", "fingerprint", resp.Fingerprint, "generation", resp.EnrollmentGeneration)
	return nil
}

// P2PStatus reports the plane B of the current device session.
func (a *Agent) P2PStatus() P2PStatus {
	pb := a.pb.Load()
	if pb == nil {
		return P2PStatus{}
	}
	return P2PStatus{Up: true, Peers: pb.pl.PeerCount(), Candidates: p2p.Strings(pb.pl.Socket().Candidates())}
}

// DropP2PGrants forgets every plane-B grant of the current device session, as
// if the hub's control pushes had been lost (a test hook: the renewal backstop
// is what restores them).
func (a *Agent) DropP2PGrants() {
	if g := a.grants.Load(); g != nil {
		g.DropAll()
	}
}
