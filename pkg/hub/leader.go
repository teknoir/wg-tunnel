package hub

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// A hub that runs with more than one replica serves from exactly one of them.
// The replicas campaign for a Lease; the winner serves (Hub.SetLeading), labels
// its own pod "leader" (the Service wg-hub selects that label) and every other
// replica is a hot standby. Leader owns this life cycle, the Elector and the
// RolePatcher are its Kubernetes ends (k8s_leader.go) and are replaced by fakes
// in tests.

// ErrLostLease is returned by Elector.Run when the lease was lost after it had
// been won (the API server was unreachable for longer than the renew
// deadline, or another process took the lease).
var ErrLostLease = errors.New("hub: lost the leader lease")

// Elector campaigns for the leader lease.
type Elector interface {
	// Run campaigns until ctx ends or the lease is lost. onStarted is called
	// once when this process wins the lease. When ctx ends, a held lease is
	// released before Run returns and Run returns nil; ErrLostLease means the
	// lease was lost while ctx was still alive.
	Run(ctx context.Context, onStarted func()) error
	// WaitSuccessor waits for at most wait until another process holds the
	// lease and reports whether one does.
	WaitSuccessor(ctx context.Context, wait time.Duration) bool
}

// RolePatcher publishes this replica's role on its own pod.
type RolePatcher interface {
	// SetRole sets the pod label api.HubRoleLabel (leader or standby) and the
	// annotation api.PodDeletionCostAnnotation (100 or 0), and nothing else.
	SetRole(ctx context.Context, leader bool) error
}

// LeaderConfig configures a Leader.
type LeaderConfig struct {
	Elector Elector
	Patcher RolePatcher
	// HandoverWait is how long a stepping-down leader waits for another
	// replica to take the lease (0 with a single replica: nobody will).
	HandoverWait time.Duration
	// HandoverSettle is the pause after a successor appeared, so that the
	// EndpointSlice, the mesh and DNS point at it before the devices are told
	// to reconnect.
	HandoverSettle time.Duration
	// PatchRetry is the delay before a failed role patch is tried again
	// (default 2 s).
	PatchRetry time.Duration
	// RoleWait bounds how long after Start the hub is held not Ready while the
	// first role patch has not succeeded (default 10 s). A restarted pod still
	// carries the label of its previous life (possibly "leader"); Ready before
	// the standby patch lands would let the Service select a standby, and a
	// rolling update would then move on while the old leader label is stale.
	// The bound keeps an unreachable API server from holding every replica
	// unready.
	RoleWait time.Duration
	Logger   *slog.Logger
}

// Leader ties a Hub to a leader election: the hub serves only while the lease
// is held, the pod label follows, and Shutdown is the planned handover.
type Leader struct {
	h   *Hub
	cfg LeaderConfig
	log *slog.Logger

	mu        sync.Mutex
	stopping  bool
	wasLeader bool
	want      string // the role the pod should show

	kick       chan struct{}
	lost       chan struct{}
	stopElect  context.CancelFunc
	stopRole   context.CancelFunc
	electDone  chan struct{}
	roleDone   chan struct{}
	startedRun bool

	started     time.Time     // when Start ran (zero before)
	roleSettled chan struct{} // closed by the first successful role patch
	settleOnce  sync.Once
}

// NewLeader makes h a hot standby (SetLeading(false)) until the election is won.
// Call it before h's HTTP servers start; Start begins the campaign.
func NewLeader(h *Hub, cfg LeaderConfig) *Leader {
	if cfg.PatchRetry <= 0 {
		cfg.PatchRetry = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = h.log
	}
	if cfg.RoleWait <= 0 {
		cfg.RoleWait = 10 * time.Second
	}
	h.SetLeading(false)
	l := &Leader{
		h: h, cfg: cfg, log: cfg.Logger, want: api.HubRoleStandby,
		kick: make(chan struct{}, 1), lost: make(chan struct{}),
		electDone: make(chan struct{}), roleDone: make(chan struct{}),
		roleSettled: make(chan struct{}),
	}
	gate := l.roleReady
	h.readyGate.Store(&gate)
	return l
}

// roleReady is the Ready gate: false until Start, then until the first role
// patch succeeded or RoleWait passed.
func (l *Leader) roleReady() bool {
	select {
	case <-l.roleSettled:
		return true
	default:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.started.IsZero() && time.Since(l.started) >= l.cfg.RoleWait
}

// Lost is closed when the lease was lost while the process was running. The
// hub already stopped serving; the caller runs Shutdown and exits so that the
// container restarts as a standby.
func (l *Leader) Lost() <-chan struct{} { return l.lost }

// Start labels the pod standby and begins the campaign. ctx bounds the
// background work; Shutdown ends it earlier.
func (l *Leader) Start(ctx context.Context) {
	l.mu.Lock()
	if l.startedRun {
		l.mu.Unlock()
		return
	}
	l.startedRun = true
	l.started = time.Now()
	l.mu.Unlock()

	rctx, stopRole := context.WithCancel(ctx)
	ectx, stopElect := context.WithCancel(ctx)
	l.stopRole, l.stopElect = stopRole, stopElect
	go l.roleLoop(rctx)
	go func() {
		defer close(l.electDone)
		err := l.cfg.Elector.Run(ectx, l.onStarted)
		if err == nil || ectx.Err() != nil {
			return
		}
		l.log.Error("leader election ended", "err", err)
		l.mu.Lock()
		if !l.stopping {
			l.h.SetLeading(false)
			l.want = api.HubRoleStandby
		}
		l.mu.Unlock()
		l.wake()
		close(l.lost)
	}()
}

// onStarted runs when this replica wins the lease: serve first, then label,
// so a request that the label attracts finds a serving hub.
func (l *Leader) onStarted() {
	l.mu.Lock()
	if l.stopping {
		l.mu.Unlock()
		return
	}
	l.wasLeader = true
	l.h.SetLeading(true)
	l.want = api.HubRoleLeader
	l.mu.Unlock()
	l.log.Info("this replica is the leader")
	l.wake()
}

func (l *Leader) wake() {
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

func (l *Leader) wanted() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.want
}

// roleLoop makes the pod show the wanted role. A failed patch is retried every
// PatchRetry, logged and counted; it never touches readiness or serving.
func (l *Leader) roleLoop(ctx context.Context) {
	defer close(l.roleDone)
	applied := ""
	for {
		if want := l.wanted(); want != applied {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := l.cfg.Patcher.SetRole(pctx, want == api.HubRoleLeader)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.h.met.rolePatchErrors.Inc()
				l.log.Error("role patch failed; retrying", "role", want, "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(l.cfg.PatchRetry):
				}
				continue
			}
			applied = want
			l.settleOnce.Do(func() { close(l.roleSettled) })
			l.log.Info("pod role set", "role", want)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-l.kick:
		}
	}
}

// Shutdown is the planned handover, for SIGTERM and for a lost lease:
//
//  1. stop serving new sessions (SetLeading(false)); existing streams run on,
//  2. label the pod standby (best effort),
//  3. release the lease,
//  4. wait up to HandoverWait for another replica to take it,
//  5. wait HandoverSettle so the routing follows,
//  6. tell every control-capable device to reconnect and close the hub
//     (Hub.Handover).
//
// A replica that never led skips 4 and 5. ctx bounds the whole sequence.
func (l *Leader) Shutdown(ctx context.Context) error {
	l.mu.Lock()
	l.stopping = true
	wasLeader := l.wasLeader
	l.h.SetLeading(false)
	l.want = api.HubRoleStandby
	l.mu.Unlock()
	l.log.Info("stepping down", "wasLeader", wasLeader)

	if l.startedRun {
		// The role loop must not race the patch below.
		l.stopRole()
		<-l.roleDone
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := l.cfg.Patcher.SetRole(pctx, false); err != nil {
		l.h.met.rolePatchErrors.Inc()
		l.log.Warn("could not label the pod standby", "err", err)
	}
	cancel()

	if l.startedRun {
		l.stopElect()
		select {
		case <-l.electDone: // the lease is released
		case <-ctx.Done():
		}
	}

	result := "not_leader"
	if wasLeader {
		result = "no_successor"
		if l.cfg.HandoverWait > 0 && l.cfg.Elector.WaitSuccessor(ctx, l.cfg.HandoverWait) {
			result = "successor"
			select {
			case <-time.After(l.cfg.HandoverSettle):
			case <-ctx.Done():
			}
		}
	}
	l.h.met.handovers.WithLabelValues(result).Inc()
	l.log.Info("handing over", "result", result)
	return l.h.Handover(ctx)
}
