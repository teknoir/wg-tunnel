package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// ElectionTimings are the client-go leader election timings. A leader survives
// an API server outage of up to RenewDeadline; another replica takes over
// LeaseDuration after the last renewal of a leader that vanished (a released
// lease is taken within about RetryPeriod).
type ElectionTimings struct {
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// K8sElector is an Elector on a coordination.k8s.io Lease.
type K8sElector struct {
	cs   kubernetes.Interface
	ns   string
	name string
	id   string
	t    ElectionTimings
	log  *slog.Logger
	// poll is how often WaitSuccessor reads the lease.
	poll time.Duration
}

// NewK8sElector returns an elector for the Lease name in ns; id is this
// replica's identity (the pod name). It validates the timings.
func NewK8sElector(cs kubernetes.Interface, ns, name, id string, t ElectionTimings, log *slog.Logger) (*K8sElector, error) {
	if id == "" || name == "" {
		return nil, errors.New("leader election needs a lease name and an identity")
	}
	e := &K8sElector{cs: cs, ns: ns, name: name, id: id, t: t, log: log, poll: 250 * time.Millisecond}
	if _, err := e.newElector(func() {}); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *K8sElector) newElector(onStarted func()) (*leaderelection.LeaderElector, error) {
	return leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Name: e.name, Namespace: e.ns},
			Client:     e.cs.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: e.id},
		},
		LeaseDuration:   e.t.LeaseDuration,
		RenewDeadline:   e.t.RenewDeadline,
		RetryPeriod:     e.t.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            e.name,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(context.Context) { onStarted() },
			OnStoppedLeading: func() {},
			OnNewLeader: func(identity string) {
				if e.log != nil {
					e.log.Info("lease holder", "lease", e.name, "holder", identity, "self", identity == e.id)
				}
			},
		},
	})
}

// Run implements Elector.
func (e *K8sElector) Run(ctx context.Context, onStarted func()) error {
	le, err := e.newElector(onStarted)
	if err != nil {
		return err
	}
	le.Run(ctx) // returns when ctx ends (the lease is released) or the lease is lost
	if ctx.Err() == nil {
		return ErrLostLease
	}
	return nil
}

// Holder returns the identity that holds the lease ("" when nobody does).
func (e *K8sElector) Holder(ctx context.Context) (string, error) {
	l, err := e.cs.CoordinationV1().Leases(e.ns).Get(ctx, e.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if l.Spec.HolderIdentity == nil {
		return "", nil
	}
	return *l.Spec.HolderIdentity, nil
}

// WaitSuccessor implements Elector: it reads the lease every poll until a
// holder other than this replica appears or wait has passed.
func (e *K8sElector) WaitSuccessor(ctx context.Context, wait time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	t := time.NewTicker(e.poll)
	defer t.Stop()
	for {
		if h, err := e.Holder(ctx); err == nil && h != "" && h != e.id {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}

// K8sRolePatcher is a RolePatcher on the replica's own Pod.
type K8sRolePatcher struct {
	cs  kubernetes.Interface
	ns  string
	pod string
}

// NewK8sRolePatcher returns a patcher for the pod named pod in ns.
func NewK8sRolePatcher(cs kubernetes.Interface, ns, pod string) *K8sRolePatcher {
	return &K8sRolePatcher{cs: cs, ns: ns, pod: pod}
}

// roleMergePatch is the whole body of a role update: the one label and the one
// annotation, so the admission policy can allow exactly this and nothing else.
func roleMergePatch(leader bool) ([]byte, error) {
	role, cost := api.HubRoleStandby, "0"
	if leader {
		role, cost = api.HubRoleLeader, "100"
	}
	return json.Marshal(map[string]any{"metadata": map[string]any{
		"labels":      map[string]string{api.HubRoleLabel: role},
		"annotations": map[string]string{api.PodDeletionCostAnnotation: cost},
	}})
}

// SetRole implements RolePatcher.
func (p *K8sRolePatcher) SetRole(ctx context.Context, leader bool) error {
	body, err := roleMergePatch(leader)
	if err != nil {
		return err
	}
	if _, err := p.cs.CoreV1().Pods(p.ns).Patch(ctx, p.pod, types.MergePatchType, body, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patching pod %s/%s: %w", p.ns, p.pod, err)
	}
	return nil
}
