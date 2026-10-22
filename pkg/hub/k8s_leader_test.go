package hub

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// fast timings: renew deadline and lease are far above the retry period so a
// loaded CI machine does not lose a lease by accident.
var fastElection = ElectionTimings{LeaseDuration: 4 * time.Second, RenewDeadline: 3 * time.Second, RetryPeriod: 50 * time.Millisecond}

func electorFor(t *testing.T, cs *fake.Clientset, id string, tm ElectionTimings) *K8sElector {
	t.Helper()
	logger, _ := captureLogger()
	e, err := NewK8sElector(cs, api.HubNamespace, api.LeaderLease, id, tm, logger)
	if err != nil {
		t.Fatal(err)
	}
	e.poll = 10 * time.Millisecond
	return e
}

type runningElector struct {
	started chan struct{}
	done    chan error
	cancel  context.CancelFunc
}

func runElector(t *testing.T, e *K8sElector) *runningElector {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	re := &runningElector{started: make(chan struct{}), done: make(chan error, 1), cancel: cancel}
	go func() { re.done <- e.Run(ctx, func() { close(re.started) }) }()
	t.Cleanup(cancel)
	return re
}

func (re *runningElector) waitStarted(t *testing.T, what string, d time.Duration) {
	t.Helper()
	select {
	case <-re.started:
	case <-time.After(d):
		t.Fatalf("%s: not leader after %v", what, d)
	}
}

// TestK8sElectorTakesOverAfterTheLeaderCancels: the standby becomes the leader
// within a few retry periods of the leader's context ending (ReleaseOnCancel
// frees the lease at once; without it the standby would wait out the whole
// lease duration, 4 s here). The leader's Run returns nil.
func TestK8sElectorTakesOverAfterTheLeaderCancels(t *testing.T) {
	cs := fake.NewSimpleClientset()
	a, b := electorFor(t, cs, "hub-a", fastElection), electorFor(t, cs, "hub-b", fastElection)
	ra := runElector(t, a)
	ra.waitStarted(t, "a", 3*time.Second)
	rb := runElector(t, b)

	select {
	case <-rb.started:
		t.Fatal("b became leader while a holds the lease")
	case <-time.After(300 * time.Millisecond):
	}
	if h, err := b.Holder(context.Background()); err != nil || h != "hub-a" {
		t.Fatalf("holder %q (%v), want hub-a", h, err)
	}

	t0 := time.Now()
	ra.cancel()
	rb.waitStarted(t, "b", 2*time.Second)
	took := time.Since(t0)
	if took > 1500*time.Millisecond {
		t.Fatalf("takeover took %v, want about the retry period (lease duration is %v)", took, fastElection.LeaseDuration)
	}
	select {
	case err := <-ra.done:
		if err != nil {
			t.Fatalf("a.Run returned %v after a cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a.Run did not return")
	}
	if h, _ := b.Holder(context.Background()); h != "hub-b" {
		t.Fatalf("holder %q after takeover, want hub-b", h)
	}
}

// TestK8sElectorSameIdentityRetakesAtOnce: a restarted container of the same
// pod has the same identity and takes its still valid lease back without
// waiting for it to expire.
func TestK8sElectorSameIdentityRetakesAtOnce(t *testing.T) {
	cs := fake.NewSimpleClientset()
	first := electorFor(t, cs, "hub-a", fastElection)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() { _ = first.Run(ctx, func() { close(started) }) }()
	<-started
	// Simulate a crash: the lease is not released (the process is gone); put
	// the holder back as a crashed process leaves it.
	cancel()
	time.Sleep(100 * time.Millisecond)
	l, _ := cs.CoordinationV1().Leases(api.HubNamespace).Get(context.Background(), api.LeaderLease, metav1.GetOptions{})
	id := "hub-a"
	l.Spec.HolderIdentity = &id
	now := metav1.NewMicroTime(time.Now())
	l.Spec.RenewTime = &now
	if _, err := cs.CoordinationV1().Leases(api.HubNamespace).Update(context.Background(), l, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Another replica must wait for the lease to expire ...
	other := runElector(t, electorFor(t, cs, "hub-b", fastElection))
	select {
	case <-other.started:
		t.Fatal("hub-b took a valid lease of a crashed hub-a at once")
	case <-time.After(500 * time.Millisecond):
	}
	// ... the restarted container of hub-a does not.
	again := electorFor(t, cs, "hub-a", fastElection)
	r := runElector(t, again)
	r.waitStarted(t, "restarted a", time.Second)
}

// TestK8sElectorLostLease: renewals that keep failing past the renew deadline
// end Run with ErrLostLease while the context is alive.
func TestK8sElectorLostLease(t *testing.T) {
	cs := fake.NewSimpleClientset()
	// The reactor is installed before anything runs (the fake clientset's
	// reactor chain is not safe to change concurrently) and fails on demand.
	var down atomic.Bool
	cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if down.Load() {
			return true, nil, errors.New("api server unreachable")
		}
		return false, nil, nil
	})
	tm := ElectionTimings{LeaseDuration: 2 * time.Second, RenewDeadline: 600 * time.Millisecond, RetryPeriod: 100 * time.Millisecond}
	e := electorFor(t, cs, "hub-a", tm)
	r := runElector(t, e)
	r.waitStarted(t, "a", 3*time.Second)
	down.Store(true)
	select {
	case err := <-r.done:
		if !errors.Is(err, ErrLostLease) {
			t.Fatalf("Run returned %v, want ErrLostLease", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the renew deadline")
	}
}

func TestNewK8sElectorValidates(t *testing.T) {
	cs := fake.NewSimpleClientset()
	logger, _ := captureLogger()
	for name, tc := range map[string]struct {
		id, lease string
		tm        ElectionTimings
	}{
		"no identity":        {"", api.LeaderLease, fastElection},
		"no lease name":      {"hub-a", "", fastElection},
		"lease <= renew":     {"hub-a", api.LeaderLease, ElectionTimings{LeaseDuration: time.Second, RenewDeadline: time.Second, RetryPeriod: 100 * time.Millisecond}},
		"renew <= retry*1.2": {"hub-a", api.LeaderLease, ElectionTimings{LeaseDuration: 10 * time.Second, RenewDeadline: time.Second, RetryPeriod: time.Second}},
		"zero retry":         {"hub-a", api.LeaderLease, ElectionTimings{LeaseDuration: 10 * time.Second, RenewDeadline: time.Second}},
	} {
		if _, err := NewK8sElector(cs, api.HubNamespace, tc.lease, tc.id, tc.tm, logger); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewK8sElector(cs, api.HubNamespace, api.LeaderLease, "hub-a", ElectionTimings{LeaseDuration: 60 * time.Second, RenewDeadline: 45 * time.Second, RetryPeriod: 2 * time.Second}, logger); err != nil {
		t.Errorf("the product defaults are rejected: %v", err)
	}
}

// TestWaitSuccessor: it sees another holder, times out on none or on itself,
// and never counts its own identity as a successor.
func TestWaitSuccessor(t *testing.T) {
	cs := fake.NewSimpleClientset()
	a := electorFor(t, cs, "hub-a", fastElection)

	t0 := time.Now()
	if a.WaitSuccessor(context.Background(), 150*time.Millisecond) {
		t.Fatal("successor with no lease at all")
	}
	if d := time.Since(t0); d < 140*time.Millisecond || d > time.Second {
		t.Fatalf("timeout after %v, want about 150ms", d)
	}

	setHolder := func(id string) {
		t.Helper()
		lease, err := cs.CoordinationV1().Leases(api.HubNamespace).Get(context.Background(), api.LeaderLease, metav1.GetOptions{})
		if err != nil {
			lease = &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: api.LeaderLease, Namespace: api.HubNamespace},
				Spec:       coordinationv1.LeaseSpec{HolderIdentity: &id},
			}
			if _, err := cs.CoordinationV1().Leases(api.HubNamespace).Create(context.Background(), lease, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			return
		}
		lease.Spec.HolderIdentity = &id
		if _, err := cs.CoordinationV1().Leases(api.HubNamespace).Update(context.Background(), lease, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	setHolder("hub-a") // itself
	if a.WaitSuccessor(context.Background(), 150*time.Millisecond) {
		t.Fatal("its own lease counted as a successor")
	}
	setHolder("") // released
	if a.WaitSuccessor(context.Background(), 150*time.Millisecond) {
		t.Fatal("a released lease counted as a successor")
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		setHolder("hub-b")
	}()
	t0 = time.Now()
	if !a.WaitSuccessor(context.Background(), 3*time.Second) {
		t.Fatal("did not see hub-b")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("took %v to see the successor", d)
	}

	// A cancelled context ends the wait at once.
	setHolder("hub-a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t0 = time.Now()
	if a.WaitSuccessor(ctx, time.Minute) || time.Since(t0) > time.Second {
		t.Fatal("a cancelled context did not end the wait")
	}
}

// ---- role patch ----

func hubPod(name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: api.HubNamespace,
		Labels:      map[string]string{"app.kubernetes.io/name": "wg-hub", "app.kubernetes.io/component": "hub", api.HubRoleLabel: api.HubRoleStandby},
		Annotations: map[string]string{"sidecar.istio.io/status": "{}", api.PodDeletionCostAnnotation: "0"},
	}}
}

// TestRolePatchChangesOnlyTheRoleKeys: the request is a JSON merge patch whose
// only content is the role label and the deletion-cost annotation (the
// admission policy allows nothing else), and applying it leaves every other
// label and annotation alone.
func TestRolePatchChangesOnlyTheRoleKeys(t *testing.T) {
	cs := fake.NewSimpleClientset(hubPod("wg-hub-1"))
	var bodies [][]byte
	var kinds []types.PatchType
	cs.PrependReactor("patch", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pa := a.(k8stesting.PatchAction)
		bodies = append(bodies, pa.GetPatch())
		kinds = append(kinds, pa.GetPatchType())
		if pa.GetName() != "wg-hub-1" || pa.GetNamespace() != api.HubNamespace || pa.GetSubresource() != "" {
			t.Errorf("patched %s/%s subresource %q, want the own pod without a subresource", pa.GetNamespace(), pa.GetName(), pa.GetSubresource())
		}
		return false, nil, nil // let the tracker apply it
	})
	p := NewK8sRolePatcher(cs, api.HubNamespace, "wg-hub-1")

	for _, tc := range []struct {
		leader     bool
		role, cost string
	}{{true, "leader", "100"}, {false, "standby", "0"}} {
		if err := p.SetRole(context.Background(), tc.leader); err != nil {
			t.Fatal(err)
		}
		body := bodies[len(bodies)-1]
		var got map[string]map[string]map[string]string
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("patch %s: %v", body, err)
		}
		if len(got) != 1 || len(got["metadata"]) != 2 || len(got["metadata"]["labels"]) != 1 || len(got["metadata"]["annotations"]) != 1 ||
			got["metadata"]["labels"][api.HubRoleLabel] != tc.role || got["metadata"]["annotations"][api.PodDeletionCostAnnotation] != tc.cost {
			t.Fatalf("patch body %s, want only %s=%s and %s=%q", body, api.HubRoleLabel, tc.role, api.PodDeletionCostAnnotation, tc.cost)
		}
		if kinds[len(kinds)-1] != types.MergePatchType {
			t.Fatalf("patch type %s", kinds[len(kinds)-1])
		}
		pod, _ := cs.CoreV1().Pods(api.HubNamespace).Get(context.Background(), "wg-hub-1", metav1.GetOptions{})
		if pod.Labels[api.HubRoleLabel] != tc.role || pod.Annotations[api.PodDeletionCostAnnotation] != tc.cost {
			t.Fatalf("pod after patch: %v %v", pod.Labels, pod.Annotations)
		}
		if pod.Labels["app.kubernetes.io/name"] != "wg-hub" || pod.Labels["app.kubernetes.io/component"] != "hub" || pod.Annotations["sidecar.istio.io/status"] != "{}" {
			t.Fatalf("the patch changed other metadata: %v %v", pod.Labels, pod.Annotations)
		}
	}
}

func TestRolePatchErrorsAreReturned(t *testing.T) {
	cs := fake.NewSimpleClientset() // the pod does not exist
	if err := NewK8sRolePatcher(cs, api.HubNamespace, "wg-hub-1").SetRole(context.Background(), true); err == nil {
		t.Fatal("a patch of a missing pod reported success")
	}
	cs = fake.NewSimpleClientset(hubPod("wg-hub-1"))
	cs.PrependReactor("patch", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("denied by ValidatingAdmissionPolicy")
	})
	if err := NewK8sRolePatcher(cs, api.HubNamespace, "wg-hub-1").SetRole(context.Background(), true); err == nil {
		t.Fatal("an admission denial was swallowed")
	}
}
