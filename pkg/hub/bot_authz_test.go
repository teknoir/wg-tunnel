package hub

import (
	"context"
	"errors"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// CanAdmin asks for create rolebindings in rbac.authorization.k8s.io.
func TestK8sAuthorizerCanAdmin(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var got authzv1.SubjectAccessReviewSpec
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview).DeepCopy()
		got = sar.Spec
		sar.Status.Allowed = sar.Spec.User == "admin@example.com"
		return true, sar, nil
	})
	a := NewK8sAuthorizer(cs)
	ctx := context.Background()

	ok, err := a.CanAdmin(ctx, "admin@example.com", "acme")
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	ra := got.ResourceAttributes
	if got.User != "admin@example.com" || ra == nil || ra.Namespace != "acme" || ra.Verb != "create" ||
		ra.Group != "rbac.authorization.k8s.io" || ra.Resource != "rolebindings" || ra.Subresource != "" {
		t.Fatalf("wrong review: %+v %+v", got, ra)
	}
	if ok, _ := a.CanAdmin(ctx, "other@example.com", "acme"); ok {
		t.Fatal("other must be denied")
	}
	// Invalid identities and namespaces are denied without asking the API.
	before := len(cs.Actions())
	for _, c := range [][2]string{{"ADMIN", "acme"}, {"no-at", "acme"}, {"admin@example.com", ""}, {"admin@example.com", "not a ns"}} {
		if ok, err := a.CanAdmin(ctx, c[0], c[1]); ok || err != nil {
			t.Fatalf("%q %q: %v %v", c[0], c[1], ok, err)
		}
	}
	if after := len(cs.Actions()); after != before {
		t.Fatalf("%d unexpected API calls", after-before)
	}
	cs.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("down")
	})
	if ok, err := a.CanAdmin(ctx, "admin@example.com", "acme"); ok || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage must deny with ErrUnavailable: %v %v", ok, err)
	}
	// A denied review is a deny even if allowed is also set.
	cs.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}}, nil
	})
	if ok, err := a.CanAdmin(ctx, "admin@example.com", "acme"); ok || err != nil {
		t.Fatalf("denied must win: %v %v", ok, err)
	}
}

// The two checks are cached under separate keys for the same email and
// namespace.
func TestCachedAuthorizerSeparatesChecks(t *testing.T) {
	clock := newFakeClock()
	inner := &countingAuthz{allow: true}
	c := newCachedAuthorizer(inner, 5*time.Second, 10, clock.Now)
	ctx := context.Background()

	if ok, err := c.CanExec(ctx, "a@x", "ns"); !ok || err != nil {
		t.Fatalf("CanExec %v %v", ok, err)
	}
	if inner.calls != 1 || inner.adminCalls != 0 {
		t.Fatalf("calls %d %d", inner.calls, inner.adminCalls)
	}
	// The same (email, ns) has its own CanAdmin answer: the cached allow of
	// CanExec must not answer it.
	if ok, err := c.CanAdmin(ctx, "a@x", "ns"); ok || err != nil {
		t.Fatalf("CanAdmin must ask the inner authorizer: %v %v", ok, err)
	}
	if inner.adminCalls != 1 {
		t.Fatalf("CanAdmin calls %d, want 1", inner.adminCalls)
	}
	// ... and CanExec's cached allow is untouched by it.
	if ok, err := c.CanExec(ctx, "a@x", "ns"); !ok || err != nil {
		t.Fatalf("CanExec %v %v", ok, err)
	}
	if inner.calls != 1 {
		t.Fatalf("CanExec calls %d, want 1: the entries were shared", inner.calls)
	}
	inner.admin = true
	// The deny is cached until the TTL ...
	if ok, _ := c.CanAdmin(ctx, "a@x", "ns"); ok {
		t.Fatal("cached deny expected within TTL")
	}
	clock.Advance(5*time.Second + time.Millisecond)
	if ok, _ := c.CanAdmin(ctx, "a@x", "ns"); !ok {
		t.Fatal("expired entry must be re-evaluated")
	}
	// Both live in the same bounded LRU.
	if c.Len() != 2 {
		t.Fatalf("cache holds %d entries, want 2", c.Len())
	}
}

func TestCachedAuthorizerCanAdminErrorsAreNotCached(t *testing.T) {
	clock := newFakeClock()
	inner := &countingAuthz{admin: true, adminErr: errors.New("api down")}
	c := newCachedAuthorizer(inner, 5*time.Second, 10, clock.Now)
	ctx := context.Background()
	if ok, err := c.CanAdmin(ctx, "a@x", "ns"); ok || err == nil {
		t.Fatalf("error must deny: %v %v", ok, err)
	}
	inner.adminErr = nil
	if ok, err := c.CanAdmin(ctx, "a@x", "ns"); !ok || err != nil {
		t.Fatalf("error must not be cached: %v %v", ok, err)
	}
	if inner.adminCalls != 2 {
		t.Fatalf("admin calls %d, want 2", inner.adminCalls)
	}
}
