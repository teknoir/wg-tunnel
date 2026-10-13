package hub

import (
	"context"
	"fmt"
	"slices"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// K8sSADelegation implements SADelegation with TokenReview and a ServiceAccount
// lookup in the hub namespace.
type K8sSADelegation struct {
	cs kubernetes.Interface
	ns string
}

var _ SADelegation = (*K8sSADelegation)(nil)

// NewK8sSADelegation returns a verifier for service accounts of hubNamespace.
func NewK8sSADelegation(cs kubernetes.Interface, hubNamespace string) *K8sSADelegation {
	return &K8sSADelegation{cs: cs, ns: hubNamespace}
}

// Verify implements SADelegation.
func (d *K8sSADelegation) Verify(ctx context.Context, token, ns, device, onBehalfOf string) (SAIdentity, error) {
	if !ValidEmail(onBehalfOf) {
		return SAIdentity{}, fmt.Errorf("%w: onBehalfOf is not a lowercase email", ErrForbidden)
	}
	if token == "" || len(token) > maxBearerTokenSize {
		return SAIdentity{}, fmt.Errorf("%w: bad token length", ErrUnauthenticated)
	}
	tr, err := d.cs.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{api.SATokenAudience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return SAIdentity{}, fmt.Errorf("%w: token review: %v", ErrUnavailable, err)
	}
	if !tr.Status.Authenticated {
		return SAIdentity{}, fmt.Errorf("%w: token not authenticated", ErrUnauthenticated)
	}
	if len(tr.Status.Audiences) > 0 && !slices.Contains(tr.Status.Audiences, api.SATokenAudience) {
		return SAIdentity{}, fmt.Errorf("%w: wrong audience", ErrUnauthenticated)
	}
	prefix := "system:serviceaccount:" + d.ns + ":"
	name, ok := strings.CutPrefix(tr.Status.User.Username, prefix)
	if !ok || name == "" || strings.Contains(name, ":") {
		return SAIdentity{}, fmt.Errorf("%w: not a service account of %s", ErrForbidden, d.ns)
	}
	sa, err := d.cs.CoreV1().ServiceAccounts(d.ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return SAIdentity{}, fmt.Errorf("%w: service account not found", ErrUnauthenticated)
	}
	if err != nil {
		return SAIdentity{}, fmt.Errorf("%w: service account lookup: %v", ErrUnavailable, err)
	}
	if sa.Annotations[api.SAAnnotationNamespace] != ns || sa.Annotations[api.SAAnnotationDevice] != device ||
		ns == "" || device == "" {
		return SAIdentity{}, fmt.Errorf("%w: service account is not bound to this device", ErrForbidden)
	}
	return SAIdentity{Name: name}, nil
}

// K8sAuthorizer implements Authorizer with a SubjectAccessReview for
// "create pods/exec" in the teamspace. Wrap it in NewCachedAuthorizer.
type K8sAuthorizer struct{ cs kubernetes.Interface }

var _ Authorizer = (*K8sAuthorizer)(nil)

// NewK8sAuthorizer returns an Authorizer backed by the API server.
func NewK8sAuthorizer(cs kubernetes.Interface) *K8sAuthorizer { return &K8sAuthorizer{cs: cs} }

// CanExec implements Authorizer.
func (a *K8sAuthorizer) CanExec(ctx context.Context, email, ns string) (bool, error) {
	if !ValidEmail(email) || !validLabel(ns) {
		return false, nil
	}
	sar, err := a.cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: email,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns, Verb: "create", Resource: "pods", Subresource: "exec",
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("%w: subject access review: %v", ErrUnavailable, err)
	}
	return sar.Status.Allowed && !sar.Status.Denied, nil
}
