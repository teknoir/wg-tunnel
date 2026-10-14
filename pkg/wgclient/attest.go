package wgclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// AttestChallenge fetches a single-use host-key attestation nonce
// (api.AttestChallengePath). bearer is an RS256 enrollment JWT
// (identity.MintEnrollJWT) minted for this call alone: the hub records its jti,
// so the same token cannot be reused for the enrollment itself.
func AttestChallenge(ctx context.Context, hubURL string, hc *http.Client, bearer string) (*api.AttestChallenge, error) {
	if _, err := parseHubURL(hubURL); err != nil {
		return nil, err
	}
	o := Options{HTTPClient: hc}
	var resp api.AttestChallenge
	if err := doJSON(ctx, o.httpClient(), hubEndpoint(hubURL, api.AttestChallengePath), bearer, struct{}{}, &resp); err != nil {
		return nil, err
	}
	if resp.Nonce == "" || resp.EnrollmentEpoch == "" {
		return nil, errors.New("hub returned a malformed attestation challenge")
	}
	return &resp, nil
}
