package wgclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

const maxResponseBody = 1 << 20

// checkBearer rejects credentials that cannot be sent as a header value.
func checkBearer(tok string) error {
	if tok == "" {
		return errors.New("empty credential")
	}
	if len(tok) > 16<<10 {
		return errors.New("credential too long")
	}
	for _, r := range tok {
		if r <= ' ' || r == 0x7f {
			return errors.New("credential contains whitespace or control characters")
		}
	}
	return nil
}

// doJSON POSTs in (nil for an empty body) with a bearer credential and decodes
// a 2xx JSON response into out (if non-nil). Non-2xx responses become *Error.
// Neither the credential nor the bodies appear in returned errors.
func doJSON(ctx context.Context, c *http.Client, url, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return errors.New("building request failed")
	}
	if bearer != "" {
		if err := checkBearer(bearer); err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err // *url.Error: method, URL and cause; no headers or bodies
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp.StatusCode, resp.Body)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(out); err != nil {
		return fmt.Errorf("decoding hub response (HTTP %d) failed", resp.StatusCode)
	}
	return nil
}

// Enroll pins a device identity key at the hub (api.DeviceEnrollPath). bearer
// is the RS256 enrollment JWT (identity.MintEnrollJWT). Denials are *Error
// (api.ReasonEnrollClosed, api.ReasonEnrollConflict, ...).
func Enroll(ctx context.Context, hubURL string, hc *http.Client, bearer string, req api.EnrollRequest) (*api.EnrollResponse, error) {
	if _, err := parseHubURL(hubURL); err != nil {
		return nil, err
	}
	o := Options{HTTPClient: hc}
	var resp api.EnrollResponse
	if err := doJSON(ctx, o.httpClient(), hubEndpoint(hubURL, api.DeviceEnrollPath), bearer, req, &resp); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(resp.Fingerprint, "SHA256:") {
		return nil, errors.New("hub returned a malformed identity fingerprint")
	}
	return &resp, nil
}
