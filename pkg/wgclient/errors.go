package wgclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// Error is a denial or failure reported by the hub (or by an ingress in front
// of it). Reason is one of the api.Reason* codes when the hub produced the
// response. Both text fields are sanitised, so they are safe to print on one line.
type Error struct {
	Status  int    // HTTP status code
	Reason  string // api.Reason*, possibly empty for non-hub responses
	Message string
}

func (e *Error) Error() string {
	switch {
	case e.Reason != "" && e.Message != "":
		return fmt.Sprintf("hub refused (HTTP %d): %s: %s", e.Status, e.Reason, e.Message)
	case e.Reason != "":
		return fmt.Sprintf("hub refused (HTTP %d): %s", e.Status, e.Reason)
	default:
		return fmt.Sprintf("hub returned HTTP %d", e.Status)
	}
}

// Denial reports whether the response is a definitive refusal that retrying
// the same request will not fix. Server errors, timeouts and rate limits are
// transient.
func (e *Error) Denial() bool {
	switch {
	case e.Status == http.StatusRequestTimeout, e.Status == http.StatusTooManyRequests:
		return false
	case e.Reason == api.ReasonRateLimited, e.Reason == api.ReasonInternal:
		return false
	}
	return e.Status >= 300 && e.Status < 500
}

// ReasonOf returns the hub reason carried by err, or "" if err holds none.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// ErrSessionClosed is returned by Dial and Listen after the session ended.
var ErrSessionClosed = errors.New("wgclient: session closed")

// ErrExpired ends a session whose renewals kept failing until it expired.
var ErrExpired = errors.New("wgclient: session expired without a successful renewal")

// ErrHandshakeTimeout is returned by Create when the WireGuard handshake with
// the hub did not complete in time.
var ErrHandshakeTimeout = errors.New("wgclient: WireGuard handshake with the hub timed out")

const maxErrorBody = 64 << 10

// decodeError builds the typed error for a non-2xx response. The body is read
// (bounded) only to extract api.Error fields; it is never logged.
func decodeError(status int, body io.Reader) *Error {
	e := &Error{Status: status}
	var ae api.Error
	if err := json.NewDecoder(io.LimitReader(body, maxErrorBody)).Decode(&ae); err == nil {
		e.Reason = sanitizeReason(ae.Reason)
		e.Message = sanitizeText(ae.Message, 200)
	}
	if e.Reason == "" {
		switch {
		case status == http.StatusUnauthorized, status >= 300 && status < 400:
			e.Reason = api.ReasonUnauthenticated
		case status == http.StatusForbidden:
			e.Reason = api.ReasonForbidden
		case status == http.StatusTooManyRequests:
			e.Reason = api.ReasonRateLimited
		case status >= 500:
			e.Reason = api.ReasonInternal
		}
	}
	return e
}

// sanitizeReason keeps [a-z0-9_] only (the api.Reason* alphabet).
func sanitizeReason(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 40 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeText drops control characters and truncates, so server-provided text
// cannot forge extra log or terminal lines.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
