package hub

import (
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// reasonStatus maps every denial reason to its HTTP status.
var reasonStatus = map[string]int{
	api.ReasonUnauthenticated: http.StatusUnauthorized,
	api.ReasonReplay:          http.StatusUnauthorized,
	api.ReasonNotEnrolled:     http.StatusForbidden,
	api.ReasonReenroll:        http.StatusForbidden,
	api.ReasonEnrollClosed:    http.StatusForbidden,
	api.ReasonEnrollConflict:  http.StatusConflict,
	api.ReasonAttestRequired:  http.StatusForbidden,
	api.ReasonSessionLimit:    http.StatusTooManyRequests,
	api.ReasonRateLimited:     http.StatusTooManyRequests,
	api.ReasonForbidden:       http.StatusForbidden,
	api.ReasonDeviceUnknown:   http.StatusForbidden,
	api.ReasonDeviceDisabled:  http.StatusForbidden,
	api.ReasonDeviceRevoked:   http.StatusForbidden,
	api.ReasonDeviceOffline:   http.StatusConflict,
	api.ReasonPortNotAllowed:  http.StatusForbidden,
	api.ReasonServiceUnknown:  http.StatusNotFound,
	api.ReasonServiceDenied:   http.StatusForbidden,
	api.ReasonPosture:         http.StatusForbidden,
	api.ReasonSessionUnknown:  http.StatusNotFound,
	api.ReasonSessionMaxAge:   http.StatusForbidden,
	api.ReasonBadRequest:      http.StatusBadRequest,
	api.ReasonInternal:        http.StatusInternalServerError,
}

// denial is an error that carries the API reason and HTTP status.
type denial struct {
	status int
	reason string
	msg    string
	// teardown is true when a denied renewal must end the session (false for
	// infrastructure errors, rate limits and malformed requests).
	teardown bool
}

func (d *denial) Error() string { return d.reason + ": " + d.msg }

func deny(reason, msg string) *denial {
	st, ok := reasonStatus[reason]
	if !ok {
		st = http.StatusForbidden
	}
	return &denial{status: st, reason: reason, msg: msg, teardown: denyTearsDown(reason)}
}

func denyUnavailable(msg string) *denial {
	return &denial{status: http.StatusServiceUnavailable, reason: api.ReasonInternal, msg: msg}
}

func denyTearsDown(reason string) bool {
	switch reason {
	case api.ReasonRateLimited, api.ReasonBadRequest, api.ReasonInternal, api.ReasonSessionLimit:
		return false
	}
	return true
}

// asDenial converts an authenticator error to a denial.
func asDenial(err error) *denial {
	var d *denial
	switch {
	case errors.As(err, &d):
		return d
	case errors.Is(err, ErrForbidden):
		return deny(api.ReasonForbidden, "access denied")
	case errors.Is(err, ErrUnavailable):
		return denyUnavailable("authentication backend unavailable")
	default:
		return deny(api.ReasonUnauthenticated, "invalid credentials")
	}
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func validLabel(s string) bool { return dnsLabel.MatchString(s) }

// splitSubject parses a device JWT subject "<ns>/<device>".
func splitSubject(sub string) (ns, device string, ok bool) {
	ns, device, found := strings.Cut(sub, "/")
	if !found || !validLabel(ns) || !validLabel(device) {
		return "", "", false
	}
	return ns, device, true
}

// ValidEmail reports whether s is a syntactically valid, lowercase, plain
// address (no display name, no quoting, no control characters).
func ValidEmail(s string) bool {
	if s == "" || len(s) > 254 || s != strings.ToLower(s) {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n\x00\"'<>(),;:\\[]") {
		return false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && domain != "" && !strings.Contains(domain, "@")
}
