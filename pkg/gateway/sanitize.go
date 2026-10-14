package gateway

import (
	"net/http"
	"net/mail"
	"strings"
)

// Header names the gateway reads or strips.
const (
	// HeaderService is set by the per-service VirtualService (and overrides
	// anything the client sent): the id of the device service the host maps to.
	HeaderService = "X-Ztna-Service"
	// HeaderEmail is set by oauth2-proxy (through Istio ext_authz) on requests
	// that passed the login.
	HeaderEmail = "X-Auth-Request-Email"
)

// platformCookie reports whether name is a cookie the platform's login owns
// and that therefore must never reach (or be set by) a device: anything with
// "oauth2" in its name (oauth2-proxy: _oauth2_proxy, _teknoir_oauth2_proxy,
// ..._csrf and the _0/_1 split variants), the platform's own "_teknoir"
// prefix, Keycloak's KEYCLOAK_* and AUTH_SESSION_ID cookies, and every name
// in extra (STRIP_COOKIES, compared case-insensitively). The match is on the
// name only and deliberately broad: an application cookie that happens to
// look like a platform cookie is lost, a platform session is never leaked.
func platformCookie(name string, extra []string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return false
	case strings.Contains(n, "oauth2"),
		strings.HasPrefix(n, "_teknoir"),
		strings.HasPrefix(n, "keycloak_"),
		strings.HasPrefix(n, "auth_session_id"):
		return true
	}
	for _, e := range extra {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" && e == n {
			return true
		}
	}
	return false
}

// stripRequestHeaders removes everything that identifies the user to the
// platform before a request is handed to the device's web service: the device
// must never see the session cookies or tokens that are valid for the other
// teamspace services behind the same login.
func stripRequestHeaders(h http.Header, extra []string) {
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
	h.Del("X-Forwarded-Access-Token")
	// oauth2-proxy identity headers in their other spellings.
	h.Del("X-Forwarded-User")
	h.Del("X-Forwarded-Email")
	h.Del("X-Forwarded-Preferred-Username")
	h.Del("X-Forwarded-Groups")
	h.Del(HeaderService)
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Auth-Request-") {
			delete(h, k)
		}
	}
	filterCookies(h, extra)
}

// filterCookies drops the oauth2 cookies from the Cookie header(s) and keeps
// the others byte for byte (an application's own cookies pass through).
func filterCookies(h http.Header, extra []string) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			name, _, _ := strings.Cut(p, "=")
			if platformCookie(name, extra) {
				continue
			}
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		h.Del("Cookie")
		return
	}
	h.Set("Cookie", strings.Join(kept, "; "))
}

// sanitizeSetCookies makes the cookies of a response host-only and keeps the
// device from touching the login cookies: a Set-Cookie with a platform
// login cookie name (see platformCookie) is dropped, and the Domain attribute is removed from every other one, so a
// cookie set by the device's app is never sent to sibling hosts.
func sanitizeSetCookies(h http.Header, extra []string) {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, line := range lines {
		if c := stripCookieDomain(line, extra); c != "" {
			h.Add("Set-Cookie", c)
		}
	}
}

// stripCookieDomain returns line without its Domain attribute, or "" if the
// cookie must be dropped.
func stripCookieDomain(line string, extra []string) string {
	parts := strings.Split(line, ";")
	name, _, _ := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if platformCookie(name, extra) {
		return ""
	}
	out := parts[:1]
	for _, attr := range parts[1:] {
		key, _, _ := strings.Cut(strings.TrimSpace(attr), "=")
		if strings.EqualFold(strings.TrimSpace(key), "domain") {
			continue
		}
		out = append(out, attr)
	}
	return strings.Join(out, ";")
}

// validEmail is a conservative copy of the hub's rule (the hub is the
// authority; this only keeps garbage from being sent to it): a lowercase plain
// address without quoting, spaces or control characters.
func validEmail(s string) bool {
	if s == "" || len(s) > 254 || s != strings.ToLower(s) {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n\x00\"'<>(),;:\\[]") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}

// isUpgrade reports whether the request asks to switch protocols (WebSocket).
func isUpgrade(h http.Header) bool { return h.Get("Upgrade") != "" }

// unsafeMethod: everything but the read-only methods needs a matching Origin.
func unsafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originOK implements the CSRF rule: the Origin must be exactly this host over https.
func originOK(origin, host string) bool {
	return host != "" && origin != "" && strings.EqualFold(origin, "https://"+host)
}
