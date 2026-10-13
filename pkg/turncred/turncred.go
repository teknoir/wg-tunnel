// Package turncred mints TURN-REST (time-windowed) credentials exactly like
// STUNner's pkg/authentication does, so the hub can hand out credentials that
// a STUNner gateway sharing the same secret accepts.
//
// Username is "<unix-expiry>:<userID>"; Password is
// base64(HMAC-SHA1(sharedSecret, Username)). SHA-1 is mandated by the TURN
// long-term credential mechanism (RFC 8489 section 9.2), not a choice.
package turncred

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TURN long-term credentials are defined with HMAC-SHA1.
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Generate returns credentials valid until now+ttl. userID should be
// "<namespace>/<id>"; it must not contain ':' (see ValidUserID), because
// STUNner locates the expiry by splitting the username on ':'.
func Generate(sharedSecret, userID string, ttl time.Duration, now time.Time) (username, password string, expiresAt time.Time) {
	expiresAt = time.Unix(now.Add(ttl).Unix(), 0)
	username = strconv.FormatInt(expiresAt.Unix(), 10) + ":" + userID
	return username, Password(sharedSecret, username), expiresAt
}

// Password returns base64(HMAC-SHA1(sharedSecret, username)).
func Password(sharedSecret, username string) string {
	mac := hmac.New(sha1.New, []byte(sharedSecret))
	mac.Write([]byte(username)) // hash.Hash.Write never returns an error
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ValidUserID reports whether userID is safe to embed in a username.
func ValidUserID(userID string) error {
	switch {
	case userID == "":
		return errors.New("turncred: empty user id")
	case strings.ContainsAny(userID, ":\x00\r\n"):
		return errors.New("turncred: user id must not contain ':' or control characters")
	}
	return nil
}
