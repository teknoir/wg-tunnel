package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

const legacyToken = "legacy-keycloak-token-SECRET"

func (r *rig) legacyAlice(enforce bool) {
	r.users.set(legacyToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	r.users.setLegacy(legacyToken, enforce)
}

func decodeSession(t *testing.T, body []byte) api.SessionResponse {
	t.Helper()
	var s api.SessionResponse
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTnctlBelow(t *testing.T) {
	for _, tc := range []struct {
		software, version string
		want              bool
	}{
		{"tnctl", "0.1.1-beta", true},
		{"tnctl", "v0.1.1-beta", true},
		{"tnctl", "0.1.1", true},
		{"tnctl", "0.0.9", true},
		{"tnctl", "0.1.2-beta", false},
		{"tnctl", "0.1.2", false},
		{"tnctl", "0.1.10", false},
		{"tnctl", "0.2.0", false},
		{"tnctl", "1.0.0+abc", false},
		{"tnctl", "dev", false},
		{"tnctl", "test", false},
		{"tnctl", "", false},
		{"tnctl", "0.1", false},
		{"tnctl", "a.b.c", false},
		{"web-terminal", "0.0.1", false},
	} {
		if got := tnctlBelow(api.Posture{Software: tc.software, Version: tc.version}, api.MinTnctlAudienceVersion); got != tc.want {
			t.Errorf("%s %q: got %v, want %v", tc.software, tc.version, got, tc.want)
		}
	}
}

func TestCreateLegacyTokenEnforce(t *testing.T) {
	for _, tc := range []struct {
		name, version, wantReason string
		wantStatus                int
	}{
		{"old tnctl is told to update", "0.1.1-beta", api.ReasonPosture, http.StatusForbidden},
		{"old tnctl with v prefix", "v0.1.0", api.ReasonPosture, http.StatusForbidden},
		{"new tnctl is told to log in", "0.1.2-beta", api.ReasonUnauthenticated, http.StatusUnauthorized},
		{"unparsable version is told to log in", "dev", api.ReasonUnauthenticated, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.legacyAlice(true)
			r.enrollOK()
			r.approve()
			r.deviceSessionOK()
			req, _ := r.clientReq(22)
			req.Posture.Version = tc.version
			st, body := r.clientSession(legacyToken, req)
			wantReason(t, st, body, tc.wantStatus, tc.wantReason)
			if strings.Contains(string(body), "session") && strings.Contains(string(body), "address") {
				t.Fatalf("session data in a denial: %s", body)
			}
			if got := counterValue(t, r.h.met.userTokens, "create", "legacy"); got != 1 {
				t.Fatalf("legacy create tokens = %v", got)
			}
			if got := counterValue(t, r.h.met.userTokens, "create", "ztna"); got != 0 {
				t.Fatalf("ztna create tokens = %v", got)
			}
			if !strings.Contains(r.logs.String(), `"token_audience":"legacy"`) {
				t.Fatalf("no token_audience=legacy in the log:\n%s", r.logs.String())
			}
		})
	}
}

func TestCreateLegacyTokenTransitionAllowed(t *testing.T) {
	r := newRig(t)
	r.legacyAlice(false)
	r.enrollOK()
	r.approve()
	r.deviceSessionOK()
	req, _ := r.clientReq(22)
	req.Posture.Version = "0.1.1-beta"
	if st, body := r.clientSession(legacyToken, req); st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	if got := counterValue(t, r.h.met.userTokens, "create", "legacy"); got != 1 {
		t.Fatalf("legacy create tokens = %v", got)
	}
	if !strings.Contains(r.logs.String(), `"token_audience":"legacy"`) {
		t.Fatalf("no token_audience=legacy in the log")
	}
}

func TestCreateZTNATokenIsCountedAndLogged(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	r.deviceSessionOK()
	r.clientSessionOK()
	if got := counterValue(t, r.h.met.userTokens, "create", "ztna"); got != 1 {
		t.Fatalf("ztna create tokens = %v", got)
	}
	if got := counterValue(t, r.h.met.userTokens, "create", "legacy"); got != 0 {
		t.Fatalf("legacy create tokens = %v", got)
	}
	if !strings.Contains(r.logs.String(), `"token_audience":"ztna"`) {
		t.Fatalf("no token_audience=ztna in the log")
	}
}

// Decisions that did not verify a Keycloak token carry no token_audience.
func TestTokenAudienceOnlyOnKeycloakDecisions(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	r.deviceSessionOK()
	for line := range strings.SplitSeq(strings.TrimSpace(r.logs.String()), "\n") {
		if strings.Contains(line, `"token_audience"`) {
			t.Fatalf("device decision carries token_audience: %s", line)
		}
	}
}

func TestRenewLegacyToken(t *testing.T) {
	// Transition: the renewal goes through and is counted legacy.
	r := newRig(t)
	r.legacyAlice(false)
	r.enrollOK()
	r.approve()
	r.deviceSessionOK()
	req, _ := r.clientReq(22)
	st, body := r.clientSession(legacyToken, req)
	if st != http.StatusCreated {
		t.Fatalf("%d %s", st, body)
	}
	sess := decodeSession(t, body)
	r.users.set(legacyToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	if st, body := r.tunnelPost(api.RenewPath, sess.Address, legacyToken, api.RenewRequest{}); st != http.StatusOK {
		t.Fatalf("renew in transition: %d %s", st, body)
	}
	if got := counterValue(t, r.h.met.userTokens, "renew", "legacy"); got != 1 {
		t.Fatalf("legacy renew tokens = %v", got)
	}

	// Enforce: the renewal is refused, counted legacy and ends the session.
	r.users.setLegacy(legacyToken, true)
	r.users.set(legacyToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	st, body = r.tunnelPost(api.RenewPath, sess.Address, legacyToken, api.RenewRequest{})
	wantReason(t, st, body, http.StatusUnauthorized, api.ReasonUnauthenticated)
	if got := counterValue(t, r.h.met.userTokens, "renew", "legacy"); got != 2 {
		t.Fatalf("legacy renew tokens = %v", got)
	}
	if !strings.Contains(r.logs.String(), `"op":"renew"`) || !strings.Contains(r.logs.String(), `"token_audience":"legacy"`) {
		t.Fatalf("renew decision lacks token_audience:\n%s", r.logs.String())
	}
}

func TestRenewZTNAToken(t *testing.T) {
	r := newRig(t)
	r.enrollOK()
	r.approve()
	r.deviceSessionOK()
	sess := r.clientSessionOK()
	r.users.set(aliceToken, aliceEmail, r.clock.Now().Add(5*time.Minute))
	if st, body := r.tunnelPost(api.RenewPath, sess.Address, aliceToken, api.RenewRequest{}); st != http.StatusOK {
		t.Fatalf("%d %s", st, body)
	}
	if got := counterValue(t, r.h.met.userTokens, "renew", "ztna"); got != 1 {
		t.Fatalf("ztna renew tokens = %v", got)
	}
}
