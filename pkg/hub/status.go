package hub

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// softwareGateway is the posture software of the web gateway (api.ClientSessionInfo.Software).
const softwareGateway = "web-gateway"

// StatusRequesterHeader (api.StatusRequesterHeader) carries the end user (a
// lowercase email) on whose behalf the Backstage backend calls the status
// listener. Only the verified Backstage service account can reach the
// listener, so the value is trusted for the audit line of an admin action; an
// invalid value is logged as "unknown".
const StatusRequesterHeader = api.StatusRequesterHeader

// reasonAdminEnd is the log and metric label of an administrator ending a session.
const reasonAdminEnd = "admin_end"

// StatusAuthenticator verifies a ServiceAccount token presented on the status
// listener and returns the username of the token's subject, e.g.
// "system:serviceaccount:teknoir-system:backstage".
type StatusAuthenticator interface {
	Authenticate(ctx context.Context, token string) (username string, err error)
}

// K8sStatusAuth implements StatusAuthenticator with a TokenReview FOR ONE
// AUDIENCE (api.StatusTokenAudience by default) and requires the review to
// confirm that audience. The Backstage backend presents a projected token with
// exactly that audience, so the hub never receives a token the API server would
// accept: a compromised hub (or its logs) cannot replay it as backstage-api.
// The caller still has to compare the username.
type K8sStatusAuth struct {
	cs       kubernetes.Interface
	audience string
}

var _ StatusAuthenticator = (*K8sStatusAuth)(nil)

// NewK8sStatusAuth returns a TokenReview-backed StatusAuthenticator for the
// audience (default api.StatusTokenAudience; main passes STATUS_AUDIENCE).
func NewK8sStatusAuth(cs kubernetes.Interface, audience ...string) *K8sStatusAuth {
	aud := api.StatusTokenAudience
	if len(audience) > 0 && audience[0] != "" {
		aud = audience[0]
	}
	return &K8sStatusAuth{cs: cs, audience: aud}
}

// Authenticate implements StatusAuthenticator.
func (a *K8sStatusAuth) Authenticate(ctx context.Context, token string) (string, error) {
	if token == "" || len(token) > maxBearerTokenSize {
		return "", fmt.Errorf("%w: bad token length", ErrUnauthenticated)
	}
	tr, err := a.cs.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{a.audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("%w: token review: %v", ErrUnavailable, err)
	}
	if !tr.Status.Authenticated || tr.Status.User.Username == "" {
		return "", fmt.Errorf("%w: token not authenticated", ErrUnauthenticated)
	}
	// An API server that ignores audiences would accept any token: demand the
	// confirmation, as VerifyDelegate does.
	if !slices.Contains(tr.Status.Audiences, a.audience) {
		return "", fmt.Errorf("%w: token is not for the status audience", ErrUnauthenticated)
	}
	return tr.Status.User.Username, nil
}

// peerHandshaker is implemented by tunnels that can report the last WireGuard
// handshake of a peer (the real one does; test doubles need not).
type peerHandshaker interface {
	PeerLastHandshake(pub wgkey.PublicKey) (time.Time, bool)
}

// PeerLastHandshake implements peerHandshaker from the device's IpcGet dump.
func (t *wgTunnel) PeerLastHandshake(pub wgkey.PublicKey) (time.Time, bool) {
	out, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	return parseLastHandshake(out, pub.Hex())
}

// parseLastHandshake finds the peer with the given hex public key in a
// wireguard-go IpcGet dump and returns its last handshake time. ok is false
// when the peer is unknown; a peer without a handshake yields the zero time.
func parseLastHandshake(dump, hexKey string) (t time.Time, ok bool) {
	var inPeer bool
	var sec, nsec int64
	for line := range strings.SplitSeq(dump, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "public_key":
			inPeer = v == hexKey
			ok = ok || inPeer
		case "last_handshake_time_sec":
			if inPeer {
				sec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "last_handshake_time_nsec":
			if inPeer {
				nsec, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if !ok || sec == 0 {
		return time.Time{}, ok
	}
	return time.Unix(sec, nsec).UTC(), true
}

// StatusHandler serves the live status and admin actions on api.HubStatusPort
// to the Backstage backend only. Every request must carry a Bearer service
// account token whose TokenReview username equals Config.BackstageSA exactly
// (another valid identity gets 403; a missing or invalid token 401). Without
// Config.BackstageSA or Deps.Status every request is refused.
//
//	GET  api.StatusDevicePath + "<ns>/<device>"       -> api.DeviceLiveStatus
//	POST api.AdminEndSessionPath + "<session id>/end" -> 204
func (h *Hub) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.StatusDevicePath+"{ns}/{device}", h.statusAuth("status", h.handleDeviceStatus))
	mux.HandleFunc("POST "+api.AdminEndSessionPath+"{id}/end", h.statusAuth("admin_end", h.handleAdminEnd))
	mux.HandleFunc(api.HealthzPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

type statusFunc func(w http.ResponseWriter, r *http.Request, d *dctx, user string) *denial

func (h *Hub) statusAuth(op string, fn statusFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := &dctx{op: op, remote: remoteIP(r.RemoteAddr), internal: true}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		fail := func(den *denial) {
			h.logDecision(d, "deny", den.reason, den.msg)
			writeJSON(w, den.status, &api.Error{Reason: den.reason, Message: den.msg})
		}
		tok := bearer(r.Header.Get("Authorization"))
		if tok == "" {
			fail(deny(api.ReasonUnauthenticated, "bearer token required"))
			return
		}
		if h.deps.Status == nil || h.cfg.BackstageSA == "" {
			fail(deny(api.ReasonForbidden, "status listener is not configured"))
			return
		}
		user, err := h.deps.Status.Authenticate(r.Context(), tok)
		if err != nil {
			fail(asDenial(err))
			return
		}
		if user != h.cfg.BackstageSA {
			d.subject = user
			fail(deny(api.ReasonForbidden, "caller is not the Backstage service account"))
			return
		}
		d.subject = user
		if den := fn(w, r, d, user); den != nil {
			fail(den)
		}
	}
}

func (h *Hub) handleDeviceStatus(w http.ResponseWriter, r *http.Request, d *dctx, _ string) *denial {
	ns, device := r.PathValue("ns"), r.PathValue("device")
	if !validLabel(ns) || !validLabel(device) {
		return deny(api.ReasonBadRequest, "invalid namespace or device")
	}
	d.ns, d.device = ns, device
	pol, ok := h.deps.Policy.Get(ns, device)
	if !ok {
		return &denial{status: http.StatusNotFound, reason: api.ReasonDeviceUnknown, msg: "no such device"}
	}
	st := h.deviceStatus(r.Context(), ns, device, pol)
	h.met.decisions.WithLabelValues(d.op, "allow", "ok").Inc()
	writeJSON(w, http.StatusOK, st)
	return nil
}

// deviceStatus assembles the live view of one device.
func (h *Hub) deviceStatus(ctx context.Context, ns, device string, pol api.PolicyEntry) *api.DeviceLiveStatus {
	k := devKey{ns, device}
	st := &api.DeviceLiveStatus{Sessions: []api.ClientSessionInfo{}, NAT: "unknown"}

	h.mu.Lock()
	dev := h.devices[k]
	clients := make([]*session, 0, len(h.clients[k]))
	for _, c := range h.clients[k] {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	if dev != nil {
		st.Connected = true
		st.ConnectedSince = dev.createdAt.UTC()
		st.Transport = "turn"
		if dev.direct {
			st.Transport = "direct-udp"
		}
		st.AgentVersion = dev.posture.Version
		st.Capabilities = slices.Clone(dev.caps)
		if hs, ok := h.tunnel.(peerHandshaker); ok {
			if t, ok := hs.PeerLastHandshake(dev.wgKey); ok {
				st.LastHandshake = t
			}
		}
	}
	// A pinned identity of the current enrollment that is not usable yet waits
	// for an admin (approval or a trusted device key).
	// Identity is the hub's own record of the pin (the identity store), not the
	// Device CR status that device editors can write.
	if pin, found, err := h.deps.Identity.Get(ctx, ns, device); err == nil && found {
		if !pin.Voided && sameEpoch(pin, pol) && !activated(viewOfPin(pin), pol) {
			st.IdentityPending = true
		}
		st.Identity = &api.LiveIdentity{
			Fingerprint: pin.Fingerprint, AttestedHostKey: pin.AttestedHostKey, AttestedHostKeyType: pin.AttestedHostKeyType,
			EnrollmentGeneration: pin.EnrollmentGeneration, EnrollmentEpoch: pin.EnrollmentEpoch, EnrolledAt: pin.EnrolledAt.UTC(),
			ActivatedBy: pin.ActivatedBy, ActivatedAt: pin.ActivatedAt.UTC(), Voided: pin.Voided, Conflicts: pin.Conflicts,
			Replacements: pin.Replacements, LastReplacedAt: pin.LastReplacedAt.UTC(),
		}
	}
	for _, c := range clients {
		st.Sessions = append(st.Sessions, c.info())
	}
	sort.Slice(st.Sessions, func(i, j int) bool {
		a, b := st.Sessions[i], st.Sessions[j]
		if !a.Since.Equal(b.Since) {
			return a.Since.Before(b.Since)
		}
		return a.ID < b.ID
	})
	return st
}

// info is the console row of a client session.
func (s *session) info() api.ClientSessionInfo {
	s.mu.Lock()
	path := s.path
	users := map[string]struct{}{}
	for c := range s.conns {
		if c.as != "" {
			users[c.as] = struct{}{}
		}
	}
	s.mu.Unlock()
	if path == "" {
		path = api.PathHub
	}
	subject := s.subject
	if s.perConn {
		// A gateway session serves many users; list the ones with an open
		// connection (the console redacts the whole field for non-admins).
		list := make([]string, 0, len(users))
		for u := range users {
			list = append(list, u)
		}
		sort.Strings(list)
		subject = strings.Join(list, ", ")
	}
	return api.ClientSessionInfo{
		ID: s.id, Subject: subject, Service: s.service, Software: s.posture.Software,
		Path: path, Since: s.createdAt.UTC(), BytesIn: s.bytesIn.Load(), BytesOut: s.bytesOut.Load(),
	}
}

func (h *Hub) handleAdminEnd(w http.ResponseWriter, r *http.Request, d *dctx, user string) *denial {
	id := r.PathValue("id")
	d.session = id
	h.mu.Lock()
	s := h.byID[id]
	h.mu.Unlock()
	if s == nil || s.kind != api.KindClient {
		return &denial{status: http.StatusNotFound, reason: api.ReasonSessionUnknown, msg: "no such client session"}
	}
	d.ns, d.device, d.kind, d.service = s.ns, s.device, s.kind, s.service
	requester := r.Header.Get(api.StatusRequesterHeader)
	if !ValidEmail(requester) {
		requester = "unknown"
	}
	if !h.endSession(s, reasonAdminEnd) {
		return &denial{status: http.StatusNotFound, reason: api.ReasonSessionUnknown, msg: "no such client session"}
	}
	h.met.revocations.WithLabelValues(reasonAdminEnd).Inc()
	h.met.decisions.WithLabelValues(reasonAdminEnd, "end", reasonAdminEnd).Inc()
	h.log.LogAttrs(context.Background(), slog.LevelWarn, "decision",
		slog.String("op", reasonAdminEnd), slog.String("decision", "end"), slog.String("reason", reasonAdminEnd),
		slog.String("kind", s.kind), slog.String("ns", s.ns), slog.String("device", s.device),
		slog.String("subject", s.subjectLabel()), slog.String("session", s.id), slog.String("remote", d.remote),
		slog.String("service", s.service), slog.String("requester", requester), slog.String("via", user))
	w.WriteHeader(http.StatusNoContent)
	return nil
}
