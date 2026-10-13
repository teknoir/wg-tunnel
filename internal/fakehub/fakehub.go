// Package fakehub is a minimal test double of the wg-hub: a wireguard-go
// netstack peer plus HTTP handlers implementing the session, enrollment and
// renewal API of pkg/api, with a TCP splice from client sessions to device
// sessions. It exists so client-side packages (wgclient, agent, wg-connect)
// can be tested end to end without pkg/hub. It is deliberately simple, keeps
// everything in memory, and is not for production use.
package fakehub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/teknoir/wg-tunnel/internal/wgtest"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/identity"
	"github.com/teknoir/wg-tunnel/pkg/turncred"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Options configures the hub.
type Options struct {
	// TURNSecret is the TURN-REST shared secret. Empty: no TURN credentials are
	// minted (direct sessions only).
	TURNSecret string
	// TURNURL is advertised in credentials (default a name that does not
	// resolve, so tests prove the client override works).
	TURNURL string
	// RenewAfter and TTL default to 60 s and 3 min.
	RenewAfter time.Duration
	TTL        time.Duration
	// RotateTURNOnRenew mints new TURN credentials on every renewal.
	RotateTURNOnRenew bool
}

// Denial makes a hook refuse a request.
type Denial struct {
	Status int
	Reason string
}

// Call is one authenticated request the hub saw. Bearer is kept for tests that
// check credential freshness; it is never logged.
type Call struct {
	Path      string
	Kind      string
	Bearer    string
	SessionID string
	OnBehalf  string
}

// DeviceSpec describes a device known to the hub.
type DeviceSpec struct {
	// RSACertPEM verifies enrollment JWTs. With SkipAuth, any non-empty bearer is accepted instead.
	RSACertPEM   []byte
	SkipAuth     bool
	AllowedPorts []int
	EnrollOpen   bool
}

type device struct {
	spec       DeviceSpec
	generation int64
	pinned     ed25519.PublicKey
	pinnedGen  int64
	state      string
	seenJTI    map[string]bool
	enrolls    int
}

type sess struct {
	id, kind, ns, dev string
	pub               wgkey.PublicKey
	ip                netip.Addr
	port              int
	hostKeys          []string
	rotations         int
	expires           time.Time
	direct            bool
	onBehalf          string
	splices           map[net.Conn]struct{}
}

// Hub is the fake hub.
type Hub struct {
	t    testing.TB
	opts Options

	// URL is the base of the outside-tunnel API.
	URL string
	// Endpoint is the hub's WireGuard UDP endpoint ("127.0.0.1:port").
	Endpoint string
	PubKey   wgkey.PublicKey

	hookMu     sync.Mutex
	onCreate   func(Call) *Denial
	onRenew    func(Call) *Denial
	clientAuth func(bearer, onBehalfOf string) *Denial

	node *wgtest.Node
	srv  *httptest.Server

	mu       sync.Mutex
	devices  map[string]*device
	sessions map[string]*sess
	byIP     map[netip.Addr]*sess
	calls    []Call
	nextID   int
	nextIP   int
}

// New starts a hub; it is stopped by t.Cleanup.
func New(t testing.TB, opts Options) *Hub {
	t.Helper()
	if opts.TURNURL == "" {
		opts.TURNURL = "turn:turn.invalid:3478?transport=udp"
	}
	if opts.RenewAfter <= 0 {
		opts.RenewAfter = 60 * time.Second
	}
	if opts.TTL <= 0 {
		opts.TTL = 3 * time.Minute
	}
	h := &Hub{
		t: t, opts: opts,
		devices: map[string]*device{}, sessions: map[string]*sess{}, byIP: map[netip.Addr]*sess{},
		nextIP: 2,
	}
	h.node = wgtest.NewNode(t, conn.NewDefaultBind(), netip.MustParseAddr(api.HubAddress))
	h.PubKey = h.node.Pub
	out, err := h.node.Dev.IpcGet()
	if err != nil {
		t.Fatalf("fakehub: IpcGet: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			h.Endpoint = "127.0.0.1:" + v
		}
	}
	if h.Endpoint == "" {
		t.Fatal("fakehub: no listen port")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+api.DeviceEnrollPath, h.handleEnroll)
	mux.HandleFunc("POST "+api.DeviceSessionPath, h.handleCreate(api.KindDevice))
	mux.HandleFunc("POST "+api.ClientSessionPath, h.handleCreate(api.KindClient))
	h.srv = httptest.NewServer(mux)
	h.URL = h.srv.URL
	t.Cleanup(h.srv.Close)

	api80, err := h.node.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(api.HubAddress), api.HubAPIPort))
	if err != nil {
		t.Fatal(err)
	}
	inTunnel := http.NewServeMux()
	inTunnel.HandleFunc("POST "+api.RenewPath, h.handleRenew)
	inTunnel.HandleFunc("POST "+api.CloseSessionPath, h.handleClose)
	isrv := &http.Server{Handler: inTunnel, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = isrv.Serve(api80) }()
	t.Cleanup(func() { _ = isrv.Close() })

	spl, err := h.node.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(api.HubAddress), api.HubSplicePort))
	if err != nil {
		t.Fatal(err)
	}
	go h.spliceLoop(spl)
	t.Cleanup(func() { _ = spl.Close() })
	return h
}

// SetOnCreate installs a hook that may refuse session creation.
func (h *Hub) SetOnCreate(f func(Call) *Denial) { h.hookMu.Lock(); h.onCreate = f; h.hookMu.Unlock() }

// SetOnRenew installs a hook that may refuse a renewal; a refusal ends the session.
func (h *Hub) SetOnRenew(f func(Call) *Denial) { h.hookMu.Lock(); h.onRenew = f; h.hookMu.Unlock() }

// SetClientAuth installs the client bearer validator (default: any non-empty value).
func (h *Hub) SetClientAuth(f func(bearer, onBehalfOf string) *Denial) {
	h.hookMu.Lock()
	h.clientAuth = f
	h.hookMu.Unlock()
}

// AddDevice registers a device (generation 1, state active).
func (h *Hub) AddDevice(ns, name string, spec DeviceSpec) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.devices[ns+"/"+name] = &device{spec: spec, generation: 1, state: api.StateActive, seenJTI: map[string]bool{}}
}

// ResetEnrollment bumps the generation and opens the enrollment window.
func (h *Hub) ResetEnrollment(ns, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.devices[ns+"/"+name]
	d.generation++
	d.spec.EnrollOpen = true
}

// SetEnrollOpen opens or closes the enrollment window.
func (h *Hub) SetEnrollOpen(ns, name string, open bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.devices[ns+"/"+name].spec.EnrollOpen = open
}

// PinnedKey returns the enrolled identity key (nil if none).
func (h *Hub) PinnedKey(ns, name string) ed25519.PublicKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.devices[ns+"/"+name].pinned
}

// SetState sets the device state; anything but active ends its sessions and
// every client session bound to it, like the real hub's revocation.
func (h *Hub) SetState(ns, name, state string) {
	h.mu.Lock()
	d := h.devices[ns+"/"+name]
	d.state = state
	var kill []*sess
	if state != api.StateActive {
		for _, s := range h.sessions {
			if s.ns == ns && s.dev == name {
				kill = append(kill, s)
			}
		}
	}
	h.mu.Unlock()
	for _, s := range kill {
		h.endSession(s)
	}
}

// KillSession ends a session at the hub, as if it had been reaped.
func (h *Hub) KillSession(id string) {
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s != nil {
		h.endSession(s)
	}
}

// Calls returns a copy of the recorded authenticated calls.
func (h *Hub) Calls() []Call {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Call(nil), h.calls...)
}

// SessionIDs lists live sessions of a kind.
func (h *Hub) SessionIDs(kind string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var ids []string
	for id, s := range h.sessions {
		if s.kind == kind {
			ids = append(ids, id)
		}
	}
	return ids
}

// HostKeys returns the SSH host keys the device session of (ns, name) reported.
func (h *Hub) HostKeys(ns, name string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.deviceSession(ns, name); s != nil {
		return append([]string(nil), s.hostKeys...)
	}
	return nil
}

func (h *Hub) deviceSession(ns, name string) *sess {
	for _, s := range h.sessions {
		if s.kind == api.KindDevice && s.ns == ns && s.dev == name {
			return s
		}
	}
	return nil
}

func writeErr(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.Error{Reason: reason, Message: "fakehub: " + reason})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return v
}

// subjectOf reads the (unverified) subject of a device JWT to find the policy.
func subjectOf(token string) (ns, name string, ok bool) {
	var c jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &c); err != nil {
		return "", "", false
	}
	ns, name, ok = strings.Cut(c.Subject, "/")
	return ns, name, ok && ns != "" && name != ""
}

func (h *Hub) handleEnroll(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	if tok == "" {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	ns, name, ok := subjectOf(tok)
	if !ok {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	var req api.EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeErr(w, 400, api.ReasonBadRequest)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, Call{Path: api.DeviceEnrollPath, Kind: api.KindDevice, Bearer: tok})
	d := h.devices[ns+"/"+name]
	if d == nil {
		writeErr(w, 404, api.ReasonDeviceUnknown)
		return
	}
	switch d.state {
	case api.StateDisabled:
		writeErr(w, 403, api.ReasonDeviceDisabled)
		return
	case api.StateRevoked:
		writeErr(w, 403, api.ReasonDeviceRevoked)
		return
	}
	if !d.spec.EnrollOpen {
		writeErr(w, 403, api.ReasonEnrollClosed)
		return
	}
	sub := api.DeviceSubject(ns, name)
	idk, err := identity.ParsePublicKey(req.IdentityPublicKey)
	if err != nil {
		writeErr(w, 400, api.ReasonBadRequest)
		return
	}
	if d.spec.SkipAuth {
		d.pin(idk)
		writeJSON(w, 201, h.enrollResponse(d, idk))
		return
	}
	claims, err := identity.VerifyEnrollJWT(tok, d.spec.RSACertPEM, sub, time.Now())
	if err != nil || claims.IdentityKey != req.IdentityPublicKey || d.seenJTI[claims.ID] {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	if err := identity.VerifyEnrollProof(idk, sub, claims.ID, req.Proof); err != nil {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	d.seenJTI[claims.ID] = true
	status := 201
	if d.pinned != nil && d.pinnedGen == d.generation {
		if !d.pinned.Equal(idk) {
			writeErr(w, 409, api.ReasonEnrollConflict)
			return
		}
		status = 200
	}
	d.pin(idk)
	writeJSON(w, status, h.enrollResponse(d, idk))
}

func (d *device) pin(k ed25519.PublicKey) {
	d.pinned, d.pinnedGen = k, d.generation
	d.enrolls++
}

func (h *Hub) enrollResponse(d *device, k ed25519.PublicKey) api.EnrollResponse {
	return api.EnrollResponse{Fingerprint: identity.Fingerprint(k), EnrollmentGeneration: d.generation, EnrolledAt: time.Now()}
}

// Enrollments counts successful pins of a device.
func (h *Hub) Enrollments(ns, name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.devices[ns+"/"+name].enrolls
}

func (h *Hub) handleCreate(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, 401, api.ReasonUnauthenticated)
			return
		}
		body := io.LimitReader(r.Body, 16<<10)
		var (
			wgPub, ns, name, onBehalf string
			port                      int
			direct                    bool
			hostKeys                  []string
		)
		if kind == api.KindDevice {
			var req api.DeviceSessionRequest
			if err := json.NewDecoder(body).Decode(&req); err != nil {
				writeErr(w, 400, api.ReasonBadRequest)
				return
			}
			wgPub, hostKeys = req.WGPublicKey, req.SSHHostKeys
			var ok bool
			if ns, name, ok = subjectOf(tok); !ok {
				writeErr(w, 401, api.ReasonUnauthenticated)
				return
			}
		} else {
			var req api.ClientSessionRequest
			if err := json.NewDecoder(body).Decode(&req); err != nil {
				writeErr(w, 400, api.ReasonBadRequest)
				return
			}
			wgPub, ns, name, port, direct, onBehalf = req.WGPublicKey, req.Namespace, req.Device, req.Port, req.Direct, req.OnBehalfOf
		}
		pub, err := wgkey.ParsePublic(wgPub)
		if err != nil {
			writeErr(w, 400, api.ReasonBadRequest)
			return
		}
		call := Call{Path: r.URL.Path, Kind: kind, Bearer: tok, OnBehalf: onBehalf}
		h.mu.Lock()
		h.calls = append(h.calls, call)
		h.mu.Unlock()
		h.hookMu.Lock()
		onCreate, clientAuth := h.onCreate, h.clientAuth
		h.hookMu.Unlock()
		if onCreate != nil {
			if d := onCreate(call); d != nil {
				writeErr(w, d.Status, d.Reason)
				return
			}
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		d := h.devices[ns+"/"+name]
		if d == nil {
			writeErr(w, 404, api.ReasonDeviceUnknown)
			return
		}
		switch d.state {
		case api.StateDisabled:
			writeErr(w, 403, api.ReasonDeviceDisabled)
			return
		case api.StateRevoked:
			writeErr(w, 403, api.ReasonDeviceRevoked)
			return
		}
		if kind == api.KindDevice {
			if status, reason := h.authDevice(d, tok, ns, name, wgPub); reason != "" {
				writeErr(w, status, reason)
				return
			}
			// One device session per device: a new one replaces the old.
			if old := h.deviceSession(ns, name); old != nil {
				h.mu.Unlock()
				h.endSession(old)
				h.mu.Lock()
			}
		} else {
			if clientAuth != nil {
				if den := clientAuth(tok, onBehalf); den != nil {
					writeErr(w, den.Status, den.Reason)
					return
				}
			}
			allowed := false
			for _, p := range d.spec.AllowedPorts {
				allowed = allowed || p == port
			}
			if !allowed {
				writeErr(w, 403, api.ReasonPortNotAllowed)
				return
			}
			if h.deviceSession(ns, name) == nil {
				writeErr(w, 409, api.ReasonDeviceOffline)
				return
			}
		}

		h.nextID++
		s := &sess{
			id: fmt.Sprintf("s%d", h.nextID), kind: kind, ns: ns, dev: name, pub: pub,
			ip: netip.AddrFrom4([4]byte{100, 96, byte(h.nextIP >> 8), byte(h.nextIP)}), port: port,
			hostKeys: hostKeys, expires: time.Now().Add(h.opts.TTL), direct: direct, onBehalf: onBehalf,
			splices: map[net.Conn]struct{}{},
		}
		h.nextIP++
		h.node.AddPeer(h.t, pub, s.ip, "", 0)
		h.sessions[s.id], h.byIP[s.ip] = s, s

		resp := api.SessionResponse{
			SessionID: s.id, Kind: kind, Address: s.ip.String(),
			HubAddress: api.HubAddress, HubPublicKey: h.PubKey.Base64(), HubEndpoint: h.Endpoint,
			ExpiresAt: s.expires, RenewAfterSeconds: max(1, int(h.opts.RenewAfter/time.Second)), MTU: api.MTU,
		}
		if !direct && h.opts.TURNSecret != "" {
			resp.TURN = h.mintTURN(s)
		}
		if kind == api.KindDevice {
			resp.AllowedPorts = append([]int(nil), d.spec.AllowedPorts...)
		} else {
			resp.SplicePort, resp.TargetPort = api.HubSplicePort, port
			resp.SSHHostKeys = h.deviceSession(ns, name).hostKeys
		}
		writeJSON(w, 201, resp)
	}
}

// authDevice checks an identity JWT against the pinned key. Caller holds mu.
func (h *Hub) authDevice(d *device, tok, ns, name, wgPub string) (int, string) {
	if d.spec.SkipAuth {
		return 0, ""
	}
	switch {
	case d.pinned == nil:
		return 403, api.ReasonNotEnrolled
	case d.pinnedGen < d.generation:
		return 403, api.ReasonReenroll
	}
	c, err := identity.VerifyIdentityJWT(tok, d.pinned, api.DeviceSubject(ns, name), time.Now())
	if err != nil || c.WGKey != wgPub {
		return 401, api.ReasonUnauthenticated
	}
	if d.seenJTI[c.ID] {
		return 401, api.ReasonReplay
	}
	d.seenJTI[c.ID] = true
	return 0, ""
}

func (h *Hub) mintTURN(s *sess) *api.TURNCredentials {
	id := s.id
	if s.rotations > 0 {
		id += "r" + strconv.Itoa(s.rotations)
	}
	user, pass, exp := turncred.Generate(h.opts.TURNSecret, s.ns+"/"+id, 30*time.Minute, time.Now())
	return &api.TURNCredentials{URLs: []string{h.opts.TURNURL}, Username: user, Password: pass, ExpiresAt: exp}
}

func (h *Hub) sessionOf(r *http.Request) *sess {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byIP[ap.Addr().Unmap()]
}

func (h *Hub) handleRenew(w http.ResponseWriter, r *http.Request) {
	s := h.sessionOf(r)
	if s == nil {
		writeErr(w, 404, api.ReasonSessionUnknown)
		return
	}
	call := Call{Path: api.RenewPath, Kind: s.kind, Bearer: bearer(r), SessionID: s.id}
	h.mu.Lock()
	h.calls = append(h.calls, call)
	h.mu.Unlock()
	if call.Bearer == "" {
		writeErr(w, 401, api.ReasonUnauthenticated)
		return
	}
	h.hookMu.Lock()
	onRenew := h.onRenew
	h.hookMu.Unlock()
	if onRenew != nil {
		if den := onRenew(call); den != nil {
			writeErr(w, den.Status, den.Reason)
			// Denial means teardown, like the real hub, but only after the
			// refusal has had time to reach the client: removing the peer
			// first would drop the response and the client would only learn of
			// it by timing out.
			time.AfterFunc(300*time.Millisecond, func() { h.endSession(s) })
			return
		}
	}
	h.mu.Lock()
	s.expires = time.Now().Add(h.opts.TTL)
	resp := api.RenewResponse{ExpiresAt: s.expires, RenewAfterSeconds: max(1, int(h.opts.RenewAfter/time.Second))}
	if h.opts.RotateTURNOnRenew && !s.direct && h.opts.TURNSecret != "" {
		s.rotations++
		resp.TURN = h.mintTURN(s)
	}
	h.mu.Unlock()
	writeJSON(w, 200, resp)
}

func (h *Hub) handleClose(w http.ResponseWriter, r *http.Request) {
	s := h.sessionOf(r)
	if s == nil {
		writeErr(w, 404, api.ReasonSessionUnknown)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	time.AfterFunc(300*time.Millisecond, func() { h.endSession(s) })
}

// endSession removes the peer, closes spliced connections and, for a device
// session, ends the client sessions bound to it.
func (h *Hub) endSession(s *sess) {
	h.mu.Lock()
	if h.sessions[s.id] != s {
		h.mu.Unlock()
		return
	}
	delete(h.sessions, s.id)
	delete(h.byIP, s.ip)
	conns := make([]net.Conn, 0, len(s.splices))
	for c := range s.splices {
		conns = append(conns, c)
	}
	var bound []*sess
	if s.kind == api.KindDevice {
		for _, o := range h.sessions {
			if o.kind == api.KindClient && o.ns == s.ns && o.dev == s.dev {
				bound = append(bound, o)
			}
		}
	}
	h.mu.Unlock()
	_ = h.node.Dev.IpcSet("public_key=" + s.pub.Hex() + "\nremove=true\n")
	for _, c := range conns {
		_ = c.Close()
	}
	for _, o := range bound {
		h.endSession(o)
	}
}

func (h *Hub) spliceLoop(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go h.splice(c)
	}
}

func (h *Hub) splice(c net.Conn) {
	defer func() { _ = c.Close() }()
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	h.mu.Lock()
	cs := h.byIP[ap.Addr().Unmap()]
	var ds *sess
	if cs != nil && cs.kind == api.KindClient {
		ds = h.deviceSession(cs.ns, cs.dev)
	}
	h.mu.Unlock()
	if ds == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dc, err := h.node.Net.DialContext(ctx, "tcp", net.JoinHostPort(ds.ip.String(), strconv.Itoa(cs.port)))
	if err != nil {
		return
	}
	defer func() { _ = dc.Close() }()
	h.mu.Lock()
	cs.splices[c] = struct{}{}
	ds.splices[dc] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(cs.splices, c)
		delete(ds.splices, dc)
		h.mu.Unlock()
	}()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(dc, c)
	go cp(c, dc)
	<-done
	<-done
}
