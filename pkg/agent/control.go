package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
)

const maxControlBody = 64 << 10

// controlServer is the hub-to-agent RPC (api.AgentControlPort): the hub pushes
// the service set and, in wave B, the plane-B grants. Only the hub's overlay
// address is served; the agent's only plane-A peer is the hub anyway, this is
// the second check.
type controlServer struct {
	log     *slog.Logger
	connect *connectServer
	grants  *GrantStore
	// planeB answers the GrantAck's plane-B parameters; nil when this agent
	// has no plane B (the hub then treats the ack as "not available").
	planeB  *planeB
	hubAddr netip.Addr
	srv     *http.Server
	// revoke ends the current device session on the hub's notice (nil: the
	// control server has no session to end and answers every notice 409).
	revoke *revokeTarget
	// revokeGrace bounds how long a revoke notice's handler waits for the hub
	// to take the answer before the session is torn down regardless.
	revokeGrace time.Duration
}

// defaultRevokeGrace is how long the answer to a revoke notice may take to
// reach the hub before the session is ended anyway. The hub waits for the
// answer for one second at most; a client that has the answer closes the
// connection at once, which ends the wait.
const defaultRevokeGrace = 500 * time.Millisecond

// revokeTarget is the device session a RevokeNotice may end.
type revokeTarget struct {
	sessionID string
	end       func(error)
}

func newControlServer(log *slog.Logger, connect *connectServer, grants *GrantStore, pb *planeB) *controlServer {
	c := &controlServer{log: log, connect: connect, grants: grants, planeB: pb, hubAddr: netip.MustParseAddr(api.HubAddress), revokeGrace: defaultRevokeGrace}
	mux := http.NewServeMux()
	mux.HandleFunc(api.ControlServicesPath, c.handle(c.services))
	mux.HandleFunc(api.ControlGrantsPath, c.handle(c.applyGrants))
	mux.HandleFunc(api.ControlRevokePath, c.handleRevoke)
	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return c
}

// Serve serves ln until it is closed or ctx is done.
func (c *controlServer) Serve(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = c.srv.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			c.log.Debug("control server stopped", "error", err.Error())
		}
		_ = c.srv.Close()
	}()
}

type controlFunc func(ctx context.Context, body []byte) (status int, resp any, err *api.Error)

func (c *controlServer) handle(fn controlFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := c.readRequest(w, r)
		if !ok {
			return
		}
		status, resp, aerr := fn(r.Context(), body)
		if aerr != nil {
			writeControlJSON(w, status, aerr)
			return
		}
		if resp == nil {
			w.WriteHeader(status)
			return
		}
		writeControlJSON(w, status, resp)
	}
}

// readRequest applies the checks every control call shares (the caller is the
// hub's overlay address, POST, bounded body) and returns the body. It has
// answered the request itself when it returns false.
func (c *controlServer) readRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || ap.Addr().Unmap() != c.hubAddr {
		writeControlJSON(w, http.StatusForbidden, &api.Error{Reason: api.ReasonForbidden, Message: "only the hub may call this"})
		return nil, false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeControlJSON(w, http.StatusMethodNotAllowed, &api.Error{Reason: api.ReasonBadRequest, Message: "POST required"})
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBody))
	if err != nil {
		writeControlJSON(w, http.StatusRequestEntityTooLarge, &api.Error{Reason: api.ReasonBadRequest, Message: "unreadable or oversized body"})
		return nil, false
	}
	return body, true
}

func writeControlJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *controlServer) services(_ context.Context, body []byte) (int, any, *api.Error) {
	var upd api.ServicesUpdate
	if err := json.Unmarshal(body, &upd); err != nil {
		return http.StatusBadRequest, nil, &api.Error{Reason: api.ReasonBadRequest, Message: "malformed JSON"}
	}
	c.connect.SetServices(upd.Services)
	c.log.Info("services updated by the hub", "count", len(upd.Services))
	return http.StatusNoContent, nil, nil
}

func (c *controlServer) applyGrants(ctx context.Context, body []byte) (int, any, *api.Error) {
	var set api.GrantSet
	if err := json.Unmarshal(body, &set); err != nil {
		return http.StatusBadRequest, nil, &api.Error{Reason: api.ReasonBadRequest, Message: "malformed JSON"}
	}
	res, err := c.grants.Apply(set)
	switch {
	case errors.Is(err, ErrStaleGrantSet):
		return http.StatusConflict, nil, &api.Error{Reason: api.ReasonBadRequest, Message: "stale grant set"}
	case err != nil:
		return http.StatusBadRequest, nil, &api.Error{Reason: api.ReasonBadRequest, Message: err.Error()}
	}
	for id, why := range res.Rejected {
		c.log.Warn("grant refused", "pair", id, "why", why)
	}
	ack := &api.GrantAck{DeviceCandidates: []string{}, Accepted: res.Accepted}
	if c.planeB != nil {
		// Without plane B the key stays empty and the hub treats the pairs as
		// not available.
		ack.DeviceWGPublicKey, ack.DeviceAddress, ack.DeviceCandidates = c.planeB.params(ctx)
	}
	return http.StatusOK, ack, nil
}

// revokeReasons are the reasons the hub may end a device session with that the
// agent acts on; any other value in a notice is refused.
var revokeReasons = map[string]bool{
	api.ReasonReenroll:        true,
	api.ReasonDeviceRevoked:   true,
	api.ReasonDeviceDisabled:  true,
	api.ReasonDeviceUnknown:   true,
	api.ReasonPendingApproval: true,
}

// handleRevoke takes the hub's notice that it is ending the device session
// (api.RevokeNotice): the session is ended at once with the notice's reason
// instead of when a renewal fails. The answer goes out first, then the session
// is torn down (which closes this very connection). Flushing only hands the
// answer to the tunnel's TCP stack; tearing the tunnel down right after would
// drop it before it reached the hub, which would then wait for it in vain. So
// the handler stays until the hub closes the connection (the request context
// ends: it has the answer) or revokeGrace has passed.
func (c *controlServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	body, ok := c.readRequest(w, r)
	if !ok {
		return
	}
	var n api.RevokeNotice
	if err := json.Unmarshal(body, &n); err != nil || !revokeReasons[n.Reason] {
		writeControlJSON(w, http.StatusBadRequest, &api.Error{Reason: api.ReasonBadRequest, Message: "malformed or unknown revoke notice"})
		return
	}
	if c.revoke == nil || n.SessionID == "" || n.SessionID != c.revoke.sessionID {
		writeControlJSON(w, http.StatusConflict, &api.Error{Reason: api.ReasonSessionUnknown, Message: "not the current session"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
	_ = http.NewResponseController(w).Flush()
	c.log.Warn("the hub is ending this session", "session", n.SessionID, "reason", n.Reason, "detail", n.Detail)
	select {
	case <-r.Context().Done():
	case <-time.After(c.revokeGrace):
	}
	end := c.revoke.end
	go end(&noticeError{err: wgclient.Revoked(n.Reason, n.Detail)})
}
