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
)

const maxControlBody = 64 << 10

// controlServer is the hub-to-agent RPC (api.AgentControlPort): the hub pushes
// the service set and, in wave B, the plane-B grants. Only the hub's overlay
// address is served; the agent's only plane-A peer is the hub anyway, this is
// the second check.
type controlServer struct {
	log      *slog.Logger
	connect  *connectServer
	grants   *GrantStore
	hubAddr  netip.Addr
	srv      *http.Server
	serveErr chan error
}

func newControlServer(log *slog.Logger, connect *connectServer, grants *GrantStore) *controlServer {
	c := &controlServer{log: log, connect: connect, grants: grants, hubAddr: netip.MustParseAddr(api.HubAddress)}
	mux := http.NewServeMux()
	mux.HandleFunc(api.ControlServicesPath, c.handle(c.services))
	mux.HandleFunc(api.ControlGrantsPath, c.handle(c.applyGrants))
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

type controlFunc func(body []byte) (status int, resp any, err *api.Error)

func (c *controlServer) handle(fn controlFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || ap.Addr().Unmap() != c.hubAddr {
			writeControlJSON(w, http.StatusForbidden, &api.Error{Reason: api.ReasonForbidden, Message: "only the hub may call this"})
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeControlJSON(w, http.StatusMethodNotAllowed, &api.Error{Reason: api.ReasonBadRequest, Message: "POST required"})
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBody))
		if err != nil {
			writeControlJSON(w, http.StatusRequestEntityTooLarge, &api.Error{Reason: api.ReasonBadRequest, Message: "unreadable or oversized body"})
			return
		}
		status, resp, aerr := fn(body)
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

func writeControlJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *controlServer) services(body []byte) (int, any, *api.Error) {
	var upd api.ServicesUpdate
	if err := json.Unmarshal(body, &upd); err != nil {
		return http.StatusBadRequest, nil, &api.Error{Reason: api.ReasonBadRequest, Message: "malformed JSON"}
	}
	c.connect.SetServices(upd.Services)
	c.log.Info("services updated by the hub", "count", len(upd.Services))
	return http.StatusNoContent, nil, nil
}

func (c *controlServer) applyGrants(body []byte) (int, any, *api.Error) {
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
	// Plane B is wave B: until then no device parameters are handed out, and
	// the hub treats an empty DeviceWGPublicKey as "not available".
	return http.StatusOK, &api.GrantAck{DeviceCandidates: []string{}, Accepted: res.Accepted}, nil
}
