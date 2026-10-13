// Package turntest runs an in-process pion TURN server for tests. It uses the
// same time-windowed credential scheme as STUNner (see pkg/turncred) and relays
// on 127.0.0.1. It is not for production use.
package turntest

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Realm is the realm STUNner uses by default.
const Realm = "stunner.l7mp.io"

// Option customises Start.
type Option func(*Server)

// WithAllocationLifetime sets the server's allocation lifetime; clients
// refresh at half of it, so a short value exercises the refresh path.
func WithAllocationLifetime(d time.Duration) Option {
	return func(s *Server) { s.lifetime = d }
}

// tracker records the live allocations of one server instance.
type tracker struct {
	mu    sync.Mutex
	alloc map[string]net.Addr // keyed by client address
}

func (tr *tracker) created(src, relay net.Addr) {
	tr.mu.Lock()
	tr.alloc[src.String()] = relay
	tr.mu.Unlock()
}

func (tr *tracker) deleted(src net.Addr) {
	tr.mu.Lock()
	delete(tr.alloc, src.String())
	tr.mu.Unlock()
}

// Server is a restartable TURN server bound to a fixed 127.0.0.1 UDP port.
type Server struct {
	// Addr is "127.0.0.1:<port>". It is stable across Restart.
	Addr string

	secret   string
	lifetime time.Duration
	t        testing.TB

	mu  sync.Mutex
	srv *turn.Server
	trk *tracker
}

// Start launches a server and registers cleanup with t.
func Start(t testing.TB, secret string, opts ...Option) *Server {
	t.Helper()
	s := &Server{secret: secret, t: t}
	for _, o := range opts {
		o(s)
	}
	s.start("127.0.0.1:0")
	t.Cleanup(s.Stop)
	return s
}

func (s *Server) start(listen string) {
	s.t.Helper()
	var (
		pc  net.PacketConn
		err error
	)
	// A restart may race with the kernel releasing the port; retry briefly.
	for i := 0; i < 100; i++ {
		pc, err = net.ListenPacket("udp4", listen)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		s.t.Fatalf("turntest: listen: %v", err)
	}
	trk := &tracker{alloc: map[string]net.Addr{}}
	lf := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:              Realm,
		AuthHandler:        turn.LongTermTURNRESTAuthHandler(s.secret, lf.NewLogger("turn")),
		LoggerFactory:      lf,
		AllocationLifetime: s.lifetime,
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(src, _ net.Addr, _, _, _ string, relay net.Addr, _ int) { trk.created(src, relay) },
			OnAllocationDeleted: func(src, _ net.Addr, _, _, _ string) { trk.deleted(src) },
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		_ = pc.Close()
		s.t.Fatalf("turntest: NewServer: %v", err)
	}
	s.mu.Lock()
	s.srv = srv
	s.trk = trk
	s.Addr = pc.LocalAddr().String()
	s.mu.Unlock()
}

// Allocations returns the number of live allocations on the current instance.
func (s *Server) Allocations() int {
	s.mu.Lock()
	trk := s.trk
	s.mu.Unlock()
	if trk == nil {
		return 0
	}
	trk.mu.Lock()
	defer trk.mu.Unlock()
	return len(trk.alloc)
}

// Stop shuts the server down, dropping every allocation. Idempotent.
func (s *Server) Stop() {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// Restart stops the server and starts a fresh one on the same address; all
// allocations are lost, exactly as when a STUNner pod restarts.
func (s *Server) Restart() {
	s.t.Helper()
	s.Stop()
	s.start(s.Addr)
}
