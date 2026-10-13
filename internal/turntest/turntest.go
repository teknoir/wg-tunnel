// Package turntest runs an in-process pion TURN server for tests. It uses the
// same time-windowed credential scheme as STUNner (see pkg/turncred) and relays
// on 127.0.0.1. It is not for production use.
package turntest

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Realm is the realm STUNner uses by default.
const Realm = "stunner.l7mp.io"

// Server is a restartable TURN server bound to a fixed 127.0.0.1 UDP port.
type Server struct {
	// Addr is "127.0.0.1:<port>". It is stable across Restart.
	Addr string

	secret string
	t      testing.TB

	mu  sync.Mutex
	srv *turn.Server
}

// Start launches a server and registers cleanup with t.
func Start(t testing.TB, secret string) *Server {
	t.Helper()
	s := &Server{secret: secret, t: t}
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
	for i := 0; i < 50; i++ {
		pc, err = net.ListenPacket("udp4", listen)
		if err == nil {
			break
		}
		sleep(20)
	}
	if err != nil {
		s.t.Fatalf("turntest: listen: %v", err)
	}
	lf := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:         Realm,
		AuthHandler:   turn.LongTermTURNRESTAuthHandler(s.secret, lf.NewLogger("turn")),
		LoggerFactory: lf,
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
	s.Addr = pc.LocalAddr().String()
	s.mu.Unlock()
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
