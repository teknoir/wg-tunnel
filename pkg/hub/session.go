package hub

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Credential kinds that created a session (renewals need the same kind).
const (
	authDevice   = "device"
	authKeycloak = "keycloak"
	authSA       = "sa"
)

// devKey identifies a device.
type devKey struct{ ns, device string }

func (k devKey) String() string { return k.ns + "/" + k.device }

// session is one WireGuard peer of the hub.
type session struct {
	id       string
	kind     string // api.KindDevice or api.KindClient
	authKind string
	ns       string
	device   string
	// subject is the device sub "<ns>/<device>" or the user's email.
	subject string
	// saName is the delegating service account (authSA only).
	saName     string
	wgKey      wgkey.PublicKey
	wgKeyB64   string
	ip         netip.Addr
	createdAt  time.Time
	targetPort int
	hostKeys   []string
	// generation is the enrollment generation of the device identity that
	// created a device session.
	generation int64
	direct     bool
	remote     string

	// ended is protected by Hub.mu.
	ended bool
	final sync.Once

	mu          sync.Mutex
	expiresAt   time.Time
	tokenExpiry time.Time
	turnExpiry  time.Time
	conns       map[*spliceConn]struct{}
	connsClosed bool
}

func (s *session) key() devKey { return devKey{s.ns, s.device} }

// subjectLabel is the log form of the subject.
func (s *session) subjectLabel() string {
	if s.authKind == authSA {
		return s.subject + " via sa:" + s.saName
	}
	return s.subject
}

func (s *session) expiry() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}

var errConnsClosed = errors.New("session closed")

// addConn registers a spliced connection; max > 0 caps the concurrent count.
func (s *session) addConn(sc *spliceConn, max int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connsClosed {
		return errConnsClosed
	}
	if max > 0 && len(s.conns) >= max {
		return fmt.Errorf("session has %d connections", len(s.conns))
	}
	if s.conns == nil {
		s.conns = map[*spliceConn]struct{}{}
	}
	s.conns[sc] = struct{}{}
	return nil
}

func (s *session) removeConn(sc *spliceConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, sc)
}

func (s *session) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// closeConns closes every spliced connection of the session and refuses new
// ones. It returns how many it closed.
func (s *session) closeConns() int {
	s.mu.Lock()
	s.connsClosed = true
	cs := make([]*spliceConn, 0, len(s.conns))
	for c := range s.conns {
		cs = append(cs, c)
	}
	s.mu.Unlock()
	for _, c := range cs {
		c.close()
	}
	return len(cs)
}

// spliceConn is one client connection spliced to one device connection.
type spliceConn struct {
	client, dev net.Conn
	cs, ds      *session
	once        sync.Once
}

func (c *spliceConn) close() {
	c.once.Do(func() {
		abort(c.client)
		abort(c.dev)
	})
}

// abort closes c abortively (RST) where the connection supports it (a
// SetLinger(0) on kernel sockets) and with a plain Close otherwise: the
// gVisor netstack connections only offer Close, which sends a FIN (or an RST
// if unread data is pending). Either way the peer's read fails or returns EOF.
func abort(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = l.SetLinger(0)
	}
	_ = c.Close()
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("hub: session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
