package wgclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// DialError is a refusal the hub answered on a spliced connection of a
// delegating (web gateway) session, with one of the api.Reason* codes.
type DialError struct{ Reason string }

func (e *DialError) Error() string { return "hub refused the connection: " + e.Reason }

const defaultDialAsTimeout = 20 * time.Second

// DialAs opens a connection to the session's service on behalf of the end user
// as. It is for a delegating client session without an asserted user (software
// "web-gateway" with an empty OnBehalfOf): the hub then expects a one-line
// api.ConnectRequest on every spliced connection, authorizes the user named in
// it with a SubjectAccessReview and tells the dialer whether the device agreed
// before a single byte is relayed. A refusal is returned as *DialError. The
// connection is closed when the session ends.
func (s *Session) DialAs(ctx context.Context, as string) (net.Conn, error) {
	if s.opts.Kind != api.KindClient {
		return nil, errors.New("wgclient: DialAs needs a client session")
	}
	if as == "" {
		return nil, errors.New("wgclient: DialAs needs a user")
	}
	port := s.resp.SplicePort
	if port == 0 {
		port = api.HubSplicePort
	}
	c, err := s.tnet.DialContext(ctx, "tcp", net.JoinHostPort(api.HubAddress, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, s: s}
	if !s.track(tc) {
		_ = c.Close()
		return nil, ErrSessionClosed
	}
	// The handshake honours ctx: cancelling it unblocks the read.
	stop := context.AfterFunc(ctx, func() { _ = tc.SetDeadline(time.Unix(1, 0)) })
	timeout := defaultDialAsTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	wrapped, resp, err := connectproto.Handshake(tc, api.ConnectRequest{Service: s.resp.Service, As: as}, timeout)
	if !stop() && ctx.Err() != nil { // ctx ended during the handshake
		_ = tc.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("wgclient: connect handshake: %w", err)
	}
	if !resp.OK {
		_ = tc.Close()
		return nil, &DialError{Reason: sanitizeReason(resp.Reason)}
	}
	return wrapped, nil
}
