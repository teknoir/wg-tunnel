package hub

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teknoir/wg-tunnel/internal/connectproto"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// serveSplice accepts client connections on the overlay and splices them.
func (h *Hub) serveSplice(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.handleSplice(ctx, c)
		}()
	}
}

// handleSplice authorizes one client connection and, if allowed, splices it
// to the device. Every connection is re-checked: session identity, device
// state, the user's access (cached SAR), the live device session and the port.
func (h *Hub) handleSplice(ctx context.Context, c net.Conn) {
	d := &dctx{op: "connect", kind: api.KindClient, remote: remoteIP(c.RemoteAddr().String())}
	// replyDenied: a perConn client reads a ConnectResponse line, so it learns
	// why it was refused (the web gateway maps the reason to an HTTP status).
	replyDenied := false
	closeDenied := func(reason, detail string) {
		h.logDecision(d, "deny", reason, detail)
		if replyDenied {
			writeReply(c, api.ConnectResponse{Reason: reason})
		}
		_ = c.Close()
	}
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		closeDenied(api.ReasonSessionUnknown, "bad remote address")
		return
	}
	s := h.sessionByAddr(ap.Addr())
	if s == nil {
		closeDenied(api.ReasonSessionUnknown, "no session for this address")
		return
	}
	d.ns, d.device, d.subject, d.session, d.service = s.ns, s.device, s.subjectLabel(), s.id, s.service
	if s.kind != api.KindClient {
		d.kind = s.kind
		closeDenied(api.ReasonForbidden, "only client sessions may connect")
		return
	}
	// subject is the user this connection acts for: the session's own user, or
	// (perConn) the one named in the preamble, who is authorized per connection.
	subject, client := s.subject, net.Conn(c)
	replyDenied = s.perConn
	if !h.now().Before(s.expiry()) {
		closeDenied(api.ReasonSessionUnknown, "session expired")
		return
	}
	if s.perConn {
		var den *denial
		if subject, client, den = h.readPreamble(c, s); den != nil {
			closeDenied(den.reason, den.msg)
			return
		}
		d.subject = subject + " via " + s.subjectLabel()
	}

	eff := computeEffective(h.deps.Policy, h.deps.Flags, s.ns, s.device)
	if !eff.Active {
		closeDenied(eff.Reason, eff.Detail)
		return
	}
	if den := serviceDenial(s, eff.Policy, false, false); den != nil {
		closeDenied(den.reason, den.msg)
		return
	}
	// The connection cap is enforced before any slow work: a reserved slot is
	// held while authorizing and dialling, so a burst of attempts cannot
	// exceed MaxConnsPerSession in flight.
	if err := s.reserveConn(h.cfg.MaxConnsPerSession); err != nil {
		closeDenied(api.ReasonSessionLimit, "too many concurrent connections")
		return
	}
	reserved := true
	defer func() {
		if reserved {
			s.unreserveConn()
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, h.cfg.DialTimeout)
	defer cancel()
	allowed, err := h.deps.Authz.CanExec(cctx, subject, s.ns)
	if err != nil {
		h.log.Error("authorization check failed", "ns", s.ns, "err", err)
		closeDenied(api.ReasonInternal, "authorization backend unavailable")
		return
	}
	if !allowed {
		closeDenied(api.ReasonForbidden, "no access to this teamspace")
		return
	}
	dev := h.deviceSession(s.ns, s.device)
	if dev == nil {
		closeDenied(api.ReasonDeviceOffline, "device has no live tunnel")
		return
	}
	if den := serviceDenial(s, eff.Policy, true, dev.hasCap(api.CapServices)); den != nil {
		closeDenied(den.reason, den.msg)
		return
	}
	dc, den := h.dialAgent(cctx, s, dev, subject)
	if den != nil {
		closeDenied(den.reason, den.msg)
		return
	}
	sc := &spliceConn{client: client, dev: dc, cs: s, ds: dev}
	if s.perConn {
		sc.as = subject
	}
	reserved = false
	if err := s.commitConn(sc); err != nil {
		_ = dc.Close()
		closeDenied(api.ReasonSessionLimit, "session ended")
		return
	}
	if err := dev.addConn(sc); err != nil {
		s.removeConn(sc)
		_ = dc.Close()
		closeDenied(api.ReasonDeviceOffline, "device session ended")
		return
	}
	// A revocation between the checks and the registration must not leave the
	// stream open: the flags are read again now that the connection is tracked.
	if again := computeEffective(h.deps.Policy, h.deps.Flags, s.ns, s.device); !again.Active {
		sc.close()
		s.removeConn(sc)
		dev.removeConn(sc)
		h.logDecision(d, "deny", again.Reason, again.Detail)
		return
	}
	if s.perConn {
		if err := writeReplyErr(client, api.ConnectResponse{OK: true}); err != nil {
			sc.close()
			s.removeConn(sc)
			dev.removeConn(sc)
			h.logDecision(d, "deny", api.ReasonDeviceOffline, "client went away")
			return
		}
	}
	h.logDecision(d, "allow", "ok", "")
	h.met.conns.Inc()
	h.met.connsTotal.Inc()
	h.pipe(sc)
	h.met.conns.Dec()
	s.removeConn(sc)
	dev.removeConn(sc)
}

// agentRefusals are the reasons a connect listener may answer with.
var agentRefusals = []string{api.ReasonServiceUnknown, api.ReasonServiceDenied, api.ReasonSessionLimit, api.ReasonBadRequest, api.ReasonInternal}

type closeWriter interface{ CloseWrite() error }

// pipe copies in both directions with half-close and returns when both
// directions are finished or the connection was closed.
func (h *Hub) pipe(sc *spliceConn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, dir string, counter *atomic.Int64) {
		defer wg.Done()
		n, err := io.Copy(countingWriter{dst, counter}, src)
		h.met.bytes.WithLabelValues(dir).Add(float64(n))
		if err != nil {
			sc.close()
			return
		}
		if cw, ok := dst.(closeWriter); !ok || cw.CloseWrite() != nil {
			sc.close() // no half-close on this connection: end both directions
		}
	}
	wg.Add(2)
	go cp(sc.dev, sc.client, "client_to_device", &sc.cs.bytesIn)
	go cp(sc.client, sc.dev, "device_to_client", &sc.cs.bytesOut)
	wg.Wait()
	sc.close()
}

// dialAgent opens the stream to the device for one client connection.
//
//   - A legacy raw port, and ssh towards a phase-1 agent, dial that port on the
//     agent's overlay address (the agent forwards it to the local host).
//   - Everything else dials the agent's connect port and speaks the preamble:
//     the agent resolves the service itself, validates the target and answers
//     before a single byte is relayed. For a session delegated by a service
//     account the end user's email travels as ConnectRequest.As (the agent only
//     logs it; the SubjectAccessReview for that user ran just before).
func (h *Hub) dialAgent(ctx context.Context, s, dev *session, as string) (net.Conn, *denial) {
	port := s.targetPort
	viaConnect := s.service != "" && dev.hasCap(api.CapServices)
	if viaConnect {
		port = api.AgentConnectPort
	}
	dc, err := h.tunnel.DialContext(ctx, netip.AddrPortFrom(dev.ip, uint16(port)))
	if err != nil {
		return nil, deny(api.ReasonDeviceOffline, "dialing the device failed")
	}
	if !viaConnect {
		return dc, nil
	}
	req := api.ConnectRequest{Service: s.service}
	if s.authKind == authSA {
		req.As = as
	}
	wrapped, resp, err := connectproto.Handshake(dc, req, h.cfg.DialTimeout)
	if err != nil {
		_ = dc.Close()
		return nil, deny(api.ReasonDeviceOffline, "the device agent did not answer")
	}
	if !resp.OK {
		_ = dc.Close()
		// The reason is a metric label and a log field: never an arbitrary
		// string from the device.
		reason := resp.Reason
		if !slices.Contains(agentRefusals, reason) {
			reason = api.ReasonInternal
		}
		return nil, deny(reason, "the device agent refused the connection")
	}
	return wrapped, nil
}

// countingWriter adds the bytes written to a live counter (status).
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// readPreamble reads the ConnectRequest line a perConn client writes first:
// the service must be the session's own and As a syntactically valid email.
// It returns the user and the client connection to splice (reads go through the
// preamble's buffer, so bytes sent right behind the line are not lost).
func (h *Hub) readPreamble(c net.Conn, s *session) (string, net.Conn, *denial) {
	_ = c.SetReadDeadline(time.Now().Add(h.cfg.DialTimeout))
	br := connectproto.NewReader(c)
	req, err := connectproto.ReadRequest(br)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return "", nil, deny(api.ReasonBadRequest, "missing or malformed connect line")
	}
	if req.Service != s.service {
		return "", nil, deny(api.ReasonBadRequest, "connect line names another service")
	}
	if !ValidEmail(req.As) {
		return "", nil, deny(api.ReasonBadRequest, "connect line needs a lowercase email in as")
	}
	return req.As, connectproto.Wrap(c, br), nil
}

const replyTimeout = 2 * time.Second

// writeReply sends a ConnectResponse to a perConn client, best effort.
func writeReply(c net.Conn, resp api.ConnectResponse) { _ = writeReplyErr(c, resp) }

func writeReplyErr(c net.Conn, resp api.ConnectResponse) error {
	_ = c.SetWriteDeadline(time.Now().Add(replyTimeout))
	defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	return connectproto.WriteResponse(c, resp)
}
