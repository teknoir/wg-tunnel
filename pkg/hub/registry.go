package hub

import (
	"net/netip"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// admit allocates an address, installs the peer and registers s, enforcing
// the limits. For a device session it first ends the device's previous session
// (removing the old peer and closing its spliced connections). The caller
// must have authenticated and authorized s; admit never trusts anything else.
func (h *Hub) admit(s *session) *denial {
	k := s.key()
	for {
		h.mu.Lock()
		if s.kind == api.KindDevice {
			if old := h.devices[k]; old != nil {
				h.detachLocked(old)
				h.mu.Unlock()
				h.p2pDeviceGone(old, true)
				h.teardown(old, h.cfg.FlushGrace)
				h.logEnd(old, "replace", "replaced")
				continue
			}
		}
		d := h.admitLocked(s)
		h.mu.Unlock()
		return d
	}
}

func (h *Hub) admitLocked(s *session) *denial {
	k := s.key()
	subjKey := s.limitKey() + "|" + k.String()
	if s.kind == api.KindClient {
		// Quotas protect against client sessions only. A device holds exactly
		// one session of its own, so clients can never fill the teamspace and
		// lock the devices out.
		perDev, perAll := h.cfg.MaxPerSubjectDevice, h.cfg.MaxPerSubject
		if s.perConn { // the web gateway keeps one session per web service
			perDev, perAll = max(perDev, api.MaxServices), max(perAll, api.MaxServices)
		}
		switch {
		case len(h.byID) >= h.cfg.MaxSessions:
			return deny(api.ReasonSessionLimit, "hub session limit reached")
		case h.perNS[s.ns] >= h.cfg.MaxPerNamespace:
			return deny(api.ReasonSessionLimit, "teamspace session limit reached")
		case h.perSubj[subjKey] >= perDev:
			return deny(api.ReasonSessionLimit, "too many sessions for this device")
		case h.perSubjAll[s.limitKey()] >= perAll:
			return deny(api.ReasonSessionLimit, "too many sessions for this user")
		}
	} else if len(h.byID) >= 2*h.cfg.MaxSessions {
		// Devices have headroom of their own on top of the client limit.
		return deny(api.ReasonSessionLimit, "hub session limit reached")
	}
	if _, dup := h.byWG[s.wgKey]; dup || s.wgKey == h.tunnel.PublicKey() {
		return deny(api.ReasonBadRequest, "WireGuard key already in use")
	}
	ip, err := h.ipam.Alloc()
	if err != nil {
		return deny(api.ReasonSessionLimit, "address pool exhausted")
	}
	if err := h.tunnel.AddPeer(s.wgKey, ip); err != nil {
		h.ipam.Free(ip)
		h.log.Error("adding peer failed", "err", err)
		return deny(api.ReasonInternal, "could not install tunnel peer")
	}
	s.ip = ip
	h.byID[s.id] = s
	h.byIP[ip] = s
	h.byWG[s.wgKey] = s
	if s.kind == api.KindDevice {
		h.devices[k] = s
	} else {
		h.perNS[s.ns]++
		m := h.clients[k]
		if m == nil {
			m = map[string]*session{}
			h.clients[k] = m
		}
		m[s.id] = s
		h.perSubj[subjKey]++
		h.perSubjAll[s.limitKey()]++
	}
	h.met.sessions.WithLabelValues(s.kind).Inc()
	h.met.creates.WithLabelValues(s.kind).Inc()
	return nil
}

// detachLocked removes s from every lookup so that no new request can find
// it. The peer is still installed and the address still reserved until
// finalize runs.
func (h *Hub) detachLocked(s *session) {
	if s.ended {
		return
	}
	s.ended = true
	k := s.key()
	delete(h.byID, s.id)
	delete(h.byIP, s.ip)
	if s.kind == api.KindDevice {
		if h.devices[k] == s {
			delete(h.devices, k)
		}
	} else {
		h.perNS[s.ns]--
		if h.perNS[s.ns] <= 0 {
			delete(h.perNS, s.ns)
		}
		if m := h.clients[k]; m != nil {
			delete(m, s.id)
			if len(m) == 0 {
				delete(h.clients, k)
			}
		}
		sk := s.limitKey() + "|" + k.String()
		h.perSubj[sk]--
		if h.perSubj[sk] <= 0 {
			delete(h.perSubj, sk)
		}
		h.perSubjAll[s.limitKey()]--
		if h.perSubjAll[s.limitKey()] <= 0 {
			delete(h.perSubjAll, s.limitKey())
		}
	}
	h.met.sessions.WithLabelValues(s.kind).Dec()
}

// teardown is the one path of every hub-initiated end of a session; s must
// already be detached. In this order:
//  1. no new connection or renewal can reach s (detach, done by the caller);
//  2. every spliced connection on both sides is closed, abortively where the
//     connection allows it, so the FIN/RST travels through the still
//     installed peers to the client and the device;
//  3. the peers stay for the flush grace so that those segments are
//     delivered; only then is the peer removed (synchronously) and the
//     address released to quarantine (finalize).
//
// Removing the peer first would drop the FIN/RST and leave the client's
// connection hanging until its renewal fails.
func (h *Hub) teardown(s *session, grace time.Duration) {
	h.teardownAfter(s, grace, nil)
}

// teardownAfter is teardown that also holds the peer until hold is closed (at
// the latest revokeNoticeTimeout after it was started, see noticeRevoke), so a
// message to the device still travels through the installed peer.
func (h *Hub) teardownAfter(s *session, grace time.Duration, hold <-chan struct{}) {
	s.closeConns()
	if grace <= 0 && hold == nil {
		h.finalize(s)
		return
	}
	time.AfterFunc(max(grace, 0), func() {
		if hold != nil {
			<-hold
		}
		h.finalize(s)
	})
}

// finalize removes the peer (synchronously) and only then releases the
// address into quarantine. It is idempotent.
func (h *Hub) finalize(s *session) {
	s.final.Do(func() { h.finalizeOnce(s) })
}

func (h *Hub) finalizeOnce(s *session) {
	s.closeConns()
	err := h.tunnel.RemovePeer(s.wgKey)
	h.mu.Lock()
	delete(h.byWG, s.wgKey)
	h.mu.Unlock()
	if err != nil {
		// Keep the address reserved: the peer may still own it.
		h.log.Error("removing peer failed; address stays reserved", "session", s.id, "err", err)
		return
	}
	h.ipam.Release(s.ip)
	h.limiterForget(s)
}

func (h *Hub) limiterForget(s *session) { h.renewLimit.Forget(s.id) }

// endSession ends a session on the hub's initiative (policy or flag change,
// device replacement, max age, reaper). The session is unreachable at once and
// its spliced connections are closed at once; the peer follows after the
// flush grace (see teardown). It reports whether this call ended the session
// (false if it was already gone).
func (h *Hub) endSession(s *session, _ string) bool {
	return h.endSessionGrace(s, h.cfg.FlushGrace)
}

// endSessionGrace is endSession with an explicit grace period; a session that
// asked for its own end (a denied renewal, a close) uses it to keep the peer
// long enough for the HTTP response to be delivered.
func (h *Hub) endSessionGrace(s *session, grace time.Duration) bool {
	return h.endSessionNotice(s, grace, nil)
}

// noticeReasons are the revocation reasons that are wire reasons the agent acts
// on (log-only reasons such as ports_changed end the session without a notice:
// the agent finds out by itself and reconnects with the new set).
var noticeReasons = map[string]bool{
	api.ReasonReenroll:        true,
	api.ReasonDeviceRevoked:   true,
	api.ReasonDeviceDisabled:  true,
	api.ReasonDeviceUnknown:   true,
	api.ReasonPendingApproval: true,
}

// endDeviceRevoked ends a device session because the hub revoked it (enrollment
// reset, flag, disabled, voided identity, identity approval withdrawn). Unlike
// endSession it first tells an agent that can take it (CapControl) with an
// api.RevokeNotice, so the agent acts at once instead of when a renewal fails.
func (h *Hub) endDeviceRevoked(dev *session, reason, detail string) bool {
	var n *api.RevokeNotice
	if dev.kind == api.KindDevice && dev.hasCap(api.CapControl) && noticeReasons[reason] {
		n = &api.RevokeNotice{Reason: reason, SessionID: dev.id, Detail: detail}
	}
	return h.endSessionNotice(dev, h.cfg.FlushGrace, n)
}

// endSessionNotice is endSessionGrace that, with a notice, also tells the
// device about the end. The session is detached first (unreachable at once,
// spliced connections closed), the notice goes out concurrently, and the peer
// is removed only after both the grace and the notice's attempt (answered,
// failed or timed out after revokeNoticeTimeout) are over. Revocation neither
// waits for nor depends on the notice: only the peer removal is held back, by
// at most revokeNoticeTimeout.
func (h *Hub) endSessionNotice(s *session, grace time.Duration, n *api.RevokeNotice) bool {
	h.mu.Lock()
	if s.ended {
		h.mu.Unlock()
		return false
	}
	h.detachLocked(s)
	h.mu.Unlock()
	h.p2pClientGone(s)
	h.p2pDeviceGone(s, false)
	var hold chan struct{}
	if n != nil && h.ctx.Err() == nil {
		hold = make(chan struct{})
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer close(hold)
			h.sendRevokeNotice(s, *n)
		}()
	}
	h.teardownAfter(s, grace, hold)
	return true
}

// sessionByAddr maps the remote address of an in-tunnel connection to its session.
func (h *Hub) sessionByAddr(ip netip.Addr) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byIP[ip.Unmap()]
}

// deviceSession returns the live device session of a device.
func (h *Hub) deviceSession(ns, device string) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.devices[devKey{ns, device}]
}
