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
				h.finalize(old)
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
	switch {
	case len(h.byID) >= h.cfg.MaxSessions:
		return deny(api.ReasonSessionLimit, "hub session limit reached")
	case h.perNS[s.ns] >= h.cfg.MaxPerNamespace:
		return deny(api.ReasonSessionLimit, "teamspace session limit reached")
	}
	subjKey := s.subject + "|" + k.String()
	if s.kind == api.KindClient && h.perSubj[subjKey] >= h.cfg.MaxPerSubjectDevice {
		return deny(api.ReasonSessionLimit, "too many sessions for this device")
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
	h.perNS[s.ns]++
	if s.kind == api.KindDevice {
		h.devices[k] = s
	} else {
		m := h.clients[k]
		if m == nil {
			m = map[string]*session{}
			h.clients[k] = m
		}
		m[s.id] = s
		h.perSubj[subjKey]++
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
	h.perNS[s.ns]--
	if h.perNS[s.ns] <= 0 {
		delete(h.perNS, s.ns)
	}
	if s.kind == api.KindDevice {
		if h.devices[k] == s {
			delete(h.devices, k)
		}
	} else {
		if m := h.clients[k]; m != nil {
			delete(m, s.id)
			if len(m) == 0 {
				delete(h.clients, k)
			}
		}
		sk := s.subject + "|" + k.String()
		h.perSubj[sk]--
		if h.perSubj[sk] <= 0 {
			delete(h.perSubj, sk)
		}
	}
	h.met.sessions.WithLabelValues(s.kind).Dec()
}

// finalize closes the session's spliced connections, removes the peer
// (synchronously) and only then releases the address into quarantine.
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

// endSession removes a session completely. It reports whether this call ended
// it (false if it was already gone).
func (h *Hub) endSession(s *session, _ string) bool {
	h.mu.Lock()
	if s.ended {
		h.mu.Unlock()
		return false
	}
	h.detachLocked(s)
	h.mu.Unlock()
	h.finalize(s)
	return true
}

// endSessionGrace ends a session that asked for it (a denied renewal, a
// close) but keeps its WireGuard peer for a short grace period so the HTTP
// response can still reach the client. The session is unreachable at once: it
// is detached from every lookup and its spliced connections are closed; only
// the peer removal and the address release are delayed. It is also what the
// hub does for any session ended from inside its own tunnel.
func (h *Hub) endSessionGrace(s *session, grace time.Duration) bool {
	h.mu.Lock()
	if s.ended {
		h.mu.Unlock()
		return false
	}
	h.detachLocked(s)
	h.mu.Unlock()
	s.closeConns()
	time.AfterFunc(grace, func() { h.finalize(s) })
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
