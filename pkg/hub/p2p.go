package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Plane B on the hub (plans/ztna-phase2.md, "P2P-lite").
//
// The hub is the matchmaker and the authority, never a data path: it
//
//   - hands out plane-B addresses (the plane-A address with the plane-B
//     prefix, see p2p.AddrFor), so the plane-A IPAM and its quarantine cover
//     them;
//   - turns a client's offer into a Grant, pushes the device's FULL grant set
//     over the control RPC and returns the device's answer to the client;
//   - keeps the grants alive while the client renews, and takes them away at
//     once when the client session ends, the policy stops allowing it or the
//     service goes away. The device renewal response carries the full set as a
//     backstop for a push that was lost.
//
// Any plane-B failure leaves the hub splice untouched.

const (
	// maxP2PPairs bounds the plane-B pairs of one device (the agent refuses
	// more anyway).
	maxP2PPairs = 64
	// p2pPushTries and p2pPushWait bound the asynchronous retries of a push.
	p2pPushTries = 3
	p2pPushWait  = 200 * time.Millisecond
	maxAckBody   = 64 << 10
)

// clientP2P is the plane-B pair of one client session (guarded by session.mu).
type clientP2P struct {
	// dev is the device session the pair lives on; a new device session starts
	// without pairs.
	dev   *session
	cands []string
	addr  netip.Addr
	// lease is when the grant ends on the device unless the client renews; the
	// device counts the same TTL from receipt of each push.
	lease    time.Time
	lastPush time.Time
}

// validateOffer checks a client's offer: a valid key and at most
// api.MaxP2PCandidates parseable, usable addresses.
func validateOffer(o *api.P2POffer) (wgkey.PublicKey, []string, *denial) {
	key, err := wgkey.ParsePublic(o.WGPublicKey)
	if err != nil {
		return key, nil, deny(api.ReasonBadRequest, "invalid plane-B public key")
	}
	cands, err := p2p.ParseCandidates(o.Candidates)
	if err != nil {
		return key, nil, deny(api.ReasonBadRequest, "invalid plane-B candidates")
	}
	return key, p2p.Strings(cands), nil
}

// ClientPath returns the data path a client session last reported.
func (h *Hub) ClientPath(sessionID string) (string, bool) {
	h.mu.Lock()
	s := h.byID[sessionID]
	h.mu.Unlock()
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path, true
}

// P2PPairs returns the plane-B pairs the hub holds for a device (diagnostics
// and tests).
func (h *Hub) P2PPairs(ns, device string) []string {
	h.mu.Lock()
	clients := make([]*session, 0, len(h.clients[devKey{ns, device}]))
	for _, c := range h.clients[devKey{ns, device}] {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	var out []string
	for _, c := range clients {
		c.mu.Lock()
		if c.p2p != nil {
			out = append(out, c.id)
		}
		c.mu.Unlock()
	}
	slices.Sort(out)
	return out
}

// p2pUnavailable explains why a client's offer cannot be taken ("" if it can).
func (h *Hub) p2pUnavailable(s, dev *session, pol api.PolicyEntry) string {
	switch {
	case s.authKind != authKeycloak:
		return "plane B is for Keycloak users only"
	case s.direct:
		return "plane B is not for direct sessions"
	case s.service == "":
		return "plane B needs a named service"
	case !pol.P2P:
		return "the device opted out of plane B"
	case dev == nil:
		return "the device is offline"
	case !dev.hasCap(api.CapP2P) || dev.p2pKey == "":
		return "the agent has no plane B"
	case !dev.hasCap(api.CapControl):
		return "the agent has no control channel"
	case agentServiceDenial(s, dev) != nil:
		return "the agent has not applied the service definition yet"
	}
	return ""
}

// offerP2P tries to establish the plane-B pair of client session s with the
// device session dev and returns the grant for the client, or nil. It never
// fails the session: on any problem the client keeps the hub splice.
func (h *Hub) offerP2P(ctx context.Context, s, dev *session, pol api.PolicyEntry, pub wgkey.PublicKey, cands []string) *api.P2PGrant {
	if why := h.p2pUnavailable(s, dev, pol); why != "" {
		h.log.Info("plane B not offered", "reason", api.ReasonP2PUnavailable, "detail", why, "ns", s.ns, "device", s.device, "session", s.id)
		return nil
	}
	clientAddr, err := p2p.AddrFor(s.ip)
	if err != nil {
		return nil
	}
	devAddr, err := p2p.AddrFor(dev.ip)
	if err != nil {
		return nil
	}
	if h.p2pPairCount(dev) >= maxP2PPairs {
		h.log.Info("plane B not offered", "reason", api.ReasonP2PUnavailable, "detail", "pair limit", "ns", s.ns, "device", s.device)
		return nil
	}
	now := h.now()
	cp := &clientP2P{dev: dev, cands: cands, addr: clientAddr, lease: now.Add(h.cfg.P2PGrantTTL), lastPush: now}
	s.mu.Lock()
	s.wgKeyB, s.p2p = pub, cp
	s.mu.Unlock()

	ack, err := h.pushGrants(ctx, dev)
	// The device holds the pair if it says so, or if we cannot tell.
	deviceHasIt := err != nil || slices.Contains(ack.Accepted, s.id)
	accepted := err == nil && deviceHasIt
	if accepted {
		if why := h.checkAck(dev, devAddr, ack); why != "" {
			h.log.Warn("plane B answer refused", "detail", why, "ns", s.ns, "device", s.device, "session", s.id)
			accepted = false
		}
	}
	if !accepted {
		// Take the pair out again: the device may or may not have applied it.
		s.mu.Lock()
		if s.p2p == cp {
			s.p2p = nil
		}
		s.mu.Unlock()
		switch {
		case err != nil:
			h.log.Warn("plane B grant push failed", "ns", s.ns, "device", s.device, "session", s.id, "err", err)
		case !deviceHasIt:
			h.log.Info("plane B not accepted by the device", "reason", api.ReasonP2PUnavailable, "ns", s.ns, "device", s.device, "session", s.id)
		}
		if deviceHasIt {
			h.pushGrantsAsync(dev)
		}
		return nil
	}
	devCands, _ := p2p.ParseCandidates(ack.DeviceCandidates)
	h.log.Info("plane B granted", "ns", s.ns, "device", s.device, "session", s.id, "subject", s.subjectLabel(), "client_candidates", len(cands), "device_candidates", len(devCands))
	return &api.P2PGrant{
		PairID: s.id, ClientAddress: clientAddr.String(), DeviceAddress: devAddr.String(),
		DeviceWGPublicKey: dev.p2pKey, DeviceCandidates: p2p.Strings(devCands), TTLSeconds: int(h.cfg.P2PGrantTTL.Seconds()),
	}
}

// checkAck validates the device's answer. The hub knows the device's plane-B
// key (from the authenticated session request) and derives its address, so
// the ack is only a confirmation; its candidates are validated like any
// candidate list before they reach a client.
func (h *Hub) checkAck(dev *session, devAddr netip.Addr, ack api.GrantAck) string {
	switch {
	case ack.DeviceWGPublicKey == "":
		return "the agent has no plane B"
	case ack.DeviceWGPublicKey != dev.p2pKey:
		return "the plane-B key differs from the one in the session request"
	case ack.DeviceAddress != devAddr.String():
		return "the plane-B address differs from the derived one"
	}
	if _, err := p2p.ParseCandidates(ack.DeviceCandidates); err != nil {
		return err.Error()
	}
	return ""
}

func (h *Hub) p2pPairCount(dev *session) int {
	h.mu.Lock()
	clients := make([]*session, 0, len(h.clients[dev.key()]))
	for _, c := range h.clients[dev.key()] {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	n := 0
	for _, c := range clients {
		c.mu.Lock()
		if c.p2p != nil && c.p2p.dev == dev {
			n++
		}
		c.mu.Unlock()
	}
	return n
}

// buildGrantSet snapshots the device's pairs as the full desired set. The
// sequence number is taken in the same critical section as the snapshot.
func (h *Hub) buildGrantSet(dev *session) api.GrantSet {
	dev.gmu.Lock()
	defer dev.gmu.Unlock()
	dev.gseq++
	set := api.GrantSet{HubInstance: h.instance, Seq: dev.gseq, Grants: []api.Grant{}}
	h.mu.Lock()
	clients := make([]*session, 0, len(h.clients[dev.key()]))
	for _, c := range h.clients[dev.key()] {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	now := h.now()
	for _, c := range clients {
		c.mu.Lock()
		cp := c.p2p
		if cp != nil && cp.dev == dev {
			// The lease is relative: whatever is left of it, never more than
			// a full TTL. A lease that ran out (the client stopped renewing)
			// is not in the set, so the agent lets the pair go.
			if left := cp.lease.Sub(now); left > 0 {
				ttl := min(int((left+time.Second-1)/time.Second), int(h.cfg.P2PGrantTTL.Seconds()))
				set.Grants = append(set.Grants, api.Grant{
					PairID: c.id, ClientWGPublicKey: c.wgKeyB.Base64(), ClientAddress: cp.addr.String(),
					ClientCandidates: slices.Clone(cp.cands), Services: []string{c.service}, TTLSeconds: max(ttl, 1),
				})
			}
		}
		c.mu.Unlock()
	}
	slices.SortFunc(set.Grants, func(a, b api.Grant) int {
		switch {
		case a.PairID < b.PairID:
			return -1
		case a.PairID > b.PairID:
			return 1
		}
		return 0
	})
	return set
}

var errStaleSet = errors.New("the agent holds a newer grant set")

// pushGrants pushes the device's current grant set and returns the agent's
// answer. A set the agent rejects as stale (a newer one overtook it) is
// rebuilt and pushed again, so the answer always reflects a set that was built
// after the caller changed the membership.
func (h *Hub) pushGrants(ctx context.Context, dev *session) (api.GrantAck, error) {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.P2PPushTimeout)
	defer cancel()
	var last error
	for range 3 {
		set := h.buildGrantSet(dev)
		ack, err := h.postGrants(ctx, dev, set)
		if err == nil {
			return ack, nil
		}
		last = err
		if !errors.Is(err, errStaleSet) {
			break
		}
	}
	return api.GrantAck{}, last
}

// pushGrantsAsync converges the device on the current set in the background
// (revocation, lease refresh, cleanup after a failed offer). It retries a few
// times; the lease on the agent bounds the damage of a device that cannot be
// reached.
func (h *Hub) pushGrantsAsync(dev *session) {
	if dev == nil || h.ctx.Err() != nil {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		var err error
		for attempt := range p2pPushTries {
			if attempt > 0 {
				select {
				case <-h.ctx.Done():
					return
				case <-time.After(p2pPushWait * time.Duration(attempt)):
				}
			}
			// A device session that is no longer the registered one is over:
			// its agent dropped every pair with it, and its overlay address
			// may belong to another device soon. Never push to it.
			if h.deviceSession(dev.ns, dev.device) != dev {
				return
			}
			if _, err = h.pushGrants(h.ctx, dev); err == nil {
				return
			}
		}
		h.log.Warn("pushing the grant set failed; the lease on the agent bounds the pairs", "ns", dev.ns, "device", dev.device, "err", err)
	}()
}

func (h *Hub) postGrants(ctx context.Context, dev *session, set api.GrantSet) (api.GrantAck, error) {
	body, err := json.Marshal(set)
	if err != nil {
		return api.GrantAck{}, err
	}
	addr := netip.AddrPortFrom(dev.ip, api.AgentControlPort)
	cl := &http.Client{
		Timeout: h.cfg.P2PPushTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return h.tunnel.DialContext(ctx, addr)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr.String()+api.ControlGrantsPath, bytes.NewReader(body))
	if err != nil {
		return api.GrantAck{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return api.GrantAck{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return api.GrantAck{}, errStaleSet
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return api.GrantAck{}, fmt.Errorf("agent answered %d", resp.StatusCode)
	}
	var ack api.GrantAck
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAckBody)).Decode(&ack); err != nil {
		return api.GrantAck{}, fmt.Errorf("unreadable grant ack: %w", err)
	}
	return ack, nil
}

// p2pClientGone takes a finished client session's pair out of the device's
// grant set at once. endSession calls it for every client session that ends,
// whatever the reason (close, expiry, revocation, policy change).
func (h *Hub) p2pClientGone(s *session) {
	if s.kind != api.KindClient {
		return
	}
	s.mu.Lock()
	cp := s.p2p
	s.p2p = nil
	s.mu.Unlock()
	if cp != nil {
		h.pushGrantsAsync(cp.dev)
	}
}

// p2pDeviceGone forgets the plane-B pairs bound to a device session that ended
// or was replaced: the agent drops every pair with its session, and a new
// session starts without any, so the pairs of the old one are dead.
//
// When the hub ends the session (revocation, expiry), one empty set still goes
// to the agent while its peer stays installed for the flush grace, so that
// direct clients are cut at once instead of when the agent notices. A session
// that was replaced by the same agent's new one gets no push at all: its peer
// is gone and its overlay address may belong to another device after the
// quarantine.
func (h *Hub) p2pDeviceGone(dev *session, replaced bool) {
	if dev == nil || dev.kind != api.KindDevice {
		return
	}
	h.mu.Lock()
	clients := make([]*session, 0, len(h.clients[dev.key()]))
	for _, c := range h.clients[dev.key()] {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	had := false
	for _, c := range clients {
		c.mu.Lock()
		if c.p2p != nil && c.p2p.dev == dev {
			c.p2p, had = nil, true
		}
		c.mu.Unlock()
	}
	if had && !replaced && h.ctx.Err() == nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			ctx, cancel := context.WithTimeout(h.ctx, h.cfg.P2PPushTimeout)
			defer cancel()
			_, _ = h.pushGrants(ctx, dev) // best effort: the lease on the agent bounds the rest
		}()
	}
}

// p2pRenewed records a client's renewal: the path it reports and, once half of
// the grant's lifetime has passed, a fresh push that restarts the TTL on the
// device (the lease is extended only here, never by the device's renewals).
func (h *Hub) p2pRenewed(s *session, path string) {
	now := h.now()
	var refresh *session
	s.mu.Lock()
	switch path {
	case api.PathDirectLAN, api.PathDirect, api.PathHub:
		s.path = path
	}
	if cp := s.p2p; cp != nil {
		if h.deviceSession(cp.dev.ns, cp.dev.device) != cp.dev {
			s.p2p = nil // the device session it lived on is gone: nothing to refresh
		} else if cp.lease = now.Add(h.cfg.P2PGrantTTL); now.Sub(cp.lastPush) >= h.cfg.P2PGrantTTL/2 {
			cp.lastPush = now
			refresh = cp.dev
		}
	}
	s.mu.Unlock()
	if refresh != nil {
		h.pushGrantsAsync(refresh)
	}
}

// syncP2P drops the plane-B pairs of a device whose policy no longer allows
// plane B, or whose live agent lost the capability.
func (h *Hub) syncP2P(k devKey, pol api.PolicyEntry, live *session, clients []*session) {
	if live == nil {
		return
	}
	allowed := pol.P2P && live.hasCap(api.CapP2P)
	changed := false
	for _, c := range clients {
		c.mu.Lock()
		if c.p2p != nil && (!allowed || c.p2p.dev != live) {
			c.p2p = nil
			changed = true
		}
		c.mu.Unlock()
	}
	if changed {
		h.log.Info("plane B pairs dropped by a policy change", "ns", k.ns, "device", k.device)
		h.pushGrantsAsync(live)
	}
}

// revokeNoticeTimeout bounds the notice to an agent about the end of its
// session (the peer is held that long at most).
const revokeNoticeTimeout = time.Second

// sendRevokeNotice tells the agent of dev about the end of its session over
// the control listener, the way pushGrants reaches it. Best effort: the
// outcome is logged at debug and never changes the revocation.
func (h *Hub) sendRevokeNotice(dev *session, n api.RevokeNotice) {
	ctx, cancel := context.WithTimeout(h.ctx, revokeNoticeTimeout)
	defer cancel()
	err := h.postRevoke(ctx, dev, n)
	if err != nil {
		h.log.Debug("revoke notice not delivered", "ns", dev.ns, "device", dev.device, "session", dev.id, "reason", n.Reason, "err", err)
		return
	}
	h.log.Debug("revoke notice delivered", "ns", dev.ns, "device", dev.device, "session", dev.id, "reason", n.Reason)
}

func (h *Hub) postRevoke(ctx context.Context, dev *session, n api.RevokeNotice) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	addr := netip.AddrPortFrom(dev.ip, api.AgentControlPort)
	cl := &http.Client{
		Timeout: revokeNoticeTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return h.tunnel.DialContext(ctx, addr)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr.String()+api.ControlRevokePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent answered %d", resp.StatusCode)
	}
	return nil
}
