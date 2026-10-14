package p2p

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/turnbind"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// Timing of the punch.
const (
	// DefaultBudget is how long a Puncher keeps probing a peer.
	DefaultBudget = 20 * time.Second
	// FastProbe is the probe interval during the first FastPhase, SlowProbe afterwards.
	FastProbe = 150 * time.Millisecond
	SlowProbe = 500 * time.Millisecond
	FastPhase = 3 * time.Second
	// SessionFresh is how long after its handshake a WireGuard session counts as
	// established (a healthy one rekeys every 2 minutes).
	SessionFresh = 150 * time.Second
	// kickEvery rate-limits the keepalive nudges that start a handshake.
	kickEvery = time.Second
	// maxLearned bounds the addresses a peer may reveal by probing.
	maxLearned = 4
	// sentPings is how many of our own recent pings are remembered per peer;
	// a pong answers a ping at most pongWindow old.
	sentPings  = 32
	pongWindow = 10 * time.Second
	// seenNonces is the replay window of probe nonces per peer.
	seenNonces = 128
	// resetEvery rate-limits the session resets an initiator makes when the
	// responder reports that it lost its session.
	resetEvery = 3 * time.Second
	// maxTargets bounds the probe destinations per tick.
	maxTargets = api.MaxP2PCandidates + maxLearned
	// DefaultRemoveGrace keeps a removed peer installed for a moment, so that
	// the FIN/RST of the connections closed with it is still delivered.
	DefaultRemoveGrace = 250 * time.Millisecond
)

// PlaneConfig configures NewPlane.
type PlaneConfig struct {
	// Socket is the plane-B socket; the plane owns it from here on.
	Socket     *Socket
	PrivateKey wgkey.PrivateKey
	// Address is this side's plane-B /32.
	Address netip.Addr
	MTU     int
	Logger  *slog.Logger
	// ProbeInterval overrides FastProbe/SlowProbe (tests).
	ProbeInterval time.Duration
}

// PeerOptions configures AddPeer.
type PeerOptions struct {
	// Candidates are the peer's addresses to probe.
	Candidates []netip.AddrPort
	// Budget bounds the probing (default DefaultBudget).
	Budget time.Duration
	// Initiator makes this side the one that starts the WireGuard handshake
	// (the client). Both sides probe, but only the initiator sends handshake
	// initiations: simultaneous initiations cancel each other in WireGuard and
	// cost a RekeyTimeout (5 s) to resolve.
	Initiator bool
}

// PeerStatus is the state of one peer.
type PeerStatus struct {
	// Present is true while the peer is installed.
	Present bool
	// Established is true when a WireGuard handshake completed recently.
	Established   bool
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	// Path is api.PathDirectLAN or api.PathDirect when Established, else "".
	Path             string
	RxBytes, TxBytes uint64
}

// Plane is one plane-B WireGuard device on a netstack over a Socket.
type Plane struct {
	cfg  PlaneConfig
	log  *slog.Logger
	sock *Socket
	tnet *netstack.Net
	dev  *device.Device
	pub  wgkey.PublicKey
	priv wgkey.PrivateKey
	self netip.Addr
	id   keyID

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	peers  map[wgkey.PublicKey]*peer
	byID   map[keyID]*peer
	closed bool

	gatherMu   sync.Mutex
	stun       string
	gatherDone chan struct{}
	refreshing bool
}

type peer struct {
	pl      *Plane
	pub     wgkey.PublicKey
	hex     string
	id      keyID
	allowed netip.Addr
	key     [32]byte

	mu        sync.Mutex
	removing  bool
	gen       int
	initiate  bool
	lastReset time.Time
	seen      [seenNonces][probeNonceLen]byte
	seenN     int
	// sent are the pings we sent recently (a ring): a pong is believed only
	// for one of them (see acceptPong).
	sent     [sentPings]sentPing
	sentN    int
	cands    []netip.AddrPort
	learned  []netip.AddrPort
	endpoint netip.AddrPort
	lastKick time.Time
	stopPuns context.CancelFunc
}

// NewPlane brings up the plane-B WireGuard device on cfg.Socket.
func NewPlane(cfg PlaneConfig) (*Plane, error) {
	if cfg.Socket == nil {
		return nil, errors.New("p2p: a plane needs a socket")
	}
	if !ValidPlaneBAddr(cfg.Address) {
		return nil, fmt.Errorf("p2p: %s is not a plane-B address", cfg.Address)
	}
	if cfg.MTU == 0 {
		cfg.MTU = api.P2PMTU
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	pub, err := cfg.PrivateKey.Public()
	if err != nil {
		return nil, err
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address.Unmap()}, nil, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("p2p: creating netstack: %w", err)
	}
	log := cfg.Logger
	bind := turnbind.New(cfg.Socket.Conn())
	dev := device.NewDevice(tun, bind, &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Warn("wireguard (plane B)", "msg", fmt.Sprintf(f, a...)) },
	})
	if err := dev.IpcSet("private_key=" + cfg.PrivateKey.Hex() + "\n"); err != nil {
		dev.Close()
		return nil, fmt.Errorf("p2p: configuring WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("p2p: bringing WireGuard up: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pl := &Plane{
		cfg: cfg, log: log, sock: cfg.Socket, tnet: tnet, dev: dev,
		pub: pub, priv: cfg.PrivateKey, self: cfg.Address.Unmap(), id: idOf(pub),
		ctx: ctx, cancel: cancel,
		peers: map[wgkey.PublicKey]*peer{}, byID: map[keyID]*peer{},
	}
	cfg.Socket.Conn().SetProbeHandler(pl.onProbe)
	return pl, nil
}

// PublicKey is the plane-B public key.
func (pl *Plane) PublicKey() wgkey.PublicKey { return pl.pub }

// Address is the plane-B address.
func (pl *Plane) Address() netip.Addr { return pl.self }

// Socket returns the plane's socket.
func (pl *Plane) Socket() *Socket { return pl.sock }

// Close removes every peer, stops the device and closes the socket.
func (pl *Plane) Close() {
	pl.mu.Lock()
	if pl.closed {
		pl.mu.Unlock()
		return
	}
	pl.closed = true
	pl.mu.Unlock()
	pl.cancel()
	pl.wg.Wait()
	pl.sock.Conn().SetProbeHandler(nil)
	pl.dev.Close()
	_ = pl.sock.Close()
	pl.priv.Zero()
}

// StartGather gathers candidates in the background (host addresses at once,
// the server-reflexive address after the STUN round trip, bounded by timeout).
func (pl *Plane) StartGather(stunServer string, timeout time.Duration) {
	pl.gatherMu.Lock()
	defer pl.gatherMu.Unlock()
	if pl.gatherDone != nil {
		return
	}
	pl.stun = stunServer
	done := make(chan struct{})
	pl.gatherDone = done
	pl.wg.Add(1)
	go func() {
		defer pl.wg.Done()
		defer close(done)
		ctx, cancel := context.WithTimeout(pl.ctx, timeout)
		defer cancel()
		pl.sock.Gather(ctx, stunServer)
	}()
}

// Candidates returns the plane's candidates, waiting (bounded by ctx) for the
// first gather. A reflexive address older than 30 s is refreshed in the
// background for the next call.
func (pl *Plane) Candidates(ctx context.Context) []netip.AddrPort {
	pl.gatherMu.Lock()
	done, stun := pl.gatherDone, pl.stun
	pl.gatherMu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	if stun != "" {
		if at := pl.sock.GatheredAt(); !at.IsZero() && time.Since(at) > 30*time.Second {
			pl.refresh(stun)
		}
	}
	return pl.sock.Candidates()
}

func (pl *Plane) refresh(stun string) {
	pl.gatherMu.Lock()
	if pl.refreshing {
		pl.gatherMu.Unlock()
		return
	}
	pl.refreshing = true
	pl.gatherMu.Unlock()
	pl.wg.Add(1)
	go func() {
		defer pl.wg.Done()
		ctx, cancel := context.WithTimeout(pl.ctx, 2*time.Second)
		defer cancel()
		pl.sock.Gather(ctx, stun)
		pl.gatherMu.Lock()
		pl.refreshing = false
		pl.gatherMu.Unlock()
	}()
}

// AddPeer installs a peer whose only allowed address is allowed/32 and starts
// probing its candidates. Adding a peer that is installed (or being removed)
// refreshes its candidates and restarts the probing.
func (pl *Plane) AddPeer(pub wgkey.PublicKey, allowed netip.Addr, opts PeerOptions) error {
	allowed = allowed.Unmap()
	if !ValidPlaneBAddr(allowed) || allowed == pl.self {
		return fmt.Errorf("p2p: %s is not a usable peer address", allowed)
	}
	if pub == pl.pub {
		return errors.New("p2p: a peer cannot use this plane's own key")
	}
	key, err := pairKey(pl.priv, pl.pub, pub)
	if err != nil {
		return fmt.Errorf("p2p: peer key: %w", err)
	}
	pl.mu.Lock()
	if pl.closed {
		pl.mu.Unlock()
		return errors.New("p2p: plane closed")
	}
	p := pl.peers[pub]
	if p != nil && p.allowed != allowed {
		pl.mu.Unlock()
		return errors.New("p2p: peer exists with another address")
	}
	if p == nil {
		p = &peer{pl: pl, pub: pub, hex: pub.Hex(), id: idOf(pub), allowed: allowed, key: key}
		conf := "public_key=" + p.hex + "\nreplace_allowed_ips=true\nallowed_ip=" + allowed.String() + "/32\n"
		if err := pl.dev.IpcSet(conf); err != nil {
			pl.mu.Unlock()
			return fmt.Errorf("p2p: installing peer: %w", err)
		}
		pl.peers[pub], pl.byID[p.id] = p, p
	}
	pl.mu.Unlock()

	p.mu.Lock()
	p.removing = false
	p.gen++
	p.initiate = opts.Initiator
	p.cands = slicesClone(opts.Candidates)
	budget := opts.Budget
	p.mu.Unlock()
	if budget <= 0 {
		budget = DefaultBudget
	}
	pl.punch(p, budget)
	return nil
}

// Punch restarts the probing of an installed peer.
func (pl *Plane) Punch(pub wgkey.PublicKey, budget time.Duration) {
	pl.mu.Lock()
	p := pl.peers[pub]
	pl.mu.Unlock()
	if p == nil {
		return
	}
	if budget <= 0 {
		budget = DefaultBudget
	}
	pl.punch(p, budget)
}

// RemovePeer stops probing the peer at once and removes it after grace (0:
// immediately). Re-adding it within the grace period cancels the removal.
func (pl *Plane) RemovePeer(pub wgkey.PublicKey, grace time.Duration) {
	pl.mu.Lock()
	p := pl.peers[pub]
	pl.mu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	p.removing = true
	p.gen++
	gen := p.gen
	if p.stopPuns != nil {
		p.stopPuns()
		p.stopPuns = nil
	}
	p.mu.Unlock()
	if grace <= 0 {
		pl.finalize(p, gen)
		return
	}
	time.AfterFunc(grace, func() { pl.finalize(p, gen) })
}

func (pl *Plane) finalize(p *peer, gen int) {
	p.mu.Lock()
	if !p.removing || p.gen != gen {
		p.mu.Unlock()
		return
	}
	// Hold p.mu while removing so that no kick can recreate the peer.
	_ = pl.dev.IpcSet("public_key=" + p.hex + "\nremove=true\n")
	pl.mu.Lock()
	if pl.peers[p.pub] == p {
		delete(pl.peers, p.pub)
		delete(pl.byID, p.id)
	}
	pl.mu.Unlock()
	p.mu.Unlock()
}

// PeerCount is the number of installed peers (including those being removed).
func (pl *Plane) PeerCount() int {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return len(pl.peers)
}

// HasPeer reports whether the peer is installed and not being removed.
func (pl *Plane) HasPeer(pub wgkey.PublicKey) bool {
	pl.mu.Lock()
	p := pl.peers[pub]
	pl.mu.Unlock()
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.removing
}

// Status reports the state of one peer.
func (pl *Plane) Status(pub wgkey.PublicKey) PeerStatus {
	pl.mu.Lock()
	p := pl.peers[pub]
	pl.mu.Unlock()
	if p == nil {
		return PeerStatus{}
	}
	p.mu.Lock()
	removing := p.removing
	p.mu.Unlock()
	st := pl.peerInfo(p.hex)
	st.Present = !removing
	return st
}

// WaitEstablished waits until the peer has a fresh WireGuard session.
func (pl *Plane) WaitEstablished(ctx context.Context, pub wgkey.PublicKey) bool {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		if pl.Status(pub).Established {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-pl.ctx.Done():
			return false
		case <-t.C:
		}
	}
}

// DialContext dials through the plane-B netstack.
func (pl *Plane) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return pl.tnet.DialContext(ctx, network, addr)
}

// Listen listens on this side's plane-B address.
func (pl *Plane) Listen(port int) (net.Listener, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("p2p: port %d out of range", port)
	}
	return pl.tnet.ListenTCPAddrPort(netip.AddrPortFrom(pl.self, uint16(port)))
}

// peerInfo reads one peer's runtime state from the device.
func (pl *Plane) peerInfo(hexKey string) PeerStatus {
	out, err := pl.dev.IpcGet()
	if err != nil {
		return PeerStatus{}
	}
	return parsePeer(out, hexKey)
}

func parsePeer(dump, hexKey string) PeerStatus {
	var st PeerStatus
	var sec, nsec int64
	in := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			in = v == hexKey
			continue
		}
		if !in {
			continue
		}
		switch k {
		case "endpoint":
			if ap, err := netip.ParseAddrPort(v); err == nil {
				st.Endpoint = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	if sec > 0 {
		st.LastHandshake = time.Unix(sec, nsec)
		st.Established = time.Since(st.LastHandshake) < SessionFresh
	}
	if st.Established && st.Endpoint.IsValid() {
		st.Path = PathOf(st.Endpoint)
	}
	return st
}

// punch (re)starts the probe loop of p.
func (pl *Plane) punch(p *peer, budget time.Duration) {
	p.mu.Lock()
	if p.stopPuns != nil {
		p.stopPuns()
	}
	if p.removing {
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(pl.ctx)
	p.stopPuns = cancel
	p.mu.Unlock()
	pl.wg.Add(1)
	go func() {
		defer pl.wg.Done()
		pl.punchLoop(ctx, p, budget)
	}()
}

func (pl *Plane) punchLoop(ctx context.Context, p *peer, budget time.Duration) {
	start := time.Now()
	base := pl.cfg.ProbeInterval
	fast, slow := FastProbe, SlowProbe
	if base > 0 {
		fast, slow = base, base
	}
	// A handshake that completes after the loop started ends it.
	since := start.Add(-time.Second)
	for {
		st := pl.peerInfo(p.hex)
		if st.Established && !st.LastHandshake.Before(since) {
			pl.log.Debug("plane B path established", "path", st.Path, "endpoint", st.Endpoint.String())
			p.keepalive()
			return
		}
		elapsed := time.Since(start)
		if elapsed > budget {
			pl.log.Debug("plane B punching gave up", "after", elapsed.Round(time.Millisecond).String())
			return
		}
		p.sendPings(!st.Established)
		d := fast
		if elapsed > FastPhase {
			d = slow
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

// sendPings probes every known address of the peer once.
func (p *peer) sendPings(noSession bool) {
	p.mu.Lock()
	targets := make([]netip.AddrPort, 0, maxTargets)
	targets = append(targets, p.cands...)
	for _, l := range p.learned {
		if !containsAP(targets, l) {
			targets = append(targets, l)
		}
	}
	p.mu.Unlock()
	var flags byte
	if noSession {
		flags |= probeNoSession
	}
	pkt, err := buildProbe(p.key, p.pl.id, probePing, flags, nil)
	if err != nil {
		return
	}
	if len(targets) > 0 {
		var n [probeNonceLen]byte
		copy(n[:], pkt[14:14+probeNonceLen])
		p.mu.Lock()
		p.sent[p.sentN%sentPings] = sentPing{nonce: n, at: time.Now(), left: len(targets)}
		p.sentN++
		p.mu.Unlock()
	}
	for _, t := range targets {
		_, _ = p.pl.sock.Conn().WriteTo(pkt, net.UDPAddrFromAddrPort(t))
	}
}

// onProbe handles a probe datagram (called from the socket pump).
func (pl *Plane) onProbe(pkt []byte, from netip.AddrPort) {
	hdr, ok := parseProbeHeader(pkt)
	if !ok {
		return
	}
	pl.mu.Lock()
	p := pl.byID[hdr.sender]
	pl.mu.Unlock()
	if p == nil || !verifyProbe(p.key, pkt) {
		return
	}
	p.mu.Lock()
	removing := p.removing
	p.mu.Unlock()
	if removing {
		return
	}
	if p.replayed(hdr.nonce, hdr.typ) {
		return
	}
	if hdr.typ == probePong && !p.acceptPong(hdr.nonce, from) {
		return // not an answer to a ping of ours: replayed, forged source or late
	}
	established := pl.peerInfo(p.hex).Established
	if hdr.typ == probePing {
		var flags byte
		if !established {
			flags |= probeNoSession
		}
		if pong, err := buildProbe(p.key, pl.id, probePong, flags, &hdr.nonce); err == nil {
			_, _ = pl.sock.Conn().WriteTo(pong, net.UDPAddrFromAddrPort(from))
		}
	}
	p.learn(from, established, hdr.flags&probeNoSession != 0)
}

// replayed records a probe nonce and reports whether it was seen before.
// Pongs echo the nonce of our own ping, so only pings are checked.
func (p *peer) replayed(n [probeNonceLen]byte, typ byte) bool {
	if typ != probePing {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.seen {
		if s == n {
			return true
		}
	}
	p.seen[p.seenN%seenNonces] = n
	p.seenN++
	return false
}

// sentPing is one ping this side sent: its nonce, when, and how many answers it
// may still get (one per address it was sent to) from addresses not yet heard.
type sentPing struct {
	nonce [probeNonceLen]byte
	at    time.Time
	left  int
	from  []netip.AddrPort
}

// acceptPong reports whether a pong with nonce n from address from answers a
// recent ping of ours, and consumes that answer. A pong carries the nonce of
// the ping it answers; without this check anyone who captured one authenticated
// pong could replay it from any address, again and again, to move the
// WireGuard endpoint before the handshake and to push the genuine learned
// addresses out. The same ping may be answered by each address it was sent to
// (once each) and only within pongWindow.
func (p *peer) acceptPong(n [probeNonceLen]byte, from netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.sent {
		e := &p.sent[i]
		if e.left <= 0 || e.nonce != n {
			continue
		}
		if time.Since(e.at) > pongWindow || containsAP(e.from, from) {
			return false
		}
		e.left--
		e.from = append(e.from, from)
		return true
	}
	return false
}

// learn records an address the peer proved to be reachable at.
//
//   - Without a fresh session the WireGuard endpoint moves there; the
//     initiator also starts the handshake (a keepalive nudge).
//   - With a fresh session the path is left to WireGuard's roaming, except that
//     an initiator whose peer reports that it LOST its session (it was removed
//     and added again, for example) starts over: the responder cannot decrypt
//     the old session, and WireGuard alone would take 15 s to notice.
func (p *peer) learn(from netip.AddrPort, established, peerNoSession bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.removing {
		return
	}
	if !containsAP(p.learned, from) && !containsAP(p.cands, from) {
		if len(p.learned) >= maxLearned {
			p.learned = p.learned[1:]
		}
		p.learned = append(p.learned, from)
	}
	pl := p.pl
	if established {
		if peerNoSession && p.initiate && time.Since(p.lastReset) > resetEvery && p.endpoint == from {
			p.lastReset = time.Now()
			p.resetLocked(from)
		}
		return
	}
	if p.endpoint != from {
		conf := "public_key=" + p.hex + "\nupdate_only=true\nendpoint=" + from.String() + "\n"
		if err := pl.dev.IpcSet(conf); err != nil {
			pl.log.Debug("setting the plane B endpoint failed", "error", err.Error())
			return
		}
		p.endpoint = from
	}
	if p.initiate && time.Since(p.lastKick) >= kickEvery {
		p.lastKick = time.Now()
		p.kickLocked()
	}
}

// resetLocked replaces the WireGuard peer by a fresh one at endpoint ep and
// starts the handshake. p.mu must be held.
func (p *peer) resetLocked(ep netip.AddrPort) {
	pl := p.pl
	if err := pl.dev.IpcSet("public_key=" + p.hex + "\nremove=true\n"); err != nil {
		return
	}
	conf := "public_key=" + p.hex + "\nreplace_allowed_ips=true\nallowed_ip=" + p.allowed.String() + "/32\nendpoint=" + ep.String() + "\n"
	if err := pl.dev.IpcSet(conf); err != nil {
		pl.log.Warn("re-installing a plane B peer failed", "error", err.Error())
		return
	}
	p.endpoint = ep
	p.lastKick = time.Now()
	p.kickLocked()
}

// kickLocked makes WireGuard send a keepalive, and with no session a handshake
// initiation, right now: persistent keepalive is switched off and on again
// (wireguard-go sends one when it turns on). p.mu must be held so that a
// removal cannot interleave; update_only keeps a removed peer from coming back.
func (p *peer) kickLocked() {
	for _, secs := range []int{0, api.PersistentKeepalive} {
		conf := "public_key=" + p.hex + "\nupdate_only=true\npersistent_keepalive_interval=" + strconv.Itoa(secs) + "\n"
		if err := p.pl.dev.IpcSet(conf); err != nil {
			p.pl.log.Debug("nudging plane B failed", "error", err.Error())
			return
		}
	}
}

// keepalive turns persistent keepalive on once a session exists (the
// responder never nudged, so it has none yet); with a session this only
// sends a keepalive packet.
func (p *peer) keepalive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.removing {
		return
	}
	conf := "public_key=" + p.hex + "\nupdate_only=true\npersistent_keepalive_interval=" + strconv.Itoa(api.PersistentKeepalive) + "\n"
	_ = p.pl.dev.IpcSet(conf)
}

func containsAP(list []netip.AddrPort, ap netip.AddrPort) bool {
	for _, x := range list {
		if x == ap {
			return true
		}
	}
	return false
}

func slicesClone(in []netip.AddrPort) []netip.AddrPort {
	if in == nil {
		return nil
	}
	return append([]netip.AddrPort(nil), in...)
}
