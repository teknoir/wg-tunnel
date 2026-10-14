package wgclient

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

func testSession(kind, service string) *Session {
	return &Session{
		opts: Options{Kind: kind},
		resp: api.SessionResponse{Kind: kind, Service: service, Address: "100.96.0.7"},
		log:  Options{}.logger(),
	}
}

func TestCheckGrant(t *testing.T) {
	_, own, _ := wgkey.Generate()
	_, dev, _ := wgkey.Generate()
	pp := &p2pPrep{pub: own}
	resp := api.SessionResponse{Address: "100.96.0.7"}
	good := func() *api.P2PGrant {
		return &api.P2PGrant{
			PairID: "pair-1", ClientAddress: "100.97.0.7", DeviceAddress: "100.97.0.2", DeviceWGPublicKey: dev.Base64(),
			DeviceCandidates: []string{"192.168.1.5:41000"}, TTLSeconds: 90,
		}
	}
	s := testSession(api.KindClient, "ssh")
	if err := s.checkGrant(pp, resp, good()); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}
	for name, mut := range map[string]func(*api.P2PGrant){
		"no pair id":           func(g *api.P2PGrant) { g.PairID = "" },
		"long pair id":         func(g *api.P2PGrant) { g.PairID = strings.Repeat("x", 65) },
		"someone else's addr":  func(g *api.P2PGrant) { g.ClientAddress = "100.97.0.99" },
		"no lifetime":          func(g *api.P2PGrant) { g.TTLSeconds = 0 },
		"plane A device addr":  func(g *api.P2PGrant) { g.DeviceAddress = "100.96.0.2" },
		"device is the client": func(g *api.P2PGrant) { g.DeviceAddress = g.ClientAddress },
		"junk device addr":     func(g *api.P2PGrant) { g.DeviceAddress = "device" },
		"bad device key":       func(g *api.P2PGrant) { g.DeviceWGPublicKey = "nope" },
		"our own key":          func(g *api.P2PGrant) { g.DeviceWGPublicKey = own.Base64() },
		"multicast candidate":  func(g *api.P2PGrant) { g.DeviceCandidates = []string{"224.0.0.1:5"} },
		"unspecified":          func(g *api.P2PGrant) { g.DeviceCandidates = []string{"0.0.0.0:5"} },
	} {
		g := good()
		mut(g)
		if err := s.checkGrant(pp, resp, g); err == nil {
			t.Errorf("%s: grant accepted", name)
		}
	}
	// A bad overlay address in the session response cannot be mapped either.
	if err := s.checkGrant(pp, api.SessionResponse{Address: "10.1.2.3"}, good()); err == nil {
		t.Error("grant accepted for a session address outside the overlay")
	}
}

func TestDialServiceValidation(t *testing.T) {
	dev := testSession(api.KindDevice, "")
	if _, err := dev.DialService(context.Background(), ""); err == nil {
		t.Error("a device session can dial")
	}
	named := testSession(api.KindClient, "web")
	if _, err := named.DialService(context.Background(), "ssh"); err == nil || !strings.Contains(err.Error(), `"web"`) {
		t.Errorf("another service accepted or unhelpful error: %v", err)
	}
	raw := testSession(api.KindClient, "")
	if _, err := raw.DialService(context.Background(), "web"); err == nil {
		t.Error("a named service on a raw-port session")
	}
}

func TestPathWithoutPlaneBIsHub(t *testing.T) {
	if p := testSession(api.KindClient, "ssh").Path(); p != api.PathHub {
		t.Fatalf("path %q", p)
	}
	if p := testSession(api.KindDevice, "").Path(); p != "" {
		t.Fatalf("a device session reports path %q", p)
	}
	if st := testSession(api.KindClient, "ssh").P2PStatus(); st.Enabled || st.Established {
		t.Fatalf("status %+v", st)
	}
}

func TestPrepareP2P(t *testing.T) {
	ctx := context.Background()
	stunSrv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stunSrv.Close()
	go p2p.ServeSTUN(stunSrv)
	fakeIfaces := func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.4.4")}, nil }
	base := Options{Kind: api.KindClient, P2P: true, P2PInterfaces: fakeIfaces, HubURL: "https://hub.example.com"}

	for name, o := range map[string]Options{
		"p2p off":        {Kind: api.KindClient, P2PInterfaces: fakeIfaces},
		"device session": {Kind: api.KindDevice, P2P: true, P2PInterfaces: fakeIfaces},
		"direct session": {Kind: api.KindClient, P2P: true, Direct: true, P2PInterfaces: fakeIfaces},
	} {
		if pp := o.prepareP2P(ctx); pp != nil {
			pp.close()
			t.Errorf("%s: plane B prepared", name)
		}
	}

	o := base
	o.P2PSTUN = stunSrv.LocalAddr().String()
	pp := o.prepareP2P(ctx)
	if pp == nil {
		t.Fatal("no plane B with a working STUN server")
	}
	defer pp.close()
	offer := pp.offer()
	if offer.WGPublicKey != pp.pub.Base64() || len(offer.Candidates) != 2 {
		t.Fatalf("offer %+v", offer)
	}
	port := pp.sock.Port()
	wantHost := netip.AddrPortFrom(netip.MustParseAddr("192.168.4.4"), uint16(port)).String()
	if offer.Candidates[0] != wantHost || !strings.HasPrefix(offer.Candidates[1], "127.0.0.1:") {
		t.Fatalf("candidates %v (host %s first, then the reflexive loopback address)", offer.Candidates, wantHost)
	}
	if _, err := p2p.ParseCandidates(offer.Candidates); err != nil {
		t.Fatalf("own candidates are not valid for the hub: %v", err)
	}

	// No STUN server derivable and no usable interface: nothing to offer.
	none := Options{Kind: api.KindClient, P2P: true, HubURL: "http://127.0.0.1:8080",
		P2PInterfaces: func() ([]netip.Addr, error) { return nil, nil }}
	start := time.Now()
	if pp := none.prepareP2P(ctx); pp != nil {
		pp.close()
		t.Fatal("plane B prepared without any candidate")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("preparing without candidates was slow")
	}
}
