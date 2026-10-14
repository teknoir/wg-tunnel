//go:build natlab

package natlab

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/p2p"
)

const (
	stunAddr   = "203.0.113.1:3478"
	clientHost = "10.77.1.2"
	deviceHost = "10.77.2.2"
	clientNAT  = "203.0.113.2"
	deviceNAT  = "203.0.113.6"
)

func script(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate natlab.sh")
	}
	return filepath.Join(filepath.Dir(file), "natlab.sh")
}

func lab(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(script(t), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("natlab.sh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// inNS runs fn on a thread that is inside the named network namespace. Sockets
// created by fn stay in that namespace for their whole life; the thread goes
// back to the original namespace afterwards (and is discarded if that fails).
func inNS(t *testing.T, name string, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer orig.Close()
	target, err := os.Open("/run/netns/" + name)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("setns %s: %v", name, err)
	}
	fn()
	if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
		// Never return a thread that is stuck in the lab to the pool.
		t.Fatalf("cannot leave namespace %s: %v", name, err)
	}
	runtime.UnlockOSThread()
}

func socketIn(t *testing.T, ns string) net.PacketConn {
	t.Helper()
	var pc net.PacketConn
	var err error
	inNS(t, ns, func() { pc, err = net.ListenPacket("udp4", "0.0.0.0:0") })
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

type outcome struct {
	granted        bool
	established    bool
	path           string
	endpoint       netip.AddrPort
	directDials    int
	waited         time.Duration
	candidates     []string
	deviceCands    []string
	spliceFallback bool
}

// run plays one scenario: the agent's plane-B socket is in wgt-hb, the
// client's in wgt-ha; hub, TURN and plane A stay on loopback.
func run(t *testing.T) outcome {
	t.Helper()
	r := e2erig.New(t, e2erig.Options{
		P2P:     true,
		P2PSTUN: stunAddr,
		P2PConn: func(who string) (net.PacketConn, error) {
			if who == "agent" {
				return socketIn(t, "wgt-hb"), nil
			}
			return socketIn(t, "wgt-ha"), nil
		},
		P2PInterfaces: func(who string) ([]netip.Addr, error) {
			if who == "agent" {
				return []netip.Addr{netip.MustParseAddr(deviceHost)}, nil
			}
			return []netip.Addr{netip.MustParseAddr(clientHost)}, nil
		},
	})
	ag := r.StartAgent()
	r.WaitDeviceUp(1)
	e2erig.Eventually(t, 10*time.Second, "the agent's plane B", func() bool { return ag.Agent.P2PStatus().Up })

	sess := r.MustP2PClient(e2erig.AliceEmail, "ssh")
	var o outcome
	g := sess.Response().P2P
	if g == nil {
		return o
	}
	o.granted = true
	o.deviceCands = g.DeviceCandidates
	o.candidates = ag.Agent.P2PStatus().Candidates

	before := r.HubLogs.Count(`"op":"connect","decision":"allow"`)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := sess.DialService(ctx, "")
	if err != nil {
		t.Fatalf("DialService: %v", err)
	}
	defer c.Close()
	if err := e2erig.RoundTrip(c, "through the lab\r\n"); err != nil {
		t.Fatalf("echo: %v", err)
	}
	o.waited = time.Since(start)
	st := sess.P2PStatus()
	o.established, o.path, o.endpoint, o.directDials = st.Established, sess.Path(), st.Endpoint, st.DirectDials
	o.spliceFallback = r.HubLogs.Count(`"op":"connect","decision":"allow"`) > before
	return o
}

func TestNATLab(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the NAT lab needs root: go test -c -tags natlab ... && sudo ./natlab.test")
	}
	lab(t, "up")
	t.Cleanup(func() { lab(t, "down") })

	var stunConn net.PacketConn
	var err error
	inNS(t, "wgt-pub", func() { stunConn, err = net.ListenPacket("udp4", stunAddr) })
	if err != nil {
		t.Fatal(err)
	}
	defer stunConn.Close()
	go p2p.ServeSTUN(stunConn)

	cases := []struct {
		name        string
		a, b        string
		wantDirect  bool
		informative bool
	}{
		{name: "EIM-EIM", a: "eim", b: "eim", wantDirect: true},
		{name: "EDM-EDM", a: "edm", b: "edm", wantDirect: false},
		{name: "EIM-EDM", a: "eim", b: "edm", informative: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab(t, "mode", "a", tc.a)
			lab(t, "mode", "b", tc.b)
			o := run(t)
			t.Logf("%s: granted=%v established=%v path=%q endpoint=%v direct-dials=%d spliced=%v waited=%v",
				tc.name, o.granted, o.established, o.path, o.endpoint, o.directDials, o.spliceFallback, o.waited.Round(time.Millisecond))
			t.Logf("%s: device candidates %v", tc.name, o.deviceCands)
			if !o.granted {
				t.Fatal("the hub gave no plane-B grant")
			}
			if tc.informative {
				return
			}
			if tc.wantDirect {
				if !o.established || o.path != api.PathDirect || o.directDials != 1 || o.spliceFallback {
					t.Fatalf("expected a direct path through the NATs, got %+v", o)
				}
				if got := o.endpoint.Addr().String(); got != deviceNAT {
					t.Fatalf("the client's endpoint is %s, want the device NAT %s", o.endpoint, deviceNAT)
				}
				return
			}
			if o.established || o.path != api.PathHub || o.directDials != 0 || !o.spliceFallback {
				t.Fatalf("expected the hub fallback, got %+v", o)
			}
			if o.waited < api.P2PDialRaceMillis*time.Millisecond-300*time.Millisecond {
				t.Fatalf("gave up after %v, before the race budget", o.waited)
			}
		})
	}
	_ = fmt.Sprint
	_ = clientNAT
}
