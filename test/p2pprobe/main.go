// Command p2pprobe is a small plane-B peer for the k3d smoke test
// (test/smoke-p2p-k3d.sh): it opens the plane-B socket, gathers candidates,
// punches towards one peer given by DNS name and, as the dialling side, echoes
// a message over the direct WireGuard path. It uses exactly the code the agent
// and the client use (pkg/p2p), so it shows what the restricted device
// container (uid 65532, no capabilities, read-only root) can and cannot do.
//
// It is a test tool: it is not part of the images.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/p2p"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(priv.Base64(), pub.Base64())
		return
	}
	var (
		role     = flag.String("role", "", "a (dials) or b (serves)")
		port     = flag.Int("port", 41000, "UDP port of the plane-B socket (peers use the same)")
		peer     = flag.String("peer", "", "DNS name of the peer")
		selfPriv = flag.String("self-priv", "", "own private key (base64)")
		peerPub  = flag.String("peer-pub", "", "peer public key (base64)")
		selfAddr = flag.String("self-addr", "", "own plane-B address")
		peerAddr = flag.String("peer-addr", "", "peer plane-B address")
		stun     = flag.String("stun", "", "STUN server host:port (optional)")
		wait     = flag.Duration("wait", 60*time.Second, "how long to wait for the whole exercise")
	)
	flag.Parse()
	if err := run(*role, *port, *peer, *selfPriv, *peerPub, *selfAddr, *peerAddr, *stun, *wait); err != nil {
		fmt.Println("RESULT: fail:", err)
		os.Exit(1)
	}
}

func run(role string, port int, peerName, selfPriv, peerPubB64, selfAddr, peerAddr, stun string, wait time.Duration) error {
	priv, err := wgkey.ParsePrivate(selfPriv)
	if err != nil {
		return err
	}
	peerPub, err := wgkey.ParsePublic(peerPubB64)
	if err != nil {
		return err
	}
	sock, err := p2p.OpenSocket(p2p.SocketConfig{Port: port})
	if err != nil {
		return fmt.Errorf("opening the socket: %w", err)
	}
	pl, err := p2p.NewPlane(p2p.PlaneConfig{Socket: sock, PrivateKey: priv, Address: netip.MustParseAddr(selfAddr)})
	if err != nil {
		return fmt.Errorf("bringing the plane up: %w", err)
	}
	defer pl.Close()
	gctx, gcancel := context.WithTimeout(context.Background(), 2*time.Second)
	cands := sock.Gather(gctx, stun)
	gcancel()
	fmt.Println("candidates:", p2p.Strings(cands))
	if len(cands) == 0 {
		return fmt.Errorf("no candidates (interface listing failed?)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	ip, err := resolve(ctx, peerName)
	if err != nil {
		return err
	}
	fmt.Println("peer", peerName, "is", ip)
	if err := pl.AddPeer(peerPub, netip.MustParseAddr(peerAddr), p2p.PeerOptions{
		Candidates: []netip.AddrPort{netip.AddrPortFrom(ip, uint16(port))},
		Initiator:  role == "a", Budget: wait,
	}); err != nil {
		return err
	}
	if role == "b" {
		ln, err := pl.Listen(2224)
		if err != nil {
			return err
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
			}
		}()
		fmt.Println("serving; waiting for the peer")
		for !pl.Status(peerPub).Established {
			select {
			case <-ctx.Done():
				return fmt.Errorf("the peer never connected")
			case <-time.After(100 * time.Millisecond):
			}
		}
		// Stay up long enough for the dialler to finish.
		time.Sleep(5 * time.Second)
		fmt.Println("RESULT: ok (served)")
		return nil
	}
	if !pl.WaitEstablished(ctx, peerPub) {
		return fmt.Errorf("no WireGuard session with the peer within %v", wait)
	}
	st := pl.Status(peerPub)
	c, err := pl.DialContext(ctx, "tcp", net.JoinHostPort(peerAddr, strconv.Itoa(2224)))
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	msg := "hello over plane B\n"
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		return fmt.Errorf("echo failed: %v", err)
	}
	fmt.Printf("RESULT: ok path=%s endpoint=%s\n", st.Path, st.Endpoint)
	return nil
}

func resolve(ctx context.Context, name string) (netip.Addr, error) {
	for {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
		if err == nil && len(ips) > 0 {
			return ips[0].Unmap(), nil
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, fmt.Errorf("resolving %s: %w", name, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
