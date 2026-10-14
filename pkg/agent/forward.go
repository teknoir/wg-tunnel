package agent

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
	"github.com/teknoir/wg-tunnel/pkg/wgclient"
	"github.com/teknoir/wg-tunnel/pkg/wgkey"
)

// serve exposes the allowed ports of sess and forwards connections until the
// session ends or ctx is cancelled. It returns how long it served and why the
// session ended (nil after a local close).
func (a *Agent) serve(ctx context.Context, sess *wgclient.Session, p2pPriv *wgkey.PrivateKey, holder *grantHolder) (time.Duration, error) {
	start := time.Now()

	resp := sess.Response()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-sess.Done():
		case <-ctx.Done():
			_ = sess.Close() // graceful shutdown: tell the hub, then tear down
		}
		cancel()
	}()

	var wg sync.WaitGroup
	if !a.serveServices(sctx, sess, resp, p2pPriv, holder, &wg) {
		_ = sess.Close()
	}
	sem := make(chan struct{}, a.cfg.MaxConns)
	for _, p := range resp.AllowedPorts {
		if p == api.AgentConnectPort || p == api.AgentControlPort {
			a.log.Warn("ignoring an allowed port that is reserved for the services listeners", "port", p)
			continue
		}
		ln, err := sess.Listen(p)
		if err != nil {
			a.log.Error("cannot listen on allowed port", "port", p, "error", err.Error())
			_ = sess.Close()
			break
		}
		a.log.Info("exposing port", "port", p, "to", net.JoinHostPort(a.cfg.ForwardHost, strconv.Itoa(p)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.acceptLoop(sctx, ln, p, sem, &wg)
		}()
	}
	if len(resp.AllowedPorts) == 0 {
		a.log.Warn("hub allowed no ports for this device")
	}
	<-sess.Done()
	wg.Wait()
	return time.Since(start), sess.Err()
}

func (a *Agent) acceptLoop(ctx context.Context, ln net.Listener, port int, sem chan struct{}, wg *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed with the session
		}
		select {
		case sem <- struct{}{}:
		default:
			a.log.Warn("too many concurrent connections; refusing one", "port", port, "max", a.cfg.MaxConns)
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			a.forward(ctx, c, port)
		}()
	}
}

// forward connects c to FORWARD_HOST:port and copies both ways until both
// directions finish or the session ends.
func (a *Agent) forward(ctx context.Context, c net.Conn, port int) {
	defer func() { _ = c.Close() }()
	d := net.Dialer{Timeout: a.cfg.DialTimeout}
	target := net.JoinHostPort(a.cfg.ForwardHost, strconv.Itoa(port))
	local, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		a.log.Warn("cannot reach local service", "port", port, "error", err.Error())
		return
	}
	defer func() { _ = local.Close() }()
	a.log.Debug("forwarding connection", "port", port)

	stop := context.AfterFunc(ctx, func() { // session over: unblock both copies
		_ = c.Close()
		_ = local.Close()
	})
	defer stop()
	pipe(c, local)
}

// pipe copies a<->b and half-closes each side when its source reaches EOF.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
