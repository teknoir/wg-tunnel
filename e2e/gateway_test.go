package e2e_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/internal/e2erig"
	"github.com/teknoir/wg-tunnel/pkg/api"
)

// seenByApp is what the device's web application reports about a request.
type seenByApp struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// webApp is the device's web application: it reports the request it got,
// sets cookies, and speaks WebSocket (a raw 101 + echo).
func webApp(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			c, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer func() { _ = c.Close() }()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(c, rw)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Add("Set-Cookie", "sid=device-session; Domain=.e2e.test; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "_oauth2_proxy=hijack; Path=/")
		_ = json.NewEncoder(w).Encode(seenByApp{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Headers: r.Header, Body: string(body)})
	})
}

func decodeApp(t *testing.T, resp *http.Response) seenByApp {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var s seenByApp
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("status %d, body %q: %v", resp.StatusCode, b, err)
	}
	return s
}

func statusCall(t *testing.T, r *e2erig.Rig, method, path, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, r.StatusURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Ztna-Requester", e2erig.AliceEmail)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func liveStatus(t *testing.T, r *e2erig.Rig) api.DeviceLiveStatus {
	t.Helper()
	st, b := statusCall(t, r, "GET", api.StatusDevicePath+e2erig.NS+"/"+e2erig.DeviceName, e2erig.BackstageToken)
	if st != 200 {
		t.Fatalf("status listener: %d %s", st, b)
	}
	var out api.DeviceLiveStatus
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A browser-like request travels gateway -> hub -> agent -> web app over the
// real tunnel, with the user named per connection and checked per connection.
func TestWebGatewayEndToEnd(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	app := r.StartWebApp(webApp(t))
	r.SetServices(r.WebAppService("web", app))
	r.StartAgent()
	r.WaitDeviceUp(1)
	gw := r.StartWebGateway(15 * time.Minute)
	origin := "https://" + e2erig.GatewayHost

	// A GET: scrubbed on the way in, host-only cookies on the way out.
	hdr := http.Header{}
	hdr.Set("Cookie", "_oauth2_proxy=LOGINSECRET; theme=dark")
	hdr.Set("Authorization", "Bearer LOGINSECRET")
	hdr.Set("X-Forwarded-Access-Token", "LOGINSECRET")
	resp, err := gw.Do("GET", "/dashboard?tab=1", e2erig.AliceEmail, "web", hdr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s\n%s", resp.StatusCode, b, gw.Logs.String())
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 1 || sc[0] != "sid=device-session; Path=/; HttpOnly" {
		t.Errorf("Set-Cookie = %q", sc)
	}
	got := decodeApp(t, resp)
	if got.Method != "GET" || got.Path != "/dashboard?tab=1" || got.Host != e2erig.GatewayHost {
		t.Errorf("app saw %+v", got)
	}
	if c := got.Headers["Cookie"]; len(c) != 1 || c[0] != "theme=dark" {
		t.Errorf("app saw cookies %v", c)
	}
	for _, h := range []string{"Authorization", "X-Forwarded-Access-Token", "X-Auth-Request-Email", "X-Ztna-Service"} {
		if v, ok := got.Headers[h]; ok {
			t.Errorf("app saw %s: %v", h, v)
		}
	}

	// A POST with a body needs the right Origin.
	h2 := http.Header{"Origin": {origin}, "Content-Type": {"text/plain"}}
	payload := strings.Repeat("form-data;", 20_000)
	resp, err = gw.Do("POST", "/save", e2erig.AliceEmail, "web", h2, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeApp(t, resp); p.Method != "POST" || p.Body != payload {
		t.Errorf("POST body mismatch: %s, %d bytes back", p.Method, len(p.Body))
	}
	resp, _ = gw.Do("POST", "/save", e2erig.AliceEmail, "web", http.Header{"Origin": {"https://evil.example"}}, strings.NewReader("x"))
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin POST: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// A second user shares the one hub session of the service.
	resp, err = gw.Do("GET", "/", e2erig.BobEmail, "web", nil, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("bob: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	if _, c := r.Hub.SessionCounts(); c != 1 {
		t.Errorf("%d client sessions at the hub for one service, want 1", c)
	}

	// WebSocket upgrade through the whole chain.
	conn, err := net.Dial("tcp", strings.TrimPrefix(gw.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: "+e2erig.GatewayHost+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: "+origin+"\r\n"+
		"X-Auth-Request-Email: "+e2erig.AliceEmail+"\r\nX-Ztna-Service: web\r\n\r\n")
	br := bufio.NewReader(conn)
	up, err := http.ReadResponse(br, nil)
	if err != nil || up.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", err, up)
	}
	for _, msg := range []string{"ping", strings.Repeat("w", 200_000)} {
		go func() { _, _ = io.WriteString(conn, msg) }()
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
			t.Fatalf("ws echo of %d bytes: %v", len(msg), err)
		}
	}

	// Live status: the gateway's session, with the user of the open socket and bytes.
	e2erig.Eventually(t, 10*time.Second, "the status to show the gateway session", func() bool {
		st := liveStatus(t, r)
		for _, c := range st.Sessions {
			if c.Software == "web-gateway" && strings.Contains(c.Subject, e2erig.AliceEmail) && c.BytesOut > 200_000 {
				return true
			}
		}
		return false
	})
	st := liveStatus(t, r)
	if !st.Connected || st.LastHandshake.IsZero() || len(st.Sessions) != 1 || st.Sessions[0].Service != "web" || st.Sessions[0].Path != api.PathHub {
		t.Errorf("status: %+v", st)
	}
	_ = conn.Close()

	// A user who lost access to the teamspace is refused by the hub on the
	// next connection (SAR per connection), without touching the session.
	// (Keep-alive connections are reused for ConnMaxAge only, 200 ms in the rig.)
	r.Authz.Set(e2erig.BobEmail, e2erig.NS, false)
	time.Sleep(400 * time.Millisecond)
	resp, _ = gw.Do("GET", "/", e2erig.BobEmail, "web", nil, nil)
	if resp.StatusCode != 403 {
		t.Errorf("bob without access: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp, _ = gw.Do("GET", "/", e2erig.AliceEmail, "web", nil, nil)
	if resp.StatusCode != 200 {
		t.Errorf("alice after bob was refused: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// No identity, no service, wrong service.
	for _, tc := range []struct {
		user, service string
		want          int
	}{{"", "web", 403}, {e2erig.AliceEmail, "", 404}, {e2erig.AliceEmail, "ghost", 404}} {
		resp, _ = gw.Do("GET", "/", tc.user, tc.service, nil, nil)
		if resp.StatusCode != tc.want {
			t.Errorf("user %q service %q: %d, want %d", tc.user, tc.service, resp.StatusCode, tc.want)
		}
		_ = resp.Body.Close()
	}

	// Nothing secret reached any log.
	for _, secret := range []string{"LOGINSECRET", e2erig.GatewayToken, e2erig.BackstageToken} {
		for name, l := range map[string]string{"gateway": gw.Logs.String(), "hub": r.HubLogs.String(), "agent": r.AgentLogs.String()} {
			if strings.Contains(l, secret) {
				t.Errorf("%s log contains %q", name, secret)
			}
		}
	}
}

// An administrator ends the gateway's session; the gateway notices, and the
// next request quietly builds a new one.
func TestWebGatewayRecoversFromAdminEndAndRevocation(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	app := r.StartWebApp(webApp(t))
	r.SetServices(r.WebAppService("web", app))
	r.StartAgent()
	r.WaitDeviceUp(1)
	gw := r.StartWebGateway(15 * time.Minute)

	get := func(want int) {
		t.Helper()
		resp, err := gw.Do("GET", "/", e2erig.AliceEmail, "web", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status %d, want %d\n%s", resp.StatusCode, want, gw.Logs.String())
		}
	}
	get(200)
	st := liveStatus(t, r)
	if len(st.Sessions) != 1 {
		t.Fatalf("sessions: %+v", st.Sessions)
	}
	code, body := statusCall(t, r, "POST", api.AdminEndSessionPath+st.Sessions[0].ID+"/end", e2erig.BackstageToken)
	if code != http.StatusNoContent {
		t.Fatalf("end: %d %s", code, body)
	}
	if !strings.Contains(r.HubLogs.String(), `"op":"admin_end"`) || !strings.Contains(r.HubLogs.String(), `"requester":"alice@example.com"`) {
		t.Error("no admin_end decision with the requester in the hub log")
	}
	// The gateway's session dies at its next renewal (2 s in the rig) and is dropped.
	e2erig.Eventually(t, 20*time.Second, "the gateway to drop the ended session", func() bool { return gw.Sessions() == 0 })
	get(200)
	if n := len(liveStatus(t, r).Sessions); n != 1 {
		t.Errorf("%d sessions after the new one was built, want 1", n)
	}

	// Revoking the device ends the session; requests are refused until it is back.
	r.Flags.Set(e2erig.NS, e2erig.DeviceName, map[string]string{api.AnnotationWireGuard: "enabled", api.AnnotationCompromised: "true"})
	e2erig.Eventually(t, 20*time.Second, "requests to be refused for the revoked device", func() bool {
		resp, err := gw.Do("GET", "/", e2erig.AliceEmail, "web", nil, nil)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == 403 || resp.StatusCode == 503
	})
}

// The gateway closes a service's session after the idle timeout; the next
// request opens a new one.
func TestWebGatewayClosesIdleSessions(t *testing.T) {
	t.Parallel()
	r := e2erig.New(t, e2erig.Options{})
	app := r.StartWebApp(webApp(t))
	r.SetServices(r.WebAppService("web", app))
	r.StartAgent()
	r.WaitDeviceUp(1)
	gw := r.StartWebGateway(300 * time.Millisecond)
	resp, err := gw.Do("GET", "/", e2erig.AliceEmail, "web", nil, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	_ = resp.Body.Close()
	if _, c := r.Hub.SessionCounts(); c != 1 {
		t.Fatalf("%d client sessions", c)
	}
	e2erig.Eventually(t, 5*time.Minute, "the idle session to be closed", func() bool {
		_, c := r.Hub.SessionCounts()
		return c == 0 && gw.Sessions() == 0
	})
	resp, err = gw.Do("GET", "/", e2erig.AliceEmail, "web", nil, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("after idle close: %v %v", err, resp)
	}
	_ = resp.Body.Close()
}
