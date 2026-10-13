package turncred

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/teknoir/wg-tunnel/internal/turntest"
)

// Golden vectors computed once with STUNner v1.2.1
// pkg/authentication.GenerateTimeWindowedUsername + GetLongTermCredential.
var vectors = []struct {
	now    int64
	ttl    time.Duration
	secret string
	uid    string
	user   string
	pass   string
}{
	{now: 1760000000, ttl: 1800000000000, secret: "s3cr3t", uid: "teknoir-demo/vdev-01", user: "1760001800:teknoir-demo/vdev-01", pass: "MIW0L4YP1UEY/5b9Dnv2gOL8MNg="},
	{now: 1760000000, ttl: 1800000000000, secret: "s3cr3t", uid: "ns/6f1c0e2a-9b7d-4c1e-8a55-3d2f1b0c9e11", user: "1760001800:ns/6f1c0e2a-9b7d-4c1e-8a55-3d2f1b0c9e11", pass: "TgqiAvAVCH1gofG/lYmKcXonsdI="},
	{now: 1893456000, ttl: 180000000000, secret: "a-much-longer-shared-secret-value-0123456789abcdef-0123456789abcdef-0123456789abcdef-0123456789abcdef", uid: "teknoir-demo/dev", user: "1893456180:teknoir-demo/dev", pass: "kQN+ppvm1Wq4fCZtfgtaDPkzjj8="},
	{now: 1, ttl: 1000000000, secret: "", uid: "x/y", user: "2:x/y", pass: "LrLRPJQWVisjNTl9Ap35Dfp8GkM="},
}

func TestGoldenVectors(t *testing.T) {
	for _, v := range vectors {
		u, p, exp := Generate(v.secret, v.uid, v.ttl, time.Unix(v.now, 0))
		if u != v.user || p != v.pass {
			t.Errorf("Generate(%q,%q) = %q,%q want %q,%q", v.secret, v.uid, u, p, v.user, v.pass)
		}
		if want := time.Unix(v.now, 0).Add(v.ttl); !exp.Equal(want) {
			t.Errorf("expiresAt = %v want %v", exp, want)
		}
		if got := Password(v.secret, v.user); got != v.pass {
			t.Errorf("Password = %q want %q", got, v.pass)
		}
	}
}

func TestSubSecondTruncated(t *testing.T) {
	now := time.Unix(1760000000, 900_000_000)
	u, _, exp := Generate("k", "a/b", 30*time.Minute, now)
	if !strings.HasPrefix(u, "1760001800:") {
		t.Fatalf("username %q", u)
	}
	if exp.Nanosecond() != 0 || exp.Unix() != 1760001800 {
		t.Fatalf("expiresAt %v", exp)
	}
}

func TestDifferentSecretDifferentPassword(t *testing.T) {
	_, p1, _ := Generate("one", "a/b", time.Minute, time.Unix(1, 0))
	_, p2, _ := Generate("two", "a/b", time.Minute, time.Unix(1, 0))
	if p1 == p2 {
		t.Fatal("password does not depend on the secret")
	}
}

func TestValidUserID(t *testing.T) {
	for _, ok := range []string{"ns/dev", "teknoir-demo/6f1c0e2a"} {
		if err := ValidUserID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a:b", "ns/dev\n", "x\x00"} {
		if err := ValidUserID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func quietClient(t *testing.T, server, user, pass string) (*turn.Client, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	lf := &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
	c, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: server, Conn: pc, Username: user, Password: pass,
		Realm: turntest.Realm, LoggerFactory: lf, RTO: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	return c, pc
}

// The credentials must be accepted by pion/turn's TURN-REST auth handler, which
// implements the same scheme STUNner serves.
func TestAcceptedByPionServer(t *testing.T) {
	const secret = "shared-secret"
	srv := turntest.Start(t, secret)

	u, p, _ := Generate(secret, "teknoir-demo/vdev-01", 30*time.Minute, time.Now())
	c, _ := quietClient(t, srv.Addr, u, p)
	defer c.Close()
	relay, err := c.Allocate()
	if err != nil {
		t.Fatalf("allocate with valid credentials: %v", err)
	}
	_ = relay.Close()
}

func TestRejectedByPionServer(t *testing.T) {
	const secret = "shared-secret"
	srv := turntest.Start(t, secret)
	now := time.Now()

	cases := map[string]func() (string, string){
		"wrong secret": func() (string, string) {
			u, p, _ := Generate("other-secret", "ns/dev", time.Hour, now)
			return u, p
		},
		"expired": func() (string, string) {
			u, p, _ := Generate(secret, "ns/dev", time.Minute, now.Add(-time.Hour))
			return u, p
		},
		"tampered username": func() (string, string) {
			u, p, _ := Generate(secret, "ns/dev", time.Hour, now)
			return strings.Replace(u, "ns/dev", "ns/other", 1), p
		},
	}
	for name, mk := range cases {
		u, p := mk()
		c, _ := quietClient(t, srv.Addr, u, p)
		if r, err := c.Allocate(); err == nil {
			_ = r.Close()
			t.Errorf("%s: allocation succeeded", name)
		}
		c.Close()
	}
}
