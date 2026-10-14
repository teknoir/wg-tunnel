package connectproto

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

func TestRoundTripKeepsBufferedBytes(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		// Preamble and payload in one write, like a dialer that does not wait.
		_, _ = io.WriteString(a, `{"service":"web","as":"u@example.com"}`+"\nSSH-2.0-payload")
	}()
	br := NewReader(b)
	req, err := ReadRequest(br)
	if err != nil || req.Service != "web" || req.As != "u@example.com" {
		t.Fatalf("req %+v err %v", req, err)
	}
	c := Wrap(b, br)
	buf := make([]byte, len("SSH-2.0-payload"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "SSH-2.0-payload" {
		t.Fatalf("payload %q err %v", buf, err)
	}
}

func TestHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		br := NewReader(b)
		req, _ := ReadRequest(br)
		if req.Service != "ssh" {
			return
		}
		// Response and the server's first bytes arrive together.
		_, _ = io.WriteString(b, `{"ok":true}`+"\nBANNER")
	}()
	c, resp, err := Handshake(a, api.ConnectRequest{Service: "ssh"}, 2*time.Second)
	if err != nil || !resp.OK {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "BANNER" {
		t.Fatalf("banner %q err %v", buf, err)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]struct {
		in   string
		want func(error) bool
	}{
		"too long":   {strings.Repeat("x", MaxLine+10) + "\n", func(e error) bool { return errors.Is(e, ErrTooLong) }},
		"no newline": {`{"service":"a"}`, func(e error) bool { return errors.Is(e, io.EOF) }},
		"malformed":  {"not json\n", func(e error) bool { return e != nil && strings.Contains(e.Error(), "malformed") }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadRequest(NewReader(strings.NewReader(tc.in)))
			if !tc.want(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := WriteRequest(io.Discard, api.ConnectRequest{Service: strings.Repeat("a", MaxLine)}); !errors.Is(err, ErrTooLong) {
		t.Fatalf("oversized write: %v", err)
	}
}
