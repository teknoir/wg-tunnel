// Package connectproto implements the one-line preamble of the agent's connect
// listener (api.AgentConnectPort): the dialer writes one JSON line
// (api.ConnectRequest), the agent answers with one JSON line
// (api.ConnectResponse) and, if OK, both sides then relay raw bytes.
//
// Both ends read through a bufio.Reader, which may hold bytes that arrived
// right behind the preamble (a dialer need not wait for the answer; a service
// that speaks first, like sshd, sends its banner right behind the response).
// Wrap carries those bytes over to the relay.
package connectproto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// MaxLine bounds the preamble and the answer, newline included.
const MaxLine = 1024

// ErrTooLong is returned when a line exceeds MaxLine.
var ErrTooLong = errors.New("connectproto: line too long")

// NewReader returns a reader with a buffer of exactly MaxLine bytes, so that a
// longer line is detected without reading it.
func NewReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, MaxLine) }

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, ErrTooLong
	case err != nil:
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// ReadRequest reads the preamble. The returned request is a copy.
func ReadRequest(br *bufio.Reader) (api.ConnectRequest, error) {
	var req api.ConnectRequest
	line, err := readLine(br)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return api.ConnectRequest{}, fmt.Errorf("connectproto: malformed request: %w", err)
	}
	return req, nil
}

// ReadResponse reads the agent's answer.
func ReadResponse(br *bufio.Reader) (api.ConnectResponse, error) {
	var resp api.ConnectResponse
	line, err := readLine(br)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return api.ConnectResponse{}, fmt.Errorf("connectproto: malformed response: %w", err)
	}
	return resp, nil
}

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > MaxLine {
		return ErrTooLong
	}
	_, err = w.Write(b)
	return err
}

// WriteRequest writes the preamble.
func WriteRequest(w io.Writer, req api.ConnectRequest) error { return writeLine(w, req) }

// WriteResponse writes the answer.
func WriteResponse(w io.Writer, resp api.ConnectResponse) error { return writeLine(w, resp) }

// Conn is a net.Conn whose reads come from a bufio.Reader (so that buffered
// bytes are not lost) and which keeps half-close.
type Conn struct {
	net.Conn
	r io.Reader
}

// Wrap returns c reading through br.
func Wrap(c net.Conn, br *bufio.Reader) *Conn { return &Conn{Conn: c, r: br} }

// Read implements io.Reader.
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the connection when the underlying one supports it.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// Handshake performs the dialer's side: it writes req and reads the answer
// within timeout, then clears the deadline. It returns the connection to
// relay on (reads go through the buffered reader) and the answer. A refused
// request (OK false) is returned as resp with a nil error.
func Handshake(c net.Conn, req api.ConnectRequest, timeout time.Duration) (*Conn, api.ConnectResponse, error) {
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
		defer func() { _ = c.SetDeadline(time.Time{}) }()
	}
	if err := WriteRequest(c, req); err != nil {
		return nil, api.ConnectResponse{}, err
	}
	br := NewReader(c)
	resp, err := ReadResponse(br)
	if err != nil {
		return nil, api.ConnectResponse{}, err
	}
	return Wrap(c, br), resp, nil
}
