package agent

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	maxHostKeyFile = 16 << 10
	maxHostKeys    = 16
)

// ReadHostKeys returns the sshd host public keys matching glob, validated and
// normalised to "<type> <base64>" (comments dropped), sorted, without
// duplicates. Unreadable or invalid files are skipped with a warning.
func ReadHostKeys(glob string, log *slog.Logger) []string {
	paths, err := filepath.Glob(glob)
	if err != nil {
		log.Warn("bad SSH host key glob", "glob", glob)
		return nil
	}
	sort.Strings(paths)
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		line, err := readHostKey(p)
		if err != nil {
			log.Warn("skipping SSH host key", "file", p, "error", err.Error())
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) == maxHostKeys {
			break
		}
	}
	return out
}

func readHostKey(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxHostKeyFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxHostKeyFile {
		return "", fmt.Errorf("file larger than %d bytes", maxHostKeyFile)
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return "", fmt.Errorf("not an SSH public key: %w", err)
	}
	if len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", fmt.Errorf("unexpected options or trailing data")
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return "", fmt.Errorf("certificates are not host keys")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}
