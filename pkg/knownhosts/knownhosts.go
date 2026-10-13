// Package knownhosts writes an OpenSSH known_hosts file from the device host
// keys the hub hands to clients (api.SessionResponse.SSHHostKeys), so ssh runs
// with StrictHostKeyChecking=yes and HostKeyAlias=<alias> over the tunnel.
package knownhosts

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxKeys = 16

// ValidAlias reports whether alias is a safe known_hosts host pattern: letters,
// digits, '.', '-' and '_' only. This excludes whitespace, commas, wildcards
// ('*', '?'), negation ('!'), '@' markers and the hashed-host '|' prefix.
func ValidAlias(alias string) error {
	if alias == "" || len(alias) > 253 {
		return errors.New("knownhosts: alias must be 1-253 characters")
	}
	for _, r := range alias {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("knownhosts: invalid character %q in alias", r)
		}
	}
	return nil
}

// Format validates every host key (authorized_keys format, as in
// /etc/ssh/ssh_host_*_key.pub) and returns known_hosts lines
// "<alias> <type> <base64>". Keys with options, trailing data, or that are
// certificates are rejected, and duplicates are dropped. At least one key is
// required: an empty file would make strict checking fail every connection
// in a confusing way.
func Format(alias string, hostKeys []string) ([]byte, error) {
	if err := ValidAlias(alias); err != nil {
		return nil, err
	}
	if len(hostKeys) == 0 {
		return nil, errors.New("knownhosts: no host keys")
	}
	if len(hostKeys) > maxKeys {
		return nil, fmt.Errorf("knownhosts: %d host keys, at most %d allowed", len(hostKeys), maxKeys)
	}
	var out bytes.Buffer
	seen := map[string]bool{}
	for i, raw := range hostKeys {
		if strings.ContainsAny(strings.TrimSpace(raw), "\r\n") {
			return nil, fmt.Errorf("knownhosts: host key %d spans multiple lines", i)
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("knownhosts: host key %d: %w", i, err)
		}
		if len(options) != 0 {
			return nil, fmt.Errorf("knownhosts: host key %d has options", i)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("knownhosts: host key %d has trailing data", i)
		}
		if _, isCert := key.(*ssh.Certificate); isCert {
			return nil, fmt.Errorf("knownhosts: host key %d is a certificate", i)
		}
		line := fmt.Sprintf("%s %s %s\n", alias, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
		if seen[line] {
			continue
		}
		seen[line] = true
		out.WriteString(line)
	}
	return out.Bytes(), nil
}

// Write validates hostKeys and atomically writes the known_hosts file at path
// (mode 0600, parent directory created with 0700 if missing), replacing any
// existing file.
func Write(path, alias string, hostKeys []string) error {
	data, err := Format(alias, hostKeys)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("knownhosts: %w", err)
	}
	f, err := os.CreateTemp(dir, ".known_hosts-*.tmp")
	if err != nil {
		return fmt.Errorf("knownhosts: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("knownhosts: writing %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("knownhosts: writing %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("knownhosts: installing %s: %w", path, err)
	}
	return nil
}
