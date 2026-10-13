//go:build linux

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// InitDir prepares the identity directory for the unprivileged agent: it
// creates dir (mode 0700) if missing and makes it, and the regular files
// directly inside it, owned by uid:uid. It runs as root in an init container,
// is idempotent, and refuses a symlink at dir. Symlinks inside dir are never
// followed or changed.
func InitDir(dir string, uid int) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return errors.New("agent init: --dir must be an absolute path")
	}
	if uid < 0 {
		return errors.New("agent init: --uid must not be negative")
	}
	dir = filepath.Clean(dir)
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("agent init: %s is a symlink; refusing to use it", dir)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return fmt.Errorf("agent init: %w", err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("agent init: %w", err)
		}
	} else {
		return fmt.Errorf("agent init: %w", err)
	}

	// Open without following symlinks and change the directory through the
	// descriptor, so nothing can be swapped in between the check and the chown.
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("agent init: opening %s (is it a symlink or not a directory?): %w", dir, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Fchown(fd, uid, uid); err != nil {
		return fmt.Errorf("agent init: chown %s: %w", dir, err)
	}
	if err := syscall.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("agent init: chmod %s: %w", dir, err)
	}
	// Files left by an earlier root-owned run must be readable by the agent.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("agent init: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := os.Lchown(filepath.Join(dir, e.Name()), uid, uid); err != nil {
			return fmt.Errorf("agent init: chown %s: %w", e.Name(), err)
		}
	}
	return nil
}
