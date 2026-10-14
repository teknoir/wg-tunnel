//go:build linux

package agent

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

// InitDir prepares the identity directory for the unprivileged agent: it
// creates dir if missing and makes it, and the regular files directly inside
// it, owned by uid:uid. The directory mode is StateDirMode (0711): only the
// owner can list or write it, but the attestor sidecar (root without any
// capability, so "other" to this directory) can traverse it to read
// identity.pub. The identity key itself is 0600. It runs as root in an init container,
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
	fi, err := os.Lstat(dir)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("agent init: %s is a symlink; refusing to use it", dir)
	case err == nil:
		// Already prepared by an earlier run (the init container runs on every
		// pod start): a StateDirMode directory owned by uid. Root in the init container
		// has no CAP_DAC_READ_SEARCH, so it could not even open it again.
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && fi.IsDir() &&
			int(st.Uid) == uid && int(st.Gid) == uid {
			switch fi.Mode().Perm() {
			case StateDirMode:
				return nil
			case 0o700:
				// Prepared by a phase-1 agent (0700). Root without DAC
				// capabilities cannot open it, but CAP_FOWNER lets it change
				// the mode by path; the parent is root-owned, and Lstat above
				// ruled out a symlink.
				if err := os.Chmod(dir, StateDirMode); err != nil {
					return fmt.Errorf("agent init: chmod %s: %w", dir, err)
				}
				return nil
			}
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return fmt.Errorf("agent init: %w", err)
		}
		if err := os.Mkdir(dir, StateDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("agent init: %w", err)
		}
	default:
		return fmt.Errorf("agent init: %w", err)
	}

	// Open without following symlinks and do everything through the
	// descriptor: nothing can be swapped in between the check and the chown,
	// and the listing below still works after the chmod even though root here
	// has no CAP_DAC_READ_SEARCH (the permission check happened at open).
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("agent init: opening %s (is it a symlink or not a directory?): %w", dir, err)
	}
	f := os.NewFile(uintptr(fd), dir)
	defer func() { _ = f.Close() }()
	// Files left by an earlier root-owned run must be readable by the agent.
	entries, err := f.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("agent init: listing %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := unix.Fchownat(fd, e.Name(), uid, uid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("agent init: chown %s: %w", e.Name(), err)
		}
	}
	if err := syscall.Fchown(fd, uid, uid); err != nil {
		return fmt.Errorf("agent init: chown %s: %w", dir, err)
	}
	if err := syscall.Fchmod(fd, uint32(StateDirMode)); err != nil {
		return fmt.Errorf("agent init: chmod %s: %w", dir, err)
	}
	return nil
}
