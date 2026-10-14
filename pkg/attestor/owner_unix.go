//go:build unix

package attestor

import (
	"errors"
	"os"
	"syscall"
)

// openRegular opens path without following a symlink and without blocking on
// a FIFO, and returns the file with its owner uid.
func openRegular(path string) (*os.File, int, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		_ = f.Close()
		return nil, 0, nil, errors.New("cannot determine file owner")
	}
	return f, int(st.Uid), fi, nil
}
