//go:build !unix

package attestor

import (
	"errors"
	"os"
)

func openRegular(string) (*os.File, int, os.FileInfo, error) {
	return nil, 0, nil, errors.New("attestor: unsupported platform")
}
