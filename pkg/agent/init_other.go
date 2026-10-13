//go:build !linux

package agent

import "errors"

// InitDir is only implemented on Linux, the only platform the agent runs on.
func InitDir(string, int) error { return errors.New("agent init: only supported on linux") }
