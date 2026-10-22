package main

import (
	"testing"
	"time"
)

func TestEnvDuration(t *testing.T) {
	t.Setenv("HANDOVER_WAIT", "")
	if d, err := envDuration("HANDOVER_WAIT", "10s"); err != nil || d != 10*time.Second {
		t.Fatalf("default: %v %v", d, err)
	}
	t.Setenv("HANDOVER_WAIT", "0s")
	if d, err := envDuration("HANDOVER_WAIT", "10s"); err != nil || d != 0 {
		t.Fatalf("zero: %v %v", d, err)
	}
	t.Setenv("HANDOVER_WAIT", "250ms")
	if d, err := envDuration("HANDOVER_WAIT", "10s"); err != nil || d != 250*time.Millisecond {
		t.Fatalf("250ms: %v %v", d, err)
	}
	// A typo or a negative value must stop the hub, not fall back silently.
	for _, bad := range []string{"10", "ten seconds", "-5s", "1x"} {
		t.Setenv("HANDOVER_WAIT", bad)
		if _, err := envDuration("HANDOVER_WAIT", "10s"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
