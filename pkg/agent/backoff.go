package agent

import (
	"context"
	"math/rand/v2"
	"time"
)

// delay returns the wait before attempt number n (0 based) after n
// consecutive failures: min*2^n capped at max, with "equal jitter" (between
// half and all of it) so a fleet restarted together does not retry in lockstep.
// rnd returns a value in [0,1).
func (b Backoff) delay(n int, rnd func() float64) time.Duration {
	d := b.Min
	for i := 0; i < n && d < b.Max; i++ {
		d *= 2
	}
	if d > b.Max {
		d = b.Max
	}
	half := d / 2
	return half + time.Duration(rnd()*float64(d-half))
}

func randFloat() float64 { return rand.Float64() } //nolint:gosec // jitter, not security.

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
