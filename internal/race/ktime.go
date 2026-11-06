package race

import (
	"time"

	"golang.org/x/sys/unix"
)

// ktimeToWallClock converts a bpf_ktime_get_ns() timestamp to wall-clock time.
// That helper reads CLOCK_MONOTONIC, whose zero is near boot, so the event's age
// on that clock is subtracted from the current wall clock.
func ktimeToWallClock(ktime uint64) time.Time {
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(mono.Nano() - int64(ktime)))
}
