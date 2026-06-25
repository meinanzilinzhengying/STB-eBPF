package collector

import (
	"log"
	"time"

	"golang.org/x/sys/unix"
)

var clockOffset time.Duration

func init() {
	initClockOffset()
}

func initClockOffset() {
	var mono, real unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		log.Printf("[TIME] CLOCK_MONOTONIC failed: %v, falling back to time.Now()", err)
		clockOffset = 0
		return
	}
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &real); err != nil {
		log.Printf("[TIME] CLOCK_REALTIME failed: %v, falling back to time.Now()", err)
		clockOffset = 0
		return
	}
	monoNs := int64(mono.Sec)*1e9 + int64(mono.Nsec)
	realNs := int64(real.Sec)*1e9 + int64(real.Nsec)
	clockOffset = time.Duration(realNs-monoNs) * time.Nanosecond
	log.Printf("[TIME] eBPF clock offset initialized: %v", clockOffset)
}

func ebpfTimeToWallTime(timestampNs uint64) time.Time {
	return time.Unix(0, int64(timestampNs)+clockOffset.Nanoseconds())
}
