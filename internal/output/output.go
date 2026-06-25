package output

import "time"

type Writer interface {
	WriteEvent(ev *Event) error
	WriteBatch(events []*Event) error
	WriteMetrics(probeID string, cpu, mem, disk float64, netRx, netTx, diskRead, diskWrite uint64) error
	WriteProcessEvent(ts time.Time, probeID string, pid, ppid uint32, comm, exe, args, eventType string) error
	WriteFileEvent(ts time.Time, probeID string, pid uint32, comm, filename, operation string, result int32) error
	WriteSyscallEvent(ts time.Time, probeID string, pid uint32, comm string, syscallNr, latencyNs, count uint64) error
	Close() error
	Flush()
}
