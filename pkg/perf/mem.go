package perf

import (
	"time"
)

// MemAllocRecord 内存分配记录
type MemAllocRecord struct {
	Timestamp   time.Time
	Pid         uint32
	Comm        string
	Size        uint64
	Pointer     uint64
	AllocType   string
}

// MemLeakDetector 内存泄漏检测器
type MemLeakDetector struct {
	allocs map[uint64]*MemAllocRecord
	leaks  []*MemAllocRecord
	stats  map[uint32]*MemStats
}

// MemStats 内存统计
type MemStats struct {
	Pid          uint32
	Comm         string
	TotalAlloc   uint64
	TotalFree    uint64
	CurrentAlloc uint64
	AllocCount   uint64
	FreeCount    uint64
	FailCount    uint64
	LargeAlloc   uint64 // > 1MB
}

func NewMemLeakDetector() *MemLeakDetector {
	return &MemLeakDetector{
		allocs: make(map[uint64]*MemAllocRecord),
		stats:  make(map[uint32]*MemStats),
	}
}

func (d *MemLeakDetector) RecordAlloc(pid uint32, comm string, size uint64, ptr uint64) {
	if ptr == 0 {
		return
	}
	d.allocs[ptr] = &MemAllocRecord{
		Timestamp: time.Now(),
		Pid:       pid,
		Comm:      comm,
		Size:      size,
		Pointer:   ptr,
		AllocType: "kmalloc",
	}
	stat, ok := d.stats[pid]
	if !ok {
		stat = &MemStats{Pid: pid, Comm: comm}
		d.stats[pid] = stat
	}
	stat.TotalAlloc += size
	stat.CurrentAlloc += size
	stat.AllocCount++
	if size > 1024*1024 {
		stat.LargeAlloc++
	}
}

func (d *MemLeakDetector) RecordFree(pid uint32, comm string, ptr uint64) {
	if alloc, ok := d.allocs[ptr]; ok {
		delete(d.allocs, ptr)
		stat, ok := d.stats[pid]
		if !ok {
			stat = &MemStats{Pid: pid, Comm: comm}
			d.stats[pid] = stat
		}
		stat.TotalFree += alloc.Size
		stat.CurrentAlloc -= alloc.Size
		stat.FreeCount++
	}
}

func (d *MemLeakDetector) GetLeaks() []*MemAllocRecord {
	var leaks []*MemAllocRecord
	now := time.Now()
	for _, alloc := range d.allocs {
		if now.Sub(alloc.Timestamp) > 5*time.Minute {
			leaks = append(leaks, alloc)
		}
	}
	return leaks
}

func (d *MemLeakDetector) GetStats() map[uint32]*MemStats {
	return d.stats
}

func (d *MemLeakDetector) Reset() {
	d.allocs = make(map[uint64]*MemAllocRecord)
	d.leaks = nil
	d.stats = make(map[uint32]*MemStats)
}
