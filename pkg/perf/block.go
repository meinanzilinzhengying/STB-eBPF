package perf

import (
	"sort"
	"time"
)

// BlockIORecord 磁盘IO记录
type BlockIORecord struct {
	Timestamp time.Time
	Dev       uint64
	Sector    uint64
	Size      uint64
	Direction string
	LatencyNs uint64
}

// BlockIOStats 块设备统计
type BlockIOStats struct {
	Dev           uint64
	ReadOps       uint64
	WriteOps      uint64
	ReadBytes     uint64
	WriteBytes    uint64
	TotalLatency  uint64
	AvgLatencyNs  uint64
	MaxLatencyNs  uint64
	IOPS          float64
	ThroughputBps float64
}

// BlockIOAnalyzer 磁盘IO分析器
type BlockIOAnalyzer struct {
	pending   map[uint64]*BlockIORecord
	stats     map[uint64]*BlockIOStats
	histogram map[uint64]uint64 // latency distribution
}

func NewBlockIOAnalyzer() *BlockIOAnalyzer {
	return &BlockIOAnalyzer{
		pending:   make(map[uint64]*BlockIORecord),
		stats:     make(map[uint64]*BlockIOStats),
		histogram: make(map[uint64]uint64),
	}
}

func (a *BlockIOAnalyzer) RecordIssue(dev, sector, size uint64, ts time.Time) {
	key := (dev << 32) | sector
	a.pending[key] = &BlockIORecord{
		Timestamp: ts,
		Dev:       dev,
		Sector:    sector,
		Size:      size,
		Direction: "rw",
	}
}

func (a *BlockIOAnalyzer) RecordComplete(dev, sector uint64, ts time.Time) {
	key := (dev << 32) | sector
	record, ok := a.pending[key]
	if !ok {
		return
	}
	delete(a.pending, key)
	latency := uint64(ts.Sub(record.Timestamp).Nanoseconds())
	stat, ok := a.stats[dev]
	if !ok {
		stat = &BlockIOStats{Dev: dev}
		a.stats[dev] = stat
	}
	stat.TotalLatency += latency
	stat.ReadOps++
	stat.ReadBytes += record.Size
	if latency > stat.MaxLatencyNs {
		stat.MaxLatencyNs = latency
	}
	// latency histogram (bucketed by 100us)
	bucket := latency / 100000
	a.histogram[bucket]++
}

func (a *BlockIOAnalyzer) GetStats() []*BlockIOStats {
	var list []*BlockIOStats
	for _, stat := range a.stats {
		if stat.ReadOps > 0 {
			stat.AvgLatencyNs = stat.TotalLatency / stat.ReadOps
		}
		list = append(list, stat)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ReadOps > list[j].ReadOps
	})
	return list
}

func (a *BlockIOAnalyzer) GetLatencyHistogram() map[uint64]uint64 {
	return a.histogram
}

func (a *BlockIOAnalyzer) Reset() {
	a.pending = make(map[uint64]*BlockIORecord)
	a.stats = make(map[uint64]*BlockIOStats)
	a.histogram = make(map[uint64]uint64)
}
