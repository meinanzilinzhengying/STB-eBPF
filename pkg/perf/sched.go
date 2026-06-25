package perf

import (
	"sort"
	"time"
)

// CPUSchedulingRecord 调度事件记录
type CPUSchedulingRecord struct {
	Timestamp    time.Time
	Pid          uint32
	NextPid      uint32
	PrevState    int64
	LatencyNs    uint64
}

// CPUUsage 进程级CPU使用统计
type CPUUsage struct {
	Pid           uint32
	Comm          string
	RunTimeNs     uint64
	WaitTimeNs    uint64
	SwitchCount   uint64
	WakeUpCount   uint64
	WakeUpLatency uint64
	CPUUsagePct   float64
}

// SchedAnalyzer 调度分析器
type SchedAnalyzer struct {
	pidStats      map[uint32]*CPUUsage
	switchEvents  []CPUSchedulingRecord
	lastRunTime   map[uint32]time.Time
}

func NewSchedAnalyzer() *SchedAnalyzer {
	return &SchedAnalyzer{
		pidStats:     make(map[uint32]*CPUUsage),
		lastRunTime:  make(map[uint32]time.Time),
	}
}

func (a *SchedAnalyzer) RecordSwitch(pid, nextPid uint32, prevState int64, ts time.Time) {
	if prevState == 0 { // 进程主动让出CPU
		if lastRun, ok := a.lastRunTime[pid]; ok {
			runTime := uint64(ts.Sub(lastRun).Nanoseconds())
			if stat, ok := a.pidStats[pid]; ok {
				stat.RunTimeNs += runTime
				stat.SwitchCount++
			} else {
				a.pidStats[pid] = &CPUUsage{Pid: pid, RunTimeNs: runTime, SwitchCount: 1}
			}
		}
	}
	a.lastRunTime[nextPid] = ts
}

func (a *SchedAnalyzer) RecordWakeUp(pid uint32, latencyNs uint64) {
	if stat, ok := a.pidStats[pid]; ok {
		stat.WakeUpCount++
		stat.WakeUpLatency += latencyNs
	} else {
		a.pidStats[pid] = &CPUUsage{Pid: pid, WakeUpCount: 1, WakeUpLatency: latencyNs}
	}
}

func (a *SchedAnalyzer) GetTopCPUUsage(n int) []*CPUUsage {
	var list []*CPUUsage
	for _, stat := range a.pidStats {
		list = append(list, stat)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].RunTimeNs > list[j].RunTimeNs
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func (a *SchedAnalyzer) GetAvgWakeUpLatency() uint64 {
	var total uint64
	var count uint64
	for _, stat := range a.pidStats {
		if stat.WakeUpCount > 0 {
			total += stat.WakeUpLatency / stat.WakeUpCount
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / count
}

func (a *SchedAnalyzer) Reset() {
	a.pidStats = make(map[uint32]*CPUUsage)
	a.lastRunTime = make(map[uint32]time.Time)
}
