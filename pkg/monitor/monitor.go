package monitor

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
)

// SelfMonitor eBPF 探针自监控器
type SelfMonitor struct {
	programs    map[string]*ebpf.Program
	maps        map[string]*ebpf.Map
	ringBuffers map[string]struct{}
	startTime   time.Time
	stats       *MonitorStats
}

// MonitorStats 自监控统计
type MonitorStats struct {
	ProgramStats    map[string]*ProgramStat    `json:"program_stats"`
	MapStats        map[string]*MapStat        `json:"map_stats"`
	RingBufferStats map[string]*RingBufferStat `json:"ring_buffer_stats"`
	LoadTimeMs      int64                      `json:"load_time_ms"`
	ReloadCount     int                        `json:"reload_count"`
	LastCheckTime   time.Time                  `json:"last_check_time"`
}

// ProgramStat 单个程序统计
type ProgramStat struct {
	Name       string `json:"name"`
	Tag        string `json:"tag"`
	Type       string `json:"type"`
	RunTimeNs  uint64 `json:"run_time_ns"`
	RunCount   uint64 `json:"run_count"`
	LoadTimeMs int64  `json:"load_time_ms"`
	Status     string `json:"status"`
}

// MapStat 单个 Map 统计
type MapStat struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
	Flags      uint32 `json:"flags"`
}

// RingBufferStat Ring Buffer 统计
type RingBufferStat struct {
	Name       string `json:"name"`
	MaxEntries uint32 `json:"max_entries"`
	DataSize   uint32 `json:"data_size"`
	Overflows  uint64 `json:"overflows"`
}

func NewSelfMonitor() *SelfMonitor {
	return &SelfMonitor{
		programs:    make(map[string]*ebpf.Program),
		maps:        make(map[string]*ebpf.Map),
		ringBuffers:   make(map[string]struct{}),
		startTime:   time.Now(),
		stats: &MonitorStats{
			ProgramStats:    make(map[string]*ProgramStat),
			MapStats:        make(map[string]*MapStat),
			RingBufferStats: make(map[string]*RingBufferStat),
		},
	}
}

// RegisterProgram 注册 eBPF 程序
func (m *SelfMonitor) RegisterProgram(name string, prog *ebpf.Program) {
	m.programs[name] = prog
}

// RegisterMap 注册 eBPF Map
func (m *SelfMonitor) RegisterMap(name string, mp *ebpf.Map) {
	m.maps[name] = mp
}

// RegisterRingBuffer 注册 Ring Buffer
func (m *SelfMonitor) RegisterRingBuffer(name string) {
	m.ringBuffers[name] = struct{}{}
}

// Collect 收集当前统计信息
func (m *SelfMonitor) Collect() *MonitorStats {
	stats := &MonitorStats{
		ProgramStats:    make(map[string]*ProgramStat),
		MapStats:        make(map[string]*MapStat),
		RingBufferStats: make(map[string]*RingBufferStat),
		LoadTimeMs:      m.stats.LoadTimeMs,
		ReloadCount:     m.stats.ReloadCount,
		LastCheckTime:   time.Now(),
	}

	// 收集程序统计
	for name, prog := range m.programs {
		info, err := prog.Info()
		if err != nil {
			log.Printf("[MONITOR] 获取程序 %s 信息失败: %v", name, err)
			continue
		}
		runtime, _ := info.Runtime()
		runcount, _ := info.RunCount()
		stats.ProgramStats[name] = &ProgramStat{
			Name:       name,
			Tag:        info.Tag,
			Type:       info.Type.String(),
			RunTimeNs:  uint64(runtime),
			RunCount:   runcount,
			LoadTimeMs: m.stats.LoadTimeMs,
			Status:     "running",
		}
	}

	// 收集 Map 统计
	for name, mp := range m.maps {
		info, err := mp.Info()
		if err != nil {
			continue
		}
		stats.MapStats[name] = &MapStat{
			Name:       name,
			Type:       info.Type.String(),
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
			MaxEntries: info.MaxEntries,
			Flags:      info.Flags,
		}
	}

	// 收集 Ring Buffer 统计
	for name := range m.ringBuffers {
		stats.RingBufferStats[name] = &RingBufferStat{
			Name:       name,
			MaxEntries: 0,
		}
	}

	m.stats = stats
	return stats
}

// RecordLoadTime 记录加载时间
func (m *SelfMonitor) RecordLoadTime(duration time.Duration) {
	m.stats.LoadTimeMs = duration.Milliseconds()
}

// RecordReload 记录重载次数
func (m *SelfMonitor) RecordReload() {
	m.stats.ReloadCount++
}

// Summary 返回摘要信息
func (m *SelfMonitor) Summary() string {
	stats := m.Collect()
	var totalRunCount, totalRunTime uint64
	for _, ps := range stats.ProgramStats {
		totalRunCount += ps.RunCount
		totalRunTime += ps.RunTimeNs
	}
	uptime := time.Since(m.startTime)
	return fmt.Sprintf(
		"[SelfMonitor] 运行时间: %v, 程序数: %d, 总运行次数: %d, 总运行时间: %d ns, 重载次数: %d",
		uptime, len(m.programs), totalRunCount, totalRunTime, stats.ReloadCount,
	)
}

// StartPeriodicCheck 启动周期性检查
func (m *SelfMonitor) StartPeriodicCheck(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			log.Println(m.Summary())
		}
	}()
}
