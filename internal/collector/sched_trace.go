package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
	"github.com/meinanzilinzhengying/ebpf-probe/pkg/perf"
)

//go:embed sched_trace.bpf.o
var schedTraceBpfO []byte

type SchedTraceCollector struct {
	output     output.Writer
	probeID    string
	running    bool
	stopCh     chan struct{}
	coll       *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	analyzer   *perf.SchedAnalyzer
}

func NewSchedTraceCollector(out output.Writer, probeID string) *SchedTraceCollector {
	return &SchedTraceCollector{
		output:   out,
		probeID:  probeID,
		stopCh:   make(chan struct{}),
		analyzer: perf.NewSchedAnalyzer(),
	}
}

func (s *SchedTraceCollector) Name() string   { return "sched_trace" }
func (s *SchedTraceCollector) Category() string { return "performance" }

func (s *SchedTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFTracepoint {
		return fmt.Errorf("no tracepoint support")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(schedTraceBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	s.coll = loaded

	if prog := loaded.Programs["tracepoint_sched_switch"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_switch", prog, nil)
		if err != nil { log.Printf("[SCHED] attach sched_switch: %v", err) } else { s.links = append(s.links, l) }
	}
	if prog := loaded.Programs["tracepoint_sched_wakeup"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_wakeup", prog, nil)
		if err != nil { log.Printf("[SCHED] attach sched_wakeup: %v", err) } else { s.links = append(s.links, l) }
	}

	rbMap := loaded.Maps["rb"]
	if rbMap == nil {
		return fmt.Errorf("ringbuf map not found")
	}
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	s.reader = reader
	return nil
}

func (s *SchedTraceCollector) Start(ctx context.Context) error {
	s.running = true
	go s.readLoop()
	go s.flushLoop(ctx)
	return nil
}

func (s *SchedTraceCollector) readLoop() {
	defer s.reader.Close()
	for s.running {
		record, err := s.reader.Read()
		if err != nil {
			if s.running { log.Printf("[SCHED] ringbuf read: %v", err) }
			continue
		}
		s.handleEvent(record.RawSample)
	}
}

func (s *SchedTraceCollector) handleEvent(data []byte) {
	if len(data) < 48 { return }
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	ppid := binary.LittleEndian.Uint32(data[16:20])
	latency := binary.LittleEndian.Uint64(data[48:56])
	now := time.Now()

	if etype == 12 { // sched_switch
		s.analyzer.RecordSwitch(pid, ppid, int64(latency), now)
	} else if etype == 13 { // sched_wakeup
		s.analyzer.RecordWakeUp(pid, latency)
	}
}

func (s *SchedTraceCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *SchedTraceCollector) flush() {
	stats := s.analyzer.GetTopCPUUsage(10)
	for _, stat := range stats {
		_ = s.output.WriteEvent(&output.Event{
			Timestamp: time.Now(), ProbeID: s.probeID, Category: "performance", EventType: "sched",
			Details: fmt.Sprintf("pid=%d cpu=%.1f%% switches=%d", stat.Pid, stat.CPUUsagePct, stat.SwitchCount),
			Tags: fmt.Sprintf("wakeup=%d", stat.WakeUpCount),
		})
	}
	s.analyzer.Reset()
}

func (s *SchedTraceCollector) Stop() {
	close(s.stopCh)
	s.running = false
	if s.reader != nil { s.reader.Close() }
	for _, l := range s.links { l.Close() }
	if s.coll != nil { s.coll.Close() }
}

func (s *SchedTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": s.Name(), "running": s.running, "category": s.Category()}
}
