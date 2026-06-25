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

//go:embed mem_trace.bpf.o
var memTraceBpfO []byte

type MemTraceCollector struct {
	output    output.Writer
	probeID   string
	running   bool
	stopCh    chan struct{}
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	detector  *perf.MemLeakDetector
}

func NewMemTraceCollector(out output.Writer, probeID string) *MemTraceCollector {
	return &MemTraceCollector{
		output:   out,
		probeID:  probeID,
		stopCh:   make(chan struct{}),
		detector: perf.NewMemLeakDetector(),
	}
}

func (m *MemTraceCollector) Name() string   { return "mem_trace" }
func (m *MemTraceCollector) Category() string { return "performance" }

func (m *MemTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe {
		return fmt.Errorf("no kprobe support")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(memTraceBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	m.coll = loaded

	if prog := loaded.Programs["trace_kmalloc"]; prog != nil {
		l, err := link.Kprobe("__kmalloc", prog, nil)
		if err != nil { log.Printf("[MEM] attach __kmalloc: %v", err) } else { m.links = append(m.links, l) }
	}
	if prog := loaded.Programs["trace_kfree"]; prog != nil {
		l, err := link.Kprobe("kfree", prog, nil)
		if err != nil { log.Printf("[MEM] attach kfree: %v", err) } else { m.links = append(m.links, l) }
	}

	rbMap := loaded.Maps["rb"]
	if rbMap == nil {
		return fmt.Errorf("ringbuf map not found")
	}
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	m.reader = reader
	return nil
}

func (m *MemTraceCollector) Start(ctx context.Context) error {
	m.running = true
	go m.readLoop()
	go m.flushLoop(ctx)
	return nil
}

func (m *MemTraceCollector) readLoop() {
	defer m.reader.Close()
	for m.running {
		record, err := m.reader.Read()
		if err != nil {
			if m.running { log.Printf("[MEM] ringbuf read: %v", err) }
			continue
		}
		m.handleEvent(record.RawSample)
	}
}

func (m *MemTraceCollector) handleEvent(data []byte) {
	if len(data) < 48 { return }
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	bytes := binary.LittleEndian.Uint64(data[40:48])
	_ = pid

	if etype == 14 { // kmalloc
		m.detector.RecordAlloc(pid, "", bytes, 0)
	} else if etype == 15 { // kfree
		m.detector.RecordFree(pid, "", 0)
	}
}

func (m *MemTraceCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.flush()
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (m *MemTraceCollector) flush() {
	stats := m.detector.GetStats()
	for pid, stat := range stats {
		_ = m.output.WriteEvent(&output.Event{
			Timestamp: time.Now(), ProbeID: m.probeID, Category: "performance", EventType: "mem",
			Details: fmt.Sprintf("pid=%d alloc=%d free=%d current=%d", pid, stat.AllocCount, stat.FreeCount, stat.CurrentAlloc),
			Tags: fmt.Sprintf("large=%d", stat.LargeAlloc),
		})
	}
	m.detector.Reset()
}

func (m *MemTraceCollector) Stop() {
	close(m.stopCh)
	m.running = false
	if m.reader != nil { m.reader.Close() }
	for _, l := range m.links { l.Close() }
	if m.coll != nil { m.coll.Close() }
}

func (m *MemTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": m.Name(), "running": m.running, "category": m.Category()}
}
