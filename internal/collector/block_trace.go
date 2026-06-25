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

//go:embed block_trace.bpf.o
var blockTraceBpfO []byte

type BlockTraceCollector struct {
	output    output.Writer
	probeID   string
	running   bool
	stopCh    chan struct{}
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	analyzer  *perf.BlockIOAnalyzer
}

func NewBlockTraceCollector(out output.Writer, probeID string) *BlockTraceCollector {
	return &BlockTraceCollector{
		output:   out,
		probeID:  probeID,
		stopCh:   make(chan struct{}),
		analyzer: perf.NewBlockIOAnalyzer(),
	}
}

func (b *BlockTraceCollector) Name() string   { return "block_trace" }
func (b *BlockTraceCollector) Category() string { return "performance" }

func (b *BlockTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFTracepoint {
		return fmt.Errorf("no tracepoint support")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(blockTraceBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	b.coll = loaded

	if prog := loaded.Programs["tracepoint_block_rq_issue"]; prog != nil {
		l, err := link.Tracepoint("block", "block_rq_issue", prog, nil)
		if err != nil { log.Printf("[BLOCK] attach block_rq_issue: %v", err) } else { b.links = append(b.links, l) }
	}
	if prog := loaded.Programs["tracepoint_block_rq_complete"]; prog != nil {
		l, err := link.Tracepoint("block", "block_rq_complete", prog, nil)
		if err != nil { log.Printf("[BLOCK] attach block_rq_complete: %v", err) } else { b.links = append(b.links, l) }
	}

	rbMap := loaded.Maps["rb"]
	if rbMap == nil {
		return fmt.Errorf("ringbuf map not found")
	}
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	b.reader = reader
	return nil
}

func (b *BlockTraceCollector) Start(ctx context.Context) error {
	b.running = true
	go b.readLoop()
	go b.flushLoop(ctx)
	return nil
}

func (b *BlockTraceCollector) readLoop() {
	defer b.reader.Close()
	for b.running {
		record, err := b.reader.Read()
		if err != nil {
			if b.running { log.Printf("[BLOCK] ringbuf read: %v", err) }
			continue
		}
		b.handleEvent(record.RawSample)
	}
}

func (b *BlockTraceCollector) handleEvent(data []byte) {
	if len(data) < 48 { return }
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	bytes := binary.LittleEndian.Uint64(data[40:48])
	latency := binary.LittleEndian.Uint64(data[48:56])
	now := time.Now()
	_ = pid

	if etype == 16 { // block_issue
		b.analyzer.RecordIssue(uint64(pid), bytes, latency, now)
	} else if etype == 17 { // block_complete
		b.analyzer.RecordComplete(uint64(pid), bytes, now)
	}
}

func (b *BlockTraceCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.flush()
		case <-b.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (b *BlockTraceCollector) flush() {
	stats := b.analyzer.GetStats()
	for _, stat := range stats {
		_ = b.output.WriteEvent(&output.Event{
			Timestamp: time.Now(), ProbeID: b.probeID, Category: "performance", EventType: "block",
			Details: fmt.Sprintf("dev=%d iops=%.0f bw=%.0fB/s", stat.Dev, stat.IOPS, stat.ThroughputBps),
			Tags: fmt.Sprintf("avg=%dns,max=%dns", stat.AvgLatencyNs, stat.MaxLatencyNs),
		})
	}
	b.analyzer.Reset()
}

func (b *BlockTraceCollector) Stop() {
	close(b.stopCh)
	b.running = false
	if b.reader != nil { b.reader.Close() }
	for _, l := range b.links { l.Close() }
	if b.coll != nil { b.coll.Close() }
}

func (b *BlockTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": b.Name(), "running": b.running, "category": b.Category()}
}
