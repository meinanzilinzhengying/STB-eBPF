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
)

//go:embed process_exec.bpf.o
var processExecBpfO []byte

type PerformanceCollector struct {
	output   output.Writer
	probeID  string
	running  bool
	stopCh   chan struct{}
	coll     *ebpf.Collection
	links    []link.Link
	reader   *ringbuf.Reader
}

func NewPerformanceCollector(out output.Writer, probeID string) *PerformanceCollector {
	return &PerformanceCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (p *PerformanceCollector) Name() string   { return "performance" }
func (p *PerformanceCollector) Category() string { return "performance" }

func (p *PerformanceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe && !cap.HasBPFTracepoint {
		return fmt.Errorf("no kprobe/tracepoint support")
	}
	// 加载 BPF 对象
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(processExecBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	p.coll = loaded

	// attach tracepoint
	if prog := loaded.Programs["tracepoint_sched_process_exec"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_process_exec", prog, nil)
		if err != nil {
			log.Printf("[PERF] attach exec tracepoint: %v", err)
		} else {
			p.links = append(p.links, l)
		}
	}
	if prog := loaded.Programs["tracepoint_sched_process_exit"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_process_exit", prog, nil)
		if err != nil {
			log.Printf("[PERF] attach exit tracepoint: %v", err)
		} else {
			p.links = append(p.links, l)
		}
	}

	rbMap := loaded.Maps["rb"]
	if rbMap == nil {
		return fmt.Errorf("ringbuf map not found")
	}
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	p.reader = reader
	return nil
}

func (p *PerformanceCollector) Start(ctx context.Context) error {
	p.running = true
	go func() {
		if p.reader != nil { defer p.reader.Close() }
		for p.running {
			if p.reader == nil { return }
			record, err := p.reader.Read()
			if err != nil {
				if p.running {
					log.Printf("[PERF] ringbuf read: %v", err)
				}
				continue
			}
			p.handleEvent(record.RawSample)
		}
	}()
	return nil
}

func (p *PerformanceCollector) handleEvent(data []byte) {
	if len(data) < 48 {
		return
	}
	timestampNs := binary.LittleEndian.Uint64(data[0:8])
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	ppid := binary.LittleEndian.Uint32(data[16:20])
	comm := string(bytes.Trim(data[72:88], "\x00"))
	argData := string(bytes.Trim(data[88:344], "\x00"))

	_ = timestampNs
	now := time.Now()
	switch etype {
	case 4: // EVENT_TYPE_EXEC
		if err := p.output.WriteProcessEvent(now, p.probeID, pid, ppid, comm, "", argData, "execve"); err != nil { log.Printf("[PERF] WriteProcessEvent failed: %v", err) }
	case 5: // EVENT_TYPE_EXIT
		if err := p.output.WriteProcessEvent(now, p.probeID, pid, ppid, comm, "", "", "exit"); err != nil { log.Printf("[PERF] WriteProcessEvent failed: %v", err) }
	}
}

func (p *PerformanceCollector) Stop() {
	close(p.stopCh)
	p.running = false
	if p.reader != nil {
		p.reader.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}

func (p *PerformanceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": p.Name(), "running": p.running, "category": p.Category()}
}
