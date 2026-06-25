package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

//go:embed security_trace.bpf.o
var securityTraceBpfO []byte

type SecurityTraceCollector struct {
	output    output.Writer
	probeID   string
	running   bool
	stopCh    chan struct{}
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
}

func NewSecurityTraceCollector(out output.Writer, probeID string) *SecurityTraceCollector {
	return &SecurityTraceCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (s *SecurityTraceCollector) Name() string   { return "security_trace" }
func (s *SecurityTraceCollector) Category() string { return "security" }

func (s *SecurityTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe {
		return fmt.Errorf("no kprobe support")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(securityTraceBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	s.coll = loaded

	if prog := loaded.Programs["trace_cap_capable"]; prog != nil {
		l, err := link.Kprobe("cap_capable", prog, nil)
		if err != nil { log.Printf("[SEC] attach cap_capable: %v", err) } else { s.links = append(s.links, l) }
	}
	if prog := loaded.Programs["trace_security_file_open"]; prog != nil {
		l, err := link.Kprobe("security_file_open", prog, nil)
		if err != nil { log.Printf("[SEC] attach security_file_open: %v", err) } else { s.links = append(s.links, l) }
	}
	if prog := loaded.Programs["trace_load_module"]; prog != nil {
		l, err := link.Kprobe("load_module", prog, nil)
		if err != nil { log.Printf("[SEC] attach load_module: %v", err) } else { s.links = append(s.links, l) }
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

func (s *SecurityTraceCollector) Start(ctx context.Context) error {
	s.running = true
	go func() {
		defer s.reader.Close()
		for s.running {
			record, err := s.reader.Read()
			if err != nil {
				if s.running { log.Printf("[SEC] ringbuf read: %v", err) }
				continue
			}
			s.handleEvent(record.RawSample)
		}
	}()
	return nil
}

func (s *SecurityTraceCollector) handleEvent(data []byte) {
	if len(data) < 48 { return }
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	count := binary.LittleEndian.Uint64(data[64:72])
	latency := binary.LittleEndian.Uint64(data[48:56])
	payload := string(bytes.Trim(data[72:328], "\x00"))
	now := time.Now()

	var eventType, details, tags string
	switch etype {
	case 18:
		eventType = "cap_capable"
		details = fmt.Sprintf("pid=%d cap=%d", pid, count)
		tags = fmt.Sprintf("opt=%d", latency)
	case 19:
		eventType = "security_file_open"
		details = fmt.Sprintf("pid=%d file=%s", pid, payload)
		if isSensitiveFile(payload) {
			tags = "sensitive=true"
		}
	case 20:
		eventType = "load_module"
		details = fmt.Sprintf("pid=%d module_load", pid)
		tags = "alert=kernel_module"
	}

	_ = s.output.WriteEvent(&output.Event{
		Timestamp: now, ProbeID: s.probeID, Category: "security", EventType: eventType,
		Details: details, Tags: tags,
	})
}

func isSensitiveFile(filename string) bool {
	sensitive := []string{"/etc/shadow", "/etc/passwd", "/root", "/proc/kcore", "/proc/kallsyms"}
	for _, s := range sensitive {
		if strings.Contains(filename, s) {
			return true
		}
	}
	return false
}

func (s *SecurityTraceCollector) Stop() {
	close(s.stopCh)
	s.running = false
	if s.reader != nil { s.reader.Close() }
	for _, l := range s.links { l.Close() }
	if s.coll != nil { s.coll.Close() }
}

func (s *SecurityTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": s.Name(), "running": s.running, "category": s.Category()}
}
