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

//go:embed syscall.bpf.o
var syscallBpfO []byte

type SyscallCollector struct {
	output  output.Writer
	probeID string
	running bool
	stopCh  chan struct{}
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
}

func NewSyscallCollector(out output.Writer, probeID string) *SyscallCollector {
	return &SyscallCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (s *SyscallCollector) Name() string   { return "syscall" }
func (s *SyscallCollector) Category() string { return "syscall" }

func (s *SyscallCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFTracepoint {
		return fmt.Errorf("no tracepoint support")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallBpfO))
	if err != nil {
		return fmt.Errorf("load syscall spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load syscall collection: %w", err)
	}
	s.coll = loaded

	if prog := loaded.Programs["tracepoint_sys_enter"]; prog != nil {
		l, err := link.Tracepoint("raw_syscalls", "sys_enter", prog, nil)
		if err != nil {
			log.Printf("[SYSCALL] attach sys_enter: %v", err)
		} else {
			s.links = append(s.links, l)
		}
	}
	if prog := loaded.Programs["tracepoint_sys_exit"]; prog != nil {
		l, err := link.Tracepoint("raw_syscalls", "sys_exit", prog, nil)
		if err != nil {
			log.Printf("[SYSCALL] attach sys_exit: %v", err)
		} else {
			s.links = append(s.links, l)
		}
	}

	rb := loaded.Maps["rb"]
	if rb != nil {
		s.reader, _ = ringbuf.NewReader(rb)
	}

	return nil
}

func (s *SyscallCollector) Start(ctx context.Context) error {
	s.running = true
	if s.reader != nil {
		go s.readLoop()
	}
	return nil
}

func (s *SyscallCollector) readLoop() {
	defer s.reader.Close()
	for s.running {
		record, err := s.reader.Read()
		if err != nil {
			if s.running {
				log.Printf("[SYSCALL] ringbuf read: %v", err)
			}
			continue
		}
		s.handleEvent(record.RawSample)
	}
}

func (s *SyscallCollector) handleEvent(data []byte) {
	if len(data) < 88 {
		return
	}
	pid := binary.LittleEndian.Uint32(data[12:16])
	comm := string(bytes.Trim(data[72:88], "\x00"))
	latencyNs := binary.LittleEndian.Uint64(data[56:64])
	syscallNr := binary.LittleEndian.Uint64(data[64:72])
	count := uint64(1)

	_ = s.output.WriteSyscallEvent(time.Now(), s.probeID, pid, comm, syscallNr, latencyNs, count)
}

func (s *SyscallCollector) Stop() {
	close(s.stopCh)
	s.running = false
	if s.reader != nil { s.reader.Close() }
	for _, l := range s.links { l.Close() }
	if s.coll != nil { s.coll.Close() }
}

func (s *SyscallCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": s.Name(), "running": s.running, "category": s.Category()}
}
