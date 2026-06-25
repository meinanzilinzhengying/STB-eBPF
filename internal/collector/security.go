package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

//go:embed file_open.bpf.o
var fileOpenBpfO []byte

//go:embed tcp_connect.bpf.o
var tcpConnectBpfO []byte

type SecurityCollector struct {
	output      output.Writer
	probeID     string
	running     bool
	stopCh      chan struct{}
	fileColl    *ebpf.Collection
	tcpColl     *ebpf.Collection
	fileLinks   []link.Link
	tcpLinks    []link.Link
	fileReader  *ringbuf.Reader
	tcpReader   *ringbuf.Reader
}

func NewSecurityCollector(out output.Writer, probeID string) *SecurityCollector {
	return &SecurityCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (s *SecurityCollector) Name() string   { return "security" }
func (s *SecurityCollector) Category() string { return "security" }

func (s *SecurityCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFLSM && !cap.HasBPFKprobe {
		return fmt.Errorf("no lsm/kprobe support")
	}
	// 加载 file_open bpf
	fileSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fileOpenBpfO))
	if err != nil {
		return fmt.Errorf("load file_open spec: %w", err)
	}
	fileLoaded, err := ebpf.NewCollection(fileSpec)
	if err != nil {
		return fmt.Errorf("load file_open collection: %w", err)
	}
	s.fileColl = fileLoaded

	if prog := fileLoaded.Programs["trace_do_filp_open"]; prog != nil {
		l, err := link.Kprobe("do_filp_open", prog, nil)
		if err != nil {
			log.Printf("[SEC] attach do_filp_open: %v", err)
		} else {
			s.fileLinks = append(s.fileLinks, l)
		}
	}
	if prog := fileLoaded.Programs["trace_vfs_write"]; prog != nil {
		l, err := link.Kprobe("vfs_write", prog, nil)
		if err != nil {
			log.Printf("[SEC] attach vfs_write: %v", err)
		} else {
			s.fileLinks = append(s.fileLinks, l)
		}
	}

	fileRb := fileLoaded.Maps["rb"]
	if fileRb != nil {
		s.fileReader, _ = ringbuf.NewReader(fileRb)
	}

	// 加载 tcp_connect bpf
	tcpSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcpConnectBpfO))
	if err != nil {
		return fmt.Errorf("load tcp_connect spec: %w", err)
	}
	tcpLoaded, err := ebpf.NewCollection(tcpSpec)
	if err != nil {
		return fmt.Errorf("load tcp_connect collection: %w", err)
	}
	s.tcpColl = tcpLoaded

	if prog := tcpLoaded.Programs["trace_tcp_v4_connect"]; prog != nil {
		l, err := link.Kprobe("tcp_v4_connect", prog, nil)
		if err != nil {
			log.Printf("[SEC] attach tcp_v4_connect: %v", err)
		} else {
			s.tcpLinks = append(s.tcpLinks, l)
		}
	}
	if prog := tcpLoaded.Programs["trace_tcp_v4_connect_exit"]; prog != nil {
		l, err := link.Kretprobe("tcp_v4_connect", prog, nil)
		if err != nil {
			log.Printf("[SEC] attach tcp_v4_connect ret: %v", err)
		} else {
			s.tcpLinks = append(s.tcpLinks, l)
		}
	}

	tcpRb := tcpLoaded.Maps["rb"]
	if tcpRb != nil {
		s.tcpReader, _ = ringbuf.NewReader(tcpRb)
	}

	return nil
}

func (s *SecurityCollector) Start(ctx context.Context) error {
	s.running = true
	if s.fileReader != nil {
		go s.readLoop(s.fileReader, "file")
	}
	if s.tcpReader != nil {
		go s.readLoop(s.tcpReader, "tcp")
	}
	return nil
}

func (s *SecurityCollector) readLoop(reader *ringbuf.Reader, label string) {
	defer reader.Close()
	for s.running {
		record, err := reader.Read()
		if err != nil {
			if s.running {
				log.Printf("[SEC] %s ringbuf read: %v", label, err)
			}
			continue
		}
		s.handleEvent(record.RawSample)
	}
}

func (s *SecurityCollector) handleEvent(data []byte) {
	if len(data) < 48 {
		return
	}
	timestampNs := binary.LittleEndian.Uint64(data[0:8])
	etype := binary.LittleEndian.Uint32(data[8:12])
	pid := binary.LittleEndian.Uint32(data[12:16])
	comm := string(bytes.Trim(data[72:88], "\x00"))
	rawData := data[88:344]
	nullIdx := bytes.IndexByte(rawData, 0)
	if nullIdx >= 0 {
		rawData = rawData[:nullIdx]
	}
	dataStr := string(rawData)
	now := ebpfTimeToWallTime(timestampNs)

	switch etype {
	case 6: // EVENT_TYPE_FILE_OPEN
		if err := s.output.WriteFileEvent(now, s.probeID, pid, comm, dataStr, "open", 0); err != nil { log.Printf("[SEC] WriteFileEvent failed: %v", err) }
	case 7: // EVENT_TYPE_TCP_CONNECT
		if err := s.output.WriteEvent(&output.Event{
			Timestamp: now, ProbeID: s.probeID, Category: "security", EventType: "connect",
			Details: fmt.Sprintf("pid=%d comm=%s", pid, comm),
		}); err != nil {
			log.Printf("[SEC] WriteEvent failed: %v", err)
		}
	}
}

func (s *SecurityCollector) Stop() {
	close(s.stopCh)
	s.running = false
	if s.fileReader != nil { s.fileReader.Close() }
	if s.tcpReader != nil { s.tcpReader.Close() }
	for _, l := range s.fileLinks { l.Close() }
	for _, l := range s.tcpLinks { l.Close() }
	if s.fileColl != nil { s.fileColl.Close() }
	if s.tcpColl != nil { s.tcpColl.Close() }
}

func (s *SecurityCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": s.Name(), "running": s.running, "category": s.Category()}
}
