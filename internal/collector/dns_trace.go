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

//go:embed dns_trace.bpf.o
var dnsTraceBpfO []byte

type DNSTraceCollector struct {
	output    output.Writer
	probeID   string
	running   bool
	stopCh    chan struct{}
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
}

func NewDNSTraceCollector(out output.Writer, probeID string) *DNSTraceCollector {
	return &DNSTraceCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (d *DNSTraceCollector) Name() string   { return "dns_trace" }
func (d *DNSTraceCollector) Category() string { return "protocol" }

func (d *DNSTraceCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFKprobe {
		return fmt.Errorf("no kprobe support")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dnsTraceBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	d.coll = loaded

	if prog := loaded.Programs["trace_udp_sendmsg"]; prog != nil {
		l, err := link.Kprobe("udp_sendmsg", prog, nil)
		if err != nil { log.Printf("[DNS] attach udp_sendmsg: %v", err) } else { d.links = append(d.links, l) }
	}
	if prog := loaded.Programs["trace_udp_recvmsg"]; prog != nil {
		l, err := link.Kprobe("udp_recvmsg", prog, nil)
		if err != nil { log.Printf("[DNS] attach udp_recvmsg: %v", err) } else { d.links = append(d.links, l) }
	}

	rbMap := loaded.Maps["rb"]
	if rbMap == nil {
		return fmt.Errorf("ringbuf map not found")
	}
	reader, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	d.reader = reader
	return nil
}

func (d *DNSTraceCollector) Start(ctx context.Context) error {
	d.running = true
	go func() {
		defer d.reader.Close()
		for d.running {
			record, err := d.reader.Read()
			if err != nil {
				if d.running { log.Printf("[DNS] ringbuf read: %v", err) }
				continue
			}
			d.handleEvent(record.RawSample)
		}
	}()
	return nil
}

func (d *DNSTraceCollector) handleEvent(data []byte) {
	if len(data) < 48 { return }
	etype := binary.LittleEndian.Uint32(data[8:12])
	if etype != 3 { return }
	pid := binary.LittleEndian.Uint32(data[12:16])
	srcIP := binary.LittleEndian.Uint32(data[20:24])
	dstIP := binary.LittleEndian.Uint32(data[24:28])
	srcPort := binary.LittleEndian.Uint16(data[28:30])
	dstPort := binary.LittleEndian.Uint16(data[30:32])
	_ = pid

	payload := data[72:328]
	now := time.Now()

	// 直接上报原始payload，不做协议解析（协议解析在Edge层完成）
	_ = d.output.WriteEvent(&output.Event{
		Timestamp: now, ProbeID: d.probeID, Category: "protocol", EventType: "dns_raw",
		SrcIP: ipToString(srcIP), DstIP: ipToString(dstIP), SrcPort: srcPort, DstPort: dstPort,
		Protocol: "DNS", Bytes: uint64(len(payload)),
		Details: string(payload), // 原始payload，由Edge解析
		Tags: fmt.Sprintf("etype=%d", etype),
	})
}

func (d *DNSTraceCollector) Stop() {
	close(d.stopCh)
	d.running = false
	if d.reader != nil { d.reader.Close() }
	for _, l := range d.links { l.Close() }
	if d.coll != nil { d.coll.Close() }
}

func (d *DNSTraceCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": d.Name(), "running": d.running, "category": d.Category()}
}
