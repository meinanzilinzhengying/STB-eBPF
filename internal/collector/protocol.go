package collector

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

type ProtocolCollector struct {
	output   output.Writer
	probeID  string
	iface    string
	running  bool
	stopCh   chan struct{}
	mu       sync.Mutex
	flows    map[string]*FlowRecord
	httpReqs []HTTPRecord
	dnsQs    []DNSRecord
}

type FlowRecord struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
	Bytes    uint64
	Packets  uint64
	SynFlag  bool
	FinFlag  bool
	RstFlag  bool
}

type HTTPRecord struct {
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Method     string
	Host       string
	URL        string
	StatusCode int
	Bytes      uint64
	LatencyMs  float64
}

type DNSRecord struct {
	SrcIP     string
	DstIP     string
	QueryName string
	QueryType string
}

func NewProtocolCollector(out output.Writer, probeID, iface string) *ProtocolCollector {
	return &ProtocolCollector{
		output:   out, probeID: probeID, iface: iface, stopCh: make(chan struct{}),
		flows:    make(map[string]*FlowRecord),
		httpReqs: make([]HTTPRecord, 0),
		dnsQs:    make([]DNSRecord, 0),
	}
}

func (p *ProtocolCollector) Name() string   { return "protocol" }
func (p *ProtocolCollector) Category() string { return "protocol" }
func (p *ProtocolCollector) Init(cap kernel.Capabilities) error { return nil }

func (p *ProtocolCollector) Start(ctx context.Context) error {
	p.running = true
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("AF_PACKET failed: %w", err)
	}
	go p.captureLoop(fd)
	go p.flushLoop(ctx)
	return nil
}

func (p *ProtocolCollector) captureLoop(fd int) {
	defer syscall.Close(fd)
	buf := make([]byte, 65536)
	for p.running {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if strings.Contains(err.Error(), "interrupted") { continue }
			log.Printf("[PROTOCOL] read error: %v", err)
			continue
		}
		if n < 14 { continue }
		if buf[12] == 0x08 && buf[13] == 0x00 {
			p.processIPv4(buf[14:n])
		}
	}
}

func (p *ProtocolCollector) processIPv4(payload []byte) {
	if len(payload) < 20 { return }
	versionIHL := payload[0]
	ihl := int(versionIHL&0x0F) * 4
	if ihl > len(payload) { return }
	protocol := payload[9]
	srcIP := net.IP(payload[12:16]).String()
	dstIP := net.IP(payload[16:20]).String()
	if srcIP == "127.0.0.1" || dstIP == "127.0.0.1" { return }
	protoName := "IP"
	srcPort, dstPort := uint16(0), uint16(0)
	var tcpFlags uint8 = 0
	var tcpPayload []byte
	switch protocol {
	case 6:
		protoName = "TCP"
		if len(payload) >= ihl+20 {
			srcPort = binary.BigEndian.Uint16(payload[ihl : ihl+2])
			dstPort = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
			tcpFlags = payload[ihl+13]
			tcpDataOffset := int((payload[ihl+12] >> 4) * 4)
			if ihl+tcpDataOffset < len(payload) { tcpPayload = payload[ihl+tcpDataOffset:] }
		}
		if (dstPort == 80 || dstPort == 8080 || dstPort == 8000 || dstPort == 3000 || dstPort == 443 || dstPort == 8443 || (dstPort >= 8000 && dstPort <= 9999)) && len(tcpPayload) > 0 {
			if httpRec := p.parseHTTP(tcpPayload, srcIP, dstIP, srcPort, dstPort); httpRec != nil {
				p.mu.Lock()
				p.httpReqs = append(p.httpReqs, *httpRec)
				if len(p.httpReqs) > 1000 { p.httpReqs = p.httpReqs[len(p.httpReqs)-500:] }
				p.mu.Unlock()
			}
		}
	case 17:
		protoName = "UDP"
		if len(payload) >= ihl+8 {
			srcPort = binary.BigEndian.Uint16(payload[ihl : ihl+2])
			dstPort = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
		}
		if (srcPort == 53 || dstPort == 53) && len(payload) > ihl+8 {
			dnsPayload := payload[ihl+8:]
			if dnsRec := p.parseDNS(dnsPayload, srcIP, dstIP, srcPort, dstPort); dnsRec != nil {
				p.mu.Lock()
				p.dnsQs = append(p.dnsQs, *dnsRec)
				if len(p.dnsQs) > 1000 { p.dnsQs = p.dnsQs[len(p.dnsQs)-500:] }
				p.mu.Unlock()
			}
		}
	case 1:
		protoName = "ICMP"
	}
	key := fmt.Sprintf("%s:%d->%s:%d:%s", srcIP, srcPort, dstIP, dstPort, protoName)
	p.mu.Lock()
	synFlag := (tcpFlags & 0x02) != 0
	finFlag := (tcpFlags & 0x01) != 0
	rstFlag := (tcpFlags & 0x04) != 0
	if ag, ok := p.flows[key]; ok {
		ag.Bytes += uint64(len(payload))
		ag.Packets++
		if synFlag { ag.SynFlag = true }
		if finFlag { ag.FinFlag = true }
		if rstFlag { ag.RstFlag = true }
	} else {
		p.flows[key] = &FlowRecord{
			SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
			Protocol: protoName, Bytes: uint64(len(payload)), Packets: 1,
			SynFlag: synFlag, FinFlag: finFlag, RstFlag: rstFlag,
		}
	}
	p.mu.Unlock()
}

func (p *ProtocolCollector) parseHTTP(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) *HTTPRecord {
	text := string(payload)
	if len(text) < 8 { return nil }
	if strings.HasPrefix(text, "GET ") || strings.HasPrefix(text, "POST ") || strings.HasPrefix(text, "PUT ") || strings.HasPrefix(text, "DELETE ") || strings.HasPrefix(text, "HEAD ") || strings.HasPrefix(text, "PATCH ") || strings.HasPrefix(text, "OPTIONS ") {
		rec := &HTTPRecord{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Bytes: uint64(len(payload))}
		parts := strings.SplitN(text, " ", 3)
		if len(parts) >= 2 { rec.Method = parts[0]; rec.URL = parts[1] }
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.ToLower(line), "host:") { rec.Host = strings.TrimSpace(line[5:]); break }
		}
		return rec
	}
	if strings.HasPrefix(text, "HTTP/") {
		rec := &HTTPRecord{SrcIP: dstIP, DstIP: srcIP, SrcPort: dstPort, DstPort: srcPort, Bytes: uint64(len(payload))}
		parts := strings.SplitN(text, " ", 3)
		if len(parts) >= 2 { code, _ := strconv.Atoi(parts[1]); rec.StatusCode = code }
		return rec
	}
	return nil
}

func (p *ProtocolCollector) parseDNS(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) *DNSRecord {
	if len(payload) < 12 { return nil }
	questions := binary.BigEndian.Uint16(payload[4:6])
	if questions == 0 { return nil }
	rec := &DNSRecord{SrcIP: srcIP, DstIP: dstIP}
	offset := 12
	var nameParts []string
	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 { break }
		if length&0xC0 == 0xC0 { offset += 2; break }
		if offset+1+length > len(payload) { break }
		nameParts = append(nameParts, string(payload[offset+1:offset+1+length]))
		offset += 1 + length
	}
	rec.QueryName = strings.Join(nameParts, ".")
	if offset+4 <= len(payload) {
		qtype := binary.BigEndian.Uint16(payload[offset+2:])
		switch qtype {
		case 1: rec.QueryType = "A"
		case 28: rec.QueryType = "AAAA"
		case 5: rec.QueryType = "CNAME"
		case 15: rec.QueryType = "MX"
		case 16: rec.QueryType = "TXT"
		case 2: rec.QueryType = "NS"
		default: rec.QueryType = fmt.Sprintf("TYPE%d", qtype)
		}
	}
	return rec
}

func (p *ProtocolCollector) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C: p.flush()
		case <-p.stopCh: return
		case <-ctx.Done(): return
		}
	}
}

func (p *ProtocolCollector) flush() {
	p.mu.Lock()
	snapshot := p.flows; p.flows = make(map[string]*FlowRecord)
	httpSnapshot := p.httpReqs; p.httpReqs = nil
	dnsSnapshot := p.dnsQs; p.dnsQs = nil
	p.mu.Unlock()

	now := time.Now()
	for _, ag := range snapshot {
		_ = p.output.WriteEvent(&output.Event{
			Timestamp: now, ProbeID: p.probeID, Category: "protocol", EventType: "flow",
			SrcIP: ag.SrcIP, DstIP: ag.DstIP, SrcPort: ag.SrcPort, DstPort: ag.DstPort,
			Protocol: ag.Protocol, Bytes: ag.Bytes, Packets: ag.Packets,
		})
	}
	for _, hr := range httpSnapshot {
		_ = p.output.WriteEvent(&output.Event{
			Timestamp: now, ProbeID: p.probeID, Category: "protocol", EventType: "http",
			SrcIP: hr.SrcIP, DstIP: hr.DstIP, SrcPort: hr.SrcPort, DstPort: hr.DstPort,
			Protocol: "HTTP", Bytes: hr.Bytes, LatencyMs: hr.LatencyMs,
			Service: hr.Host, Details: hr.Method + " " + hr.URL,
		})
	}
	for _, dr := range dnsSnapshot {
		_ = p.output.WriteEvent(&output.Event{
			Timestamp: now, ProbeID: p.probeID, Category: "protocol", EventType: "dns",
			SrcIP: dr.SrcIP, DstIP: dr.DstIP, SrcPort: 53, DstPort: 53,
			Protocol: "DNS", Details: dr.QueryName, Tags: dr.QueryType,
		})
	}
}

func (p *ProtocolCollector) Stop() {
	close(p.stopCh)
	p.running = false
}

func (p *ProtocolCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": p.Name(), "running": p.running, "category": p.Category()}
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }
