package protocol

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// DNSEvent 完整DNS事件
type DNSEvent struct {
	Timestamp     int64    `json:"timestamp"`
	PID           uint32   `json:"pid"`
	SrcIP         string   `json:"src_ip"`
	DstIP         string   `json:"dst_ip"`
	SrcPort       uint16   `json:"src_port"`
	DstPort       uint16   `json:"dst_port"`
	QueryID       uint16   `json:"query_id"`
	QType         string   `json:"q_type"`
	QName         string   `json:"q_name"`
	RCode         uint8    `json:"r_code"`
	Answers       []string `json:"answers"`
	LatencyMs     int64    `json:"latency_ms"`
	Direction     uint8    `json:"direction"` // 0=查询 1=响应
	IsNXDOMAIN    bool     `json:"is_nxdomain"`
	IsSuspicious  bool     `json:"is_suspicious"`
	IsTunnel      bool     `json:"is_tunnel"`
	IsTimeout     bool     `json:"is_timeout"`
}

// DNSMatchKey 查询-响应匹配键
type DNSMatchKey struct {
	QueryID uint16
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// DNSPending 待匹配的DNS查询
type DNSPending struct {
	Key       DNSMatchKey
	QName     string
	QType     string
	Timestamp time.Time
}

// DNSMatcher DNS查询-响应匹配器
type DNSMatcher struct {
	mu       sync.RWMutex
	requests map[DNSMatchKey]*DNSPending
	window   time.Duration
}

func NewDNSMatcher(window time.Duration) *DNSMatcher {
	if window <= 0 {
		window = 10 * time.Second
	}
	m := &DNSMatcher{
		requests: make(map[DNSMatchKey]*DNSPending),
		window:   window,
	}
	go m.cleanupLoop()
	return m
}

func (m *DNSMatcher) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.cleanup(time.Now().Add(-m.window))
	}
}

func (m *DNSMatcher) cleanup(before time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.requests {
		if v.Timestamp.Before(before) {
			delete(m.requests, k)
		}
	}
}

// RecordQuery 记录DNS查询等待响应
func (m *DNSMatcher) RecordQuery(key DNSMatchKey, qname, qtype string, ts time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[key] = &DNSPending{
		Key:       key,
		QName:     qname,
		QType:     qtype,
		Timestamp: ts,
	}
}

// MatchResponse 匹配DNS响应并计算延迟
func (m *DNSMatcher) MatchResponse(key DNSMatchKey) (*DNSPending, int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[key]
	if !ok {
		return nil, 0, false
	}
	latency := time.Since(req.Timestamp).Milliseconds()
	delete(m.requests, key)
	return req, latency, true
}

// ParseDNSPacket 解析完整DNS报文
func ParseDNSPacket(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *DNSEvent {
	if len(payload) < 12 {
		return nil
	}
	rec := &DNSEvent{
		Timestamp: time.Now().UnixMilli(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		Direction: direction,
	}
	// Transaction ID
	rec.QueryID = binary.BigEndian.Uint16(payload[0:2])
	// Flags
	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := (flags >> 15) & 1
	rec.RCode = uint8(flags & 0x0F)
	rec.IsNXDOMAIN = rec.RCode == 3

	questions := binary.BigEndian.Uint16(payload[4:6])
	answerRRs := binary.BigEndian.Uint16(payload[6:8])
	authorityRRs := binary.BigEndian.Uint16(payload[8:10])
	additionalRRs := binary.BigEndian.Uint16(payload[10:12])
	_ = authorityRRs
	_ = additionalRRs

	offset := 12
	// Parse questions
	if questions > 0 {
		name, newOffset := parseDNSName(payload, offset)
		if newOffset < 0 || newOffset+2 > len(payload) {
			return nil
		}
		rec.QName = name
		rec.QType = queryTypeName(binary.BigEndian.Uint16(payload[newOffset : newOffset+2]))
		offset = newOffset + 4 // skip QType + QClass
	}

	// Parse answers (if response)
	if isResponse == 1 && answerRRs > 0 {
		for i := 0; i < int(answerRRs) && offset < len(payload); i++ {
			name, newOffset := parseDNSName(payload, offset)
			if newOffset < 0 || newOffset+10 > len(payload) {
				break
			}
			atype := binary.BigEndian.Uint16(payload[newOffset : newOffset+2])
			aclass := binary.BigEndian.Uint16(payload[newOffset+2 : newOffset+4])
			ttl := binary.BigEndian.Uint32(payload[newOffset+4 : newOffset+8])
			rdlen := binary.BigEndian.Uint16(payload[newOffset+8 : newOffset+10])
			newOffset += 10
			if newOffset+int(rdlen) > len(payload) {
				break
			}
			rdata := payload[newOffset : newOffset+int(rdlen)]
			answer := fmt.Sprintf("%s %s %d %s", name, queryTypeName(atype), ttl, parseRData(atype, aclass, rdata))
			rec.Answers = append(rec.Answers, answer)
			offset = newOffset + int(rdlen)
		}
	}

	rec.IsSuspicious = DetectDGADomain(rec.QName)
	rec.IsTunnel = DetectDNSTunnel(rec.QName)
	return rec
}

// parseDNSName 解析DNS域名，支持压缩指针
func parseDNSName(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", -1
	}
	var parts []string
	jumped := false
	originalOffset := offset
	maxJumps := 5
	jumps := 0

	for {
		if offset >= len(data) {
			return "", -1
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// Compression pointer: 0xC0 | offset
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", -1
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
			}
			if jumps >= maxJumps {
				return "", -1
			}
			jumps++
			offset = pointer
			jumped = true
			continue
		}
		if length > 63 {
			return "", -1
		}
		if offset+1+length > len(data) {
			return "", -1
		}
		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	if jumped {
		return strings.Join(parts, "."), originalOffset
	}
	return strings.Join(parts, "."), offset
}

// parseRData 解析资源记录数据
func parseRData(atype, aclass uint16, rdata []byte) string {
	if aclass != 1 { // IN class
		return fmt.Sprintf("CLASS%d:%x", aclass, rdata)
	}
	switch atype {
	case 1: // A
		if len(rdata) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case 2, 5, 12: // NS, CNAME, PTR
		name, _ := parseDNSName(rdata, 0)
		return name
	case 15: // MX
		if len(rdata) >= 2 {
			pref := binary.BigEndian.Uint16(rdata[0:2])
			name, _ := parseDNSName(rdata, 2)
			return fmt.Sprintf("%d %s", pref, name)
		}
	case 16: // TXT
		return string(rdata)
	case 28: // AAAA
		if len(rdata) == 16 {
			return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(rdata[0:2]), binary.BigEndian.Uint16(rdata[2:4]),
				binary.BigEndian.Uint16(rdata[4:6]), binary.BigEndian.Uint16(rdata[6:8]),
				binary.BigEndian.Uint16(rdata[8:10]), binary.BigEndian.Uint16(rdata[10:12]),
				binary.BigEndian.Uint16(rdata[12:14]), binary.BigEndian.Uint16(rdata[14:16]))
		}
	case 33: // SRV
		if len(rdata) >= 6 {
			priority := binary.BigEndian.Uint16(rdata[0:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			name, _ := parseDNSName(rdata, 6)
			return fmt.Sprintf("%d %d %d %s", priority, weight, port, name)
		}
	}
	return fmt.Sprintf("%x", rdata)
}

func queryTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// DetectDGADomain DGA域名检测
func DetectDGADomain(domain string) bool {
	if len(domain) > 50 {
		return true
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	subdomain := parts[0]
	if len(subdomain) > 20 {
		entropy := calculateEntropy(subdomain)
		if entropy > 3.5 {
			return true
		}
	}
	return false
}

// DetectDNSTunnel DNS隧道检测
func DetectDNSTunnel(domain string) bool {
	if len(domain) > 60 {
		return true
	}
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		if len(p) > 30 {
			return true
		}
	}
	return false
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(s))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// DNSRecord 向后兼容
type DNSRecord struct {
	Timestamp     time.Time
	ProbeID       string
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	QueryName     string
	QueryType     string
	ResponseCode  int
	LatencyMs     float64
	IsNXDOMAIN    bool
	IsSuspicious  bool
	IsTunnel      bool
}

func ParseDNS(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) *DNSRecord {
	if len(payload) < 12 {
		return nil
	}
	rec := &DNSRecord{
		Timestamp: time.Now(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	rec.ResponseCode = int(flags & 0x0F)
	rec.IsNXDOMAIN = rec.ResponseCode == 3
	questions := binary.BigEndian.Uint16(payload[4:6])
	if questions == 0 {
		return nil
	}
	offset := 12
	var nameParts []string
	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			offset += 2
			break
		}
		if offset+1+length > len(payload) {
			break
		}
		nameParts = append(nameParts, string(payload[offset+1:offset+1+length]))
		offset += 1 + length
	}
	rec.QueryName = strings.Join(nameParts, ".")
	rec.QueryType = queryTypeName(binary.BigEndian.Uint16(payload[offset : offset+2]))
	rec.IsSuspicious = DetectDGADomain(rec.QueryName)
	rec.IsTunnel = DetectDNSTunnel(rec.QueryName)
	return rec
}

// BuildDNSEvent 构建完整DNS事件
func BuildDNSEvent(query, response *DNSEvent) *DNSEvent {
	if query == nil || response == nil {
		return nil
	}
	return &DNSEvent{
		Timestamp:    query.Timestamp,
		PID:          query.PID,
		SrcIP:        query.SrcIP,
		DstIP:        query.DstIP,
		SrcPort:      query.SrcPort,
		DstPort:      query.DstPort,
		QueryID:      query.QueryID,
		QType:        query.QType,
		QName:        query.QName,
		RCode:        response.RCode,
		Answers:      response.Answers,
		LatencyMs:    response.LatencyMs,
		Direction:    1,
		IsNXDOMAIN:   response.IsNXDOMAIN,
		IsSuspicious: query.IsSuspicious || response.IsSuspicious,
		IsTunnel:     query.IsTunnel || response.IsTunnel,
	}
}
