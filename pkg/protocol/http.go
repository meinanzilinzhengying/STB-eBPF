package protocol

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// HTTPEvent 完整HTTP事件
type HTTPEvent struct {
	Timestamp     int64  `json:"timestamp"`
	PID           uint32 `json:"pid"`
	Comm          string `json:"comm"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	Host          string `json:"host"`
	UserAgent     string `json:"user_agent"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	LatencyMs     int64  `json:"latency_ms"`
	Direction     uint8  `json:"direction"` // 0=请求 1=响应
}

// HTTPMatchKey 五元组匹配键
type HTTPMatchKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// HTTPPending 待匹配的请求
type HTTPPending struct {
	Key       HTTPMatchKey
	Method    string
	URL       string
	Host      string
	UserAgent string
	Timestamp time.Time
}

// HTTPMatcher 请求-响应匹配器
type HTTPMatcher struct {
	mu       sync.RWMutex
	requests map[HTTPMatchKey]*HTTPPending
	window   time.Duration
}

func NewHTTPMatcher(window time.Duration) *HTTPMatcher {
	if window <= 0 {
		window = 30 * time.Second
	}
	m := &HTTPMatcher{
		requests: make(map[HTTPMatchKey]*HTTPPending),
		window:   window,
	}
	go m.cleanupLoop()
	return m
}

func (m *HTTPMatcher) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.cleanup(time.Now().Add(-m.window))
	}
}

func (m *HTTPMatcher) cleanup(before time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.requests {
		if v.Timestamp.Before(before) {
			delete(m.requests, k)
		}
	}
}

// RecordRequest 记录请求等待响应
func (m *HTTPMatcher) RecordRequest(key HTTPMatchKey, method, url, host, ua string, ts time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[key] = &HTTPPending{
		Key:       key,
		Method:    method,
		URL:       url,
		Host:      host,
		UserAgent: ua,
		Timestamp: ts,
	}
}

// MatchResponse 匹配响应并计算延迟
func (m *HTTPMatcher) MatchResponse(key HTTPMatchKey) (*HTTPPending, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[key]
	if !ok {
		return nil, 0
	}
	latency := time.Since(req.Timestamp).Milliseconds()
	delete(m.requests, key)
	return req, latency
}

// ParseHTTPRequest 解析HTTP请求
func ParseHTTPRequest(data []byte) (method, url, host, ua string, ok bool) {
	reader := bufio.NewReader(bytes.NewReader(data))
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 8 {
		return
	}
	upper := strings.ToUpper(line)
	if !strings.Contains(upper, "HTTP/") {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return
	}
	method = parts[0]
	url = parts[1]
	ok = true

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "host":
			host = val
		case "user-agent":
			ua = val
		}
	}
	return
}

// ParseHTTPResponse 解析HTTP响应
func ParseHTTPResponse(data []byte) (statusCode int, contentLength int64, ok bool) {
	reader := bufio.NewReader(bytes.NewReader(data))
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 12 {
		return
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return
	}
	fmt.Sscanf(parts[1], "%d", &statusCode)
	ok = true

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		if key == "content-length" {
			fmt.Sscanf(val, "%d", &contentLength)
		}
	}
	return
}

// IsChunked 检测是否chunked编码
func IsChunked(data []byte) bool {
	return bytes.Contains(bytes.ToLower(data), []byte("transfer-encoding: chunked"))
}

// IsGzipResponse 检测是否gzip压缩
func IsGzipResponse(data []byte) bool {
	return bytes.Contains(bytes.ToLower(data), []byte("content-encoding: gzip"))
}

// DecompressGzipBody 解压gzip body
func DecompressGzipBody(body []byte) ([]byte, error) {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// DetectHTTPMethod 从payload快速检测HTTP方法
func DetectHTTPMethod(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	// 请求
	if bytes.HasPrefix(data, []byte("GET ")) {
		return "GET"
	}
	if bytes.HasPrefix(data, []byte("POST ")) {
		return "POST"
	}
	if bytes.HasPrefix(data, []byte("PUT ")) {
		return "PUT"
	}
	if bytes.HasPrefix(data, []byte("DELETE ")) {
		return "DELETE"
	}
	if bytes.HasPrefix(data, []byte("HEAD ")) {
		return "HEAD"
	}
	if bytes.HasPrefix(data, []byte("PATCH ")) {
		return "PATCH"
	}
	if bytes.HasPrefix(data, []byte("OPTIONS ")) {
		return "OPTIONS"
	}
	// 响应
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		return "RESPONSE"
	}
	return ""
}

// HTTPRecord 向后兼容的解析入口（旧接口）
type HTTPRecord struct {
	Timestamp   time.Time
	ProbeID     string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Method      string
	Host        string
	URL         string
	StatusCode  int
	Bytes       uint64
	LatencyMs   float64
	ContentType string
	UserAgent   string
	Referer     string
	IsChunked   bool
	IsGzip      bool
	IsError     bool
	IsSlow      bool
}

func ParseHTTP(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *HTTPRecord {
	if len(data) < 10 {
		return nil
	}
	rec := &HTTPRecord{
		Timestamp: time.Now(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
	}
	if direction == 1 {
		rec.SrcIP, rec.DstIP = rec.DstIP, rec.SrcIP
		rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
	}
	return parseHTTPPayload(data, rec)
}

func parseHTTPPayload(data []byte, rec *HTTPRecord) *HTTPRecord {
	reader := bufio.NewReader(strings.NewReader(string(data)))
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 8 {
		return nil
	}
	if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") || strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "DELETE ") || strings.HasPrefix(line, "HEAD ") || strings.HasPrefix(line, "PATCH ") || strings.HasPrefix(line, "OPTIONS ") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 2 {
			rec.Method = parts[0]
			rec.URL = parts[1]
		}
	} else if strings.HasPrefix(line, "HTTP/") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &rec.StatusCode)
			rec.IsError = rec.StatusCode >= 400
		}
	} else {
		return nil
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "host":
			rec.Host = val
		case "content-type":
			rec.ContentType = val
		case "user-agent":
			rec.UserAgent = val
		case "referer":
			rec.Referer = val
		case "transfer-encoding":
			rec.IsChunked = strings.Contains(strings.ToLower(val), "chunked")
		case "content-encoding":
			rec.IsGzip = strings.Contains(strings.ToLower(val), "gzip")
		}
	}
	rec.IsSlow = rec.LatencyMs > 1000
	return rec
}

func DetectGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// BuildHTTPRecord 从请求+响应构建完整记录
func BuildHTTPRecord(req *HTTPEvent, resp *HTTPEvent) *HTTPRecord {
	return &HTTPRecord{
		Timestamp:   time.Unix(0, req.Timestamp*int64(time.Millisecond)),
		SrcIP:       req.SrcIP,
		DstIP:       req.DstIP,
		SrcPort:     req.SrcPort,
		DstPort:     req.DstPort,
		Method:      req.Method,
		Host:        req.Host,
		URL:         req.URL,
		UserAgent:   req.UserAgent,
		StatusCode:  resp.StatusCode,
		LatencyMs:   float64(resp.LatencyMs),
		IsError:     resp.StatusCode >= 400,
		IsSlow:      resp.LatencyMs > 1000,
	}
}
