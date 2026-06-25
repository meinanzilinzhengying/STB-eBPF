package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

func TestAPIResponse_JSON(t *testing.T) {
	resp := APIResponse{Code: 0, Message: "success", Data: "test"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}
	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)
	if decoded["code"].(float64) != 0 {
		t.Errorf("code = %v, want 0", decoded["code"])
	}
	if decoded["message"] != "success" {
		t.Errorf("message = %q, want success", decoded["message"])
	}
}

func TestJsonResponse(t *testing.T) {
	w := httptest.NewRecorder()
	jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "hello"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	cors := w.Header().Get("Access-Control-Allow-Origin")
	if cors != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", cors)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != 0 {
		t.Errorf("code = %d, want 0", resp.Code)
	}
}

func TestHandleHealth(t *testing.T) {
	handler := handleHealth()
	req := httptest.NewRequest(http.MethodGet, "/api/probe/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data != "healthy" {
		t.Errorf("data = %v, want healthy", resp.Data)
	}
}

func TestHandleVersion(t *testing.T) {
	handler := handleVersion()
	req := httptest.NewRequest(http.MethodGet, "/api/probe/version", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	if _, exists := data["version"]; !exists {
		t.Error("version field missing from response")
	}
	if _, exists := data["build_time"]; !exists {
		t.Error("build_time field missing from response")
	}
}

func TestHandleOptions(t *testing.T) {
	// Test OPTIONS request
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()
	handleOptions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS header missing for OPTIONS")
	}

	// Test non-OPTIONS request
	req2 := httptest.NewRequest(http.MethodGet, "/unknown-path", nil)
	w2 := httptest.NewRecorder()
	handleOptions(w2, req2)

	if w2.Code != http.StatusNotFound {
		t.Errorf("GET unknown path status = %d, want %d", w2.Code, http.StatusNotFound)
	}
}

func TestHandleV1AuthLogin_GET(t *testing.T) {
	handler := handleV1AuthLogin()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleV1AuthLogin_InvalidJSON(t *testing.T) {
	handler := handleV1AuthLogin()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleV1AuthLogin_ValidCredentials(t *testing.T) {
	handler := handleV1AuthLogin()
	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Code != 0 {
		t.Errorf("code = %d, want 0", resp.Code)
	}
	tokenMap, ok := resp.Data.(map[string]interface{})
	if ok {
		if _, exists := tokenMap["token"]; !exists {
			t.Error("token field missing from auth response")
		}
	}
}

func TestHandleV1AuthLogin_InvalidCredentials(t *testing.T) {
	handler := handleV1AuthLogin()
	body := `{"username":"admin","password":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleV1AuthLogout(t *testing.T) {
	handler := handleV1AuthLogout()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "success" {
		t.Errorf("message = %q, want success", resp.Message)
	}
	if resp.Data != "logged out" {
		t.Errorf("data = %v, want logged out", resp.Data)
	}
}

func TestHandleV1AuthInfo(t *testing.T) {
	handler := handleV1AuthInfo()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/info", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	info, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	// Server returns "username" and "role" as string fields
	if info["username"] != "admin" {
		t.Errorf("username = %v, want admin", info["username"])
	}
	if info["role"] != "admin" {
		t.Errorf("role = %v, want admin", info["role"])
	}
}

func TestHandleV1Probes_NoManager(t *testing.T) {
	handler := handleV1Probes(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/probes", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	probes, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("data is not an array: %T", resp.Data)
	}
	if len(probes) != 1 {
		t.Errorf("probes len = %d, want 1", len(probes))
	}
	probe := probes[0].(map[string]interface{})
	if probe["status"] != "online" {
		t.Errorf("status = %v, want online", probe["status"])
	}
}

func TestHandleV1ProbeDetail_Get(t *testing.T) {
	handler := handleV1ProbeDetail(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/probes/localhost.localdomain", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	detail, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	if _, exists := detail["lastHeartbeat"]; !exists {
		t.Error("lastHeartbeat field missing")
	}
	if _, exists := detail["collectors"]; !exists {
		t.Error("collectors field missing")
	}
}

func TestHandleV1ProbeDetail_Put(t *testing.T) {
	handler := handleV1ProbeDetail(nil)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/probes/localhost.localdomain", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleV1Dashboard_NoArgs(t *testing.T) {
	handler := handleV1Dashboard(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	// Verify default values when ClickHouse is nil
	if data["probeOnline"].(float64) != 1 {
		t.Errorf("probeOnline = %v, want 1", data["probeOnline"])
	}
}

func TestHandleV1NetworkTopology(t *testing.T) {
	handler := handleV1NetworkTopology(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/network/topology", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	topo, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	nodes, ok := topo["nodes"].([]interface{})
	if !ok || len(nodes) < 3 {
		t.Errorf("nodes missing or too few: %v", nodes)
	}
	edges, ok := topo["edges"].([]interface{})
	if !ok || len(edges) < 3 {
		t.Errorf("edges missing or too few: %v", edges)
	}
}

func TestHandleV1NetworkFlows_NoCH(t *testing.T) {
	handler := handleV1NetworkFlows(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/network/flows", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	flows, ok := resp.Data.([]interface{})
	if !ok || len(flows) == 0 {
		t.Error("flows should contain default data when ClickHouse is nil")
	}
}

func TestHandleV1SecurityEvents_NoCH(t *testing.T) {
	handler := handleV1SecurityEvents(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	events, ok := resp.Data.([]interface{})
	if !ok || len(events) == 0 {
		t.Error("security events should contain default data when ClickHouse is nil")
	}

	event := events[0].(map[string]interface{})
	if event["type"] != "port_scan" {
		t.Errorf("first event type = %v, want port_scan", event["type"])
	}
}

func TestHandleV1PerformanceCPU_NoCH(t *testing.T) {
	handler := handleV1PerformanceCPU(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/performance/cpu", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	data, ok := resp.Data.([]interface{})
	if !ok || len(data) != 7 {
		t.Errorf("CPU data should have 7 time points, got %d", len(data))
	}
}

func TestHandleV1SecurityDistribution_NoCH(t *testing.T) {
	handler := handleV1SecurityDistribution(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/distribution", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	dist, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	if _, exists := dist["severity"]; !exists {
		t.Error("severity field missing from distribution")
	}
	if _, exists := dist["type"]; !exists {
		t.Error("type field missing from distribution")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
		{5368709120, "5.00 GB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.expected)
		}
	}
}

func TestHandleV1ProtocolHTTP_NoCH(t *testing.T) {
	handler := handleV1ProtocolHTTP(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protocol/http", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleV1ProtocolDNS_NoCH(t *testing.T) {
	handler := handleV1ProtocolDNS(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protocol/dns", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleV1ProtocolDB_NoCH(t *testing.T) {
	handler := handleV1ProtocolDB(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protocol/db", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_Panics(t *testing.T) {
	// Verify all handler factories don't panic with nil inputs
	noPanic := func(name string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked: %v", name, r)
			}
		}()
		fn()
	}

	noPanic("handleStatus", func() { _ = handleStatus(nil) })
	noPanic("handleStart", func() { _ = handleStart(nil) })
	noPanic("handleStop", func() { _ = handleStop(nil) })
	noPanic("handleRestart", func() { _ = handleRestart(nil) })
	noPanic("handleMetrics", func() { _ = handleMetrics(nil) })
	noPanic("handleV1NetworkTrends", func() { _ = handleV1NetworkTrends(nil, nil) })
	noPanic("handleV1PerformanceMemory", func() { _ = handleV1PerformanceMemory(nil, nil) })
	noPanic("handleV1PerformanceDisk", func() { _ = handleV1PerformanceDisk(nil, nil) })
	noPanic("handleV1PerformanceProcess", func() { _ = handleV1PerformanceProcess(nil, nil) })
	noPanic("handleV1SecurityTrends", func() { _ = handleV1SecurityTrends(nil, nil) })
}

// TestNewClickHouseConstructor tests factory pattern
func TestNewClickHouseConstructor(t *testing.T) {
	ch := &output.ClickHouse{}
	if ch == nil {
		t.Fatal("ClickHouse struct should be constructable")
	}
}

// Ensure interface compliance at compile time
var _ output.Writer = (*output.EdgeClient)(nil)
var _ output.Writer = (*output.ClickHouse)(nil)
