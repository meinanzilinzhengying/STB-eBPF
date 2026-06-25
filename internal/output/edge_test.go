package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewEdgeClient(t *testing.T) {
	client, err := NewEdgeClient("127.0.0.1:9104")
	if err != nil {
		t.Fatalf("NewEdgeClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.addr != "127.0.0.1:9104" {
		t.Errorf("addr = %q, want %q", client.addr, "127.0.0.1:9104")
	}
	if len(client.batch) != 0 {
		t.Errorf("batch len = %d, want 0", len(client.batch))
	}
	client.Close()
}

func TestEdgeClient_WriteEvent_Sampling(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0, 2000),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// security_events has 100% sampling - should always be added
	ev := &Event{
		Timestamp: time.Now(),
		ProbeID:   "probe-1",
		Category:  "security_events",
		EventType: "test",
	}
	err := client.WriteEvent(ev)
	if err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}
	client.mu.Lock()
	got := len(client.batch)
	client.mu.Unlock()
	if got != 1 {
		t.Errorf("batch len = %d, want 1 for security_events", got)
	}
}

func TestEdgeClient_WriteEvent_BatchFlush(t *testing.T) {
	// Create a server that captures the POST
	received := make(chan []*Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var events []*Event
		json.NewDecoder(r.Body).Decode(&events)
		received <- events
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract host:port from srv.URL
	addr := srv.URL[7:] // strip "http://"
	client, err := NewEdgeClient(addr)
	if err != nil {
		t.Fatalf("NewEdgeClient failed: %v", err)
	}
	defer client.Close()

	// Write 2000 events to trigger flush
	for i := 0; i < 2000; i++ {
		ev := &Event{
			Timestamp: time.Now(),
			ProbeID:   "probe-1",
			Category:  "security_events",
			EventType: "test",
		}
		client.WriteEvent(ev)
	}

	// Wait for the flush to happen
	select {
	case events := <-received:
		if len(events) != 2000 {
			t.Errorf("received %d events, want 2000", len(events))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for flush")
	}
}

func TestEdgeClient_WriteEvent_SamplingFileEvents(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0, 2000),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// file_events has 1% sampling rate
	added := 0
	for i := 0; i < 1000; i++ {
		ev := &Event{
			Timestamp: time.Now(),
			ProbeID:   "probe-1",
			Category:  "file_events",
			EventType: "test",
		}
		client.WriteEvent(ev)
	}

	client.mu.Lock()
	added = len(client.batch)
	client.mu.Unlock()

	// At 1% with 1000 events, statistically ~10 should pass
	// We just verify the sampling mechanism works (less than 100% pass)
	if added == 1000 {
		t.Error("expected sampling to filter some file_events, but all 1000 passed")
	}
	if added == 0 {
		t.Log("sampling passed 0 of 1000 file_events (possible but unlikely at 1% rate)")
	}
}

func TestEdgeClient_WriteMetrics(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0, 2000),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	err := client.WriteMetrics("probe-1", 50.5, 60.2, 30.1, 1024, 2048, 512, 256)
	if err != nil {
		t.Fatalf("WriteMetrics failed: %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.batch) != 1 {
		t.Fatalf("batch len = %d, want 1", len(client.batch))
	}

	ev := client.batch[0]
	if ev.Category != "metrics" {
		t.Errorf("category = %q, want %q", ev.Category, "metrics")
	}
	if ev.EventType != "host_metrics" {
		t.Errorf("event_type = %q, want %q", ev.EventType, "host_metrics")
	}
	if ev.ProbeID != "probe-1" {
		t.Errorf("probe_id = %q, want %q", ev.ProbeID, "probe-1")
	}

	// Verify details JSON
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(ev.Details), &details); err != nil {
		t.Fatalf("details is not valid JSON: %v", err)
	}
	if details["cpu_percent"] != 50.5 {
		t.Errorf("cpu_percent = %v, want 50.5", details["cpu_percent"])
	}
}

func TestEdgeClient_WriteProcessEvent(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	ts := time.Now()
	err := client.WriteProcessEvent(ts, "probe-1", 1234, 1, "nginx", "/usr/sbin/nginx", "-g daemon off;", "exec")
	if err != nil {
		t.Fatalf("WriteProcessEvent failed: %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.batch) != 1 {
		t.Fatalf("batch len = %d, want 1", len(client.batch))
	}

	ev := client.batch[0]
	if ev.Category != "process" {
		t.Errorf("category = %q, want process", ev.Category)
	}

	var details map[string]interface{}
	json.Unmarshal([]byte(ev.Details), &details)
	if details["pid"].(float64) != 1234 {
		t.Errorf("pid = %v, want 1234", details["pid"])
	}
}

func TestEdgeClient_WriteBatch(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	events := []*Event{
		{Timestamp: time.Now(), ProbeID: "p1", Category: "security_events", EventType: "t1"},
		{Timestamp: time.Now(), ProbeID: "p1", Category: "security_events", EventType: "t2"},
		{Timestamp: time.Now(), ProbeID: "p1", Category: "network_events", EventType: "t3"},
	}

	err := client.WriteBatch(events)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	// All security and network events should pass sampling (security=100%, network=10%)
	if len(client.batch) < 2 {
		t.Errorf("batch len = %d, want at least 2 (security events)", len(client.batch))
	}
}

func TestEdgeClient_WriteBatch_Empty(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// All syscall with 0.1% rate - unlikely any pass for small batch
	events := []*Event{
		{Timestamp: time.Now(), Category: "syscall", EventType: "test"},
		{Timestamp: time.Now(), Category: "syscall", EventType: "test"},
	}

	err := client.WriteBatch(events)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	// Should not panic, even if all filtered
	client.mu.Lock()
	got := len(client.batch)
	client.mu.Unlock()
	t.Logf("after WriteBatch(2 syscall events), batch len = %d", got)
}

func TestEdgeClient_Flush_NoEvents(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// Flush with no events should not panic
	client.flush()
	client.Flush()
}

func TestEdgeClient_Flush_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	addr := srv.URL[7:]
	client := &EdgeClient{
		addr:   addr,
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// Add events and flush - should retry (put events back)
	client.batch = append(client.batch, &Event{
		Timestamp: time.Now(),
		ProbeID:   "p1",
		Category:  "security_events",
		EventType: "test",
	})
	client.flush()

	client.mu.Lock()
	got := len(client.batch)
	client.mu.Unlock()

	if got != 1 {
		t.Errorf("batch len = %d, want 1 (events should be re-queued on error)", got)
	}
}

func TestEdgeClient_Close(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}

	err := client.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify stopCh is closed
	select {
	case <-client.stopCh:
		// expected
	default:
		t.Error("stopCh should be closed after Close()")
	}
}

func TestShouldSample(t *testing.T) {
	tests := []struct {
		category string
		wantPass bool // for 100% rate, always pass
	}{
		{"security_events", true},
		{"file_events", false},  // 1% - usually false in tests
		{"network_events", false}, // 10%
		{"process_events", false}, // 10%
		{"unknown_category", true}, // defaults to 100%
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			result := shouldSample(tt.category)
			if tt.wantPass && !result {
				t.Errorf("shouldSample(%q) = false, want true", tt.category)
			}
		})
	}
}

func TestEdgeClient_Flush_RetryWithMaxCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	addr := srv.URL[7:]
	client := &EdgeClient{
		addr:   addr,
		batch:  make([]*Event, 0, 2000),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	// Add many events
	for i := 0; i < 15000; i++ {
		client.batch = append(client.batch, &Event{
			Timestamp: time.Now(),
			ProbeID:   "p1",
			Category:  "security_events",
			EventType: "test",
		})
	}
	client.flush()

	client.mu.Lock()
	got := len(client.batch)
	client.mu.Unlock()

	// Should be capped at 10000
	if got > 10000 {
		t.Errorf("batch len = %d, want <= 10000 (max cap)", got)
	}
}

func TestEdgeClient_WriteFileEvent(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	ts := time.Now()
	err := client.WriteFileEvent(ts, "probe-1", 5678, "python", "/etc/passwd", "open", 0)
	if err != nil {
		t.Fatalf("WriteFileEvent failed: %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.batch) != 1 {
		t.Fatalf("batch len = %d, want 1", len(client.batch))
	}
	var details map[string]interface{}
	json.Unmarshal([]byte(client.batch[0].Details), &details)
	if details["filename"] != "/etc/passwd" {
		t.Errorf("filename = %v, want /etc/passwd", details["filename"])
	}
}

func TestEdgeClient_WriteSyscallEvent(t *testing.T) {
	client := &EdgeClient{
		addr:   "127.0.0.1:9104",
		batch:  make([]*Event, 0),
		ticker: time.NewTicker(time.Hour),
		stopCh: make(chan struct{}),
	}
	defer client.Close()

	ts := time.Now()
	err := client.WriteSyscallEvent(ts, "probe-1", 9999, "bash", 59, 15000, 100)
	if err != nil {
		t.Fatalf("WriteSyscallEvent failed: %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	// syscall has 0.1% sampling - most events will be filtered
	// We just verify no panic and category is set correctly if event passes
	if len(client.batch) > 0 {
		if client.batch[0].Category != "syscall" {
			t.Errorf("category = %q, want syscall", client.batch[0].Category)
		}
	}
}
