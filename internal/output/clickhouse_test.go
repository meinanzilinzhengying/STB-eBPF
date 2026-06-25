package output

import (
	"testing"
	"time"
)

func TestEvent_Struct(t *testing.T) {
	now := time.Now()
	ev := &Event{
		Timestamp: now,
		ProbeID:   "probe-01",
		Category:  "network_events",
		EventType: "tcp_connect",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54321,
		DstPort:   443,
		Protocol:  "tcp",
		Bytes:     4096,
		Packets:   8,
		LatencyMs: 12.5,
		Service:   "nginx",
		Details:   `{"method":"GET","url":"/api/health"}`,
		Tags:      "production,web",
	}

	if ev.ProbeID != "probe-01" {
		t.Errorf("ProbeID = %q, want %q", ev.ProbeID, "probe-01")
	}
	if ev.Category != "network_events" {
		t.Errorf("Category = %q, want %q", ev.Category, "network_events")
	}
	if ev.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", ev.SrcPort)
	}
	if ev.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", ev.DstPort)
	}
	if ev.Bytes != 4096 {
		t.Errorf("Bytes = %d, want 4096", ev.Bytes)
	}
	if ev.LatencyMs != 12.5 {
		t.Errorf("LatencyMs = %f, want 12.5", ev.LatencyMs)
	}
}

func TestEvent_ZeroValueFields(t *testing.T) {
	ev := &Event{
		Timestamp: time.Now(),
		ProbeID:   "probe-01",
		Category:  "test",
	}

	// Zero values should be expected defaults
	if ev.SrcPort != 0 {
		t.Errorf("SrcPort = %d, want 0", ev.SrcPort)
	}
	if ev.DstPort != 0 {
		t.Errorf("DstPort = %d, want 0", ev.DstPort)
	}
	if ev.Protocol != "" {
		t.Errorf("Protocol = %q, want empty", ev.Protocol)
	}
	if ev.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0", ev.Bytes)
	}
}

func TestWriter_Interface(t *testing.T) {
	// Verify that EdgeClient and ClickHouse satisfy the Writer interface
	var _ Writer = (*EdgeClient)(nil)
	var _ Writer = (*ClickHouse)(nil)
}

func TestNewClickHouse_InvalidAddr(t *testing.T) {
	// Test with invalid address - should fail
	ch, err := NewClickHouse("invalid-host-that-does-not-exist:9999", "user", "pass", "test")
	if err == nil {
		t.Error("expected error for invalid ClickHouse address, got nil")
		if ch != nil {
			ch.Close()
		}
	}
}

func TestClickHouse_WriteBatch_Empty(t *testing.T) {
	ch := &ClickHouse{}
	err := ch.WriteBatch(nil)
	if err != nil {
		t.Errorf("WriteBatch(nil) should not error: %v", err)
	}
	err = ch.WriteBatch([]*Event{})
	if err != nil {
		t.Errorf("WriteBatch([]) should not error: %v", err)
	}
}

func TestClickHouse_FlushAndClose(t *testing.T) {
	ch := &ClickHouse{}
	ch.Flush() // should not panic

	// Close on nil db will panic due to nil pointer - test that Flush is safe
	// Close with nil db is expected to panic, so we skip the Close test
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected: Close on nil db panicked: %v", r)
		}
	}()
	ch.Close()
}

func TestClickHouse_QueryRow_NilDB(t *testing.T) {
	ch := &ClickHouse{}
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Expected: QueryRow on nil db panicked: %v", r)
		}
	}()
	ch.QueryRow("SELECT 1")
}
