package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

func main() {
	ch, err := output.NewClickHouse("192.168.58.130", "default", "", "cloudflow")
	if err != nil {
		log.Fatalf("[EDGE] ClickHouse init failed: %v", err)
	}
	defer ch.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		var events []*output.Event
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, ev := range events {
			ch.WriteEvent(ev)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success"})
	})

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "healthy"})
	})

	log.Printf("[EDGE] Edge service starting on :9102")
	if err := http.ListenAndServe(":9102", mux); err != nil {
		log.Fatalf("[EDGE] server failed: %v", err)
	}
}
