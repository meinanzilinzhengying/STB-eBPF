package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	ebpfprobe "github.com/meinanzilinzhengying/ebpf-probe"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/collector"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

func Start(port string, mgr *collector.Manager, ch *output.ClickHouse) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/probe/status", handleStatus(mgr))
	mux.HandleFunc("/api/probe/start", handleStart(mgr))
	mux.HandleFunc("/api/probe/stop", handleStop(mgr))
	mux.HandleFunc("/api/probe/restart", handleRestart(mgr))
	mux.HandleFunc("/api/probe/metrics", handleMetrics(mgr))
	mux.HandleFunc("/api/probe/health", handleHealth())
	mux.HandleFunc("/api/probe/version", handleVersion())

	mux.HandleFunc("/api/v1/login", handleV1AuthLogin())
	mux.HandleFunc("/api/v1/auth/login", handleV1AuthLogin())
	mux.HandleFunc("/api/v1/auth/logout", handleV1AuthLogout())
	mux.HandleFunc("/api/v1/auth/info", handleV1AuthInfo())
	mux.HandleFunc("/api/v1/dashboard", handleV1Dashboard(mgr, ch))
	mux.HandleFunc("/api/v1/dashboard/overview", handleV1Dashboard(mgr, ch))
	mux.HandleFunc("/api/v1/probes", handleV1Probes(mgr))
	mux.HandleFunc("/api/v1/probes/", handleV1ProbeDetail(mgr))
	mux.HandleFunc("/api/v1/network/topology", handleV1NetworkTopology(mgr))
	mux.HandleFunc("/api/v1/network/flows", handleV1NetworkFlows(mgr, ch))
	mux.HandleFunc("/api/v1/network/trends", handleV1NetworkTrends(mgr, ch))
	mux.HandleFunc("/api/v1/protocol/http", handleV1ProtocolHTTP(mgr, ch))
	mux.HandleFunc("/api/v1/protocol/dns", handleV1ProtocolDNS(mgr, ch))
	mux.HandleFunc("/api/v1/protocol/db", handleV1ProtocolDB(mgr, ch))
	mux.HandleFunc("/api/v1/performance/cpu", handleV1PerformanceCPU(mgr, ch))
	mux.HandleFunc("/api/v1/performance/memory", handleV1PerformanceMemory(mgr, ch))
	mux.HandleFunc("/api/v1/performance/disk", handleV1PerformanceDisk(mgr, ch))
	mux.HandleFunc("/api/v1/performance/process", handleV1PerformanceProcess(mgr, ch))
	mux.HandleFunc("/api/v1/security/events", handleV1SecurityEvents(mgr, ch))
	mux.HandleFunc("/api/v1/security/distribution", handleV1SecurityDistribution(mgr, ch))
	mux.HandleFunc("/api/v1/security/trends", handleV1SecurityTrends(mgr, ch))
	mux.HandleFunc("/", handleOptions)

	log.Printf("[API] 管理API启动在端口 %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Printf("[API] HTTP服务异常: %v", err)
	}
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func handleStatus(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: mgr.Status()})
	}
}

func handleStart(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "probe started"})
	}
}

func handleStop(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mgr.Stop()
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "probe stopped"})
	}
}

func handleRestart(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "probe restarted"})
	}
}

func handleMetrics(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: mgr.Status()})
	}
}

func handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "healthy"})
	}
}

func handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]string{
			"version":    ebpfprobe.Version,
			"build_time": ebpfprobe.BuildTime,
		}})
	}
}

func handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func handleV1AuthLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonResponse(w, http.StatusMethodNotAllowed, APIResponse{Code: -1, Message: "method not allowed"})
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonResponse(w, http.StatusBadRequest, APIResponse{Code: -1, Message: "invalid request"})
			return
		}
		if req.Username == "admin" && req.Password == "admin" {
			jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]string{
				"token":    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock-token",
				"username": req.Username,
			}})
		} else {
			jsonResponse(w, http.StatusUnauthorized, APIResponse{Code: -1, Message: "invalid credentials"})
		}
	}
}

func handleV1AuthLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "logged out"})
	}
}

func handleV1AuthInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]string{
			"username": "admin",
			"role":     "admin",
		}})
	}
}

func formatBytes(b uint64) string {
	if b == 0 {
		return "0 B"
	}
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
}

func handleV1Dashboard(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var traffic uint64
		var activeAlerts uint64
		var monitoredHosts uint64
		if ch != nil {
			ch.QueryRow("SELECT sum(bytes) FROM cloudflow.ebpf_events WHERE timestamp >= today()").Scan(&traffic)
			ch.QueryRow("SELECT count() FROM cloudflow.ebpf_events WHERE category = 'security' AND timestamp >= today()").Scan(&activeAlerts)
			ch.QueryRow("SELECT uniq(src_ip) FROM cloudflow.ebpf_events WHERE timestamp >= today()").Scan(&monitoredHosts)
		}

		flowTrend := []map[string]interface{}{
			{"time": "00:00", "rx": 120, "tx": 80},
			{"time": "04:00", "rx": 150, "tx": 100},
			{"time": "08:00", "rx": 280, "tx": 180},
			{"time": "12:00", "rx": 350, "tx": 220},
			{"time": "16:00", "rx": 420, "tx": 260},
			{"time": "20:00", "rx": 380, "tx": 240},
			{"time": "23:59", "rx": 290, "tx": 190},
		}
		protocolDist := []map[string]interface{}{
			{"name": "HTTP", "value": 45},
			{"name": "DNS", "value": 25},
			{"name": "MySQL", "value": 15},
			{"name": "Redis", "value": 8},
			{"name": "Other", "value": 7},
		}
		topHosts := []map[string]interface{}{
			{"ip": "192.168.1.100", "bytes": 2048000, "percent": "32%"},
			{"ip": "192.168.1.101", "bytes": 1536000, "percent": "24%"},
			{"ip": "10.0.0.50", "bytes": 1024000, "percent": "16%"},
		}
		recentAlerts := []map[string]interface{}{
			{"time": "10:23:15", "level": "high", "message": "检测到可疑端口扫描 (192.168.1.55)"},
			{"time": "09:45:02", "level": "medium", "message": "DNS请求量突增 (+500%)"},
			{"time": "08:12:33", "level": "low", "message": "MySQL慢查询 (2.5s)"},
		}

		if ch != nil {
			rows, err := ch.Query("SELECT toHour(timestamp) as h, sum(bytes) as total FROM cloudflow.ebpf_events WHERE timestamp >= today() GROUP BY h ORDER BY h")
			if err == nil && rows != nil {
				flowTrend = []map[string]interface{}{}
				for rows.Next() {
					var h int
					var total uint64
					rows.Scan(&h, &total)
					flowTrend = append(flowTrend, map[string]interface{}{
						"time": fmt.Sprintf("%02d:00", h),
						"rx":   total / 2,
						"tx":   total / 2,
					})
				}
				rows.Close()
			}

			rows2, err := ch.Query("SELECT protocol, count() as cnt FROM cloudflow.ebpf_events WHERE timestamp >= today() GROUP BY protocol ORDER BY cnt DESC LIMIT 5")
			if err == nil && rows2 != nil {
				protocolDist = []map[string]interface{}{}
				for rows2.Next() {
					var proto string
					var cnt uint64
					rows2.Scan(&proto, &cnt)
					protocolDist = append(protocolDist, map[string]interface{}{
						"name":  proto,
						"value": cnt,
					})
				}
				rows2.Close()
			}

			rows3, err := ch.Query("SELECT src_ip, sum(bytes) as total FROM cloudflow.ebpf_events WHERE timestamp >= today() GROUP BY src_ip ORDER BY total DESC LIMIT 5")
			if err == nil && rows3 != nil {
				topHosts = []map[string]interface{}{}
				var totalBytes uint64
				for rows3.Next() {
					var ip string
					var b uint64
					rows3.Scan(&ip, &b)
					totalBytes += b
					topHosts = append(topHosts, map[string]interface{}{
						"ip":     ip,
						"bytes":  b,
						"percent": "0%",
					})
				}
				rows3.Close()
				for i := range topHosts {
					if totalBytes > 0 {
						pct := float64(topHosts[i]["bytes"].(uint64)) / float64(totalBytes) * 100
						topHosts[i]["percent"] = fmt.Sprintf("%.0f%%", pct)
					}
				}
			}

			rows4, err := ch.Query("SELECT toString(timestamp), event_type, details FROM cloudflow.ebpf_events WHERE category = 'security' ORDER BY timestamp DESC LIMIT 5")
			if err == nil && rows4 != nil {
				recentAlerts = []map[string]interface{}{}
				for rows4.Next() {
					var ts, etype, details string
					rows4.Scan(&ts, &etype, &details)
					recentAlerts = append(recentAlerts, map[string]interface{}{
						"time":    ts,
						"level":   "high",
						"message": fmt.Sprintf("%s: %s", etype, details),
					})
				}
				rows4.Close()
			}
		}

		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]interface{}{
			"probeOnline":    1,
			"probeTotal":     1,
			"todayTraffic":   formatBytes(traffic),
			"trafficTrend":   "+8.2%",
			"activeAlerts":   activeAlerts,
			"alertTrend":     "-2",
			"monitoredHosts": monitoredHosts,
			"hostTrend":      "0",
			"flowTrend":      flowTrend,
			"protocolDist":   protocolDist,
			"topHosts":       topHosts,
			"recentAlerts":   recentAlerts,
		}})
	}
}

func handleV1Probes(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: []map[string]interface{}{
			{
				"id":         "localhost.localdomain",
				"hostname":   "localhost.localdomain",
				"ip":         "192.168.58.131",
				"version":    ebpfprobe.Version,
				"status":     "online",
				"cpu":        12.5,
				"memory":     256.0,
				"kernel":     "5.14.0-710.el9.x86_64",
				"btf":        true,
				"uptime":     86400,
				"collectors": []string{"network", "performance", "protocol", "security", "host_metrics"},
			},
		}})
	}
}

func handleV1ProbeDetail(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: "config updated"})
			return
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]interface{}{
			"id":             "localhost.localdomain",
			"hostname":       "localhost.localdomain",
			"ip":             "192.168.58.131",
			"version":        ebpfprobe.Version,
			"status":         "online",
			"cpu":            12.5,
			"memory":         256.0,
			"kernel":         "5.14.0-710.el9.x86_64",
			"btf":            true,
			"uptime":         86400,
			"collectors":     []string{"network", "performance", "protocol", "security", "host_metrics"},
			"arch":           "x86_64",
			"platform":       "vm",
			"hooks":          []string{"tc", "xdp", "kprobe", "tracepoint", "perf_event", "lsm"},
			"ringBufferSize": "256MB",
			"lastHeartbeat":  time.Now().Format("2006-01-02 15:04:05"),
		}})
	}
}

func handleV1NetworkTopology(mgr *collector.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]interface{}{
			"nodes": []map[string]interface{}{
				{"id": "n1", "name": "Gateway", "ip": "192.168.1.1", "type": "router", "status": "online"},
				{"id": "n2", "name": "Web Server", "ip": "192.168.1.10", "type": "server", "status": "online"},
				{"id": "n3", "name": "DB Server", "ip": "192.168.1.20", "type": "database", "status": "online"},
				{"id": "n4", "name": "Client-A", "ip": "192.168.1.100", "type": "client", "status": "online"},
				{"id": "n5", "name": "Client-B", "ip": "192.168.1.101", "type": "client", "status": "warning"},
			},
			"edges": []map[string]interface{}{
				{"source": "n1", "target": "n2", "label": "1.2Gbps", "status": "normal"},
				{"source": "n1", "target": "n3", "label": "800Mbps", "status": "normal"},
				{"source": "n2", "target": "n3", "label": "500Mbps", "status": "normal"},
				{"source": "n4", "target": "n1", "label": "200Mbps", "status": "normal"},
				{"source": "n5", "target": "n1", "label": "150Mbps", "status": "warning"},
			},
		}})
	}
}

func handleV1NetworkFlows(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "10:23:15", "src": "192.168.1.100", "dst": "192.168.1.10", "sport": 54321, "dport": 80, "protocol": "TCP", "bytes": 2048, "packets": 15, "status": "success"},
			{"time": "10:23:12", "src": "192.168.1.101", "dst": "192.168.1.20", "sport": 54322, "dport": 3306, "protocol": "TCP", "bytes": 1024, "packets": 8, "status": "success"},
			{"time": "10:23:08", "src": "192.168.1.100", "dst": "8.8.8.8", "sport": 0, "dport": 53, "protocol": "UDP", "bytes": 128, "packets": 1, "status": "success"},
			{"time": "10:22:55", "src": "10.0.0.50", "dst": "192.168.1.10", "sport": 0, "dport": 443, "protocol": "TCP", "bytes": 8192, "packets": 25, "status": "success"},
			{"time": "10:22:30", "src": "192.168.1.55", "dst": "192.168.1.10", "sport": 0, "dport": 22, "protocol": "TCP", "bytes": 512, "packets": 10, "status": "blocked"},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, http_status FROM cloudflow.flows WHERE timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, srcIP, dstIP, proto string
					var sport, dport uint16
					var bytes, packets uint64
					var status int
					rows.Scan(&ts, &srcIP, &dstIP, &sport, &dport, &proto, &bytes, &packets, &status)
					statusStr := "success"
					if status >= 400 {
						statusStr = "error"
					}
					data = append(data, map[string]interface{}{
						"time":     ts, "src": srcIP, "dst": dstIP,
						"sport":    sport, "dport": dport, "protocol": proto,
						"bytes":    bytes, "packets": packets, "status": statusStr,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1NetworkTrends(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "00:00", "rx": 120, "tx": 80, "pps": 500},
			{"time": "04:00", "rx": 150, "tx": 100, "pps": 600},
			{"time": "08:00", "rx": 280, "tx": 180, "pps": 1200},
			{"time": "12:00", "rx": 350, "tx": 220, "pps": 1500},
			{"time": "16:00", "rx": 420, "tx": 260, "pps": 1800},
			{"time": "20:00", "rx": 380, "tx": 240, "pps": 1600},
			{"time": "23:59", "rx": 290, "tx": 190, "pps": 1100},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toHour(timestamp) as h, sum(bytes) as total FROM cloudflow.ebpf_events WHERE timestamp >= today() GROUP BY h ORDER BY h")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var h int
					var total uint64
					rows.Scan(&h, &total)
					data = append(data, map[string]interface{}{
						"time": fmt.Sprintf("%02d:00", h),
						"rx":   total / 2,
						"tx":   total / 2,
						"pps":  total / 1024,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1ProtocolHTTP(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "10:23:15", "src": "192.168.1.100", "method": "GET", "host": "api.example.com", "path": "/users", "status": 200, "bytes": 2048, "latency": 45},
			{"time": "10:23:12", "src": "192.168.1.101", "method": "POST", "host": "api.example.com", "path": "/orders", "status": 201, "bytes": 512, "latency": 120},
			{"time": "10:23:08", "src": "192.168.1.100", "method": "GET", "host": "cdn.example.com", "path": "/static/logo.png", "status": 200, "bytes": 8192, "latency": 25},
			{"time": "10:22:55", "src": "10.0.0.50", "method": "DELETE", "host": "api.example.com", "path": "/sessions/123", "status": 204, "bytes": 0, "latency": 30},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), src_ip, http_method, http_host, http_url, http_status, bytes, latency_ms FROM cloudflow.flows WHERE http_method != '' AND timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, srcIP, method, host, path string
					var status int
					var bytes uint64
					var latency float64
					rows.Scan(&ts, &srcIP, &method, &host, &path, &status, &bytes, &latency)
					data = append(data, map[string]interface{}{
						"time":    ts, "src": srcIP, "method": method,
						"host":    host, "path": path, "status": status,
						"bytes":   bytes, "latency": latency,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1ProtocolDNS(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "10:23:15", "src": "192.168.1.100", "query": "example.com", "type": "A", "response": "93.184.216.34", "rcode": "NOERROR", "latency": 12},
			{"time": "10:23:12", "src": "192.168.1.101", "query": "api.example.com", "type": "A", "response": "104.16.25.35", "rcode": "NOERROR", "latency": 8},
			{"time": "10:23:08", "src": "192.168.1.100", "query": "8.8.8.8.in-addr.arpa", "type": "PTR", "response": "dns.google", "rcode": "NOERROR", "latency": 15},
			{"time": "10:22:55", "src": "10.0.0.50", "query": "suspicious.xyz", "type": "A", "response": "", "rcode": "NXDOMAIN", "latency": 45, "dga": true},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), src_ip, dns_query, dns_type, dst_ip, 0, latency_ms FROM cloudflow.flows WHERE dns_query != '' AND timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, srcIP, query, qtype, response string
					var rcode int
					var latency float64
					rows.Scan(&ts, &srcIP, &query, &qtype, &response, &rcode, &latency)
					rcodeStr := "NOERROR"
					if rcode != 0 {
						rcodeStr = fmt.Sprintf("%d", rcode)
					}
					data = append(data, map[string]interface{}{
						"time":     ts, "src": srcIP, "query": query,
						"type":     qtype, "response": response, "rcode": rcodeStr,
						"latency":  latency,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1ProtocolDB(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "10:23:15", "src": "192.168.1.10", "dbType": "MySQL", "operation": "SELECT", "table": "users", "rows": 150, "latency": 45, "slow": false},
			{"time": "10:23:12", "src": "192.168.1.10", "dbType": "MySQL", "operation": "INSERT", "table": "orders", "rows": 1, "latency": 120, "slow": true},
			{"time": "10:23:08", "src": "192.168.1.20", "dbType": "Redis", "operation": "GET", "table": "session:123", "rows": 1, "latency": 2, "slow": false},
			{"time": "10:22:55", "src": "192.168.1.20", "dbType": "Redis", "operation": "DEL", "table": "cache:*", "rows": 1000, "latency": 8, "slow": false, "dangerous": true},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), src_ip, protocol, event_type, service, bytes, latency_ms FROM cloudflow.ebpf_events WHERE (event_type LIKE '%db%' OR protocol IN ('MySQL','PostgreSQL','Redis')) AND timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, srcIP, dbType, operation, table string
					var rowsAffected uint64
					var latency float64
					rows.Scan(&ts, &srcIP, &dbType, &operation, &table, &rowsAffected, &latency)
					data = append(data, map[string]interface{}{
						"time":      ts, "src": srcIP, "dbType": dbType,
						"operation": operation, "table": table, "rows": rowsAffected,
						"latency":   latency, "slow": latency > 100,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1PerformanceCPU(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "00:00", "usage": 15, "user": 8, "system": 5, "iowait": 2},
			{"time": "04:00", "usage": 22, "user": 12, "system": 7, "iowait": 3},
			{"time": "08:00", "usage": 45, "user": 25, "system": 15, "iowait": 5},
			{"time": "12:00", "usage": 38, "user": 20, "system": 12, "iowait": 6},
			{"time": "16:00", "usage": 52, "user": 30, "system": 18, "iowait": 4},
			{"time": "20:00", "usage": 35, "user": 18, "system": 12, "iowait": 5},
			{"time": "23:59", "usage": 18, "user": 10, "system": 6, "iowait": 2},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toHour(timestamp) as h, avg(cpu_percent) as avg_cpu FROM cloudflow.host_metrics WHERE timestamp >= today() GROUP BY h ORDER BY h")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var h int
					var avgCPU float64
					rows.Scan(&h, &avgCPU)
					data = append(data, map[string]interface{}{
						"time":   fmt.Sprintf("%02d:00", h),
						"usage":  avgCPU,
						"user":   avgCPU * 0.6,
						"system": avgCPU * 0.3,
						"iowait": avgCPU * 0.1,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1PerformanceMemory(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"total": 8192,
			"used":  6144,
			"free":  2048,
			"cache": 1024,
			"buffers": 512,
			"trend": []map[string]interface{}{
				{"time": "00:00", "used": 4500, "free": 3692},
				{"time": "04:00", "used": 4800, "free": 3392},
				{"time": "08:00", "used": 5800, "free": 2392},
				{"time": "12:00", "used": 6200, "free": 1992},
				{"time": "16:00", "used": 6500, "free": 1692},
				{"time": "20:00", "used": 6000, "free": 2192},
				{"time": "23:59", "used": 5500, "free": 2692},
			},
		}
		if ch != nil {
			var memPercent float64
			ch.QueryRow("SELECT avg(memory_percent) FROM cloudflow.host_metrics WHERE timestamp >= today()").Scan(&memPercent)
			if memPercent > 0 {
				total := 8192.0
				used := total * memPercent / 100.0
				data["used"] = used
				data["free"] = total - used
			}
			rows, err := ch.Query("SELECT toHour(timestamp) as h, avg(memory_percent) as avg_mem FROM cloudflow.host_metrics WHERE timestamp >= today() GROUP BY h ORDER BY h")
			if err == nil && rows != nil {
				trend := []map[string]interface{}{}
				for rows.Next() {
					var h int
					var avgMem float64
					rows.Scan(&h, &avgMem)
					used := 8192.0 * avgMem / 100.0
					trend = append(trend, map[string]interface{}{
						"time": fmt.Sprintf("%02d:00", h),
						"used": used,
						"free": 8192.0 - used,
					})
				}
				rows.Close()
				if len(trend) > 0 {
					data["trend"] = trend
				}
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1PerformanceDisk(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "00:00", "read": 20, "write": 15, "iops": 200, "latency": 5},
			{"time": "04:00", "read": 25, "write": 18, "iops": 250, "latency": 6},
			{"time": "08:00", "read": 80, "write": 60, "iops": 800, "latency": 12},
			{"time": "12:00", "read": 65, "write": 50, "iops": 650, "latency": 10},
			{"time": "16:00", "read": 90, "write": 70, "iops": 900, "latency": 15},
			{"time": "20:00", "read": 70, "write": 55, "iops": 700, "latency": 11},
			{"time": "23:59", "read": 30, "write": 20, "iops": 300, "latency": 7},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toHour(timestamp) as h, avg(disk_read_bytes + disk_write_bytes) as avg_io FROM cloudflow.host_metrics WHERE timestamp >= today() GROUP BY h ORDER BY h")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var h int
					var avgIO float64
					rows.Scan(&h, &avgIO)
					data = append(data, map[string]interface{}{
						"time":    fmt.Sprintf("%02d:00", h),
						"read":    avgIO / 2 / 1024 / 1024,
						"write":   avgIO / 2 / 1024 / 1024,
						"iops":    avgIO / 1024 / 1024,
						"latency": avgIO / 1024 / 1024,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1PerformanceProcess(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"pid": 1234, "name": "nginx", "cpu": 2.5, "memory": 128, "status": "running", "threads": 8, "io": 15},
			{"pid": 5678, "name": "mysqld", "cpu": 8.2, "memory": 512, "status": "running", "threads": 32, "io": 120},
			{"pid": 9012, "name": "redis-server", "cpu": 1.5, "memory": 64, "status": "running", "threads": 4, "io": 8},
			{"pid": 3456, "name": "python", "cpu": 15.0, "memory": 256, "status": "running", "threads": 16, "io": 45, "anomaly": true},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), pid, comm, 0.0, 0, event_type, 0, 0 FROM cloudflow.process_events WHERE timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, name, status string
					var pid, threads, io uint64
					var cpu, memory float64
					rows.Scan(&ts, &pid, &name, &cpu, &memory, &status, &threads, &io)
					data = append(data, map[string]interface{}{
						"pid":     pid, "name": name, "cpu": cpu,
						"memory":  memory, "status": status, "threads": threads,
						"io":      io,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1SecurityEvents(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "10:23:15", "type": "port_scan", "severity": "high", "src": "192.168.1.55", "dst": "192.168.1.10", "description": "检测到端口扫描行为", "status": "new"},
			{"time": "10:23:12", "type": "privilege_escalation", "severity": "critical", "src": "192.168.1.100", "dst": "", "description": "尝试提升权限 (sudo)"},
			{"time": "10:23:08", "type": "dga", "severity": "medium", "src": "192.168.1.100", "dst": "8.8.8.8", "description": "检测到DGA域名查询"},
			{"time": "10:22:55", "type": "dangerous_op", "severity": "high", "src": "192.168.1.20", "dst": "", "description": "Redis执行危险操作 (DEL cache:*)"},
			{"time": "10:22:30", "type": "privilege_escalation", "severity": "critical", "src": "192.168.1.101", "dst": "", "description": "内核模块加载 (lsm)"},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toString(timestamp), event_type, tags, src_ip, dst_ip, details FROM cloudflow.ebpf_events WHERE category = 'security' AND timestamp >= today() ORDER BY timestamp DESC LIMIT 50")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var ts, eventType, tags, srcIP, dstIP, details string
					rows.Scan(&ts, &eventType, &tags, &srcIP, &dstIP, &details)
					severity := "medium"
					if tags == "high" || tags == "critical" {
						severity = tags
					}
					data = append(data, map[string]interface{}{
						"time":        ts, "type": eventType, "severity": severity,
						"src":         srcIP, "dst": dstIP, "description": details,
						"status":      "new",
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}

func handleV1SecurityDistribution(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		severityData := []map[string]interface{}{
			{"name": "严重", "value": 8},
			{"name": "高危", "value": 15},
			{"name": "中危", "value": 32},
			{"name": "低危", "value": 45},
		}
		typeData := []map[string]interface{}{
			{"name": "权限提升", "value": 25},
			{"name": "端口扫描", "value": 18},
			{"name": "DGA域名", "value": 12},
			{"name": "危险操作", "value": 20},
			{"name": "异常流量", "value": 15},
			{"name": "其他", "value": 10},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT event_type, count() as cnt FROM cloudflow.ebpf_events WHERE category = 'security' AND timestamp >= today() GROUP BY event_type ORDER BY cnt DESC")
			if err == nil && rows != nil {
				typeData = []map[string]interface{}{}
				for rows.Next() {
					var eventType string
					var cnt uint64
					rows.Scan(&eventType, &cnt)
					typeData = append(typeData, map[string]interface{}{
						"name":  eventType,
						"value": cnt,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: map[string]interface{}{
			"severity": severityData,
			"type":     typeData,
		}})
	}
}

func handleV1SecurityTrends(mgr *collector.Manager, ch *output.ClickHouse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]interface{}{
			{"time": "00:00", "high": 2, "medium": 5, "low": 8},
			{"time": "04:00", "high": 1, "medium": 3, "low": 6},
			{"time": "08:00", "high": 3, "medium": 8, "low": 12},
			{"time": "12:00", "high": 2, "medium": 6, "low": 10},
			{"time": "16:00", "high": 4, "medium": 10, "low": 15},
			{"time": "20:00", "high": 3, "medium": 7, "low": 11},
			{"time": "23:59", "high": 2, "medium": 4, "low": 7},
		}
		if ch != nil {
			rows, err := ch.Query("SELECT toHour(timestamp) as h, tags, count() as cnt FROM cloudflow.ebpf_events WHERE category = 'security' AND timestamp >= today() GROUP BY h, tags ORDER BY h")
			if err == nil && rows != nil {
				data = []map[string]interface{}{}
				for rows.Next() {
					var h int
					var tags string
					var cnt uint64
					rows.Scan(&h, &tags, &cnt)
					data = append(data, map[string]interface{}{
						"time":    fmt.Sprintf("%02d:00", h),
						"high":    cnt,
						"medium":  cnt / 2,
						"low":     cnt / 3,
					})
				}
				rows.Close()
			}
		}
		jsonResponse(w, http.StatusOK, APIResponse{Code: 0, Message: "success", Data: data})
	}
}
