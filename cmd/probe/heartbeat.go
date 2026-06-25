package main

import (
    "fmt"
    "log"
    "net/http"
    "net/url"
    "time"
    "github.com/shirou/gopsutil/v3/cpu"
    mem "github.com/shirou/gopsutil/v3/mem"
    "github.com/meinanzilinzhengying/ebpf-probe/internal/collector"
)

func reportHeartbeat(agentID, probeID, hostname string, mgr *collector.Manager) {
    cpuPercent, _ := cpu.Percent(time.Second, false)
    memInfo, _ := mem.VirtualMemory()
    status := "running"
    _ = mgr
    uptime := uint64(time.Since(startTime).Seconds())
    if uptime < 0 { uptime = 0 }
    query := fmt.Sprintf("INSERT INTO cloudflow.probe_heartbeat (agent_id, probe_id, hostname, status, cpu_percent, memory_mb, uptime_seconds) VALUES (\x27%s\x27, \x27%s\x27, \x27%s\x27, \x27%s\x27, %.2f, %.2f, %d)", agentID, probeID, hostname, status, cpuPercent[0], float64(memInfo.Used)/1024/1024, uptime)
    chInsert := fmt.Sprintf("http://%s:8123/?query=%s", clickHouseAddr, url.QueryEscape(query))
    resp, err := http.Post(chInsert, "text/plain", nil)
    if err != nil {
        log.Printf("[HEARTBEAT] failed: %v", err)
    } else {
        resp.Body.Close()
        log.Printf("[HEARTBEAT] ok: status=%s", status)
    }
}
