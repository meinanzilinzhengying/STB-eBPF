package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"strings"

	"github.com/google/uuid"

	ebpfprobe "github.com/meinanzilinzhengying/ebpf-probe"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/api"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/collector"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
	"github.com/meinanzilinzhengying/ebpf-probe/pkg/platform"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	probeID            = envOrDefault("PROBE_ID", platform.Hostname())
	agentID            = "" // Global unique agent ID
	startTime          time.Time
	hostname           = platform.Hostname()
	edgeAddr           = envOrDefault("EDGE_ADDR", ":9104")
	clickHouseAddr     = envOrDefault("CLICKHOUSE_ADDR", "")
	clickHouseUser     = envOrDefault("CLICKHOUSE_USER", "default")
	clickHousePassword = envOrDefault("CLICKHOUSE_PASSWORD", "")
	clickHouseDB       = envOrDefault("CLICKHOUSE_DATABASE", "cloudflow")
	apiPort            = envOrDefault("API_PORT", "9090")
	ifaceName          = envOrDefault("INTERFACE", "ens33")
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}


// loadOrCreateAgentID loads existing agent_id or generates a new UUID
func loadOrCreateAgentID() string {
	agentIDFile := "/opt/cloudflow/ebpf-probe/agent_id"
	if data, err := os.ReadFile(agentIDFile); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			log.Printf("[AGENT] Loaded agent_id: %s", id)
			return id
		}
	}
	id := uuid.New().String()
	os.MkdirAll("/opt/cloudflow/ebpf-probe", 0755)
	if err := os.WriteFile(agentIDFile, []byte(id), 0644); err != nil {
		log.Printf("[AGENT] Failed to save agent_id: %v", err)
	} else {
		log.Printf("[AGENT] Generated new agent_id: %s", id)
	}
	return id
}

func main() {
	startTime = time.Now()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("[CloudFlow eBPF Probe v%s]\n", ebpfprobe.Version)
	fmt.Printf("  probe_id:   %s\n", probeID)
	fmt.Printf("  platform:   %s\n", platform.Detect())
	fmt.Printf("  kernel:     %s\n", kernel.Version())
	fmt.Printf("  btf:        %v\n", kernel.HasBTF())
	fmt.Printf("  edge:       %s\n", edgeAddr)
	fmt.Printf("  clickhouse: %s\n", clickHouseAddr)
	fmt.Printf("  api_port:   %s\n", apiPort)
	fmt.Println("═══════════════════════════════════════════")

	// Initialize agent_id
	agentID = loadOrCreateAgentID()

	kernelCap := kernel.DetectCapabilities()
	log.Printf("[KERNEL] 可用钩子: %+v", kernelCap.AvailableHooks)

	// EdgeClient 用于输出
	out, err := output.NewEdgeClient(edgeAddr)
	if err != nil {
		log.Printf("[WARN] EdgeClient 初始化失败: %v", err)
	}
	defer out.Close()
	log.Printf("[OK] Edge 输出就绪")

	// ClickHouse 用于 API 查询
	ch, err := output.NewClickHouse(clickHouseAddr, clickHouseUser, clickHousePassword, clickHouseDB)
	if err != nil {
		log.Printf("[WARN] ClickHouse 查询客户端初始化失败: %v", err)
	}
	defer ch.Close()
	log.Printf("[OK] ClickHouse 查询就绪")

	// 使用默认配置（所有扩展功能默认关闭）
	cfg := collector.DefaultConfig()

	mgr := collector.NewManager(out, probeID, ifaceName, cfg)
	if err := mgr.Init(kernelCap); err != nil {
		log.Printf("[WARN] 采集器初始化失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		log.Printf("[WARN] 采集器启动失败: %v", err)
	}
	log.Printf("[OK] 所有采集器已启动")

	go api.Start(apiPort, mgr, ch)
	// 配置表轮询（每30秒检查前端下发的命令）
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[CONFIG] 轮询goroutine恢复: %v", r)
			}
		}()
		log.Printf("[CONFIG] 启动配置表轮询 (每30秒), probe_id=%s", probeID)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// 查询未应用的配置命令
			query := fmt.Sprintf(
				"SELECT probe_id, command, config_json, toString(created_at) FROM cloudflow.probe_config WHERE applied = 0 AND probe_id = '%s' ORDER BY created_at LIMIT 10 FORMAT JSON",
				probeID,
			)

			// 使用HTTP API查询ClickHouse
			chQuery := fmt.Sprintf("http://%s:8123/?query=%s", clickHouseAddr, url.QueryEscape(query))
			log.Printf("[CONFIG] 查询配置表: %s", chQuery[:min(len(chQuery), 100)])
			resp, err := http.Get(chQuery)
			if err != nil {
				log.Printf("[CONFIG] 查询配置表失败: %v", err)
				continue
			}
			log.Printf("[CONFIG] HTTP状态码: %d", resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[CONFIG] 响应体长度: %d, 完整响应: %s", len(body), string(body))

			// 解析JSON响应
			if len(body) == 0 {
				log.Printf("[CONFIG] 配置表为空")
				continue
			}
			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				log.Printf("[CONFIG] 解析响应失败: %v, body: %s", err, string(body)[:min(len(body), 200)])
				continue
				}

			log.Printf("[CONFIG] JSON解析成功, rows=%v, data=%v", result["rows"], len(result["data"].([]interface{})))
			rows, ok := result["data"].([]interface{})
			if !ok {
				log.Printf("[CONFIG] data字段类型错误: %T", result["data"])
				continue
				}
			if len(rows) == 0 {
				log.Printf("[CONFIG] 没有未处理的命令")
				continue
				}

			for _, row := range rows {
				record := row.(map[string]interface{})
				if len(record) < 3 {
					continue
				}

			cmd := record["command"].(string)
				log.Printf("[CONFIG] 收到命令: %s", cmd)
				// Mark as applied first
				upQ := fmt.Sprintf("ALTER TABLE cloudflow.probe_config UPDATE applied = 1 WHERE probe_id = '%s' AND applied = 0", probeID)
				chUp := fmt.Sprintf("http://%s:8123/?query=%s", clickHouseAddr, url.QueryEscape(upQ))
				respUp, errUp := http.Get(chUp)
				if errUp != nil {
					log.Printf("[CONFIG] Mark fail: %v", errUp)
				} else {
					respUp.Body.Close()
					log.Printf("[CONFIG] Mark ok: %d", respUp.StatusCode)
				}
				switch cmd {
				case "stop":
					mgr.Stop()
					log.Printf("[CONFIG] 已停止所有采集器（进程继续运行）")
				case "start":
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					mgr.Start(ctx)
					log.Printf("[CONFIG] 已启动所有采集器")
				case "restart":
					mgr.Stop()
					time.Sleep(2 * time.Second)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					mgr.Start(ctx)
					log.Printf("[CONFIG] 已重启所有采集器")
				case "update_config":
					if len(record) > 2 && record["config_json"] != nil {
						configJSON := record["config_json"].(string)
						// 解析并更新配置
						log.Printf("[CONFIG] 更新配置: %s", configJSON)
						// TODO: 解析configJSON并更新mgr配置
					}
				}

			}
		}
	}()



	// Start heartbeat reporting (every 30 seconds)
	go func() {
		log.Printf("[HEARTBEAT] start, agent_id=%s", agentID)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		reportHeartbeat(agentID, probeID, hostname, mgr)
		for range ticker.C {
			reportHeartbeat(agentID, probeID, hostname, mgr)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[EBPF] 收到停止信号，正在清理...")
	cancel()
	mgr.Stop()
	out.Flush()
	log.Printf("[EBPF] 已安全退出")
}
