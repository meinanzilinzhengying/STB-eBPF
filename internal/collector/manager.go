package collector

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

type Collector interface {
	Name() string
	Category() string
	Init(cap kernel.Capabilities) error
	Start(ctx context.Context) error
	Stop()
	Status() map[string]interface{}
}

// CollectorConfig 采集器配置
type CollectorConfig struct {
	NetworkFlow   bool `yaml:"network_flow"`
	ProcessExec   bool `yaml:"process_exec"`
	FileOpen      bool `yaml:"file_open"`
	TCPCConnect   bool `yaml:"tcp_connect"`
	Syscall       bool `yaml:"syscall"`
	HTTPTrace     bool `yaml:"http_trace"`
	DNSTrace      bool `yaml:"dns_trace"`
	DBTrace       bool `yaml:"db_trace"`
	SchedTrace    bool `yaml:"sched_trace"`
	MemTrace      bool `yaml:"mem_trace"`
	BlockTrace    bool `yaml:"block_trace"`
	SecurityTrace bool `yaml:"security_trace"`
	HostMetrics   bool `yaml:"host_metrics"`
}

func DefaultConfig() CollectorConfig {
	return CollectorConfig{
		NetworkFlow: true,
		ProcessExec: true,
		FileOpen:    true,
		TCPCConnect: true,
		Syscall:     true,
		HTTPTrace:   false,
		DNSTrace:    false,
		DBTrace:     false,
		SchedTrace:  false,
		MemTrace:    false,
		BlockTrace:  false,
		SecurityTrace: false,
		HostMetrics: true,
	}
}

type Manager struct {
	output     output.Writer
	probeID    string
	ifaceName  string
	config     CollectorConfig
	collectors []Collector
	mu         sync.RWMutex
}

func NewManager(out output.Writer, probeID, iface string, cfg CollectorConfig) *Manager {
	return &Manager{output: out, probeID: probeID, ifaceName: iface, config: cfg}
}

func (m *Manager) Init(cap kernel.Capabilities) error {
	// P0 核心采集器
	if m.config.NetworkFlow && (cap.HasBPFTC || cap.HasBPFXDP) {
		m.collectors = append(m.collectors, NewNetworkCollector(m.output, m.probeID, m.ifaceName))
	}
	if m.config.ProcessExec && (cap.HasBPFKprobe || cap.HasBPFTracepoint) {
		m.collectors = append(m.collectors, NewPerformanceCollector(m.output, m.probeID))
	}
	if m.config.TCPCConnect && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewSecurityCollector(m.output, m.probeID))
	}
	if m.config.Syscall && cap.HasBPFTracepoint {
		m.collectors = append(m.collectors, NewSyscallCollector(m.output, m.probeID))
	}
	m.collectors = append(m.collectors, NewProtocolCollector(m.output, m.probeID, m.ifaceName))

	// P1 扩展采集器
	if m.config.HTTPTrace && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewHTTPTraceCollector(m.output, m.probeID))
	}
	if m.config.DNSTrace && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewDNSTraceCollector(m.output, m.probeID))
	}
	if m.config.DBTrace && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewDBTraceCollector(m.output, m.probeID))
	}
	if m.config.SchedTrace && cap.HasBPFTracepoint {
		m.collectors = append(m.collectors, NewSchedTraceCollector(m.output, m.probeID))
	}
	if m.config.MemTrace && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewMemTraceCollector(m.output, m.probeID))
	}
	if m.config.BlockTrace && cap.HasBPFTracepoint {
		m.collectors = append(m.collectors, NewBlockTraceCollector(m.output, m.probeID))
	}
	if m.config.SecurityTrace && cap.HasBPFKprobe {
		m.collectors = append(m.collectors, NewSecurityTraceCollector(m.output, m.probeID))
	}

	// 主机指标（始终可用）
	if m.config.HostMetrics {
		m.collectors = append(m.collectors, NewHostMetricsCollector(m.output, m.probeID))
	}

	for _, c := range m.collectors {
		if err := c.Init(cap); err != nil {
			log.Printf("[COLLECTOR] %s 初始化失败: %v", c.Name(), err)
		} else {
			log.Printf("[COLLECTOR] %s 已就绪", c.Name())
		}
	}
	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	for _, c := range m.collectors {
		if err := c.Start(ctx); err != nil {
			log.Printf("[COLLECTOR] %s 启动失败: %v", c.Name(), err)
		}
	}
	return nil
}

func (m *Manager) Stop() {
	for _, c := range m.collectors {
		c.Stop()
	}
}

func (m *Manager) Unload(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.collectors {
		if c.Name() == name {
			c.Stop()
			m.collectors = append(m.collectors[:i], m.collectors[i+1:]...)
			log.Printf("[MANAGER] 采集器 %s 已卸载", name)
			return nil
		}
	}
	return fmt.Errorf("采集器 %s 未找到", name)
}

func (m *Manager) Reload(name string, cap kernel.Capabilities) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 找到旧采集器
	var oldIdx = -1
	for i, c := range m.collectors {
		if c.Name() == name {
			oldIdx = i
			break
		}
	}
	if oldIdx < 0 {
		return fmt.Errorf("采集器 %s 未找到，无法重载", name)
	}

	// 创建新实例（原子替换：先创建新的，成功后再替换旧的）
	newCollector, err := m.createCollector(name, cap)
	if err != nil {
		log.Printf("[MANAGER] 采集器 %s 重载失败（创建新实例）: %v", name, err)
		return fmt.Errorf("创建新实例失败: %w", err)
	}
	if err := newCollector.Init(cap); err != nil {
		log.Printf("[MANAGER] 采集器 %s 重载失败（Init）: %v", name, err)
		return fmt.Errorf("Init 失败: %w", err)
	}

	// 启动新实例
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := newCollector.Start(ctx); err != nil {
		log.Printf("[MANAGER] 采集器 %s 重载失败（Start）: %v", name, err)
		newCollector.Stop() // 清理失败的实例
		return fmt.Errorf("Start 失败: %w", err)
	}

	// 新实例成功，卸载旧实例
	oldCollector := m.collectors[oldIdx]
	oldCollector.Stop()
	m.collectors[oldIdx] = newCollector
	log.Printf("[MANAGER] 采集器 %s 热重载成功", name)
	return nil
}

func (m *Manager) createCollector(name string, cap kernel.Capabilities) (Collector, error) {
	switch name {
	case "network_flow":
		if cap.HasBPFTC || cap.HasBPFXDP {
			return NewNetworkCollector(m.output, m.probeID, m.ifaceName), nil
		}
	case "process_exec":
		if cap.HasBPFKprobe || cap.HasBPFTracepoint {
			return NewPerformanceCollector(m.output, m.probeID), nil
		}
	case "tcp_connect":
		if cap.HasBPFKprobe {
			return NewSecurityCollector(m.output, m.probeID), nil
		}
	case "syscall":
		if cap.HasBPFTracepoint {
			return NewSyscallCollector(m.output, m.probeID), nil
		}
	case "protocol":
		return NewProtocolCollector(m.output, m.probeID, m.ifaceName), nil
	case "http_trace":
		if cap.HasBPFKprobe {
			return NewHTTPTraceCollector(m.output, m.probeID), nil
		}
	case "dns_trace":
		if cap.HasBPFKprobe {
			return NewDNSTraceCollector(m.output, m.probeID), nil
		}
	case "db_trace":
		if cap.HasBPFKprobe {
			return NewDBTraceCollector(m.output, m.probeID), nil
		}
	case "sched_trace":
		if cap.HasBPFTracepoint {
			return NewSchedTraceCollector(m.output, m.probeID), nil
		}
	case "mem_trace":
		if cap.HasBPFKprobe {
			return NewMemTraceCollector(m.output, m.probeID), nil
		}
	case "block_trace":
		if cap.HasBPFTracepoint {
			return NewBlockTraceCollector(m.output, m.probeID), nil
		}
	case "security_trace":
		if cap.HasBPFKprobe {
			return NewSecurityTraceCollector(m.output, m.probeID), nil
		}
	case "host_metrics":
		return NewHostMetricsCollector(m.output, m.probeID), nil
	}
	return nil, fmt.Errorf("采集器 %s 在当前内核环境下不可用", name)
}

// WatchConfig 热加载配置文件
func (m *Manager) WatchConfig(ctx context.Context, path string, cap kernel.Capabilities) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建 watcher 失败: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		return fmt.Errorf("监听配置文件失败: %w", err)
	}

	log.Printf("[MANAGER] 开始监听配置文件: %s", path)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("watcher 通道关闭")
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Printf("[MANAGER] 配置文件变化: %s", event.Name)
				// 简单的防抖
				time.Sleep(500 * time.Millisecond)
				if err := m.reloadFromConfig(path, cap); err != nil {
					log.Printf("[MANAGER] 配置文件热加载失败: %v", err)
				} else {
					log.Printf("[MANAGER] 配置文件热加载成功")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher 错误通道关闭")
			}
			log.Printf("[MANAGER] watcher 错误: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *Manager) reloadFromConfig(path string, cap kernel.Capabilities) error {
	// 这里简化实现，实际应该解析 YAML 并对比配置差异
	// 对于当前版本，提供一个扩展点
	log.Printf("[MANAGER] 热加载配置扩展点: %s", path)
	return nil
}

func (m *Manager) Status() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := map[string]interface{}{"probe_id": m.probeID, "collectors": []map[string]interface{}{}}
	for _, c := range m.collectors {
		status["collectors"] = append(status["collectors"].([]map[string]interface{}), c.Status())
	}
	return status
}

func (m *Manager) CollectorNames() []string {
	var names []string
	for _, c := range m.collectors {
		names = append(names, c.Name())
	}
	return names
}

// HostMetricsCollector 用户态主机指标
type HostMetricsCollector struct {
	output  output.Writer
	probeID string
	running bool
	stopCh  chan struct{}
}

func NewHostMetricsCollector(out output.Writer, probeID string) *HostMetricsCollector {
	return &HostMetricsCollector{output: out, probeID: probeID, stopCh: make(chan struct{})}
}

func (h *HostMetricsCollector) Name() string   { return "host_metrics" }
func (h *HostMetricsCollector) Category() string { return "performance" }
func (h *HostMetricsCollector) Init(cap kernel.Capabilities) error { return nil }
func (h *HostMetricsCollector) Start(ctx context.Context) error {
	h.running = true
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m := getHostMetrics()
				_ = h.output.WriteMetrics(h.probeID, m.CPUPercent, m.MemoryPercent, m.DiskPercent, m.NetRxBytes, m.NetTxBytes, m.DiskReadBytes, m.DiskWriteBytes)
			case <-h.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
func (h *HostMetricsCollector) Stop() {
	select {
	case <-h.stopCh:
		// already closed
	default:
		close(h.stopCh)
	}
	h.running = false
}
func (h *HostMetricsCollector) Status() map[string]interface{} {
	return map[string]interface{}{"name": h.Name(), "running": h.running, "category": h.Category()}
}
