package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"time"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/meinanzilinzhengying/ebpf-probe/internal/kernel"
	"github.com/meinanzilinzhengying/ebpf-probe/internal/output"
)

//go:embed network_flow.bpf.o
var networkFlowBpfO []byte

const bpfMapPinPath = "/sys/fs/bpf/tc/globals"

type NetworkCollector struct {
	output     output.Writer
	probeID    string
	iface      string
	running    bool
	stopCh     chan struct{}
	coll       *ebpf.Collection
	reader     *perf.Reader
	httpReader *perf.Reader
}

func NewNetworkCollector(out output.Writer, probeID, iface string) *NetworkCollector {
	return &NetworkCollector{output: out, probeID: probeID, iface: iface, stopCh: make(chan struct{})}
}
func (n *NetworkCollector) Name() string     { return "network" }
func (n *NetworkCollector) Category() string { return "network" }

func (n *NetworkCollector) Init(cap kernel.Capabilities) error {
	if !cap.HasBPFTC && !cap.HasBPFXDP {
		return fmt.Errorf("no tc/xdp support")
	}
	ensureBPFFS()
	collSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(networkFlowBpfO))
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	loaded, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	n.coll = loaded

	// Pin all maps
	for name, m := range loaded.Maps {
		pinPath := filepath.Join(bpfMapPinPath, name)
		os.Remove(pinPath)
		if err := m.Pin(pinPath); err != nil {
			n.logPrintf("pin map %s: %v", name, err)
		}
	}

	n.writeExcludeIPsToBPF()
	n.attachTC()

	// Flow events reader
	perfMap, ok := loaded.Maps["events"]
	if !ok {
		return fmt.Errorf("events map not found")
	}
	reader, err := perf.NewReader(perfMap, 4096)
	if err != nil {
		return fmt.Errorf("flow reader: %w", err)
	}
	n.reader = reader

	// HTTP events reader
	httpMap, ok := loaded.Maps["http_events"]
	if ok {
		httpReader, err := perf.NewReader(httpMap, 4096)
		if err != nil {
			log.Printf("[NETWORK] http reader: %v (non-fatal)", err)
		} else {
			n.httpReader = httpReader
			log.Printf("[NETWORK] http reader initialized")
		}
	}

	n.logPrintf("initialized: events fd=%d, iface=%s", perfMap.FD(), n.iface)
	return nil
}

func (n *NetworkCollector) attachTC() {
	if n.coll == nil || n.coll.Programs == nil {
		log.Printf("[NETWORK] no programs to attach")
		return
	}
	for name, prog := range n.coll.Programs {
		if prog == nil || prog.FD() < 0 {
			continue
		}
		dir := "ingress"
		if name == "f2" {
			dir = "egress"
		}
		if err := attachBPFNetlink(n.iface, dir, prog.FD()); err != nil {
			log.Printf("[NETWORK] %s attach: %v", dir, err)
		} else {
			log.Printf("[NETWORK] %s attached (fd=%d)", dir, prog.FD())
		}
	}
}

func attachBPFNetlink(ifaceName, direction string, progFD int) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get iface: %w", err)
	}
	clsact := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(clsact); err != nil {
		if !os.IsExist(err) && !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("add clsact: %w", err)
		}
	}
	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if direction == "egress" {
		parent = uint32(netlink.HANDLE_MIN_EGRESS)
	}
	// Clean old filters
	_ = netlink.FilterDel(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index, Parent: parent,
		Handle: 0, Priority: 1, Protocol: unix.ETH_P_ALL,
	}})
	// Add single filter
	f := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index, Parent: parent,
		Handle: 1, Priority: 1, Protocol: unix.ETH_P_ALL,
	}, Fd: progFD, Name: "cf_" + direction, DirectAction: true}
	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("filter add: %w", err)
	}
	return nil
}

func (n *NetworkCollector) writeExcludeIPsToBPF() error {
	excludeMap := n.coll.Maps["exclude_dest_ips"]
	if excludeMap == nil {
		return nil
	}
	ips := []string{"10.115.107.91"}
	if env := os.Getenv("EXCLUDE_IPS"); env != "" {
		for _, ip := range strings.Split(env, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	var written int
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := binary.BigEndian.Uint32(ip4)
			val := uint8(1)
			if err := excludeMap.Put(&key, &val); err == nil {
				written++
			}
		}
	}
	log.Printf("[NETWORK] exclude IPs: %d/%d", written, len(ips))
	return nil
}

func (n *NetworkCollector) Start(ctx context.Context) error {
	n.running = true
	if n.reader == nil {
		log.Printf("[NETWORK] flow reader nil, skip")
		return nil
	}
	// Flow reader goroutine
	go func() {
		defer n.reader.Close()
		for n.running {
			record, err := n.reader.Read()
			if err != nil {
				if n.running { log.Printf("[NETWORK] flow read: %v", err) }
				continue
			}
			if len(record.RawSample) == 0 { continue }
			n.handleFlowEvent(record.RawSample)
		}
	}()
	// HTTP reader goroutine
	if n.httpReader != nil {
		go func() {
			defer n.httpReader.Close()
			log.Printf("[NETWORK] http reader started")
			for n.running {
				record, err := n.httpReader.Read()
				if err != nil {
					if n.running { log.Printf("[NETWORK] http read: %v", err) }
					continue
				}
				if len(record.RawSample) == 0 { continue }
				n.handleHTTPEvent(record.RawSample)
			}
		}()
	}
	return nil
}

// handleFlowEvent: P0 - parse 32-byte aligned flow_event from BPF
func (n *NetworkCollector) handleFlowEvent(data []byte) {
	if len(data) < 32 { return }
	srcIP := binary.BigEndian.Uint32(data[8:12])
	dstIP := binary.BigEndian.Uint32(data[12:16])
	pktBytes := uint64(binary.LittleEndian.Uint32(data[16:20]))
	pkts := uint64(binary.LittleEndian.Uint32(data[20:24]))
	srcPort := binary.LittleEndian.Uint16(data[24:26])
	dstPort := binary.LittleEndian.Uint16(data[26:28])
	proto := data[28]

	protoString := "IP"
	switch proto {
	case 6: protoString = "TCP"
	case 17: protoString = "UDP"
	}
	n.output.WriteEvent(&output.Event{
		Timestamp: time.Now(),
		ProbeID:   n.probeID + "-bpf",
		Category:  "network", EventType: "flow",
		SrcIP: ipToString(srcIP), DstIP: ipToString(dstIP),
		SrcPort: srcPort, DstPort: dstPort,
		Protocol: protoString, Bytes: pktBytes, Packets: pkts,
	})
}

// handleHTTPEvent: parse HTTP event from BPF (ts=8,si=4,di=4,sp=2,dp=2,dir=1,url=128)
func (n *NetworkCollector) handleHTTPEvent(data []byte) {
	if len(data) < 24 { return }
	ts := binary.LittleEndian.Uint64(data[0:8]); _ = ts
	srcIP := binary.BigEndian.Uint32(data[8:12])
	dstIP := binary.BigEndian.Uint32(data[12:16])
	srcPort := binary.LittleEndian.Uint16(data[16:18])
	dstPort := binary.LittleEndian.Uint16(data[18:20])
	urlBytes := bytes.TrimRight(data[21:], "\x00")
	urlStr := string(urlBytes)
	if urlStr == "" { return }

	n.output.WriteEvent(&output.Event{
		Timestamp: time.Now(),
		ProbeID:   n.probeID + "-bpf",
		Category:  "network", EventType: "http",
		SrcIP: ipToString(srcIP), DstIP: ipToString(dstIP),
		SrcPort: srcPort, DstPort: dstPort,
		Protocol: "HTTP", Details: urlStr,
	})
}

func ipToString(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func (n *NetworkCollector) Stop() {
	close(n.stopCh)
	n.running = false
	if n.reader != nil { n.reader.Close() }
	if n.httpReader != nil { n.httpReader.Close() }
	if n.coll != nil { n.coll.Close() }
}

func (n *NetworkCollector) Status() map[string]interface{} {
	return map[string]interface{}{
		"name": n.Name(), "running": n.running,
		"category": n.Category(), "interface": n.iface,
	}
}

func (n *NetworkCollector) logPrintf(f string, a ...interface{}) {
	log.Printf("[NETWORK] "+f, a...)
}

func ensureBPFFS() { os.MkdirAll(bpfMapPinPath, 0700) }
