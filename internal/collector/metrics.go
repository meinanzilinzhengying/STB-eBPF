package collector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type HostMetrics struct {
	CPUPercent     float64
	MemoryPercent  float64
	DiskPercent    float64
	NetRxBytes     uint64
	NetTxBytes     uint64
	DiskReadBytes  uint64
	DiskWriteBytes uint64
}

func getHostMetrics() HostMetrics {
	m := HostMetrics{}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		line := strings.Split(string(data), "\n")[0]
		parts := strings.Fields(line)
		if len(parts) > 4 {
			user, _ := strconv.ParseUint(parts[1], 10, 64)
			nice, _ := strconv.ParseUint(parts[2], 10, 64)
			system, _ := strconv.ParseUint(parts[3], 10, 64)
			idle, _ := strconv.ParseUint(parts[4], 10, 64)
			total := user + nice + system + idle
			if total > 0 { m.CPUPercent = float64(user+nice+system) / float64(total) * 100 }
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") { fmt.Sscanf(line, "MemTotal: %d", &total) }
			if strings.HasPrefix(line, "MemAvailable:") { fmt.Sscanf(line, "MemAvailable: %d", &avail) }
		}
		if total > 0 { m.MemoryPercent = float64(total-avail) / float64(total) * 100 }
	}
	if out, err := exec.Command("df", "/").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 1 {
			parts := strings.Fields(lines[1])
			if len(parts) > 4 {
				use, _ := strconv.Atoi(strings.TrimSuffix(parts[4], "%"))
				m.DiskPercent = float64(use)
			}
		}
	}
	if data, err := os.ReadFile("/proc/net/dev"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) > 0 && (line[0] == 'e' || line[0] == 'e' || line[0] == 'e') {
				parts := strings.Fields(line)
				if len(parts) > 10 {
					if rx, err := strconv.ParseUint(parts[1], 10, 64); err == nil { m.NetRxBytes += rx }
					if tx, err := strconv.ParseUint(parts[9], 10, 64); err == nil { m.NetTxBytes += tx }
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/diskstats"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, " sda ") || strings.Contains(line, " vda ") || strings.Contains(line, " nvme0n1 ") || strings.Contains(line, " xvda ") {
				parts := strings.Fields(line)
				if len(parts) > 13 {
					if read, err := strconv.ParseUint(parts[5], 10, 64); err == nil { m.DiskReadBytes += read * 512 }
					if write, err := strconv.ParseUint(parts[9], 10, 64); err == nil { m.DiskWriteBytes += write * 512 }
				}
			}
		}
	}
	return m
}
