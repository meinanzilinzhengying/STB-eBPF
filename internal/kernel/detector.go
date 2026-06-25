package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

type Capabilities struct {
	Version          string
	HasBTF           bool
	HasCO_RE         bool
	HasBPFLSM        bool
	HasBPFTracing    bool
	HasBPFKprobe     bool
	HasBPFTracepoint bool
	HasBPFXDP        bool
	HasBPFTC         bool
	HasBPFPerfEvent  bool
	AvailableHooks   []string
}

func Version() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		var b []byte
		for _, c := range uname.Release {
			if c == 0 { break }
			b = append(b, byte(c))
		}
		return string(b)
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func HasBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

func HasBPFLSM() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil { return false }
	return strings.Contains(string(data), "bpf")
}

func HasBPFTracepoint() bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil { return false }
	return strings.Contains(string(data), "bpf_trace_run")
}

func HasBPFKprobe() bool {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil { return false }
	return strings.Contains(string(data), "kprobe_dispatcher")
}

func HasBPFPerfEvent() bool {
	_, err := os.Stat("/sys/kernel/debug/tracing/")
	return err == nil
}

func HasBPFTC() bool {
	out, err := exec.Command("tc", "qdisc", "show").Output()
	return err == nil && len(out) > 0
}

func HasBPFXDP() bool {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil { return false }
	return strings.Contains(string(data), "eth") || strings.Contains(string(data), "ens")
}

func HasCO_RE() bool {
	if !HasBTF() { return false }
	out, err := exec.Command("bpftool", "--version").Output()
	return err == nil && strings.Contains(string(out), "bpftool")
}

func DetectCapabilities() Capabilities {
	cap := Capabilities{Version: Version(), HasBTF: HasBTF(), HasCO_RE: HasCO_RE()}
	cap.HasBPFLSM = HasBPFLSM()
	cap.HasBPFTracepoint = HasBPFTracepoint()
	cap.HasBPFKprobe = HasBPFKprobe()
	cap.HasBPFPerfEvent = HasBPFPerfEvent()
	cap.HasBPFTC = HasBPFTC()
	cap.HasBPFXDP = HasBPFXDP()
	cap.HasBPFTracing = cap.HasBPFKprobe || cap.HasBPFTracepoint
	if cap.HasBPFTC     { cap.AvailableHooks = append(cap.AvailableHooks, "tc") }
	if cap.HasBPFXDP    { cap.AvailableHooks = append(cap.AvailableHooks, "xdp") }
	if cap.HasBPFKprobe { cap.AvailableHooks = append(cap.AvailableHooks, "kprobe") }
	if cap.HasBPFTracepoint { cap.AvailableHooks = append(cap.AvailableHooks, "tracepoint") }
	if cap.HasBPFPerfEvent { cap.AvailableHooks = append(cap.AvailableHooks, "perf_event") }
	if cap.HasBPFLSM { cap.AvailableHooks = append(cap.AvailableHooks, "lsm") }
	return cap
}

func KernelVersionCode() int {
	v := Version()
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	m := re.FindStringSubmatch(v)
	if len(m) == 4 {
		major, minor, patch := 0, 0, 0
		fmt.Sscanf(m[1], "%d", &major)
		fmt.Sscanf(m[2], "%d", &minor)
		fmt.Sscanf(m[3], "%d", &patch)
		return major*65536 + minor*256 + patch
	}
	return 0
}
