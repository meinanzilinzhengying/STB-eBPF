package platform

import (
	"os"
	"runtime"
)

func Hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return h
}

func Detect() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if contains(s, "kubepods") || contains(s, "kubernetes") {
			return "kubernetes"
		}
		if contains(s, "docker") {
			return "docker"
		}
	}
	if _, err := os.Stat("/dev/dvb"); err == nil {
		return "stb"
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if containsAny(string(data), []string{"OpenStack", "KVM", "VMware", "Virtual"}) {
			return "vm"
		}
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		if containsAny(string(data), []string{"Alibaba", "Tencent", "Huawei", "AWS", "Azure"}) {
			return "ecs"
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSub(s, sub))
}

func containsSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}
