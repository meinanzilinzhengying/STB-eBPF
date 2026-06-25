package injector

import (
	"bytes"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Injector 动态 eBPF 代码注入器
type Injector struct {
	programs map[string]*InjectedProgram
}

// InjectedProgram 已注入的程序
type InjectedProgram struct {
	Name       string
	Tag        string
	Collection *ebpf.Collection
	Links      []link.Link
	Spec       *ebpf.CollectionSpec
}

func New() *Injector {
	return &Injector{programs: make(map[string]*InjectedProgram)}
}

// LoadFromFile 从文件加载 eBPF 字节码并注入
func (i *Injector) LoadFromFile(name, path string, opts *ebpf.CollectionOptions) (*InjectedProgram, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}
	return i.LoadFromBytes(name, data, opts)
}

// LoadFromBytes 从字节加载 eBPF 程序
func (i *Injector) LoadFromBytes(name string, data []byte, opts *ebpf.CollectionOptions) (*InjectedProgram, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("解析 eBPF 程序失败: %w", err)
	}
	return i.LoadFromSpec(name, spec, opts)
}

// LoadFromSpec 从 CollectionSpec 加载
func (i *Injector) LoadFromSpec(name string, spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) (*InjectedProgram, error) {
	if opts == nil {
		opts = &ebpf.CollectionOptions{}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF 集合失败: %w", err)
	}
	prog := &InjectedProgram{
		Name:       name,
		Collection: coll,
		Spec:       spec,
	}
	i.programs[name] = prog
	return prog, nil
}

// AttachKprobe 附加 kprobe
func (p *InjectedProgram) AttachKprobe(progName, symbol string) error {
	prog := p.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("程序 %s 未找到", progName)
	}
	l, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		return fmt.Errorf("附加 kprobe 失败: %w", err)
	}
	p.Links = append(p.Links, l)
	return nil
}

// AttachTracepoint 附加 tracepoint
func (p *InjectedProgram) AttachTracepoint(progName, group, name string) error {
	prog := p.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("程序 %s 未找到", progName)
	}
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return fmt.Errorf("附加 tracepoint 失败: %w", err)
	}
	p.Links = append(p.Links, l)
	return nil
}

// Unload 卸载注入的程序
func (i *Injector) Unload(name string) error {
	prog, ok := i.programs[name]
	if !ok {
		return fmt.Errorf("程序 %s 未找到", name)
	}
	for _, l := range prog.Links {
		l.Close()
	}
	prog.Collection.Close()
	delete(i.programs, name)
	return nil
}

// List 列出所有已注入的程序
func (i *Injector) List() []string {
	var names []string
	for name := range i.programs {
		names = append(names, name)
	}
	return names
}

// Get 获取已注入的程序
func (i *Injector) Get(name string) *InjectedProgram {
	return i.programs[name]
}

// Close 卸载所有程序
func (i *Injector) Close() {
	for name := range i.programs {
		i.Unload(name)
	}
}

// Stats 获取注入程序的统计信息
func (p *InjectedProgram) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"name":  p.Name,
		"links": len(p.Links),
	}
	for progName, prog := range p.Collection.Programs {
		info, err := prog.Info()
		if err != nil {
			continue
		}
		stats[progName] = map[string]interface{}{
			"tag": info.Tag,
		}
		if runtime, ok := info.Runtime(); ok {
			stats[progName].(map[string]interface{})["run_time"] = runtime
		}
		if runcount, ok := info.RunCount(); ok {
			stats[progName].(map[string]interface{})["run_count"] = runcount
		}
	}
	return stats
}
