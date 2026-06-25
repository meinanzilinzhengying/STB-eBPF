#!/usr/bin/env python3
"""
Convert BPF C files from CO-RE + ringbuf to legacy + perf buffer.
Usage: python3 convert_to_legacy.py <input.bpf.c> <output.bpf.c>
"""
import sys
import re

def convert_bpf_file(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    output_lines = []
    
    # Track if we added vmlinux_legacy.h include
    added_legacy_include = False
    in_map_definition = False
    map_indent = ""
    has_ringbuf_map = False
    
    for i, line in enumerate(lines):
        # 1. Remove #include "bpf_core_read.h"
        if '#include "bpf_core_read.h"' in line:
            continue
        
        # 2. Add #include "vmlinux_legacy.h" after other includes
        if not added_legacy_include and ('#include "bpf_helpers.h"' in line or '#include "vmlinux.h"' in line):
            if '#include "vmlinux.h"' in line:
                # Replace vmlinux.h with vmlinux_legacy.h
                output_lines.append('#include "vmlinux_legacy.h"')
            else:
                output_lines.append(line)
                output_lines.append('#include "vmlinux_legacy.h"')
            added_legacy_include = True
            continue
        
        # 3. Replace BPF_MAP_TYPE_RINGBUF with BPF_MAP_TYPE_PERF_EVENT_ARRAY
        if 'BPF_MAP_TYPE_RINGBUF' in line:
            indent = len(line) - len(line.lstrip())
            map_indent = ' ' * indent
            output_lines.append(f'{map_indent}struct {{')
            output_lines.append(f'{map_indent}    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);')
            output_lines.append(f'{map_indent}    __uint(key_size, sizeof(int));')
            output_lines.append(f'{map_indent}    __uint(value_size, sizeof(int));')
            output_lines.append(f'{map_indent}    __uint(max_entries, 64);')
            output_lines.append(f'{map_indent}}} perf_map SEC(".maps");')
            in_map_definition = True
            has_ringbuf_map = True
            continue
        
        # Skip ringbuf map closing brace
        if in_map_definition and '}' in line and 'SEC' in line:
            in_map_definition = False
            # Add SEC annotation
            output_lines.append(line)
            continue
        
        if in_map_definition:
            continue
        
        # 4. Replace BPF_CORE_READ macros with bpf_probe_read_kernel
        # Simple pattern: BPF_CORE_READ(var, field) -> bpf_probe_read_kernel(&dest, sizeof(dest), &var->field)
        # This is complex - we'll need to track variable names and destinations
        
        # For now, let's handle common patterns
        # Pattern: e->field = BPF_CORE_READ(ptr, member);
        core_read_pattern = r'BPF_CORE_READ\((\w+),\s*(\w+)\)'
        core_read_nested_pattern = r'BPF_CORE_READ\((\w+),\s*(\w+),\s*(\w+)\)'
        
        if 'BPF_CORE_READ' in line:
            # Try to replace simple BPF_CORE_READ
            # This is a simplified replacement - may need manual fixes
            line = re.sub(r'BPF_CORE_READ\((\w+),\s*(\w+)\)', 
                         r'({ bpftool_probe_read_kernel(&temp, sizeof(temp), &\1->\2); })', line)
        
        # 5. Replace bpf_ringbuf_reserve + bpf_ringbuf_submit with bpf_perf_event_output
        if 'bpf_ringbuf_reserve' in line and has_ringbuf_map:
            # This needs complete rewrite of the function
            # For now, comment out and warn
            output_lines.append(f'// TODO: Convert to bpf_perf_event_output')
            output_lines.append(f'// Original: {line}')
            continue
        
        if 'bpf_ringbuf_submit' in line:
            output_lines.append(f'// TODO: Convert to bpf_perf_event_output')
            output_lines.append(f'// Original: {line}')
            continue
        
        output_lines.append(line)
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(output_lines))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bpf.c> <output.bpf.c>")
        sys.exit(1)
    
    convert_bpf_file(sys.argv[1], sys.argv[2])
    print(f"Converted {sys.argv[1]} -> {sys.argv[2]}")
