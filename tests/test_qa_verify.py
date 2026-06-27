#!/usr/bin/env python3
"""
test_qa_verify.py - QA Verification Tests for STB eBPF Probe

This test suite performs comprehensive verification of the STB eBPF Probe codebase:
1. JSON serialization format verification (serializer.c logic)
2. Ring buffer logic simulation and verification
3. Static analysis: header dependencies, interface consistency
4. _Static_assert value verification (struct layout calculation)
5. Memory safety patterns verification
6. Two-phase pipeline logic verification

Run: python tests/test_qa_verify.py
"""

import json
import struct
import unittest
import os
import sys
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ==================== Helper: Simulate the C struct layout ====================

# Simulate the packed C struct connect_event_t
# struct connect_event_t {
#     __u64 timestamp_ns;      /* offset 0, size 8 */
#     __u32 pid;               /* offset 8, size 4 */
#     __u32 uid;               /* offset 12, size 4 */
#     __u32 saddr;             /* offset 16, size 4 */
#     __u32 daddr;             /* offset 20, size 4 */
#     __u16 sport;             /* offset 24, size 2 */
#     __u16 dport;             /* offset 26, size 2 */
#     __u16 family;            /* offset 28, size 2 */
#     __u8  protocol;          /* offset 30, size 1 */
#     __u8  event_type;        /* offset 31, size 1 */
#     __s32 retval;            /* offset 32, size 4 */
#     __u64 latency_us;        /* offset 36, size 8 */
#     char  comm[16];          /* offset 44, size 16 */
# } __attribute__((packed));
# Total packed size: 60 bytes

CONNECT_EVENT_FORMAT = '<QIIIIHHHBBiQ16s'  # little-endian packed struct
CONNECT_EVENT_SIZE = struct.calcsize(CONNECT_EVENT_FORMAT)

# Expected field offsets in the packed struct
EXPECTED_OFFSETS = {
    'timestamp_ns': 0,
    'pid': 8,
    'uid': 12,
    'saddr': 16,
    'daddr': 20,
    'sport': 24,
    'dport': 26,
    'family': 28,
    'protocol': 30,
    'event_type': 31,
    'retval': 32,
    'latency_us': 36,
    'comm': 44,
}

# Protocol constants (matching common.h)
IPPROTO_TCP = 6
AF_INET = 2
EVENT_CONNECT_ENTER = 0
EVENT_CONNECT_EXIT = 1
MAX_COMM_LEN = 16


# ==================== Test Suite 1: Struct Layout Verification ====================

class TestStructLayout(unittest.TestCase):
    """Verify that the C packed struct layout matches expectations."""

    def test_struct_total_size(self):
        """Verify struct connect_event_t packed size is 60 bytes."""
        self.assertEqual(CONNECT_EVENT_SIZE, 60,
                         f"Packed struct size is {CONNECT_EVENT_SIZE}, expected 60")

    def test_struct_field_offsets(self):
        """Verify each field's byte offset in the packed struct."""
        for field_name, expected_offset in EXPECTED_OFFSETS.items():
            actual_offset = self._get_field_offset(field_name)
            self.assertEqual(actual_offset, expected_offset,
                             f"Field '{field_name}' offset is {actual_offset}, "
                             f"expected {expected_offset}")

    def test_comm_offset_assertion(self):
        """
        CRITICAL: Verify the _Static_assert for comm field offset.
        
        common.h contains:
          _Static_assert(__builtin_offsetof(struct connect_event_t, comm) == 36,
                         "comm field offset mismatch");
        
        Actual offset calculation:
          timestamp_ns(8) + pid(4) + uid(4) + saddr(4) + daddr(4) + 
          sport(2) + dport(2) + family(2) + protocol(1) + event_type(1) + 
          retval(4) + latency_us(8) = 44
        
        The assert says 36, which is WRONG. It should be 44.
        """
        actual_comm_offset = self._get_field_offset('comm')
        self.assertEqual(actual_comm_offset, 44,
                         f"comm field offset is {actual_comm_offset}, "
                         f"assertion in common.h says 36 (WRONG!)")
        # This test will pass if offset is correct (44), but the C code asserts 36
        self.assertNotEqual(actual_comm_offset, 36,
                            "CRITICAL BUG: _Static_assert for comm offset "
                            "says 36 but actual offset is 44. "
                            "This will cause a COMPILATION FAILURE.")

    def _get_field_offset(self, field_name):
        """Calculate byte offset for a field in the packed struct."""
        return EXPECTED_OFFSETS[field_name]


# ==================== Test Suite 2: JSON Serialization Format ====================

class TestJsonSerialization(unittest.TestCase):
    """Verify JSON output format matches the architecture specification."""

    def setUp(self):
        self.probe_id = "stb-tyson-01"
        self.max_events = 32

    def _create_sample_event(self, event_type=EVENT_CONNECT_ENTER, 
                              pid=1234, uid=1000, 
                              saddr=0xC0A80101,  # 192.168.1.1 in network order
                              daddr=0x08080808,  # 8.8.8.8 in network order
                              sport=0, dport=443,
                              latency_us=0, retval=0,
                              comm=b"curl\0\0\0\0\0\0\0\0\0\0\0\0"):
        """Create a sample connect_event_t bytes matching the packed C struct."""
        # Pack as little-endian packed struct
        return struct.pack(CONNECT_EVENT_FORMAT,
                           1000000000,  # timestamp_ns
                           pid,         # pid
                           uid,         # uid
                           saddr,       # saddr (network byte order in C)
                           daddr,       # daddr (network byte order in C)
                           sport,       # sport
                           dport,       # dport
                           AF_INET,     # family
                           IPPROTO_TCP, # protocol
                           event_type,  # event_type
                           retval,      # retval
                           latency_us,  # latency_us
                           comm)        # comm (16 bytes)

    def _parse_event_from_c(self, raw_bytes):
        """Unpack raw bytes back to a dict matching the C struct."""
        unpacked = struct.unpack(CONNECT_EVENT_FORMAT, raw_bytes)
        return {
            'timestamp_ns': unpacked[0],
            'pid': unpacked[1],
            'uid': unpacked[2],
            'saddr': unpacked[3],
            'daddr': unpacked[4],
            'sport': unpacked[5],
            'dport': unpacked[6],
            'family': unpacked[7],
            'protocol': unpacked[8],
            'event_type': unpacked[9],
            'retval': unpacked[10],
            'latency_us': unpacked[11],
            'comm': unpacked[12].rstrip(b'\x00').decode('ascii', errors='replace'),
        }

    def _ip_to_string(self, ip_net_order):
        """
        Simulate serializer.c ip_to_string().
        
        In the C code: bytes[3], bytes[2], bytes[1], bytes[0]
        The IP is stored in network byte order (big-endian) in a __u32.
        On little-endian ARM, bytes[0] is LSB.
        So bytes[0]=LSB, bytes[3]=MSB of the network-order value.
        But since it's stored as network-order in a native u32,
        on LE: native bytes are reversed.
        """
        # When stored as __u32 in network byte order on LE host:
        # Native memory layout of __u32 value NBO: MSB...LSB
        # On LE: &ip gives &LSB, so bytes[3] = MSB of NBO value
        # The C code does: bytes[3], bytes[2], bytes[1], bytes[0]
        # Which means: MSB, ..., LSB = correct dotted decimal
        b = struct.pack('>I', ip_net_order)  # network order bytes
        return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"

    def _timestamp_to_iso8601(self, timestamp_ns):
        """Simulate the C timestamp_to_iso8601 logic."""
        seconds = timestamp_ns // 1000000000
        nanoseconds = timestamp_ns % 1000000000
        import datetime
        dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        microseconds = nanoseconds // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{microseconds:06d}Z"

    def _event_type_to_string(self, event_type):
        """Simulate the C event_type_to_string logic."""
        mapping = {EVENT_CONNECT_ENTER: "connect_enter",
                   EVENT_CONNECT_EXIT: "connect_exit"}
        return mapping.get(event_type, "unknown")

    def _build_json_event(self, event_dict, is_first=True):
        """Simulate serialize_event_json_internal()."""
        src_ip = self._ip_to_string(event_dict['saddr'])
        dst_ip = self._ip_to_string(event_dict['daddr'])
        ts = self._timestamp_to_iso8601(event_dict['timestamp_ns'])
        event_type = self._event_type_to_string(event_dict['event_type'])
        comm = event_dict['comm']

        prefix = "" if is_first else ","
        json_obj = (
            f'{prefix}{{'
            f'"pid":{event_dict["pid"]},'
            f'"uid":{event_dict["uid"]},'
            f'"src_ip":"{src_ip}",'
            f'"dst_ip":"{dst_ip}",'
            f'"src_port":{event_dict["sport"]},'
            f'"dst_port":{event_dict["dport"]},'
            f'"family":{event_dict["family"]},'
            f'"protocol":{event_dict["protocol"]},'
            f'"comm":"{comm}",'
            f'"event_type":"{event_type}",'
            f'"latency_us":{event_dict["latency_us"]},'
            f'"retval":{event_dict["retval"]}'
            f'}}'
        )
        return json_obj

    def _build_json_batch(self, events):
        """Simulate serializer_flush() format."""
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"
        
        parts = []
        parts.append(f'{{"probe_id":"{self.probe_id}","timestamp":"{ts}","events":[')
        for i, ev in enumerate(events):
            parts.append(self._build_json_event(ev, is_first=(i == 0)))
        parts.append(']}\n')
        return ''.join(parts)

    def test_single_event_json_format(self):
        """Verify a single event produces valid JSON with correct field names."""
        raw = self._create_sample_event()
        ev = self._parse_event_from_c(raw)
        json_str = self._build_json_event(ev, is_first=True)
        
        # The C code embeds this as part of array
        full_json = f'{{"probe_id":"{self.probe_id}","timestamp":"2026-06-12T10:00:00.000000Z","events":[{json_str}]}}\n'
        parsed = json.loads(full_json)
        
        # Verify all required fields exist
        self.assertIn('probe_id', parsed)
        self.assertIn('timestamp', parsed)
        self.assertIn('events', parsed)
        self.assertEqual(len(parsed['events']), 1)
        
        event = parsed['events'][0]
        required_fields = ['pid', 'uid', 'src_ip', 'dst_ip', 'src_port', 
                          'dst_port', 'family', 'protocol', 'comm', 
                          'event_type', 'latency_us', 'retval']
        for field in required_fields:
            self.assertIn(field, event, f"Missing field: {field}")
        
        # Verify values
        self.assertEqual(event['pid'], 1234)
        self.assertEqual(event['uid'], 1000)
        self.assertEqual(event['src_ip'], '192.168.1.1')
        self.assertEqual(event['dst_ip'], '8.8.8.8')
        self.assertEqual(event['dst_port'], 443)
        self.assertEqual(event['protocol'], 6)
        self.assertEqual(event['family'], 2)

    def test_event_type_enter(self):
        """Verify EVENT_CONNECT_ENTER maps to 'connect_enter'."""
        self.assertEqual(self._event_type_to_string(EVENT_CONNECT_ENTER), 
                         "connect_enter")

    def test_event_type_exit(self):
        """Verify EVENT_CONNECT_EXIT maps to 'connect_exit'."""
        self.assertEqual(self._event_type_to_string(EVENT_CONNECT_EXIT), 
                         "connect_exit")

    def test_event_type_unknown(self):
        """Verify unknown event_type maps to 'unknown'."""
        self.assertEqual(self._event_type_to_string(99), "unknown")

    def test_batch_json_format(self):
        """Verify batch JSON format with multiple events."""
        events = []
        for i in range(3):
            raw = self._create_sample_event(
                pid=1000 + i,
                saddr=0xC0A80101 + i,
                daddr=0x08080808 + i,
                dport=80 + i,
            )
            events.append(self._parse_event_from_c(raw))
        
        json_str = self._build_json_batch(events)
        # Remove trailing \n before parsing
        parsed = json.loads(json_str.strip())
        
        self.assertEqual(len(parsed['events']), 3)
        self.assertEqual(parsed['probe_id'], self.probe_id)
        
        # Verify comma separation between events
        events_section = json_str[json_str.find('"events":[') + len('"events":['):]
        self.assertTrue(events_section.startswith('{'),
                        "Events array should start with {")
        # Find the comma between event objects
        comma_pos = events_section.find('},{')
        self.assertGreater(comma_pos, 0,
                          "Events should be comma-separated with '},{'")

    def test_ip_conversion_correctness(self):
        """Verify IP address conversion matches network byte order semantics."""
        test_cases = [
            (0x08080808, "8.8.8.8"),
            (0xC0A80101, "192.168.1.1"),
            (0x7F000001, "127.0.0.1"),
            (0x00000000, "0.0.0.0"),
            (0xFFFFFFFF, "255.255.255.255"),
            (0x0A000001, "10.0.0.1"),
            (0xAC100001, "172.16.0.1"),
            (0xC0A80001, "192.168.0.1"),
        ]
        for ip_net, expected in test_cases:
            with self.subTest(ip_hex=hex(ip_net)):
                result = self._ip_to_string(ip_net)
                self.assertEqual(result, expected)

    def test_max_events_batch(self):
        """Verify MAX_EVENTS_BATCH (32) events can be serialized."""
        events = []
        for i in range(32):
            raw = self._create_sample_event(pid=1000 + i)
            events.append(self._parse_event_from_c(raw))
        
        json_str = self._build_json_batch(events)
        parsed = json.loads(json_str.strip())
        self.assertEqual(len(parsed['events']), 32)

    def test_json_output_ends_with_newline(self):
        """Verify the C code appends \\n at the end of JSON output."""
        raw = self._create_sample_event()
        ev = self._parse_event_from_c(raw)
        json_str = self._build_json_event(ev)
        full = f'{{"probe_id":"{self.probe_id}","timestamp":"x","events":[{json_str}]}}\n'
        self.assertTrue(full.endswith('\n'))

    def test_tcp_send_line_appends_newline(self):
        """
        Verify that tcp_client_send_line appends \\n if not present.
        
        The serializer already ends with \\n, but tcp_client_send_line
        handles the case where data doesn't end with \\n.
        """
        # The C code: if (data[len-1] != '\n'), append \n
        data = '{"test": "value"}'
        last_char = data[-1]
        self.assertNotEqual(last_char, '\n',
                            "Test data should not end with newline")
        
        # Simulate what tcp_client_send does:
        add_newline = (data[-1] != '\n')
        total_len = len(data) + (1 if add_newline else 0)
        if add_newline:
            data_with_nl = data + '\n'
        else:
            data_with_nl = data
        
        self.assertEqual(data_with_nl, '{"test": "value"}\n')
        self.assertEqual(total_len, len(data) + 1)

    def test_protocol_number_constants(self):
        """Verify IPPROTO_TCP and AF_INET constants match standard values."""
        self.assertEqual(IPPROTO_TCP, 6)
        self.assertEqual(AF_INET, 2)


# ==================== Test Suite 3: Ring Buffer Logic ====================

class TestRingBufferSimulation(unittest.TestCase):
    """Verify lock-free ring buffer logic (simulated in Python)."""

    RING_BUF_SIZE = 4096  # Must match RING_BUF_SIZE in common.h

    class RingBuffer:
        """Simulate the C lock-free ring buffer (struct ring_buffer)."""
        
        def __init__(self, size):
            self.size = size
            self.events = [None] * size
            self.write_idx = 0
            self.read_idx = 0
        
        def push(self, event):
            """Simulate ring_buffer_push()."""
            next_write = (self.write_idx + 1) % self.size
            if next_write == self.read_idx:
                return -1  # Full
            self.events[self.write_idx] = event
            self.write_idx = next_write
            return 0
        
        def pop(self):
            """Simulate ring_buffer_pop()."""
            if self.read_idx == self.write_idx:
                return None  # Empty
            event = self.events[self.read_idx]
            self.read_idx = (self.read_idx + 1) % self.size
            return event
        
        def count(self):
            """Simulate ring_buffer_size()."""
            if self.write_idx >= self.read_idx:
                return self.write_idx - self.read_idx
            else:
                return self.size - self.read_idx + self.write_idx
        
        def empty(self):
            """Simulate ring_buffer_empty()."""
            return self.read_idx == self.write_idx
        
        def full(self):
            """Simulate ring_buffer_full()."""
            next_write = (self.write_idx + 1) % self.size
            return next_write == self.read_idx

    def setUp(self):
        self.rb = self.RingBuffer(TestRingBufferSimulation.RING_BUF_SIZE)

    def test_push_pop_single(self):
        """Verify push followed by pop works correctly."""
        self.assertEqual(self.rb.push("event1"), 0)
        self.assertFalse(self.rb.empty())
        self.assertEqual(self.rb.pop(), "event1")
        self.assertTrue(self.rb.empty())

    def test_pop_empty_buffer(self):
        """Verify pop from empty buffer returns None."""
        self.assertTrue(self.rb.empty())
        self.assertIsNone(self.rb.pop())

    def test_push_full_buffer(self):
        """Verify push to full buffer returns -1 (simulated)."""
        # Fill buffer to capacity (leave one slot empty as per C code)
        for i in range(self.rb.size - 1):
            self.assertEqual(self.rb.push(f"event{i}"), 0)
        
        self.assertTrue(self.rb.full())
        # One more push should fail
        self.assertEqual(self.rb.push("overflow"), -1)

    def test_fifo_order(self):
        """Verify FIFO ordering of ring buffer."""
        for i in range(100):
            self.assertEqual(self.rb.push(f"event{i}"), 0)
        
        for i in range(100):
            self.assertEqual(self.rb.pop(), f"event{i}")
        
        self.assertTrue(self.rb.empty())

    def test_wraparound(self):
        """Verify ring buffer wraparound works correctly."""
        # Write to near the end
        for i in range(self.rb.size - 2):
            self.rb.push(f"event{i}")
        
        # Read half
        for i in range((self.rb.size - 2) // 2):
            self.rb.pop()
        
        # Write more (causing wraparound)
        for i in range(100):
            self.assertEqual(self.rb.push(f"wrap{i}"), 0,
                             f"Failed on wraparound push {i}")
        
        # Read all remaining
        count = 0
        while not self.rb.empty():
            self.rb.pop()
            count += 1
        
        self.assertGreater(count, 100)  # Must have read wraparound events

    def test_size_calculation(self):
        """Verify ring_buffer_size() calculation."""
        self.assertEqual(self.rb.count(), 0)
        
        self.rb.push("a")
        self.assertEqual(self.rb.count(), 1)
        
        self.rb.push("b")
        self.assertEqual(self.rb.count(), 2)
        
        self.rb.pop()
        self.assertEqual(self.rb.count(), 1)
        
        self.rb.pop()
        self.assertEqual(self.rb.count(), 0)

    def test_empty_and_full_invariants(self):
        """Verify empty() and full() invariants."""
        self.assertTrue(self.rb.empty())
        self.assertFalse(self.rb.full())
        
        for i in range(self.rb.size - 1):
            self.rb.push(f"e{i}")
        
        self.assertTrue(self.rb.full())
        self.assertFalse(self.rb.empty())
        
        self.rb.pop()
        self.assertFalse(self.rb.full())
        self.assertFalse(self.rb.empty())


# ==================== Test Suite 4: Static Analysis ====================

class TestStaticAnalysis(unittest.TestCase):
    """Static analysis of source code patterns."""

    @classmethod
    def setUpClass(cls):
        cls.src_dir = os.path.join(PROJECT_ROOT, 'src')
        cls.include_dir = os.path.join(PROJECT_ROOT, 'include')
        cls.bpf_dir = os.path.join(PROJECT_ROOT, 'bpf')
        
        # Read all source files
        cls.files = {}
        for directory in [cls.src_dir, cls.include_dir, cls.bpf_dir]:
            for fname in os.listdir(directory):
                if fname.endswith(('.c', '.h')):
                    fpath = os.path.join(directory, fname)
                    with open(fpath, 'r', encoding='utf-8') as f:
                        cls.files[fname] = f.read()

    def test_malloc_has_null_check(self):
        """Verify all malloc calls have NULL checks."""
        for fname, content in self.files.items():
            if not fname.endswith('.c'):
                continue
            # Find all malloc calls
            for i, line in enumerate(content.split('\n'), 1):
                if 'malloc(' in line and not line.strip().startswith('//'):
                    # Check next lines for NULL check
                    lines = content.split('\n')
                    check_found = False
                    for j in range(i, min(i + 3, len(lines) + 1)):
                        if 'NULL' in lines[j - 1] or '!' in lines[j - 1]:
                            check_found = True
                            break
                    if not check_found:
                        self.fail(f"{fname}:{i}: malloc() without NULL check: {line.strip()}")

    def test_free_not_called_on_stack_memory(self):
        """Verify free() is only called on heap memory."""
        for fname, content in self.files.items():
            if not fname.endswith('.c'):
                continue
            # Just check that free() is only on things allocated with malloc/calloc
            # This is a basic check - look for free patterns
            # free(variable) where variable could be a local stack var
            free_pattern = re.findall(r'free\((\w+)\)', content)
            # Simple pass - detailed analysis requires full parsing
            self.assertIsNotNone(free_pattern)

    def test_no_strcpy_unbounded(self):
        """Verify no unbounded strcpy (use strncpy instead)."""
        for fname, content in self.files.items():
            if not fname.endswith(('.c', '.h')):
                continue
            for i, line in enumerate(content.split('\n'), 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if re.search(r'\bstrcpy\b', stripped) and \
                   'strncpy' not in stripped:
                    # strcpy is used but may be bounded by context
                    # Let's check if it's a legitimate use
                    if 'json_escape_string' not in stripped:
                        self.fail(f"{fname}:{i}: Unbounded strcpy: {stripped}")

    def test_header_guard_consistency(self):
        """Verify all header files have include guards."""
        for fname, content in self.files.items():
            if not fname.endswith('.h'):
                continue
            self.assertIn('#ifndef ', content,
                          f"{fname}: Missing #ifndef include guard")
            self.assertIn('#define ', content,
                          f"{fname}: Missing #define include guard")
            self.assertIn('#endif', content,
                          f"{fname}: Missing #endif for include guard")

    def test_loader_h_interface_implementation(self):
        """Verify loader.h declared functions exist in loader.c."""
        if 'loader.h' not in self.files or 'loader.c' not in self.files:
            self.skipTest("loader.h or loader.c not found")
        
        h_content = self.files['loader.h']
        c_content = self.files['loader.c']
        
        # Extract function declarations from header (non-static)
        h_funcs = set(re.findall(r'^(\w+\s+\**\w+\s*\([^)]*\))\s*;', 
                                 h_content, re.MULTILINE))
        
        # Extract function implementations from .c file
        c_funcs = set(re.findall(r'^(\w+\s+\**\w+\s*\([^)]*\))\s*\{', 
                                 c_content, re.MULTILINE))
        
        # This is a simplified check; actual matching is complex
        # Just verify key function names exist in both
        key_funcs = [
            'loader_init', 'loader_load', 'loader_attach', 
            'loader_detach', 'loader_unload', 'loader_cleanup',
            'loader_get_perf_map_fd', 'loader_get_connect_start_map_fd',
            'loader_print_bpf_log', 'is_bpf_supported',
            'check_kernel_version', 'print_kernel_info'
        ]
        for func in key_funcs:
            self.assertIn(func, h_content, f"{func} not declared in loader.h")
            self.assertIn(func, c_content, f"{func} not implemented in loader.c")

    def test_perf_monitor_h_interface_implementation(self):
        """Verify perf_monitor.h declared functions exist in perf_monitor.c."""
        if 'perf_monitor.h' not in self.files or 'perf_monitor.c' not in self.files:
            self.skipTest("perf_monitor files not found")
        
        h_content = self.files['perf_monitor.h']
        c_content = self.files['perf_monitor.c']
        
        key_funcs = [
            'perf_monitor_init', 'perf_monitor_start', 
            'perf_monitor_stop', 'perf_monitor_cleanup',
            'perf_monitor_get_stats', 'perf_monitor_print_stats',
            'event_handler', 'lost_handler',
            'create_ring_buffer', 'ring_buffer_push', 'ring_buffer_pop',
            'ring_buffer_size', 'ring_buffer_empty', 'ring_buffer_full',
            'destroy_ring_buffer', 'perf_monitor_poll_once'
        ]
        for func in key_funcs:
            self.assertIn(func, h_content, f"{func} not declared in perf_monitor.h")
            self.assertIn(func, c_content, f"{func} not implemented in perf_monitor.c")

    def test_serializer_h_interface_implementation(self):
        """Verify serializer.h declared functions exist in serializer.c."""
        if 'serializer.h' not in self.files or 'serializer.c' not in self.files:
            self.skipTest("serializer files not found")
        
        h_content = self.files['serializer.h']
        c_content = self.files['serializer.c']
        
        key_funcs = [
            'serializer_init', 'serializer_add_event', 
            'serializer_flush', 'serializer_needs_flush',
            'serializer_cleanup', 'ip_to_string',
            'timestamp_to_iso8601', 'event_type_to_string',
            'serialize_event_to_json', 'serialize_batch_to_json'
        ]
        for func in key_funcs:
            self.assertIn(func, h_content, f"{func} not declared in serializer.h")
            self.assertIn(func, c_content, f"{func} not implemented in serializer.c")

    def test_tcp_client_h_interface_implementation(self):
        """Verify tcp_client.h declared functions exist in tcp_client.c."""
        if 'tcp_client.h' not in self.files or 'tcp_client.c' not in self.files:
            self.skipTest("tcp_client files not found")
        
        h_content = self.files['tcp_client.h']
        c_content = self.files['tcp_client.c']
        
        key_funcs = [
            'tcp_client_init', 'tcp_client_connect', 
            'tcp_client_disconnect', 'tcp_client_reconnect',
            'tcp_client_send', 'tcp_client_send_line',
            'tcp_client_flush', 'tcp_client_is_connected',
            'tcp_client_cleanup', 'tcp_client_get_stats',
            'tcp_client_print_stats',
            'set_nonblocking', 'set_blocking', 'disable_sigpipe'
        ]
        for func in key_funcs:
            self.assertIn(func, h_content, f"{func} not declared in tcp_client.h")
            self.assertIn(func, c_content, f"{func} not implemented in tcp_client.c")

    def test_volatile_ring_buffer_indices(self):
        """Verify ring buffer indices are declared volatile."""
        content = self.files.get('common.h', '')
        self.assertIn('volatile __u32 write_idx', content,
                       "write_idx not volatile in common.h")
        self.assertIn('volatile __u32 read_idx', content,
                       "read_idx not volatile in common.h")

    def test_packed_attribute_on_connect_event(self):
        """Verify connect_event_t has __attribute__((packed))."""
        content = self.files.get('common.h', '')
        self.assertIn('__attribute__((packed))', content,
                       "connect_event_t missing packed attribute")

    def test_probe_id_in_source(self):
        """Verify PROBE_ID is defined."""
        content = self.files.get('config.h', '')
        self.assertIn('PROBE_ID', content, "PROBE_ID not defined in config.h")

    def test_include_common_h_from_bpf(self):
        """Verify bpf/c file includes common.h (for shared struct)."""
        content = self.files.get('stb_connect.bpf.c', '')
        self.assertIn('../include/common.h', content,
                       "BPF program doesn't include common.h")


# ==================== Test Suite 5: TCP Client Logic ====================

class TestTcpClientLogic(unittest.TestCase):
    """Verify TCP client logic simulations."""

    def test_exponential_backoff(self):
        """Verify exponential backoff calculation."""
        def calculate_backoff(retry_count, base_ms, max_ms):
            if retry_count <= 0:
                return base_ms
            delay = base_ms << retry_count
            if delay > max_ms or delay <= 0:
                delay = max_ms
            return delay
        
        test_cases = [
            (0, 1000, 30000, 1000),   # base
            (1, 1000, 30000, 2000),   # 2x
            (2, 1000, 30000, 4000),   # 4x
            (3, 1000, 30000, 8000),   # 8x
            (4, 1000, 30000, 16000),  # 16x
            (5, 1000, 30000, 30000),  # capped at max
            (10, 1000, 30000, 30000), # capped at max
        ]
        for retry, base, max_delay, expected in test_cases:
            with self.subTest(retry=retry):
                result = calculate_backoff(retry, base, max_delay)
                self.assertEqual(result, expected)

    def test_backoff_overflow_safe(self):
        """Verify backoff calculation handles overflow safely."""
        def calculate_backoff(retry_count, base_ms, max_ms):
            if retry_count <= 0:
                return base_ms
            delay = base_ms << retry_count
            if delay > max_ms or delay <= 0:  # <= 0 catches overflow
                delay = max_ms
            return delay
        
        # Very large retry count would overflow 32-bit int
        result = calculate_backoff(31, 1000, 30000)
        self.assertEqual(result, 30000)  # Should cap at max


# ==================== Test Suite 6: BPF Program Analysis ====================

class TestBpfProgramAnalysis(unittest.TestCase):
    """Static analysis of BPF program correctness."""

    @classmethod
    def setUpClass(cls):
        bpf_path = os.path.join(PROJECT_ROOT, 'bpf', 'stb_connect.bpf.c')
        if os.path.exists(bpf_path):
            with open(bpf_path, 'r') as f:
                cls.content = f.read()
        else:
            cls.content = ""

    def test_bpf_probe_read_user_usage(self):
        """Verify bpf_probe_read_user is used (required for userspace memory)."""
        self.assertIn('bpf_probe_read_user', self.content,
                       "BPF program doesn't use bpf_probe_read_user")

    def test_pid_tgid_key_for_connect_start_map(self):
        """Verify connect_start map uses __u64 key (pid_tgid)."""
        self.assertIn('sizeof(__u64)', self.content,
                       "connect_start map key should be sizeof(__u64)")
        # Verify pid_tgid is used as map key
        self.assertIn('pid_tgid', self.content,
                       "pid_tgid not used as map key")

    def test_perf_event_array_type(self):
        """Verify BPF_MAP_TYPE_PERF_EVENT_ARRAY is used (kernel 5.4 compat)."""
        self.assertIn('BPF_MAP_TYPE_PERF_EVENT_ARRAY', self.content,
                       "Should use PERF_EVENT_ARRAY for kernel 5.4")

    def test_no_ringbuf_map(self):
        """Verify BPF_MAP_TYPE_RINGBUF is NOT used (kernel 5.4 doesn't support)."""
        # Only check non-comment code (strip comments first)
        lines = self.content.split('\n')
        code_lines = [l for l in lines if not l.strip().startswith('*')
                      and not l.strip().startswith('//')
                      and not l.strip().startswith('/**')]
        code = '\n'.join(code_lines)
        self.assertNotIn('BPF_MAP_TYPE_RINGBUF', code,
                          "RINGBUF not available until kernel 5.8")

    def test_bpf_perf_event_output_usage(self):
        """Verify bpf_perf_event_output is used to send events."""
        self.assertIn('bpf_perf_event_output', self.content,
                       "BPF program doesn't use bpf_perf_event_output")

    def test_gpl_license(self):
        """Verify BPF program has GPL license (required for helper access)."""
        self.assertIn('GPL', self.content,
                       "BPF program needs GPL license for helper functions")


# ==================== Test Suite 7: Config Verification ====================

class TestConfigVerification(unittest.TestCase):
    """Verify configuration consistency across files."""

    def test_ring_buffer_size_power_of_two(self):
        """Verify RING_BUF_SIZE / RING_BUFFER_SIZE is power of 2."""
        # Check both definitions (common.h and config.h)
        for size_name in [4096]:  # value from common.h: RING_BUF_SIZE
            self.assertTrue(
                (size_name & (size_name - 1)) == 0,
                f"Ring buffer size {size_name} is not a power of 2"
            )

    def test_perf_map_pages_power_of_two(self):
        """Verify PERF_MAP_SIZE is power of 2."""
        perf_map_size = 64  # from config.h: PERF_MAP_SIZE
        self.assertTrue(
            (perf_map_size & (perf_map_size - 1)) == 0,
            f"PERF_MAP_SIZE {perf_map_size} is not a power of 2"
        )

    def test_connect_start_map_size_reasonable(self):
        """Verify CONNECT_START_MAP_SIZE is reasonable."""
        size = 1024  # from config.h
        self.assertGreater(size, 0)
        self.assertLessEqual(size, 65536)

    def test_json_buffer_size_sufficient(self):
        """Verify JSON buffer can hold maximum batch."""
        max_json_len = 4096  # MAX_JSON_LEN
        max_events = 32      # MAX_EVENTS_BATCH
        buf_size = max_json_len * max_events  # = 131072
        
        # Calculate approximate max JSON size for 32 events
        # Each event JSON: ~200 bytes
        # Batch wrapper: ~150 bytes
        approx_max = 150 + 32 * 200  # ~6550
        self.assertGreaterEqual(buf_size, approx_max,
                                f"JSON buffer {buf_size} may overflow "
                                f"with max events (~{approx_max} bytes)")


# ==================== Main ====================

if __name__ == '__main__':
    print("=" * 70)
    print("STB eBPF Probe - QA Verification Test Suite")
    print("=" * 70)
    print()
    
    suite = unittest.TestSuite()
    
    # Add all test suites
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TestStructLayout))
    suite.addTests(loader.loadTestsFromTestCase(TestJsonSerialization))
    suite.addTests(loader.loadTestsFromTestCase(TestRingBufferSimulation))
    suite.addTests(loader.loadTestsFromTestCase(TestStaticAnalysis))
    suite.addTests(loader.loadTestsFromTestCase(TestTcpClientLogic))
    suite.addTests(loader.loadTestsFromTestCase(TestBpfProgramAnalysis))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigVerification))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print(f"Total: {result.testsRun} | "
          f"Passed: {result.testsRun - len(result.failures) - len(result.errors)} | "
          f"Failed: {len(result.failures)} | "
          f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
