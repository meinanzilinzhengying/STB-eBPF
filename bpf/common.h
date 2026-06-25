//go:build ignore

#ifndef __COMMON_H__
#define __COMMON_H__

#define TASK_COMM_LEN 16
#define EXE_LEN 64
#define ARGS_LEN 128
#define FILENAME_LEN 128
#define HOST_LEN 64
#define URL_LEN 128
#define METHOD_LEN 8
#define DATA_LEN 256

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

enum event_type {
    EVENT_TYPE_FLOW = 1,
    EVENT_TYPE_HTTP = 2,
    EVENT_TYPE_DNS = 3,
    EVENT_TYPE_EXEC = 4,
    EVENT_TYPE_EXIT = 5,
    EVENT_TYPE_FILE_OPEN = 6,
    EVENT_TYPE_TCP_CONNECT = 7,
    EVENT_TYPE_SYSCALL = 8,
    EVENT_TYPE_DISK_IO = 9,
    EVENT_TYPE_MAX = 10,
    // 扩展类型
    EVENT_TYPE_SCHED_SWITCH = 12,
    EVENT_TYPE_SCHED_WAKEUP = 13,
    EVENT_TYPE_KMALLOC = 14,
    EVENT_TYPE_KFREE = 15,
    EVENT_TYPE_BLOCK_ISSUE = 16,
    EVENT_TYPE_BLOCK_COMPLETE = 17,
    EVENT_TYPE_CAP_CAPABLE = 18,
    EVENT_TYPE_SECURITY_FILE_OPEN = 19,
    EVENT_TYPE_LOAD_MODULE = 20,
    EVENT_TYPE_MYSQL = 10,
    EVENT_TYPE_REDIS = 11,
};

struct event {
    __u64 timestamp_ns;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 padding[7];
    __u64 bytes;
    __u64 packets;
    __u64 latency_ns;
    __u64 count;
    char comm[TASK_COMM_LEN];
    char data[DATA_LEN];
};

#endif
