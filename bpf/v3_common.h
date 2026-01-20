
#ifndef V3_COMMON_H
#define V3_COMMON_H

#include <linux/types.h>

// =========================================================
// 1. 核心常量 (必须与用户态程序一致)
// =========================================================
#define V3_PORT         51820       // v3 服务监听的 UDP 端口
#define V3_HEADER_SIZE  52          // v3 协议头的固定长度
#define V3_MAGIC_SLOTS  8           // Magic 表槽位数量
// =========================================================
// 2. XDP 统计计数器索引 (用于监控)
// =========================================================
enum stats_key {
    STAT_PASSED = 0,                // 验证通过并放行的包
    STAT_DROPPED_BLACKLIST,         // 因 IP 黑名单被丢弃的包
    STAT_DROPPED_RATELIMIT,         // 因速率超限被丢弃的包
    STAT_DROPPED_INVALID_MAGIC,     // 因 Magic 错误被丢弃的包
    STAT_DROPPED_TOO_SHORT,         // 因包太短被丢弃的包
    STAT_DROPPED_NOT_UDP,           // (非 UDP，通常放行)
    STAT_TOTAL_PROCESSED,           // XDP 处理的总包数
    STAT_MAX
};

// =========================================================
// 3. v3 协议头 (仅 XDP 解析 Magic)
// =========================================================
struct v3_header {
    __u32 magic_derived;
    __u8  nonce[12];
    __u8  enc_block[16];
    __u8  tag[16];
    __u16 early_len;
    __u16 pad;
} __attribute__((packed));

// =========================================================
// 4. BPF Map 共享数据结构
// =========================================================

// 黑名单 Value 结构
struct blacklist_entry {
    __u64 fail_count;       // 失败次数
    __u64 last_fail_ns;     // 最后一次失败的时间戳
};

// 速率限制 Value 结构
struct rate_entry {
    __u64 window_start_ns;  // 时间窗口开始时间
    __u64 packet_count;     // 窗口内包计数
};

// 已验证连接缓存 Value 结构
struct conn_cache_entry {
    __u64 last_seen_ns;     // 上次见到该连接的时间
    __u32 magic;            // 上次验证通过的 magic
};

#endif // V3_COMMON_H
