// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "v3_common.h"

// =========================================================
// 1. 配置常量 (内核态)
// =========================================================
#define BLACKLIST_THRESHOLD   100      // 失败次数超过此值则拉黑
#define RATE_LIMIT_PPS        10000    // 每个源 IP 每秒最大包数
#define RATE_WINDOW_NS        1000000000ULL  // 1秒 (纳秒)
#define DECAY_INTERVAL_NS     60000000000ULL // 60秒衰减周期

// =========================================================
// 2. BPF Maps
// =========================================================

// Magic 表 (由用户态 loader 定时更新)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} valid_magics SEC(".maps");

// 基础统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// [新增] 延迟直方图
// Bucket 0: < 1us
// Bucket 1: 1-10us
// Bucket 2: 10-100us
// Bucket 3: > 100us
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4); 
    __type(key, __u32);
    __type(value, __u64);
} latency_histogram SEC(".maps");

// 黑名单 (LRU)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct blacklist_entry);
} blacklist SEC(".maps");

// 速率限制表
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rate_entry);
} rate_limit SEC(".maps");

// 连接缓存表
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64);
    __type(value, struct conn_cache_entry);
} conn_cache SEC(".maps");

// =========================================================
// 3. 内联辅助函数
// =========================================================

static __always_inline void stats_increment(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

static __always_inline void record_latency(__u64 elapsed_ns) {
    __u32 bucket;
    if (elapsed_ns < 1000) bucket = 0;
    else if (elapsed_ns < 10000) bucket = 1;
    else if (elapsed_ns < 100000) bucket = 2;
    else bucket = 3;

    __u64 *count = bpf_map_lookup_elem(&latency_histogram, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

// =========================================================
// 4. XDP 主程序
// =========================================================
SEC("xdp")
int v3_filter(struct xdp_md *ctx) {
    __u64 start_ns = bpf_ktime_get_ns();
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 默认返回值，在最后统计耗时
    int action = XDP_PASS;
    // 用于记录是否需要更新统计
    __u32 stat_key = STAT_TOTAL_PROCESSED;
    
    // 提前增量总数
    stats_increment(STAT_TOTAL_PROCESSED);

    // --- L2: Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
        action = XDP_PASS;
        goto out;
    }

    // --- L3: IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        action = XDP_PASS;
        goto out;
    }
    
    if (ip->protocol != IPPROTO_UDP) {
        stats_increment(STAT_DROPPED_NOT_UDP);
        action = XDP_PASS;
        goto out;
    }
    __u32 src_ip = ip->saddr;

    // --- L4: UDP ---
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end || udp->dest != bpf_htons(V3_PORT)) {
        action = XDP_PASS;
        goto out;
    }

    // --- Check 1: Blacklist (带衰减) ---
    __u64 now_ns = start_ns; // 复用 start_ns 作为当前时间
    struct blacklist_entry *bl_entry = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (bl_entry) {
        __u64 decay_periods = (now_ns - bl_entry->last_fail_ns) / DECAY_INTERVAL_NS;

		if (decay_periods > 0) {
        __u64 shift = decay_periods > 8 ? 8 : decay_periods;  // 最多右移8位
            bl_entry->fail_count >>= shift;
            bl_entry->last_fail_ns = now_ns;
        }
        if (bl_entry->fail_count >= BLACKLIST_THRESHOLD) {
            stats_increment(STAT_DROPPED_BLACKLIST);
            action = XDP_DROP;
            goto out;
        }
    }

    // --- Check 2: Rate Limit ---
    struct rate_entry *rl_entry = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (!rl_entry) {
        struct rate_entry new_rl = {.window_start_ns = now_ns, .packet_count = 1};
        bpf_map_update_elem(&rate_limit, &src_ip, &new_rl, BPF_NOEXIST);
    } else {
        if (now_ns - rl_entry->window_start_ns < RATE_WINDOW_NS) {
            if (rl_entry->packet_count >= RATE_LIMIT_PPS) {
                stats_increment(STAT_DROPPED_RATELIMIT);
                action = XDP_DROP;
                goto out;
            }
            __sync_fetch_and_add(&rl_entry->packet_count, 1);
        } else {
            rl_entry->window_start_ns = now_ns;
            rl_entry->packet_count = 1;
        }
    }

    // --- L7: v3 Protocol Header ---
    void *payload = (void *)(udp + 1);
    if (payload + sizeof(struct v3_header) > data_end) {
        stats_increment(STAT_DROPPED_TOO_SHORT);
        action = XDP_DROP;
        goto out;
    }

    __u32 received_magic = ((struct v3_header *)payload)->magic_derived;
	__u64 conn_key = ((__u64)src_ip << 32) | ((__u32)bpf_ntohs(udp->source) << 16) | bpf_ntohs(udp->dest);

    // --- Check 3: Connection Cache (Fast Path) ---
    struct conn_cache_entry *cache = bpf_map_lookup_elem(&conn_cache, &conn_key);
    if (cache && cache->magic == received_magic) {
        cache->last_seen_ns = now_ns;
        stats_increment(STAT_PASSED);
        action = XDP_PASS;
        goto out;
    }

    // --- Check 4: Full Magic Verification (Slow Path) ---
    int magic_valid = 0;
	#pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        __u32 *valid = bpf_map_lookup_elem(&valid_magics, &i);
        if (valid && *valid == received_magic) {
            magic_valid = 1;
            break;
        }
    }

    if (!magic_valid) {
        if (bl_entry) {
            __sync_fetch_and_add(&bl_entry->fail_count, 1);
            bl_entry->last_fail_ns = now_ns;
        } else {
            struct blacklist_entry new_bl = {.fail_count = 1, .last_fail_ns = now_ns};
            bpf_map_update_elem(&blacklist, &src_ip, &new_bl, BPF_NOEXIST);
        }
        stats_increment(STAT_DROPPED_INVALID_MAGIC);
        action = XDP_DROP;
        goto out;
    }

    // --- Success ---
    struct conn_cache_entry new_cache = {.last_seen_ns = now_ns, .magic = received_magic};
    bpf_map_update_elem(&conn_cache, &conn_key, &new_cache, BPF_ANY);
    stats_increment(STAT_PASSED);
    action = XDP_PASS;

out:
    // 计算并记录耗时
    record_latency(bpf_ktime_get_ns() - start_ns);
    return action;
}

char _license[] SEC("license") = "GPL";
