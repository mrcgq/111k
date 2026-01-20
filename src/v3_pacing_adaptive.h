
#ifndef V3_PACING_ADAPTIVE_H
#define V3_PACING_ADAPTIVE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =========================================================
// 自适应 Pacing
// =========================================================
typedef struct {
    // 基础配置
    uint64_t    target_bps;
    uint64_t    max_bps;
    uint64_t    min_bps;
    
    // 令牌桶
    double      tokens;
    double      tokens_per_ns;
    uint64_t    last_refill_ns;
    
    // RTT 追踪
    uint64_t    rtt_us;
    uint64_t    rtt_min_us;
    uint64_t    rtt_max_us;
    double      rtt_var;
    
    // 带宽估计
    uint64_t    bw_estimate_bps;
    uint64_t    bytes_in_flight;
    uint64_t    last_bw_update_ns;
    
    // 拥塞控制状态
    enum {
        PACING_SLOW_START,
        PACING_CONGESTION_AVOIDANCE,
        PACING_RECOVERY,
    } state;
    
    uint64_t    cwnd;           // 拥塞窗口（字节）
    uint64_t    ssthresh;       // 慢启动阈值
    
    // 丢包检测
    uint64_t    last_loss_ns;
    uint32_t    loss_count;
    
    // 抖动
    bool        jitter_enabled;
    uint32_t    jitter_range_ns;
    uint64_t    rng_state;
    
    // 统计
    uint64_t    total_bytes;
    uint64_t    total_packets;
    uint64_t    throttled_count;
    uint64_t    burst_count;
} pacing_adaptive_t;

// 初始化
void pacing_adaptive_init(pacing_adaptive_t *ctx, uint64_t initial_bps);

// 设置速率范围
void pacing_adaptive_set_range(pacing_adaptive_t *ctx, 
                                uint64_t min_bps, uint64_t max_bps);

// 启用抖动
void pacing_adaptive_enable_jitter(pacing_adaptive_t *ctx, uint32_t range_ns);

// 更新 RTT（每次收到 ACK 时调用）
void pacing_adaptive_update_rtt(pacing_adaptive_t *ctx, uint64_t rtt_us);

// 报告丢包
void pacing_adaptive_report_loss(pacing_adaptive_t *ctx);

// 请求发送权限
// 返回需要等待的纳秒数（0 = 可立即发送）
uint64_t pacing_adaptive_acquire(pacing_adaptive_t *ctx, size_t bytes);

// 确认发送
void pacing_adaptive_commit(pacing_adaptive_t *ctx, size_t bytes);

// 确认接收（对端 ACK）
void pacing_adaptive_ack(pacing_adaptive_t *ctx, size_t bytes);

// 获取当前估计带宽
uint64_t pacing_adaptive_get_bw(pacing_adaptive_t *ctx);

// 允许突发？
bool pacing_adaptive_allow_burst(pacing_adaptive_t *ctx, size_t bytes);

#endif
