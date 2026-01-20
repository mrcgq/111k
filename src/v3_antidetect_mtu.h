

#ifndef V3_ANTIDETECT_MTU_H
#define V3_ANTIDETECT_MTU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// =========================================================
// MTU 感知的流量伪装
// =========================================================

typedef enum {
    AD_PROFILE_NONE = 0,
    AD_PROFILE_HTTPS,
    AD_PROFILE_VIDEO,
    AD_PROFILE_VOIP,
    AD_PROFILE_GAMING,
} ad_profile_t;

typedef struct {
    ad_profile_t profile;
    
    // MTU 配置
    uint16_t    mtu;            // 当前 MTU
    uint16_t    mss;            // 最大分片大小（留 padding 空间）
    uint16_t    min_padding;    // 最小 padding
    uint16_t    max_padding;    // 最大 padding
    
    // 流量特征
    uint16_t    typical_size_min;
    uint16_t    typical_size_max;
    uint32_t    typical_interval_us;
    uint32_t    interval_variance_us;
    
    // 状态
    enum {
        AD_STATE_NORMAL,
        AD_STATE_BURST,
        AD_STATE_IDLE,
    } state;
    int         burst_remaining;
    uint64_t    idle_until_ns;
    uint64_t    last_send_ns;
    
    // 随机数
    uint64_t    rng_state;
    
    // 统计
    uint64_t    packets_processed;
    uint64_t    padding_bytes;
    uint64_t    fragments_avoided;
} ad_mtu_ctx_t;

// 初始化
void ad_mtu_init(ad_mtu_ctx_t *ctx, ad_profile_t profile, uint16_t mtu);

// 设置 MTU（可动态调整）
void ad_mtu_set_mtu(ad_mtu_ctx_t *ctx, uint16_t mtu);

// 处理出站数据包
// buf: 数据缓冲区
// len: 当前数据长度（输入），处理后长度（输出）
// max_len: 缓冲区最大容量
// 返回：建议的发送延迟（纳秒）
uint64_t ad_mtu_process_outbound(ad_mtu_ctx_t *ctx,
                                  uint8_t *buf, size_t *len, size_t max_len);

// 处理入站数据包（移除 padding）
size_t ad_mtu_process_inbound(ad_mtu_ctx_t *ctx,
                               uint8_t *buf, size_t len);

// 获取最大安全 payload 大小（不会触发分片）
size_t ad_mtu_max_payload(ad_mtu_ctx_t *ctx);

// 判断是否需要分片（如果需要，应该在应用层处理）
bool ad_mtu_would_fragment(ad_mtu_ctx_t *ctx, size_t len);

#endif
