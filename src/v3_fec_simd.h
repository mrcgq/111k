
#ifndef V3_FEC_SIMD_H
#define V3_FEC_SIMD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// =========================================================
// FEC 类型选择
// =========================================================
typedef enum {
    FEC_TYPE_NONE = 0,      // 不使用 FEC
    FEC_TYPE_XOR,           // 简单 XOR（低 CPU，低恢复能力）
    FEC_TYPE_RS_SIMPLE,     // RS 查表法（中 CPU，高恢复能力）
    FEC_TYPE_RS_SIMD,       // RS SIMD 加速（高恢复能力，需要 AVX2/AVX-512/NEON）
    FEC_TYPE_AUTO,          // 自动选择
} fec_type_t;

// =========================================================
// 配置
// =========================================================
#define FEC_MAX_DATA_SHARDS     20
#define FEC_MAX_PARITY_SHARDS   10
#define FEC_MAX_TOTAL_SHARDS    30
#define FEC_SHARD_SIZE          1400
#define FEC_DECODE_CACHE_SIZE   128     // 解码缓存组数（可配置）
#define FEC_XOR_GROUP_SIZE      4       // XOR 模式：每 4 个数据包生成 1 个校验包

// =========================================================
// 统一 FEC 接口
// =========================================================
typedef struct fec_engine_s fec_engine_t;

// 创建 FEC 引擎
fec_engine_t* fec_create(fec_type_t type, uint8_t data_shards, uint8_t parity_shards);

// 销毁
void fec_destroy(fec_engine_t *engine);

// 编码
// 返回分片总数，分片数据写入 out_shards
int fec_encode(fec_engine_t *engine,
               const uint8_t *data, size_t len,
               uint8_t out_shards[][FEC_SHARD_SIZE],
               size_t out_lens[],
               uint32_t *group_id);

// 解码
// 返回：0=等待更多分片, 1=恢复成功, -1=失败
int fec_decode(fec_engine_t *engine,
               uint32_t group_id,
               uint8_t shard_idx,
               const uint8_t *shard_data, size_t shard_len,
               uint8_t *out_data, size_t *out_len);

// 动态调整冗余率
void fec_set_loss_rate(fec_engine_t *engine, float loss_rate);

// 获取当前类型
fec_type_t fec_get_type(fec_engine_t *engine);

// CPU 能力检测
bool fec_simd_available(void);

// [新增] 获取当前使用的 SIMD 级别名称 (如 "AVX2", "AVX-512", "NEON", "Scalar")
const char* fec_get_simd_level(void);

// [新增] 打印 FEC 模块详细信息 (到 stdout)
void fec_print_info(void);

// 性能测试
double fec_benchmark(fec_type_t type, size_t data_size, int iterations);

#endif // V3_FEC_SIMD_H


