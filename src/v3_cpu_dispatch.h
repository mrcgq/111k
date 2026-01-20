
#ifndef V3_CPU_DISPATCH_H
#define V3_CPU_DISPATCH_H

#include <stdint.h>
#include <stdbool.h>

// =========================================================
// CPU 特性标志
// =========================================================
typedef enum {
    CPU_FEATURE_SSE2      = (1 << 0),
    CPU_FEATURE_SSE3      = (1 << 1),
    CPU_FEATURE_SSSE3     = (1 << 2),
    CPU_FEATURE_SSE41     = (1 << 3),
    CPU_FEATURE_SSE42     = (1 << 4),
    CPU_FEATURE_AVX       = (1 << 5),
    CPU_FEATURE_AVX2      = (1 << 6),
    CPU_FEATURE_AVX512F   = (1 << 7),
    CPU_FEATURE_AVX512BW  = (1 << 8),
    CPU_FEATURE_NEON      = (1 << 9),
    CPU_FEATURE_SVE       = (1 << 10),
} cpu_feature_t;

// =========================================================
// CPU 级别（用于选择优化路径）
// =========================================================
typedef enum {
    CPU_LEVEL_GENERIC = 0,      // 纯 C，无 SIMD
    CPU_LEVEL_SSE42,            // x86-64-v2
    CPU_LEVEL_AVX2,             // x86-64-v3
    CPU_LEVEL_AVX512,           // x86-64-v4
    CPU_LEVEL_NEON,             // ARM64
    CPU_LEVEL_SVE,              // ARM64 SVE
    CPU_LEVEL_MAX
} cpu_level_t;

// =========================================================
// API
// =========================================================

/**
 * @brief 检测 CPU 特性（程序启动时调用一次）
 * 
 * 初始化全局 CPU 特性位图和级别。
 * 此函数不是线程安全的，应在主线程早期调用。
 */
void cpu_detect(void);

/**
 * @brief 获取 CPU 特性位图
 * @return 包含所有已检测到的 CPU_FEATURE_* 标志的位图
 */
uint32_t cpu_get_features(void);

/**
 * @brief 检查是否支持特定特性
 * @param feature 要检查的特性
 * @return 如果支持则返回 true
 */
bool cpu_has_feature(cpu_feature_t feature);

/**
 * @brief 获取当前 CPU 的最优优化级别
 * @return CPU_LEVEL_* 枚举值
 */
cpu_level_t cpu_get_level(void);

/**
 * @brief 获取 CPU 型号名称
 * @return 指向 CPU 名称字符串的指针
 */
const char* cpu_get_name(void);

/**
 * @brief 获取 CPU 级别对应的名称
 * @param level CPU_LEVEL_* 枚举值
 * @return 指向级别名称字符串的指针
 */
const char* cpu_level_name(cpu_level_t level);

/**
 * @brief 打印详细的 CPU 信息到控制台
 */
void cpu_print_info(void);

#endif // V3_CPU_DISPATCH_H

