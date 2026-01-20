
#include "v3_cpu_dispatch.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __x86_64__
#include <cpuid.h>

// 读取扩展控制寄存器 (XCR0)
static inline uint64_t xgetbv(uint32_t index) {
    uint32_t eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
    return ((uint64_t)edx << 32) | eax;
}
#endif

// =========================================================
// 全局状态
// =========================================================
static uint32_t g_cpu_features = 0;
static cpu_level_t g_cpu_level = CPU_LEVEL_GENERIC;
static char g_cpu_name[64] = "Unknown CPU";
static bool g_detected = false;

// =========================================================
// x86-64 检测
// =========================================================
#ifdef __x86_64__

static void detect_x86(void) {
    unsigned int eax, ebx, ecx, edx;
    unsigned int max_level;

    // 获取最大支持的 function id
    if (!__get_cpuid(0, &max_level, &ebx, &ecx, &edx)) {
        return;
    }

    // =========================================================
    // [修复] 获取 CPU 品牌字符串
    // =========================================================
    unsigned int max_ext_level;
    if (__get_cpuid(0x80000000, &max_ext_level, &ebx, &ecx, &edx)) {
        if (max_ext_level >= 0x80000004) {
            unsigned int brand[12];
            __get_cpuid(0x80000002, &brand[0], &brand[1], &brand[2], &brand[3]);
            __get_cpuid(0x80000003, &brand[4], &brand[5], &brand[6], &brand[7]);
            __get_cpuid(0x80000004, &brand[8], &brand[9], &brand[10], &brand[11]);
            
            memcpy(g_cpu_name, brand, 48);
            g_cpu_name[48] = '\0';
            
            // 去除前导空格
            char *p = g_cpu_name;
            while (*p == ' ') p++;
            if (p != g_cpu_name) {
                memmove(g_cpu_name, p, strlen(p) + 1);
            }
            
            // 去除尾部空格
            size_t len = strlen(g_cpu_name);
            while (len > 0 && g_cpu_name[len - 1] == ' ') {
                g_cpu_name[--len] = '\0';
            }
        }
    }

    // =========================================================
    // 1. 基础特性检测 (Function 1)
    // =========================================================
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return;
    }

    // SSE 系列（x86-64 必有 SSE2）
    if (edx & bit_SSE2)   g_cpu_features |= CPU_FEATURE_SSE2;
    if (ecx & bit_SSE3)   g_cpu_features |= CPU_FEATURE_SSE3;
    if (ecx & bit_SSSE3)  g_cpu_features |= CPU_FEATURE_SSSE3;
    if (ecx & bit_SSE4_1) g_cpu_features |= CPU_FEATURE_SSE41;
    if (ecx & bit_SSE4_2) g_cpu_features |= CPU_FEATURE_SSE42;

    // =========================================================
    // [修复] AVX 安全检查：必须 OS 支持 XSAVE 且开启了 YMM/ZMM 状态保存
    // =========================================================
    bool os_uses_xsave = !!(ecx & bit_OSXSAVE);
    
    if (os_uses_xsave) {
        uint64_t xcr0 = xgetbv(0);
        
        // 检查 XCR0 的 bit 1 (SSE) 和 bit 2 (AVX) 是否都为 1
        // 掩码 0x6 = 0b110
        bool os_avx_enabled = (xcr0 & 0x06) == 0x06;
        
        // 检查 AVX-512 状态 (bit 5, 6, 7: opmask, ZMM_Hi256, Hi16_ZMM)
        // 掩码 0xE0 = 0b11100000
        bool os_avx512_enabled = (xcr0 & 0xE6) == 0xE6;

        if (os_avx_enabled) {
            if (ecx & bit_AVX) {
                g_cpu_features |= CPU_FEATURE_AVX;
            }
            
            // 2. 扩展特性检测 (Function 7)
            if (max_level >= 7) {
                __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
                
                if (ebx & bit_AVX2) {
                    g_cpu_features |= CPU_FEATURE_AVX2;
                }
                
                if (os_avx512_enabled) {
                    if (ebx & bit_AVX512F) {
                        g_cpu_features |= CPU_FEATURE_AVX512F;
                    }
                    if (ebx & bit_AVX512BW) {
                        g_cpu_features |= CPU_FEATURE_AVX512BW;
                    }
                }
            }
        }
    }

    // =========================================================
    // 确定 CPU 级别
    // =========================================================
    if ((g_cpu_features & CPU_FEATURE_AVX512F) && 
        (g_cpu_features & CPU_FEATURE_AVX512BW)) {
        g_cpu_level = CPU_LEVEL_AVX512;
    } else if (g_cpu_features & CPU_FEATURE_AVX2) {
        g_cpu_level = CPU_LEVEL_AVX2;
    } else if (g_cpu_features & CPU_FEATURE_SSE42) {
        g_cpu_level = CPU_LEVEL_SSE42;
    } else {
        g_cpu_level = CPU_LEVEL_GENERIC;
    }
}

#endif // __x86_64__

// =========================================================
// ARM64 检测
// =========================================================
#ifdef __aarch64__
#include <sys/auxv.h>

#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)
#endif

static void detect_arm64(void) {
    // =========================================================
    // [修复] 获取 CPU 名称
    // =========================================================
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        bool found_name = false;
        
        while (fgets(line, sizeof(line), f)) {
            // 尝试多种字段名
            if (!found_name && 
                (strncmp(line, "model name", 10) == 0 ||
                 strncmp(line, "Model", 5) == 0 ||
                 strncmp(line, "CPU implementer", 15) == 0)) {
                
                char *p = strchr(line, ':');
                if (p) {
                    p++;
                    while (*p == ' ' || *p == '\t') p++;
                    
                    char *end = strchr(p, '\n');
                    if (end) *end = '\0';
                    
                    if (strlen(p) > 0) {
                        strncpy(g_cpu_name, p, sizeof(g_cpu_name) - 1);
                        g_cpu_name[sizeof(g_cpu_name) - 1] = '\0';
                        found_name = true;
                    }
                }
            }
            
            // 也尝试获取 CPU part
            if (strncmp(line, "CPU part", 8) == 0) {
                char *p = strchr(line, ':');
                if (p) {
                    p++;
                    while (*p == ' ' || *p == '\t') p++;
                    
                    // 如果还没有名称，用 part 号
                    if (!found_name || strcmp(g_cpu_name, "Unknown CPU") == 0) {
                        char part_name[32];
                        snprintf(part_name, sizeof(part_name), "ARM (Part: %s)", p);
                        char *end = strchr(part_name, '\n');
                        if (end) *end = '\0';
                        strncpy(g_cpu_name, part_name, sizeof(g_cpu_name) - 1);
                    }
                }
            }
        }
        fclose(f);
    }
    
    // 如果还是没获取到，尝试从 /sys 获取
    if (strcmp(g_cpu_name, "Unknown CPU") == 0) {
        f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver", "r");
        if (f) {
            char driver[64];
            if (fgets(driver, sizeof(driver), f)) {
                char *end = strchr(driver, '\n');
                if (end) *end = '\0';
                snprintf(g_cpu_name, sizeof(g_cpu_name), "ARM64 (%s)", driver);
            }
            fclose(f);
        }
    }

    // ARM64 默认支持 NEON
    g_cpu_features |= CPU_FEATURE_NEON;
    g_cpu_level = CPU_LEVEL_NEON;
    
    // 检查 SVE
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_SVE) {
        g_cpu_features |= CPU_FEATURE_SVE;
        g_cpu_level = CPU_LEVEL_SVE;
    }
}

#endif // __aarch64__

// =========================================================
// 通用平台检测
// =========================================================
#if !defined(__x86_64__) && !defined(__aarch64__)

static void detect_generic(void) {
    strncpy(g_cpu_name, "Generic CPU", sizeof(g_cpu_name) - 1);
    g_cpu_level = CPU_LEVEL_GENERIC;
    g_cpu_features = 0;
}

#endif

// =========================================================
// 公开 API 实现
// =========================================================

void cpu_detect(void) {
    if (g_detected) return;
    
#ifdef __x86_64__
    detect_x86();
#elif defined(__aarch64__)
    detect_arm64();
#else
    detect_generic();
#endif
    
    g_detected = true;
}

cpu_level_t cpu_get_level(void) {
    if (!g_detected) cpu_detect();
    return g_cpu_level;
}

uint32_t cpu_get_features(void) {
    if (!g_detected) cpu_detect();
    return g_cpu_features;
}

bool cpu_has_feature(cpu_feature_t feature) {
    if (!g_detected) cpu_detect();
    return (g_cpu_features & feature) != 0;
}

// =========================================================
// [修复] 实现 cpu_get_name()
// =========================================================
const char* cpu_get_name(void) {
    if (!g_detected) cpu_detect();
    return g_cpu_name;
}

const char* cpu_level_name(cpu_level_t level) {
    switch (level) {
        case CPU_LEVEL_GENERIC: return "Generic (Scalar)";
        case CPU_LEVEL_SSE42:   return "x86-64-v2 (SSE4.2)";
        case CPU_LEVEL_AVX2:    return "x86-64-v3 (AVX2)";
        case CPU_LEVEL_AVX512:  return "x86-64-v4 (AVX-512)";
        case CPU_LEVEL_NEON:    return "ARM64 (NEON)";
        case CPU_LEVEL_SVE:     return "ARM64 (SVE)";
        default:                return "Unknown";
    }
}

void cpu_print_info(void) {
    if (!g_detected) cpu_detect();
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                      CPU Information                          ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    // 打印 CPU 名称（可能需要截断）
    char name_display[56];
    strncpy(name_display, g_cpu_name, 55);
    name_display[55] = '\0';
    printf("║  Model: %-54s ║\n", name_display);
    
    printf("║  Level: %-54s ║\n", cpu_level_name(g_cpu_level));
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Features Detected:                                           ║\n");
    
#ifdef __x86_64__
    printf("║    SSE2:    %s    SSE3:    %s    SSSE3:   %s                  ║\n",
           (g_cpu_features & CPU_FEATURE_SSE2)  ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_SSE3)  ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_SSSE3) ? "✓" : "✗");
    printf("║    SSE4.1:  %s    SSE4.2:  %s    AVX:     %s                  ║\n",
           (g_cpu_features & CPU_FEATURE_SSE41) ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_SSE42) ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_AVX)   ? "✓" : "✗");
    printf("║    AVX2:    %s    AVX512F: %s    AVX512BW:%s                  ║\n",
           (g_cpu_features & CPU_FEATURE_AVX2)    ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_AVX512F) ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_AVX512BW)? "✓" : "✗");
#endif

#ifdef __aarch64__
    printf("║    NEON:    %s    SVE:     %s                                  ║\n",
           (g_cpu_features & CPU_FEATURE_NEON) ? "✓" : "✗",
           (g_cpu_features & CPU_FEATURE_SVE)  ? "✓" : "✗");
#endif

#if !defined(__x86_64__) && !defined(__aarch64__)
    printf("║    (No SIMD features detected on this platform)               ║\n");
#endif

    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}


