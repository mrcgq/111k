
# =========================================================================
# v3 Project Makefile (Ultimate Edition)
# 作用：自动化编译 v3 的所有组件，支持多 CPU 架构优化
# =========================================================================

# --- 编译器设置 ---
CC = gcc
CLANG = clang
# 基础参数 (移除 -march，由具体目标指定)
CFLAGS_COMMON = -O3 -flto -Wall -Wextra -fPIC -fno-plt -fno-omit-frame-pointer

# --- 目录路径 ---
SRC_DIR = src
BPF_DIR = bpf
BUILD_DIR = build

# --- 依赖库 ---
LIBS_MAX = -luring -lsodium -lpthread -lbpf
LIBS_WSS = -lssl -lcrypto -lpthread
LIBS_XDP_LOADER = -lbpf -lelf -lz
LIBS_BENCHMARK = -lsodium -lm
LIBS_TURBO = -luring -lpthread

# --- 源文件列表 ---

# [v3 Server Max] 主力版本源文件 (Enterprise)
SRCS_MAX = $(SRC_DIR)/v3_ultimate_optimized.c \
           $(SRC_DIR)/v3_fec_simd.c \
           $(SRC_DIR)/v3_pacing_adaptive.c \
           $(SRC_DIR)/v3_antidetect_mtu.c \
           $(SRC_DIR)/v3_cpu_dispatch.c \
           $(SRC_DIR)/v3_health.c

# [v8 Turbo] 暴力竞速版源文件
SRCS_TURBO = $(SRC_DIR)/v3_turbo.c \
             $(SRC_DIR)/v3_cpu_dispatch.c

# [v9 Turbo-Portable] 静态暴力版源文件
SRCS_TURBO_PORTABLE = $(SRC_DIR)/v3_turbo_portable.c

# [Benchmark] 基准测试工具源文件
SRCS_BENCHMARK = $(SRC_DIR)/v3_benchmark.c \
                 $(SRC_DIR)/v3_fec_simd.c \
                 $(SRC_DIR)/v3_cpu_dispatch.c

# =========================================================================
# 编译目标 (Targets)
# =========================================================================
.PHONY: all clean dirs help detect tools full release \
        v3_server_max v3_server_lite v3_server_wss v3_xdp \
        v3_server_generic v3_server_sse42 v3_server_avx2 v3_server_avx512 \
        v3_server_native v3_server_aarch64 \
        v3_server_turbo v3_server_turbo_portable \
        v3_xdp_loader v3_benchmark \
        debug analyze format-check install uninstall

# 默认目标：编译通用主力版
all: dirs v3_server_max

# 创建构建目录
dirs:
	@mkdir -p $(BUILD_DIR)

# =========================================================================
# 1. 标准构建 (Standard Builds)
# =========================================================================

# [推荐] v3 Server Max (Runtime Dispatch)
# 对应版本: v5 - Enterprise (T0 Max)
# 兼容性：好 (所有 x86_64) | 性能：优
v3_server_max: dirs $(SRCS_MAX)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building v3 Server Max (v5 Enterprise)"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_MAX) \
		-o $(BUILD_DIR)/v3_server_max \
		$(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/v3_server_max"

# v3 Server Lite (Portable) - 需 musl-gcc
# 对应版本: v6 - Portable (战术级)
# 静态编译，无依赖
v3_server_lite: dirs $(SRC_DIR)/v3_portable.c
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building v3 Server Lite (v6 Portable)"
	@echo "═══════════════════════════════════════════════════════════════"
	musl-gcc -O3 -static -s \
		$(SRC_DIR)/v3_portable.c \
		-o $(BUILD_DIR)/v3_server_lite \
		-lpthread
	@echo "✓ Output: $(BUILD_DIR)/v3_server_lite"

# v3 Server WSS (Rescue)
# 对应版本: v7 - Rescue (生存级)
# TLS WebSocket 救灾模式
v3_server_wss: dirs $(SRC_DIR)/v3_ws_server.c
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building v3 Server WSS (v7 Rescue)"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) -O3 \
		$(SRC_DIR)/v3_ws_server.c \
		-o $(BUILD_DIR)/v3_server_wss \
		$(LIBS_WSS)
	@echo "✓ Output: $(BUILD_DIR)/v3_server_wss"

# v3 Server Turbo (Brutal)
# 对应版本: v8 - Turbo (暴力级)
# 极致暴力，去除复杂逻辑
v3_server_turbo: dirs $(SRCS_TURBO)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building v3 Server Turbo (v8 Brutal)"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_TURBO) \
		-o $(BUILD_DIR)/v3_server_turbo \
		$(LIBS_TURBO)
	@echo "✓ Output: $(BUILD_DIR)/v3_server_turbo"

# v3 Server Turbo-Portable (Static Brutal)
# 对应版本: v9 - Turbo-Portable (变异级)
# 静态链接的暴力版
v3_server_turbo_portable: dirs $(SRCS_TURBO_PORTABLE)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building v3 Server Turbo-Portable (v9 Static Brutal)"
	@echo "═══════════════════════════════════════════════════════════════"
	musl-gcc -O3 -static -s \
		$(SRCS_TURBO_PORTABLE) \
		-o $(BUILD_DIR)/v3_server_turbo_portable \
		-lpthread
	@echo "✓ Output: $(BUILD_DIR)/v3_server_turbo_portable"

# XDP 内核程序
v3_xdp: dirs $(BPF_DIR)/v3_xdp.c $(BPF_DIR)/v3_common.h
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building XDP BPF Object"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CLANG) -O2 -target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-I/usr/include \
		-c $(BPF_DIR)/v3_xdp.c \
		-o $(BUILD_DIR)/v3_xdp.o
	@echo "✓ Output: $(BUILD_DIR)/v3_xdp.o"

# =========================================================================
# 2. 针对性优化构建 (CPU Specific Builds)
# =========================================================================

# Generic (x86-64-v1) - 最老旧机器
v3_server_generic: dirs $(SRCS_MAX)
	@echo "Building Generic (x86-64-v1)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# SSE4.2 (x86-64-v2) - 2009年以后 CPU
v3_server_sse42: dirs $(SRCS_MAX)
	@echo "Building SSE4.2 (x86-64-v2)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v2 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# AVX2 (x86-64-v3) - 2013年以后 CPU (推荐高性能)
v3_server_avx2: dirs $(SRCS_MAX)
	@echo "Building AVX2 (x86-64-v3)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v3 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# AVX-512 (x86-64-v4) - 现代服务器级 CPU (极限吞吐)
v3_server_avx512: dirs $(SRCS_MAX)
	@echo "Building AVX-512 (x86-64-v4)..."
	$(CC) $(CFLAGS_COMMON) -march=x86-64-v4 \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# Native - 针对当前编译机器 CPU 优化 (不可移植)
v3_server_native: dirs $(SRCS_MAX)
	@echo "Building Native (current CPU)..."
	$(CC) $(CFLAGS_COMMON) -march=native \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# ARM64 - 适用于 AWS Graviton / Oracle ARM
v3_server_aarch64: dirs $(SRCS_MAX)
	@echo "Building ARM64..."
	$(CC) $(CFLAGS_COMMON) -march=armv8-a+crypto \
		$(SRCS_MAX) -o $(BUILD_DIR)/$@ $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/$@"

# =========================================================================
# 3. 工具 (Tools)
# =========================================================================

# XDP Loader - 用户态 XDP 加载器
v3_xdp_loader: dirs $(SRC_DIR)/v3_xdp_loader.c
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building XDP Loader"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) -O2 -Wall \
		$(SRC_DIR)/v3_xdp_loader.c \
		-o $(BUILD_DIR)/v3_xdp_loader \
		$(LIBS_XDP_LOADER)
	@echo "✓ Output: $(BUILD_DIR)/v3_xdp_loader"

# Benchmark Tool - 性能基准测试
v3_benchmark: dirs $(SRCS_BENCHMARK)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  Building Benchmark Tool"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) -O3 -march=native -Wall \
		-DHAVE_SODIUM \
		$(SRCS_BENCHMARK) \
		-o $(BUILD_DIR)/v3_benchmark \
		$(LIBS_BENCHMARK)
	@echo "✓ Output: $(BUILD_DIR)/v3_benchmark"

# 编译所有工具
tools: dirs v3_xdp_loader v3_benchmark
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  All tools built successfully!"
	@echo "═══════════════════════════════════════════════════════════════"

# =========================================================================
# 4. 组合目标 (Combined Targets)
# =========================================================================

# 编译所有组件
full: dirs v3_server_max v3_server_lite v3_server_wss \
      v3_server_turbo v3_server_turbo_portable \
      v3_xdp tools
	@echo ""
	@echo "╔═════════════════════════════════════════════════════════════════╗"
	@echo "║          All components built successfully!                     ║"
	@echo "╠═════════════════════════════════════════════════════════════════╣"
	@echo "║  Servers:                                                       ║"
	@echo "║    • v3_server_max          (v5 Enterprise)                     ║"
	@echo "║    • v3_server_lite         (v6 Portable)                       ║"
	@echo "║    • v3_server_wss          (v7 Rescue)                         ║"
	@echo "║    • v3_server_turbo        (v8 Turbo)                          ║"
	@echo "║    • v3_server_turbo_port.. (v9 Turbo-Static)                   ║"
	@echo "║  Kernel:                                                        ║"
	@echo "║    • v3_xdp.o               (XDP BPF Object)                    ║"
	@echo "║  Tools:                                                         ║"
	@echo "║    • v3_xdp_loader          (XDP Loader)                        ║"
	@echo "║    • v3_benchmark           (Performance Test)                  ║"
	@echo "╚═════════════════════════════════════════════════════════════════╝"

# 编译所有优化版本 (用于发布)
release: dirs v3_server_generic v3_server_avx2 v3_server_avx512 \
         v3_server_lite v3_server_wss \
         v3_server_turbo v3_server_turbo_portable \
         v3_xdp
	@echo ""
	@echo "╔═════════════════════════════════════════════════════════════════╗"
	@echo "║          Release binaries built successfully!                   ║"
	@echo "╚═════════════════════════════════════════════════════════════════╝"

# =========================================================================
# 5. 辅助功能 (Utilities)
# =========================================================================

# 检测当前 CPU 并推荐编译选项
detect:
	@echo ""
	@echo "╔═════════════════════════════════════════════════════════════════╗"
	@echo "║                    CPU Capabilities Check                       ║"
	@echo "╚═════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Model:"
	@grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "  (Unknown)"
	@echo ""
	@echo "Flags:"
	@grep "flags" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | tr ' ' '\n' | grep -E "sse|avx|neon" | sort -u | tr '\n' ' ' || echo "  (None detected)"
	@echo ""
	@echo ""
	@echo "Recommendation:"
	@if grep -q avx512 /proc/cpuinfo 2>/dev/null; then \
		echo "  🚀 Your CPU supports AVX-512!"; \
		echo "  → make v3_server_avx512   (Maximum throughput)"; \
		echo "  → make v3_server_native   (Best for this machine)"; \
	elif grep -q avx2 /proc/cpuinfo 2>/dev/null; then \
		echo "  🚀 Your CPU supports AVX2!"; \
		echo "  → make v3_server_avx2     (Recommended)"; \
		echo "  → make v3_server_native   (Best for this machine)"; \
	elif grep -q sse4_2 /proc/cpuinfo 2>/dev/null; then \
		echo "  ✅ Your CPU supports SSE4.2"; \
		echo "  → make v3_server_sse42    (Recommended)"; \
	elif uname -m | grep -q aarch64; then \
		echo "  ✅ ARM64 detected"; \
		echo "  → make v3_server_aarch64  (Recommended)"; \
	else \
		echo "  ⚠️  No SIMD extensions detected"; \
		echo "  → make v3_server_generic  (Safe fallback)"; \
	fi
	@echo ""

# 运行基准测试
benchmark: v3_benchmark
	@echo ""
	@echo "Running benchmark..."
	@echo ""
	@$(BUILD_DIR)/v3_benchmark

# 清理
clean:
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

# 帮助
help:
	@echo ""
	@echo "╔═════════════════════════════════════════════════════════════════╗"
	@echo "║                    v3 Project Makefile                          ║"
	@echo "╚═════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Standard Targets"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  make                   Build Default Max Server (v5)"
	@echo "  make full              Build all components"
	@echo "  make release           Build distribution binaries"
	@echo "  make v3_server_turbo   Build Brutal Mode (v8)"
	@echo "  make v3_server_lite    Build Portable (v6)"
	@echo "  make v3_xdp            Build Kernel BPF Object"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Optimized Targets"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  make v3_server_generic   x86-64-v1"
	@echo "  make v3_server_avx2      x86-64-v3 (Recommended)"
	@echo "  make v3_server_avx512    x86-64-v4"
	@echo "  make v3_server_native    Current CPU"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Utilities"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  make detect             Detect CPU capabilities"
	@echo "  make install            Install binary to system"
	@echo "  make clean              Cleanup"
	@echo ""

# =========================================================================
# 6. 开发目标 (Development)
# =========================================================================

# 编译带调试信息的版本
debug: dirs $(SRCS_MAX)
	@echo "Building Debug version..."
	$(CC) -O0 -g -Wall -Wextra -DDEBUG \
		$(SRCS_MAX) -o $(BUILD_DIR)/v3_server_debug $(LIBS_MAX)
	@echo "✓ Output: $(BUILD_DIR)/v3_server_debug"

# 静态分析
analyze: $(SRCS_MAX)
	@echo "Running static analysis..."
	@for src in $(SRCS_MAX); do \
		echo "Analyzing $$src..."; \
		$(CC) -fsyntax-only -Wall -Wextra -pedantic $$src 2>&1 | head -20; \
	done

# 格式检查
format-check:
	@echo "Checking code format..."
	@find $(SRC_DIR) -name "*.c" -o -name "*.h" | xargs clang-format --dry-run --Werror 2>/dev/null || \
		echo "Note: Install clang-format for format checking"

# 安装到系统 (默认安装 v3_server_max)
install: v3_server_max
	@echo "Installing to /usr/local/bin..."
	install -m 755 $(BUILD_DIR)/v3_server_max /usr/local/bin/v3_server
	@echo "✓ Installed as /usr/local/bin/v3_server"

# 卸载
uninstall:
	@echo "Removing /usr/local/bin/v3_server..."
	rm -f /usr/local/bin/v3_server
	@echo "✓ Uninstalled"

