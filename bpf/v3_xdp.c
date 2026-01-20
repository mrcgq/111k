
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


scripts/install_v3.sh 内容：

#!/bin/bash
# v3 Universal Installer - Final Production Version
# Features: 
# 1. Supports v5-v9 versions
# 2. Active Capability Probing (io_uring/AVX2)
# 3. Installation Verification & Auto-Fallback (Crash Recovery)
# 4. Smart XDP Loading (Native -> Generic)

set -e

# =========================================================
# 1. 配置与全局定义
# =========================================================
# 请根据实际 Release 地址修改
BASE_URL="https://github.com/mrcgq/3v/releases/download/v3"
INSTALL_PATH="/usr/local/bin/v3_server"
XDP_PATH="/usr/local/etc/v3_xdp.o"
SERVICE_NAME="v3-server"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 版本文件映射
declare -A VERSION_FILES=(
    ["v5"]="v3_server_max"
    ["v6"]="v3_server_lite"
    ["v7"]="v3_server_wss"
    ["v8"]="v3_server_turbo"
    ["v9"]="v3_server_turbo_portable"
)

# 版本描述
declare -A VERSION_NAMES=(
    ["v5"]="Enterprise (T0 Max - AVX2/io_uring)"
    ["v6"]="Portable (Tactical - Static Musl)"
    ["v7"]="Rescue (Survival - WSS/TLS)"
    ["v8"]="Turbo (Brutal - Performance)"
    ["v9"]="Turbo-Portable (Brutal - Static)"
)

# 日志函数
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}╔═════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          v3 Server Universal Installer          ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════════╝${NC}"
}

print_success() {
    echo -e "${GREEN}✅ Success! v3 Server is running.${NC}"
    echo "---------------------------------------------------"
    echo "Status: systemctl status $SERVICE_NAME"
    echo "Logs:   journalctl -u $SERVICE_NAME -f"
}

# =========================================================
# 2. 系统辅助函数
# =========================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

cleanup_old() {
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "Stopping existing v3 service..."
        systemctl stop $SERVICE_NAME
    fi
    
    # 尝试卸载旧的 XDP
    local IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    if [[ -n "$IFACE" ]]; then
        ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
        ip link set dev "$IFACE" xdp off 2>/dev/null || true
    fi
    
    rm -f $INSTALL_PATH $XDP_PATH
}

# 智能 XDP 加载逻辑
attach_xdp() {
    local IFACE="$1"
    local XDP_OBJ="$2"
    
    log_info "Attempting to attach XDP program to $IFACE..."

    # 1. 尝试 Native Mode (驱动层，性能最佳)
    if ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Native XDP attached successfully (Hardware/Driver Offload)."
        return 0
    fi
    
    # 2. 尝试 Generic Mode (通用模式，兼容性好，性能略低)
    log_warn "Native XDP failed (Driver not supported?). Falling back to Generic Mode..."
    if ip link set dev "$IFACE" xdpgeneric obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Generic XDP attached successfully (Software Mode)."
        return 0
    fi
    
    log_warn "❌ Failed to attach XDP. Server will run without kernel acceleration."
    return 1
}

# =========================================================
# 3. 探测与推断模块
# =========================================================

# 运行远程探针获取真实能力
run_probe() {
    log_info "Running capability probe..."
    
    # 尝试下载并执行远程探测脚本 (设置超时防止卡死)
    if command -v curl &>/dev/null; then
        local probe_result
        probe_result=$(curl -sSL --connect-timeout 3 "$BASE_URL/v3_detect.sh" | bash -s -- --json 2>/dev/null || true)
        
        if [[ -n "$probe_result" ]]; then
            # 简单的 JSON 解析
            PROBED_VERSION=$(echo "$probe_result" | grep -o '"recommended": "[^"]*"' | cut -d'"' -f4)
            local PROBE_IO_URING=$(echo "$probe_result" | grep -o '"io_uring": "[^"]*"' | cut -d'"' -f4)
            local PROBE_AVX2=$(echo "$probe_result" | grep -o '"avx2": "[^"]*"' | cut -d'"' -f4)
            
            if [[ -n "$PROBED_VERSION" ]]; then
                log_info "Probe results:"
                log_info "  io_uring: ${PROBE_IO_URING:-Unknown}"
                log_info "  AVX2:     ${PROBE_AVX2:-Unknown}"
                log_info "  Recommended: $PROBED_VERSION"
                return 0
            fi
        fi
    fi
    
    log_warn "Probe failed or network unreachable, falling back to local inference"
    return 1
}

# 本地回退推断 (当探针失败时)
get_local_inference() {
    local ARCH=$(uname -m)
    local KERNEL=$(uname -r | cut -d. -f1)
    local HAS_AVX2=$(grep -q avx2 /proc/cpuinfo && echo "yes" || echo "no")
    
    if [[ "$ARCH" == "x86_64" ]] && [[ "$KERNEL" -ge 5 ]] && [[ "$HAS_AVX2" == "yes" ]]; then
        echo "v5" # Enterprise
    else
        echo "v6" # Portable
    fi
}

# 交互式选择菜单
interactive_select() {
    echo ""
    echo "请选择要安装的 v3 版本："
    echo ""
    echo "  1) v5 - Enterprise     [动态] 极致性能 (io_uring + AVX2 + XDP)"
    echo "  2) v6 - Portable       [静态] 极限兼容 (Musl libc, 无依赖)"
    echo "  3) v7 - Rescue         [动态] 救灾模式 (WebSocket + TLS)"
    echo "  4) v8 - Turbo          [动态] 暴力竞速 (XDP 极简逻辑)"
    echo "  5) v9 - Turbo-Portable [静态] 暴力竞速静态版"
    echo "  0) 自动检测推荐版本"
    echo ""
    read -p "请输入选项 [0-5]: " choice
    
    case "$choice" in
        1) TARGET_VERSION="v5" ;;
        2) TARGET_VERSION="v6" ;;
        3) TARGET_VERSION="v7" ;;
        4) TARGET_VERSION="v8" ;;
        5) TARGET_VERSION="v9" ;;
        0|"") TARGET_VERSION=$(run_probe && echo "$PROBED_VERSION" || get_local_inference) ;;
        *) log_error "无效选项"; exit 1 ;;
    esac
}

# =========================================================
# 4. 安装与验证逻辑 (核心)
# =========================================================

# 配置 Systemd 服务
configure_service() {
    local version="$1"
    
    # XDP 处理 (仅 v5/v8 且非 Portable)
    if [[ "$version" == "v5" ]] || [[ "$version" == "v8" ]]; then
        log_info "Downloading v3_xdp.o for kernel acceleration..."
        if curl -L -o "$XDP_PATH" "$BASE_URL/v3_xdp.o"; then
            chmod 644 "$XDP_PATH"
            local DEFAULT_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
            if [[ -n "$DEFAULT_IFACE" ]]; then
                attach_xdp "$DEFAULT_IFACE" "$XDP_PATH" || true
            fi
        fi
    fi

    log_info "Creating systemd service..."
    local EXTRA_ARGS="--port=51820 --fec --pacing=100"
    if [[ "$version" == "v7" ]]; then
        EXTRA_ARGS="--port=443 --wss --cert=/etc/v3/cert.pem --key=/etc/v3/key.pem"
        mkdir -p /etc/v3
    fi

    cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=v3 Server ($version - ${VERSION_NAMES[$version]})
After=network.target

[Service]
ExecStart=$INSTALL_PATH $EXTRA_ARGS
Restart=always
LimitNOFILE=1000000
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /run

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
}

# 下载并配置指定版本
download_and_install() {
    local version="$1"
    local fname="${VERSION_FILES[$version]}"
    
    if [[ -z "$fname" ]]; then
        log_error "Unknown version code: $version"
        return 1
    fi
    
    log_info "Downloading $fname ($version)..."
    cleanup_old # 清理旧文件
    
    if ! curl -L -o "$INSTALL_PATH" "$BASE_URL/$fname"; then
        log_error "Download failed for $fname"
        return 1
    fi
    chmod +x "$INSTALL_PATH"
    
    configure_service "$version"
}

# 验证安装 (崩溃检测与回退)
verify_installation() {
    local version="$1"
    log_info "Verifying installation..."
    
    # 1. 尝试直接运行 (捕获指令集错误/库缺失)
    # 使用 timeout 2s，因为正常启动会阻塞
    set +e
    timeout 2 "$INSTALL_PATH" --help >/dev/null 2>&1
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 132 ]]; then # SIGILL (Illegal Instruction)
        log_error "✗ Illegal Instruction detected! CPU incompatible with $version."
        return 1
    elif [[ $exit_code -eq 127 ]]; then # Library missing
        log_error "✗ Shared library missing! System incompatible with $version."
        return 1
    fi
    
    # 2. 检查服务是否存活
    sleep 2
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        log_error "✗ Service failed to start (crashed or exited)."
        journalctl -u $SERVICE_NAME -n 10 --no-pager
        return 1
    fi
    
    log_info "✓ Verification passed."
    return 0
}

# =========================================================
# 5. 主程序流程
# =========================================================
main() {
    check_root
    print_banner
    
    # 参数解析
    TARGET_VERSION=""
    INTERACTIVE=false
    AUTO_CONFIRM=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version) TARGET_VERSION="$2"; shift 2 ;;
            --interactive) INTERACTIVE=true; shift ;;
            --auto) AUTO_CONFIRM=true; shift ;;
            *) INTERACTIVE=true; shift ;; # 无参数默认交互
        esac
    done
    
    # 确定目标版本
    if [[ "$INTERACTIVE" == "true" ]] && [[ -z "$TARGET_VERSION" ]]; then
        interactive_select
    elif [[ -z "$TARGET_VERSION" ]]; then
        if run_probe; then
            TARGET_VERSION="$PROBED_VERSION"
        else
            TARGET_VERSION=$(get_local_inference)
        fi
        log_info "Auto-selected: $TARGET_VERSION"
    fi
    
    # 用户确认 (非自动模式)
    if [[ "$AUTO_CONFIRM" != "true" ]]; then
        echo "Will install: $TARGET_VERSION - ${VERSION_NAMES[$TARGET_VERSION]}"
        read -p "Continue? [Y/n] " confirm
        if [[ ! "$confirm" =~ ^[Yy]?$ ]]; then echo "Aborted."; exit 0; fi
    fi
    
    # --- 阶段 1: 首次安装 ---
    download_and_install "$TARGET_VERSION"
    
    # --- 阶段 2: 验证与回退 ---
    if ! verify_installation "$TARGET_VERSION"; then
        log_warn "Primary installation failed verification."
        
        # 如果当前尝试的不是 Portable 版，则自动回退
        if [[ "$TARGET_VERSION" != "v6" ]]; then
            log_info ">>> Initiating AUTOMATIC FALLBACK to v6 (Portable)..."
            
            # 强制回退到最稳定的 v6
            download_and_install "v6"
            
            if verify_installation "v6"; then
                log_info "Fallback successful! v6 Portable is running."
                print_success
                exit 0
            else
                log_error "Fallback failed. System may be incompatible."
                exit 1
            fi
        else
            log_error "Portable version failed. Check logs."
            exit 1
        fi
    fi
    
    print_success
}

main "$@"
