
#!/bin/bash
#
# v3 Runtime Probe - 运行时能力实测
# 不靠推断，只信实际执行结果
#

set -e

PROBE_DIR="/tmp/v3_probe_$$"
mkdir -p "$PROBE_DIR"
trap "rm -rf $PROBE_DIR" EXIT

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

probe_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
probe_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
probe_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# =========================================================
# 1. io_uring 实测（不是推断！）
# =========================================================
probe_io_uring() {
    echo "[PROBE] Testing io_uring syscall..."
    
    cat > "$PROBE_DIR/test_io_uring.c" << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <string.h>
#include <errno.h>

int main() {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    
    int fd = syscall(__NR_io_uring_setup, 1, &params);
    if (fd < 0) {
        printf("FAIL:%d\n", errno);
        return 1;
    }
    
    close(fd);
    printf("PASS\n");
    return 0;
}
EOF

    if ! command -v gcc &>/dev/null; then
        probe_warn "io_uring: No gcc, cannot verify"
        echo "io_uring=unknown"
        return
    fi
    
    if gcc -o "$PROBE_DIR/test_io_uring" "$PROBE_DIR/test_io_uring.c" 2>/dev/null; then
        result=$("$PROBE_DIR/test_io_uring" 2>&1)
        if [[ "$result" == "PASS" ]]; then
            probe_pass "io_uring: Available and working"
            echo "io_uring=yes"
        else
            probe_fail "io_uring: Syscall failed (errno=${result#FAIL:})"
            echo "io_uring=no"
        fi
    else
        probe_fail "io_uring: Headers not available"
        echo "io_uring=no"
    fi
}

# =========================================================
# 2. AVX/AVX2 实测（执行真指令）
# =========================================================
probe_avx() {
    echo "[PROBE] Testing AVX/AVX2 instructions..."
    
    cat > "$PROBE_DIR/test_avx.c" << 'EOF'
#include <stdio.h>
#include <immintrin.h>

int test_avx2() {
    __m256i a = _mm256_set1_epi32(1);
    __m256i b = _mm256_set1_epi32(2);
    __m256i c = _mm256_add_epi32(a, b);
    
    int result[8];
    _mm256_storeu_si256((__m256i*)result, c);
    return result[0] == 3 ? 0 : 1;
}

int main() {
    return test_avx2();
}
EOF

    if ! command -v gcc &>/dev/null; then
        probe_warn "AVX: No gcc, cannot verify"
        echo "avx2=unknown"
        return
    fi
    
    # 尝试编译 AVX2 代码
    if gcc -mavx2 -o "$PROBE_DIR/test_avx" "$PROBE_DIR/test_avx.c" 2>/dev/null; then
        # 关键：实际执行！如果 OS 没开启 XSAVE，这里会 SIGILL
        if timeout 1 "$PROBE_DIR/test_avx" 2>/dev/null; then
            probe_pass "AVX2: Available and executable"
            echo "avx2=yes"
        else
            probe_fail "AVX2: CPU supports but OS blocked (SIGILL)"
            echo "avx2=no"
        fi
    else
        probe_fail "AVX2: Not supported by CPU"
        echo "avx2=no"
    fi
}

# =========================================================
# 3. XDP 实测（尝试加载空程序）
# =========================================================
probe_xdp() {
    echo "[PROBE] Testing XDP/BPF capability..."
    
    # 检查是否有 CAP_NET_ADMIN
    if [[ $EUID -ne 0 ]]; then
        probe_warn "XDP: Need root to test"
        echo "xdp=unknown"
        return
    fi
    
    # 检查 bpf 系统调用
    if [[ ! -d /sys/fs/bpf ]]; then
        probe_fail "XDP: /sys/fs/bpf not mounted"
        echo "xdp=no"
        return
    fi
    
    # 尝试创建 BPF map
    cat > "$PROBE_DIR/test_bpf.c" << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <string.h>

int main() {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    
    int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        printf("FAIL\n");
        return 1;
    }
    close(fd);
    printf("PASS\n");
    return 0;
}
EOF

    if gcc -o "$PROBE_DIR/test_bpf" "$PROBE_DIR/test_bpf.c" 2>/dev/null; then
        result=$("$PROBE_DIR/test_bpf" 2>&1)
        if [[ "$result" == "PASS" ]]; then
            probe_pass "XDP: BPF syscall working"
            echo "xdp=yes"
        else
            probe_fail "XDP: BPF syscall blocked"
            echo "xdp=no"
        fi
    else
        probe_warn "XDP: Cannot compile test"
        echo "xdp=unknown"
    fi
}

# =========================================================
# 4. 网络 UDP 实测
# =========================================================
probe_udp() {
    echo "[PROBE] Testing UDP socket..."
    
    # 尝试绑定 UDP 端口
    if command -v python3 &>/dev/null; then
        result=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', 51821))
    s.close()
    print('PASS')
except Exception as e:
    print(f'FAIL:{e}')
" 2>&1)
        
        if [[ "$result" == "PASS" ]]; then
            probe_pass "UDP: Can bind port"
            echo "udp=yes"
        else
            probe_fail "UDP: $result"
            echo "udp=no"
        fi
    else
        probe_warn "UDP: No python3 for test"
        echo "udp=unknown"
    fi
}

# =========================================================
# 5. 内存压力测试
# =========================================================
probe_memory() {
    echo "[PROBE] Testing memory allocation..."
    
    local mem_mb=$(grep MemAvailable /proc/meminfo | awk '{print int($2/1024)}')
    
    if [[ $mem_mb -lt 64 ]]; then
        probe_fail "Memory: Only ${mem_mb}MB available (need 64MB+)"
        echo "memory=critical"
    elif [[ $mem_mb -lt 128 ]]; then
        probe_warn "Memory: ${mem_mb}MB available (low)"
        echo "memory=low"
    elif [[ $mem_mb -lt 256 ]]; then
        probe_pass "Memory: ${mem_mb}MB available (adequate)"
        echo "memory=adequate"
    else
        probe_pass "Memory: ${mem_mb}MB available (good)"
        echo "memory=good"
    fi
}

# =========================================================
# 主程序
# =========================================================
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    v3 Runtime Probe - 能力实测                                 ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    declare -A RESULTS
    
    # 执行所有探针
    while IFS='=' read -r key value; do
        RESULTS[$key]=$value
    done < <(probe_io_uring)
    
    while IFS='=' read -r key value; do
        RESULTS[$key]=$value
    done < <(probe_avx)
    
    while IFS='=' read -r key value; do
        RESULTS[$key]=$value
    done < <(probe_xdp)
    
    while IFS='=' read -r key value; do
        RESULTS[$key]=$value
    done < <(probe_udp)
    
    while IFS='=' read -r key value; do
        RESULTS[$key]=$value
    done < <(probe_memory)
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  探测结果汇总"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 决策逻辑
    local recommended="v6"  # 默认最安全
    
    if [[ "${RESULTS[io_uring]}" == "yes" && "${RESULTS[avx2]}" == "yes" ]]; then
        if [[ "${RESULTS[memory]}" == "good" || "${RESULTS[memory]}" == "adequate" ]]; then
            recommended="v5"
            echo "  ✅ 推荐: v5 Enterprise (全功能已验证)"
        fi
    elif [[ "${RESULTS[io_uring]}" == "yes" ]]; then
        if [[ "${RESULTS[memory]}" == "low" || "${RESULTS[memory]}" == "critical" ]]; then
            recommended="v8"
            echo "  ✅ 推荐: v8 Turbo (低内存 + io_uring)"
        else
            recommended="v5"
            echo "  ✅ 推荐: v5 Enterprise (io_uring 可用)"
        fi
    elif [[ "${RESULTS[memory]}" == "critical" ]]; then
        recommended="v9"
        echo "  ✅ 推荐: v9 Turbo-Portable (极限兼容)"
    else
        recommended="v6"
        echo "  ✅ 推荐: v6 Portable (安全回退)"
    fi
    
    echo ""
    echo "  备选方案:"
    echo "    • v7 Rescue - UDP 不可用时的备用 (WSS)"
    echo "    • v6 Portable - 任何环境都能运行"
    echo ""
    
    # 输出机器可读结果
    if [[ "$1" == "--json" ]]; then
        echo "{"
        echo "  \"probe_results\": {"
        for key in "${!RESULTS[@]}"; do
            echo "    \"$key\": \"${RESULTS[$key]}\","
        done
        echo "  },"
        echo "  \"recommended\": \"$recommended\""
        echo "}"
    fi
}

main "$@"

