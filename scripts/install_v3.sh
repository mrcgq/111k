#!/bin/bash
# v3 Universal Installer - (Recommended Final Version)
# Combines the best features of both versions

set -e

# =========================================================
# 1. 配置与全局定义 (来自版本2，已修正)
# =========================================================
BASE_URL="https://github.com/mrcgq/111k/releases/download/ffff"
# 【重要】如果你的 Release Tag 不是 "v3"，请修改上面的地址
# 例如，如果你的 Tag 是 "ffff"，就改成 https://github.com/mrcgq/111k/releases/download/ffff

INSTALL_PATH="/usr/local/bin/v3_server"
XDP_PATH="/usr/local/etc/v3_xdp.o"
SERVICE_NAME="v3-server"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 文件名映射 (来自版本2，正确)
declare -A VERSION_FILES=(
    ["v5"]="v3_server_v5_avx2"
    ["v6"]="v3_server_v6_portable"
    ["v7"]="v3_server_v7_rescue"
    ["v8"]="v3_server_v8_turbo"
    ["v9"]="v3_server_v9_turbo_portable"
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
    
    local IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    if [[ -n "$IFACE" ]]; then
        ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
        ip link set dev "$IFACE" xdp off 2>/dev/null || true
    fi
    
    rm -f $INSTALL_PATH $XDP_PATH
}

attach_xdp() {
    local IFACE="$1"
    local XDP_OBJ="$2"
    
    log_info "Attempting to attach XDP program to $IFACE..."

    if ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Native XDP attached successfully."
        return 0
    fi
    
    log_warn "Native XDP failed. Falling back to Generic Mode..."
    if ip link set dev "$IFACE" xdpgeneric obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Generic XDP attached successfully."
        return 0
    fi
    
    log_warn "❌ Failed to attach XDP. Server will run without kernel acceleration."
    return 1
}

# =========================================================
# 3. 探测与推断模块 (来自版本1，更智能)
# =========================================================
run_probe() {
    log_info "Running capability probe..."
    local DETECT_URL="https://raw.githubusercontent.com/mrcgq/111k/main/scripts/v3_detect.sh"
    
    if command -v curl &>/dev/null; then
        local probe_result
        probe_result=$(curl -sSL --connect-timeout 3 "$DETECT_URL" | bash -s -- --json 2>/dev/null || true)
        
        if [[ -n "$probe_result" ]]; then
            PROBED_VERSION=$(echo "$probe_result" | grep -o '"best_version": "[^"]*"' | cut -d'"' -f4)
            if [[ -n "$PROBED_VERSION" ]]; then
                log_info "Probe recommended version: $PROBED_VERSION"
                return 0
            fi
        fi
    fi
    
    log_warn "Probe failed or network unreachable, falling back to local inference"
    return 1
}

get_local_inference() {
    local ARCH=$(uname -m)
    local KERNEL=$(uname -r | cut -d. -f1)
    
    if [[ "$ARCH" == "x86_64" ]] && [[ "$KERNEL" -ge 5 ]] && grep -q avx2 /proc/cpuinfo; then
        echo "v5"
    else
        echo "v6"
    fi
}

interactive_select() {
    echo ""
    echo "Please select v3 version to install:"
    echo "  1) v5 - Enterprise     [Dynamic] Ultimate Performance"
    echo "  2) v6 - Portable       [Static]  Maximum Compatibility"
    echo "  3) v7 - Rescue         [Dynamic] WSS/TLS Mode"
    echo "  4) v8 - Turbo          [Dynamic] Brutal Speed"
    echo "  5) v9 - Turbo-Portable [Static]  Brutal Speed Static"
    echo "  0) Auto-detect recommended version"
    echo ""
    read -p "Enter option [0-5]: " choice
    
    case "$choice" in
        1) TARGET_VERSION="v5" ;;
        2) TARGET_VERSION="v6" ;;
        3) TARGET_VERSION="v7" ;;
        4) TARGET_VERSION="v8" ;;
        5) TARGET_VERSION="v9" ;;
        0|"") 
            if ! run_probe; then
                TARGET_VERSION=$(get_local_inference)
            else
                TARGET_VERSION="$PROBED_VERSION"
            fi
            ;;
        *) log_error "Invalid option"; exit 1 ;;
    esac
}

# =========================================================
# 4. 安装与验证逻辑
# =========================================================
configure_service() {
    local version="$1"
    
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
    local EXTRA_ARGS="--port=51820" # 简化默认参数

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

download_and_install() {
    local version="$1"
    local fname="${VERSION_FILES[$version]}"
    
    if [[ -z "$fname" ]]; then
        log_error "Unknown version code: $version"
        return 1
    fi
    
    log_info "Downloading $fname ($version) from release..."
    cleanup_old
    
    if ! curl -L -o "$INSTALL_PATH" "$BASE_URL/$fname"; then
        log_error "Download failed for $fname. Please check the release page and version tag."
        return 1
    fi
    chmod +x "$INSTALL_PATH"
    
    configure_service "$version"
}

# 验证函数 (来自版本1，更精确)
verify_installation() {
    local version="$1"
    log_info "Verifying installation of $version..."
    
    # 1. 预检查，捕获指令集错误
    set +e
    timeout 2 "$INSTALL_PATH" --help >/dev/null 2>&1
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 132 ]]; then # SIGILL (Illegal Instruction)
        log_error "✗ Illegal Instruction! Your CPU is not compatible with $version."
        return 1
    elif [[ $exit_code -eq 127 ]]; then # 找不到库
        log_error "✗ Shared library missing! Your system is not compatible with $version."
        return 1
    fi
    
    # 2. 检查服务是否存活
    sleep 2
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        log_error "✗ Service failed to start. It may have crashed."
        journalctl -u $SERVICE_NAME -n 10 --no-pager
        return 1
    fi
    
    log_info "✓ Verification passed. Service is active."
    return 0
}

# =========================================================
# 5. 主程序流程 (来自版本1，更灵活)
# =========================================================
main() {
    check_root
    print_banner
    
    TARGET_VERSION=""
    INTERACTIVE=false
    AUTO_CONFIRM=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version) TARGET_VERSION="$2"; shift 2 ;;
            --interactive) INTERACTIVE=true; shift ;;
            --auto) AUTO_CONFIRM=true; shift ;;
            *) INTERACTIVE=true; shift ;; # 默认交互模式
        esac
    done
    
    if [[ "$INTERACTIVE" == "true" ]] && [[ -z "$TARGET_VERSION" ]]; then
        interactive_select
    elif [[ -z "$TARGET_VERSION" ]]; then
        if ! run_probe; then
            TARGET_VERSION=$(get_local_inference)
        else
            TARGET_VERSION="$PROBED_VERSION"
        fi
        log_info "Auto-selected version: $TARGET_VERSION"
    fi
    
    if [[ "$AUTO_CONFIRM" != "true" ]]; then
        log_info "Will install version: $TARGET_VERSION - ${VERSION_NAMES[$TARGET_VERSION]}"
        read -p "Continue? [Y/n] " confirm
        if [[ ! "$confirm" =~ ^[Yy]?$ ]]; then echo "Aborted."; exit 0; fi
    fi
    
    # --- 安装阶段 ---
    download_and_install "$TARGET_VERSION"
    
    # --- 验证与回退阶段 ---
    if ! verify_installation "$TARGET_VERSION"; then
        log_warn "Primary installation failed verification."
        
        if [[ "$TARGET_VERSION" != "v6" ]]; then
            log_info ">>> Initiating AUTOMATIC FALLBACK to v6 (Portable)..."
            download_and_install "v6"
            
            if verify_installation "v6"; then
                log_info "Fallback to v6 successful! v6 Portable is now running."
                print_success
                exit 0
            else
                log_error "Fallback to v6 also failed. The system may be incompatible."
                exit 1
            fi
        else
            log_error "The most compatible version (v6) failed to run. Please check logs."
            exit 1
        fi
    fi
    
    print_success
}

main "$@"
