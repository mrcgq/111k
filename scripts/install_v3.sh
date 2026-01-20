#!/bin/bash
# v3 Universal Installer - Final Production Version

set -e

# =========================================================
# 1. 配置与全局定义
# =========================================================
# 【关键修复 #1】URL 已修正为你自己的仓库地址
BASE_URL="https://github.com/mrcgq/111k/releases/download/v3"
INSTALL_PATH="/usr/local/bin/v3_server"
XDP_PATH="/usr/local/etc/v3_xdp.o"
SERVICE_NAME="v3-server"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 【关键修复 #2】文件名已修正为与你的 GitHub Actions 编译产物完全一致
declare -A VERSION_FILES=(
    ["v5"]="v3_server_v5_avx2"  # 默认使用 v5 的 AVX2 版本作为代表
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
        log_info "✅ Native XDP attached successfully (Hardware/Driver Offload)."
        return 0
    fi
    
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
# 注意：run_probe 依赖 v3_detect.sh 也能被正确下载，这里简化为只使用本地推断
get_local_inference() {
    log_info "Inferring best version based on local system..."
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
    echo ""
    echo "  1) v5 - Enterprise     [Dynamic] Ultimate Performance (io_uring + AVX2 + XDP)"
    echo "  2) v6 - Portable       [Static]  Extreme Compatibility (Musl libc)"
    echo "  3) v7 - Rescue         [Dynamic] Survival Mode (WebSocket + TLS)"
    echo "  4) v8 - Turbo          [Dynamic] Brutal Speed (Minimal Logic)"
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
        0|"") TARGET_VERSION=$(get_local_inference) ;;
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
    # 示例参数，你可以根据需要调整
    local EXTRA_ARGS="--port=51820 --fec --pacing=100"
    if [[ "$version" == "v7" ]]; then
        # v7 需要证书路径作为参数
        EXTRA_ARGS="--port=443 --cert=/etc/v3/cert.pem --key=/etc/v3/key.pem"
        mkdir -p /etc/v3
        log_warn "v7 (Rescue) requires SSL certificates at /etc/v3/cert.pem and /etc/v3/key.pem"
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

verify_installation() {
    local version="$1"
    log_info "Verifying installation of $version..."
    
    # 稍微等待服务启动
    sleep 2
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        log_error "✗ Service failed to start. It may have crashed."
        log_error "Please check logs with: journalctl -u $SERVICE_NAME -n 20"
        return 1
    fi
    
    log_info "✓ Verification passed. Service is active."
    return 0
}

# =========================================================
# 5. 主程序流程
# =========================================================
main() {
    check_root
    print_banner
    
    TARGET_VERSION=""
    # 简化参数处理，支持 --version v5 或 --interactive
    if [[ "$1" == "--version" && -n "$2" ]]; then
        TARGET_VERSION="$2"
    else
        interactive_select
    fi
    
    log_info "Will install version: $TARGET_VERSION - ${VERSION_NAMES[$TARGET_VERSION]}"
    read -p "Continue? [Y/n] " confirm
    if [[ ! "$confirm" =~ ^[Yy]?$ ]]; then echo "Aborted."; exit 0; fi
    
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
