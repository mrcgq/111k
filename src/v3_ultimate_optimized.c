/*
 * v3 Server Max (Ultimate Optimized)
 * 集成：io_uring, SIMD FEC, Pacing, Anti-Detect, Health Check
 * 
 * [修复版] 包含正确的 Magic 派生和验证逻辑
 * [增强版] 支持通过 --bind 参数指定监听地址
 * [协议对齐] 元数据解析与 111w 客户端完全匹配
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <liburing.h>
#include <sodium.h>
#include <getopt.h>

// 引入模块头文件
#include "v3_fec_simd.h"
#include "v3_pacing_adaptive.h"
#include "v3_antidetect_mtu.h"
#include "v3_cpu_dispatch.h"
#include "v3_health.h"

// =========================================================
// 配置常量
// =========================================================
#define V3_PORT             51820
#define QUEUE_DEPTH         4096
#define BUF_SIZE            2048
#define MAX_CONNS           32768
#define MAGIC_WINDOW_SEC    60
#define MAGIC_TOLERANCE     1

// =========================================================
// 全局配置结构
// =========================================================
typedef struct {
    bool        fec_enabled;
    fec_type_t  fec_type;
    uint8_t     fec_data_shards;
    uint8_t     fec_parity_shards;
    bool        pacing_enabled;
    uint64_t    pacing_initial_bps;
    uint64_t    pacing_min_bps;
    uint64_t    pacing_max_bps;
    ad_profile_t ad_profile;
    uint16_t     mtu;
    uint16_t    port;
    const char *bind_addr;
    bool        verbose;
    bool        benchmark;
    bool        health_enabled;
    int         health_port;
    int         health_interval;
} config_t;

static config_t g_config = {
    .fec_enabled = false,
    .fec_type = FEC_TYPE_AUTO,
    .fec_data_shards = 5,
    .fec_parity_shards = 2,
    .pacing_enabled = false,
    .pacing_initial_bps = 100 * 1000 * 1000,
    .pacing_min_bps = 1 * 1000 * 1000,
    .pacing_max_bps = 1000 * 1000 * 1000,
    .ad_profile = AD_PROFILE_NONE,
    .mtu = 1500,
    .port = 51820,
    .bind_addr = "0.0.0.0",
    .verbose = false,
    .benchmark = false,
    .health_enabled = true,
    .health_port = 8080,
    .health_interval = 60,
};

// =========================================================
// 全局状态
// =========================================================
static fec_engine_t *g_fec = NULL;
static pacing_adaptive_t g_pacing;
static ad_mtu_ctx_t g_antidetect;
static v3_health_ctx_t g_health_ctx;
static struct io_uring g_ring;
static volatile sig_atomic_t g_running = 1;
static uint8_t g_master_key[32];

// =========================================================
// 协议定义
// =========================================================
typedef struct __attribute__((packed)) {
    uint32_t magic_derived; 
    uint8_t  nonce[12];     
    uint8_t  enc_block[16]; 
    uint8_t  tag[16];
    uint16_t early_len;     
    uint16_t pad;
} v3_header_t;

#define V3_HEADER_SIZE sizeof(v3_header_t)

typedef struct {
    int fd;
    struct sockaddr_in addr;
    struct iovec iov;
    struct msghdr msg;
    uint8_t buf[BUF_SIZE];
    enum { OP_READ, OP_WRITE } op;
} io_context_t;

static io_context_t g_io_ctx_pool[MAX_CONNS];

// =========================================================
// Magic 派生与验证（安全实现）
// =========================================================
static uint32_t derive_magic(uint64_t window) {
    uint8_t input[40];
    memcpy(input, g_master_key, 32);
    for (int i=0; i<8; i++) input[32+i] = (window >> (i*8)) & 0xFF;
    
    uint8_t hash[32];
    if (crypto_generichash(hash, sizeof(hash), input, sizeof(input), NULL, 0) != 0) return 0;
    
    uint32_t magic;
    memcpy(&magic, hash, 4);
    return magic;
}

static uint32_t get_current_magic(void) {
    time_t now = time(NULL);
    return derive_magic(now / MAGIC_WINDOW_SEC);
}

static bool verify_magic(uint32_t received) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    if (received == derive_magic(current_window)) return true;
    for (int offset = 1; offset <= MAGIC_TOLERANCE; offset++) {
        if (received == derive_magic(current_window - offset)) return true;
        if (received == derive_magic(current_window + offset)) return true;
    }
    return false;
}

static void get_valid_magics(uint32_t magics[3]) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    magics[0] = derive_magic(current_window - 1);
    magics[1] = derive_magic(current_window);
    magics[2] = derive_magic(current_window + 1);
}

// =========================================================
// 健康检查打印线程
// =========================================================
static void* health_print_thread(void *arg) {
    int interval = *(int*)arg;
    while (g_running) {
        sleep(interval);
        if (!g_running) break;
        v3_health_t health;
        v3_health_snapshot(&g_health_ctx, &health);
        v3_health_print(&health);
    }
    return NULL;
}

// =========================================================
// 模块初始化
// =========================================================
static void init_modules(void) {
    cpu_detect();
    if (g_config.verbose) cpu_print_info();

    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] libsodium initialization failed\n");
        exit(1);
    }
    
    randombytes_buf(g_master_key, sizeof(g_master_key));
    if (g_config.verbose) {
        printf("[Crypto] Master key generated\n");
        printf("[Crypto] Current magic: 0x%08X\n", get_current_magic());
    }

    if (g_config.fec_enabled) {
        g_fec = fec_create(g_config.fec_type, g_config.fec_data_shards, g_config.fec_parity_shards);
        if (g_config.verbose) printf("[FEC] Engine initialized (Type: %d, %d:%d)\n", g_config.fec_type, g_config.fec_data_shards, g_config.fec_parity_shards);
    }
    
    if (g_config.pacing_enabled) {
        pacing_adaptive_init(&g_pacing, g_config.pacing_initial_bps);
        pacing_adaptive_set_range(&g_pacing, g_config.pacing_min_bps, g_config.pacing_max_bps);
        pacing_adaptive_enable_jitter(&g_pacing, 50000);
        if (g_config.verbose) printf("[Pacing] Enabled (Initial: %lu Mbps)\n", g_config.pacing_initial_bps / 1000000);
    }
    
    if (g_config.ad_profile != AD_PROFILE_NONE) {
        ad_mtu_init(&g_antidetect, g_config.ad_profile, g_config.mtu);
        if (g_config.verbose) {
            const char* names[] = {"None", "HTTPS", "Video", "VoIP", "Gaming"};
            printf("[AntiDetect] Profile: %s, MTU: %d\n", names[g_config.ad_profile], g_config.mtu);
        }
    }

    v3_health_init(&g_health_ctx);
    v3_health_set_modules(&g_health_ctx, false, g_config.fec_enabled, g_config.pacing_enabled, g_config.ad_profile != AD_PROFILE_NONE);

    if (g_config.health_enabled) {
        if (v3_health_start_server(&g_health_ctx, g_config.health_port) == 0) {
            if (g_config.verbose) printf("[Health] HTTP API listening on http://127.0.0.1:%d/\n", g_config.health_port);
        } else {
            fprintf(stderr, "[WARN] Failed to start health server on port %d\n", g_config.health_port);
        }
    }
}

// =========================================================
// I/O 操作
// =========================================================
static void prepare_recv(struct io_uring *ring, int fd, io_context_t *ctx) {
    ctx->fd = fd;
    ctx->op = OP_READ;
    ctx->iov.iov_base = ctx->buf;
    ctx->iov.iov_len = BUF_SIZE;
    ctx->msg.msg_name = &ctx->addr;
    ctx->msg.msg_namelen = sizeof(ctx->addr);
    ctx->msg.msg_iov = &ctx->iov;
    ctx->msg.msg_iovlen = 1;
    ctx->msg.msg_control = NULL;
    ctx->msg.msg_controllen = 0;
    ctx->msg.msg_flags = 0;
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    while (!sqe) {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }
    
    io_uring_prep_recvmsg(sqe, fd, &ctx->msg, 0);
    io_uring_sqe_set_data(sqe, ctx);
}

static void submit_recv(io_context_t *ctx) {
    prepare_recv(&g_ring, ctx->fd, ctx);
}

// =========================================================
// 包处理逻辑
// =========================================================
static void handle_packet(io_context_t *ctx, int len) {
    v3_health_record_rx(&g_health_ctx, len);

    if (len < (int)V3_HEADER_SIZE) {
        v3_health_record_drop(&g_health_ctx, 2);
        submit_recv(ctx);
        return;
    }
    
    v3_header_t *hdr = (v3_header_t*)ctx->buf;
    
    if (!verify_magic(hdr->magic_derived)) {
        v3_health_record_drop(&g_health_ctx, 1);
        if (g_config.verbose) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ctx->addr.sin_addr, client_ip, sizeof(client_ip));
            printf("[DROP] Invalid magic 0x%08X from %s:%d\n", hdr->magic_derived, client_ip, ntohs(ctx->addr.sin_port));
        }
        submit_recv(ctx);
        return;
    }
    
    uint8_t aad[8];
    memcpy(aad + 0, &hdr->early_len, 2);
    memcpy(aad + 2, &hdr->pad, 2);
    memcpy(aad + 4, &hdr->magic_derived, 4);
    
    uint8_t combined[32];
    memcpy(combined, hdr->enc_block, 16);
    memcpy(combined + 16, hdr->tag, 16);
    
    uint8_t plaintext[16];
    unsigned long long decrypted_len;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &decrypted_len, 
            NULL, combined, 32, aad, sizeof(aad), hdr->nonce, g_master_key) != 0) {
        v3_health_record_drop(&g_health_ctx, 1);
        submit_recv(ctx);
        return;
    }

    /* === 关键修改点 1: 修正元数据解析 === */
    uint64_t session_id;
    uint16_t stream_id;
    uint16_t flags;
    uint32_t sequence;
    
    memcpy(&session_id, plaintext, 8);
    memcpy(&stream_id, plaintext + 8, 2);
    memcpy(&flags, plaintext + 10, 2);
    memcpy(&sequence, plaintext + 12, 4);
    
    int payload_len = len - (int)V3_HEADER_SIZE;
    
    if (g_config.verbose) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ctx->addr.sin_addr, client_ip, sizeof(client_ip));
        /* === 关键修改点 2: 更新日志打印的变量 === */
        printf("[RECV] Session: 0x%lX, Stream: %d, Seq: %u, Payload: %d bytes from %s\n",
               session_id, stream_id, sequence, payload_len, client_ip);
    }
    
    if (g_config.pacing_enabled && payload_len > 0) {
        pacing_adaptive_ack(&g_pacing, len);
    }
    
    submit_recv(ctx);
}

// =========================================================
// 信号处理
// =========================================================
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n[INFO] Received signal, shutting down...\n");
}

// =========================================================
// 命令行解析
// =========================================================
static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --port=PORT           Listen port (default: 51820)\n");
    printf("  --bind=IP             Bind address (default: 0.0.0.0, use 127.0.0.1 for WSS gateway)\n");
    printf("  --fec                 Enable FEC (auto mode)\n");
    printf("  --fec-shards=D:P      FEC data:parity shards (default: 5:2)\n");
    printf("  --pacing=MBPS         Enable pacing with initial rate\n");
    printf("  --profile=TYPE        Anti-detect profile (https|video|voip|gaming)\n");
    printf("  --health              Enable health HTTP API\n");
    printf("  --health-port=PORT    Health API port (default: 8080)\n");
    printf("  --health-interval=SEC Stats print interval (default: 60)\n");
    printf("  --verbose, -v         Verbose output\n");
    printf("  --benchmark           Run FEC benchmark and exit\n");
    printf("  --help, -h            Show this help\n");
    printf("\n");
}

static void parse_args(int argc, char **argv) {
    static struct option long_opts[] = {
        {"fec",             optional_argument, 0, 'f'},
        {"fec-shards",      required_argument, 0, 'F'},
        {"pacing",          required_argument, 0, 'P'},
        {"profile",         required_argument, 0, 'A'},
        {"port",            required_argument, 0, 'p'},
        {"bind",            required_argument, 0, 1000},
        {"health",          optional_argument, 0, 'H'},
        {"health-port",     required_argument, 0, 1001},
        {"health-interval", required_argument, 0, 1002},
        {"verbose",         no_argument,       0, 'v'},
        {"benchmark",       no_argument,       0, 'B'},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "f::F:P:A:p:H::vBh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'f': g_config.fec_enabled = true; g_config.fec_type = FEC_TYPE_AUTO; break;
            case 'F':
                if (sscanf(optarg, "%hhu:%hhu", &g_config.fec_data_shards, &g_config.fec_parity_shards) != 2) {
                    fprintf(stderr, "Invalid FEC shards format. Use D:P\n"); exit(1);
                }
                g_config.fec_enabled = true;
                break;
            case 'P': g_config.pacing_enabled = true; g_config.pacing_initial_bps = atoll(optarg) * 1000000ULL; break;
            case 'A':
                if (strcmp(optarg, "https") == 0) g_config.ad_profile = AD_PROFILE_HTTPS;
                else if (strcmp(optarg, "video") == 0) g_config.ad_profile = AD_PROFILE_VIDEO;
                else if (strcmp(optarg, "voip") == 0) g_config.ad_profile = AD_PROFILE_VOIP;
                else if (strcmp(optarg, "gaming") == 0) g_config.ad_profile = AD_PROFILE_GAMING;
                else { fprintf(stderr, "Unknown profile: %s\n", optarg); exit(1); }
                break;
            case 'p': g_config.port = atoi(optarg); break;
            case 1000: g_config.bind_addr = optarg; break;
            case 'H': g_config.health_enabled = true; if (optarg) g_config.health_port = atoi(optarg); break;
            case 1001: g_config.health_port = atoi(optarg); break;
            case 1002: g_config.health_interval = atoi(optarg); break;
            case 'v': g_config.verbose = true; break;
            case 'B': g_config.benchmark = true; break;
            case 'h': usage(argv[0]); exit(0);
            default: usage(argv[0]); exit(1);
        }
    }
}

// =========================================================
// 基准测试
// =========================================================
static void run_benchmark(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 FEC Benchmark                           ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    cpu_print_info();
    
    if (!g_config.fec_enabled) {
        g_fec = fec_create(FEC_TYPE_AUTO, 10, 4);
    }
    
    if (g_fec) {
        printf("[Benchmark] Running FEC encode test...\n");
        double throughput = fec_benchmark(fec_get_type(g_fec), 1400 * 10, 10000);
        printf("[Result] Throughput: %.2f MB/s\n", throughput);
        printf("[Result] FEC Type: %d\n", fec_get_type(g_fec));
        fec_destroy(g_fec);
    }
    
    printf("\nBenchmark complete.\n");
}

// =========================================================
// 主程序
// =========================================================
int main(int argc, char **argv) {
    parse_args(argc, argv);
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║               v3 Ultimate Server (Enterprise)                 ║\n");
    printf("║         io_uring + SIMD FEC + Adaptive Pacing                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    init_modules();
    
    if (g_config.benchmark) {
        run_benchmark();
        return 0;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    pthread_t health_tid = 0;
    if (g_config.health_interval > 0) {
        pthread_create(&health_tid, NULL, health_print_thread, &g_config.health_interval);
    }
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    
    int bufsize = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_config.port),
        .sin_addr.s_addr = inet_addr(g_config.bind_addr)
    };
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    
    struct io_uring_params params = {0};
    if (geteuid() == 0) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;
    }
    if (io_uring_queue_init_params(QUEUE_DEPTH, &g_ring, &params) < 0) {
        perror("io_uring_queue_init");
        close(fd);
        return 1;
    }
    
    printf("[INFO] v3 UDP Core listening on %s:%d\n", g_config.bind_addr, g_config.port);
    printf("[INFO] Health API: http://127.0.0.1:%d/\n", g_config.health_port);
    printf("[INFO] Press Ctrl+C to stop\n\n");
    
    for (int i = 0; i < MAX_CONNS; i++) {
        prepare_recv(&g_ring, fd, &g_io_ctx_pool[i]);
    }
    io_uring_submit(&g_ring);
    
    struct io_uring_cqe *cqe;
    while (g_running) {
        int ret = io_uring_wait_cqe(&g_ring, &cqe);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            perror("io_uring_wait_cqe");
            break;
        }
        
        io_context_t *ctx = (io_context_t *)io_uring_cqe_get_data(cqe);
        if (cqe->res > 0 && ctx->op == OP_READ) {
            handle_packet(ctx, cqe->res);
        } else {
            submit_recv(ctx);
        }
        io_uring_cqe_seen(&g_ring, cqe);
    }
    
    printf("[INFO] Cleaning up...\n");
    v3_health_stop_server();
    if (health_tid) {
        pthread_cancel(health_tid);
        pthread_join(health_tid, NULL);
    }
    io_uring_queue_exit(&g_ring);
    close(fd);
    if (g_fec) {
        fec_destroy(g_fec);
    }
    
    printf("[INFO] Shutdown complete.\n");
    return 0;
}
