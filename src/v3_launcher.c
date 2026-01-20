
/*
 * v3 Launcher - 自动降级启动器
 * 
 * 功能：
 * - 尝试启动最优版本
 * - 失败自动降级
 * - 记录降级原因
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>

// =========================================================
// 版本定义（按优先级排序）
// =========================================================
typedef struct {
    const char *name;
    const char *binary;
    const char *description;
    int         priority;
} v3_version_t;

static const v3_version_t VERSIONS[] = {
    {"v5", "v3_server_v5",     "Enterprise (Full)",       1},
    {"v8", "v3_server_v8",     "Turbo (Brutal)",          2},
    {"v6", "v3_server_v6",     "Portable (Static)",       3},
    {"v9", "v3_server_v9",     "Turbo-Portable (Hybrid)", 4},
    {"v7", "v3_server_v7",     "Rescue (WSS)",            5},
    {NULL, NULL, NULL, 0}
};

static const char *SEARCH_PATHS[] = {
    "/usr/local/bin",
    "/opt/v3/bin",
    "/usr/bin",
    ".",
    NULL
};

// =========================================================
// 查找可执行文件
// =========================================================
static char* find_binary(const char *name) {
    static char path[512];
    struct stat st;
    
    for (int i = 0; SEARCH_PATHS[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", SEARCH_PATHS[i], name);
        if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return path;
        }
    }
    return NULL;
}

// =========================================================
// 尝试启动版本（带超时检测）
// =========================================================
static int try_start_version(const v3_version_t *ver, char **argv) {
    char *binary_path = find_binary(ver->binary);
    if (!binary_path) {
        fprintf(stderr, "[Launcher] %s: Binary not found\n", ver->name);
        return -1;
    }
    
    printf("[Launcher] Trying %s (%s)...\n", ver->name, ver->description);
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // 子进程：执行实际服务器
        argv[0] = binary_path;
        execv(binary_path, argv);
        
        // exec 失败
        fprintf(stderr, "[Launcher] Failed to exec %s: %s\n", 
                ver->binary, strerror(errno));
        _exit(127);
    }
    
    if (pid < 0) {
        fprintf(stderr, "[Launcher] Fork failed: %s\n", strerror(errno));
        return -1;
    }
    
    // 等待 2 秒，检查是否立即崩溃
    sleep(2);
    
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    
    if (result == 0) {
        // 还在运行，说明启动成功
        printf("[Launcher] %s started successfully (PID: %d)\n", ver->name, pid);
        
        // 等待子进程结束（正常运行模式）
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;  // 正常退出
        }
        
        printf("[Launcher] %s exited with status %d\n", 
               ver->name, WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    
    if (result == pid) {
        // 已经退出，检查原因
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            fprintf(stderr, "[Launcher] %s crashed with signal %d", 
                    ver->name, sig);
            
            if (sig == SIGILL) {
                fprintf(stderr, " (Illegal instruction - CPU feature not available)\n");
            } else if (sig == SIGSEGV) {
                fprintf(stderr, " (Segmentation fault)\n");
            } else {
                fprintf(stderr, "\n");
            }
        } else {
            fprintf(stderr, "[Launcher] %s exited immediately with code %d\n",
                    ver->name, WEXITSTATUS(status));
        }
        return -1;
    }
    
    return -1;
}

// =========================================================
// 主程序
// =========================================================
int main(int argc, char **argv) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║              v3 Auto-Fallback Launcher                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    // 检测可用版本
    printf("[Launcher] Scanning available versions...\n");
    
    int available_count = 0;
    for (int i = 0; VERSIONS[i].name; i++) {
        char *path = find_binary(VERSIONS[i].binary);
        if (path) {
            printf("  ✓ %s: %s\n", VERSIONS[i].name, path);
            available_count++;
        } else {
            printf("  ✗ %s: Not found\n", VERSIONS[i].name);
        }
    }
    
    if (available_count == 0) {
        fprintf(stderr, "\n[Launcher] ERROR: No v3 versions found!\n");
        fprintf(stderr, "Please install v3 first.\n");
        return 1;
    }
    
    printf("\n[Launcher] Starting with auto-fallback...\n\n");
    
    // 按优先级尝试启动
    for (int i = 0; VERSIONS[i].name; i++) {
        char *path = find_binary(VERSIONS[i].binary);
        if (!path) continue;
        
        int result = try_start_version(&VERSIONS[i], argv);
        
        if (result == 0) {
            // 正常退出
            return 0;
        }
        
        if (result > 0) {
            // 非正常退出，但不是崩溃
            printf("[Launcher] %s failed, trying fallback...\n\n", 
                   VERSIONS[i].name);
        }
        
        // 继续尝试下一个版本
    }
    
    fprintf(stderr, "\n[Launcher] All versions failed!\n");
    return 1;
}




