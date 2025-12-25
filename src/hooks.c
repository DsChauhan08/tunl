/*
 * SPF Custom Security Hooks - Linux-way extensibility
 * 
 * Users can add custom security logic via external scripts/programs.
 * Like iptables but for L4 proxying - any language works.
 * 
 * Hook scripts receive connection info via environment variables:
 *   SPF_CLIENT_IP, SPF_CLIENT_PORT, SPF_RULE_ID, SPF_BACKEND_IP,
 *   SPF_BACKEND_PORT, SPF_TIMESTAMP, SPF_EVENT_TYPE
 * 
 * Return codes:
 *   0 = ALLOW connection
 *   1 = BLOCK connection
 *   2 = RATE_LIMIT (soft block)
 *   Other = ALLOW (fail-open for safety)
 * 
 * Hook types:
 *   on_connect    - before accepting connection
 *   on_disconnect - after connection closes
 *   on_block      - when IP gets blocked
 *   on_health     - when backend health changes
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#define SPF_HOOK_TIMEOUT_MS 1000
#define SPF_MAX_HOOKS 8
#define SPF_HOOK_PATH_MAX 512

// spf_hook_type_t is defined in common.h

typedef struct {
    char path[SPF_HOOK_PATH_MAX];
    bool enabled;
    bool async;          // Don't wait for result (fire-and-forget)
    uint32_t timeout_ms;
} spf_hook_t;

typedef struct {
    spf_hook_t hooks[SPF_HOOK_COUNT][SPF_MAX_HOOKS];
    uint8_t hook_count[SPF_HOOK_COUNT];
    bool enabled;
    char hooks_dir[SPF_PATH_MAX];
    pthread_mutex_t lock;
} spf_hooks_t;

static spf_hooks_t g_hooks;

static const char* hook_type_names[] = {
    "on_connect",
    "on_disconnect", 
    "on_block",
    "on_health"
};

void spf_hooks_init(void) {
    memset(&g_hooks, 0, sizeof(g_hooks));
    pthread_mutex_init(&g_hooks.lock, NULL);
    strncpy(g_hooks.hooks_dir, "/etc/spf/hooks.d", SPF_PATH_MAX - 1);
    g_hooks.enabled = true;
    spf_log(SPF_LOG_INFO, "hooks: initialized, dir=%s", g_hooks.hooks_dir);
}

void spf_hooks_cleanup(void) {
    pthread_mutex_destroy(&g_hooks.lock);
}

void spf_hooks_set_dir(const char* dir) {
    pthread_mutex_lock(&g_hooks.lock);
    strncpy(g_hooks.hooks_dir, dir, SPF_PATH_MAX - 1);
    g_hooks.hooks_dir[SPF_PATH_MAX - 1] = '\0';
    pthread_mutex_unlock(&g_hooks.lock);
}

int spf_hooks_add(spf_hook_type_t type, const char* path, bool async, uint32_t timeout_ms) {
    if (type >= SPF_HOOK_COUNT) return -1;
    
    pthread_mutex_lock(&g_hooks.lock);
    
    if (g_hooks.hook_count[type] >= SPF_MAX_HOOKS) {
        pthread_mutex_unlock(&g_hooks.lock);
        return -1;
    }
    
    int idx = g_hooks.hook_count[type];
    strncpy(g_hooks.hooks[type][idx].path, path, SPF_HOOK_PATH_MAX - 1);
    g_hooks.hooks[type][idx].path[SPF_HOOK_PATH_MAX - 1] = '\0';
    g_hooks.hooks[type][idx].enabled = true;
    g_hooks.hooks[type][idx].async = async;
    g_hooks.hooks[type][idx].timeout_ms = timeout_ms ? timeout_ms : SPF_HOOK_TIMEOUT_MS;
    g_hooks.hook_count[type]++;
    
    pthread_mutex_unlock(&g_hooks.lock);
    
    spf_log(SPF_LOG_INFO, "hooks: added %s hook: %s (async=%d)", 
            hook_type_names[type], path, async);
    return 0;
}

// Auto-discover hooks from hooks.d directory
int spf_hooks_autodiscover(void) {
    char pattern[SPF_PATH_MAX * 2];
    
    for (int t = 0; t < SPF_HOOK_COUNT; t++) {
        snprintf(pattern, sizeof(pattern), "%s/%s", g_hooks.hooks_dir, hook_type_names[t]);
        
        struct stat st;
        if (stat(pattern, &st) == 0 && (st.st_mode & S_IXUSR)) {
            spf_hooks_add((spf_hook_type_t)t, pattern, false, SPF_HOOK_TIMEOUT_MS);
        }
        
        // Also check for numbered hooks: on_connect.1, on_connect.2, etc.
        for (int i = 1; i <= 9; i++) {
            snprintf(pattern, sizeof(pattern), "%s/%s.%d", g_hooks.hooks_dir, hook_type_names[t], i);
            if (stat(pattern, &st) == 0 && (st.st_mode & S_IXUSR)) {
                spf_hooks_add((spf_hook_type_t)t, pattern, false, SPF_HOOK_TIMEOUT_MS);
            }
        }
    }
    
    return 0;
}

// Execute a single hook script
static int exec_hook(const char* path, const char* client_ip, uint16_t client_port,
                     uint32_t rule_id, const char* backend_ip, uint16_t backend_port,
                     const char* event_type, bool async, uint32_t timeout_ms) {
    
    pid_t pid = fork();
    if (pid < 0) {
        spf_log(SPF_LOG_ERROR, "hooks: fork failed: %s", strerror(errno));
        return 0; // Fail-open
    }
    
    if (pid == 0) {
        // Child process
        // Set up environment
        char buf[64];
        
        setenv("SPF_CLIENT_IP", client_ip ? client_ip : "", 1);
        snprintf(buf, sizeof(buf), "%u", client_port);
        setenv("SPF_CLIENT_PORT", buf, 1);
        snprintf(buf, sizeof(buf), "%u", rule_id);
        setenv("SPF_RULE_ID", buf, 1);
        setenv("SPF_BACKEND_IP", backend_ip ? backend_ip : "", 1);
        snprintf(buf, sizeof(buf), "%u", backend_port);
        setenv("SPF_BACKEND_PORT", buf, 1);
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)time(NULL));
        setenv("SPF_TIMESTAMP", buf, 1);
        setenv("SPF_EVENT_TYPE", event_type ? event_type : "", 1);
        setenv("SPF_VERSION", SPF_VERSION, 1);
        
        // Redirect stdin/stdout/stderr to /dev/null for clean execution
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            // Keep stderr for debugging
            close(devnull);
        }
        
        // Execute the hook
        execl(path, path, (char*)NULL);
        _exit(127); // Exec failed
    }
    
    // Parent process
    if (async) {
        // Don't wait, let child run in background
        return 0;
    }
    
    // Wait with timeout
    int status = 0;
    uint32_t elapsed = 0;
    const uint32_t sleep_interval_us = 10000; // 10ms
    
    while (elapsed < timeout_ms) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            // Child exited
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            return 0; // Abnormal exit, fail-open
        }
        if (result < 0) {
            return 0; // Error, fail-open
        }
        
        usleep(sleep_interval_us);
        elapsed += sleep_interval_us / 1000;
    }
    
    // Timeout - kill child and fail-open
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    spf_log(SPF_LOG_WARN, "hooks: %s timed out after %ums", path, timeout_ms);
    return 0;
}

// Run all hooks for a given type
int spf_hooks_run(spf_hook_type_t type, const char* client_ip, uint16_t client_port,
                  uint32_t rule_id, const char* backend_ip, uint16_t backend_port) {
    
    if (!g_hooks.enabled || type >= SPF_HOOK_COUNT) return 0;
    
    pthread_mutex_lock(&g_hooks.lock);
    uint8_t count = g_hooks.hook_count[type];
    
    if (count == 0) {
        pthread_mutex_unlock(&g_hooks.lock);
        return 0;
    }
    
    // Copy hooks to avoid holding lock during execution
    spf_hook_t hooks_copy[SPF_MAX_HOOKS];
    memcpy(hooks_copy, g_hooks.hooks[type], sizeof(spf_hook_t) * count);
    pthread_mutex_unlock(&g_hooks.lock);
    
    int result = 0;
    for (int i = 0; i < count; i++) {
        if (!hooks_copy[i].enabled) continue;
        
        int ret = exec_hook(hooks_copy[i].path, client_ip, client_port,
                           rule_id, backend_ip, backend_port,
                           hook_type_names[type], hooks_copy[i].async, 
                           hooks_copy[i].timeout_ms);
        
        // Non-async hooks: check return code
        if (!hooks_copy[i].async && ret != 0) {
            result = ret;
            // Return code 1 = BLOCK, stop processing
            if (ret == 1) break;
        }
    }
    
    return result;
}

// Convenience wrappers
int spf_hook_on_connect(const char* client_ip, uint16_t client_port,
                        uint32_t rule_id, const char* backend_ip, uint16_t backend_port) {
    return spf_hooks_run(SPF_HOOK_ON_CONNECT, client_ip, client_port, 
                        rule_id, backend_ip, backend_port);
}

void spf_hook_on_disconnect(const char* client_ip, uint16_t client_port,
                            uint32_t rule_id, const char* backend_ip, uint16_t backend_port) {
    spf_hooks_run(SPF_HOOK_ON_DISCONNECT, client_ip, client_port,
                 rule_id, backend_ip, backend_port);
}

void spf_hook_on_block(const char* client_ip, uint32_t rule_id, const char* reason) {
    // For block events, pass reason in backend_ip field
    spf_hooks_run(SPF_HOOK_ON_BLOCK, client_ip, 0, rule_id, reason, 0);
}

void spf_hook_on_health(const char* backend_ip, uint16_t backend_port, 
                        uint32_t rule_id, bool is_up) {
    spf_hooks_run(SPF_HOOK_ON_HEALTH, is_up ? "UP" : "DOWN", 0,
                 rule_id, backend_ip, backend_port);
}

// Load hook config from file
int spf_hooks_load_config(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // Trim
        char* s = line;
        while (*s && (*s == ' ' || *s == '\t')) s++;
        size_t len = strlen(s);
        while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' || s[len-1] == ' ')) {
            s[--len] = '\0';
        }
        
        // Skip empty lines and comments
        if (*s == '\0' || *s == '#') continue;
        
        // Format: TYPE:PATH[:async][:timeout_ms]
        char type_str[32], hook_path[SPF_HOOK_PATH_MAX];
        int is_async = 0, timeout = SPF_HOOK_TIMEOUT_MS;
        
        int parsed = sscanf(s, "%31[^:]:%511[^:]:%d:%d", type_str, hook_path, &is_async, &timeout);
        if (parsed < 2) continue;
        
        spf_hook_type_t type = SPF_HOOK_COUNT;
        for (int i = 0; i < SPF_HOOK_COUNT; i++) {
            if (strcmp(type_str, hook_type_names[i]) == 0) {
                type = (spf_hook_type_t)i;
                break;
            }
        }
        
        if (type < SPF_HOOK_COUNT) {
            spf_hooks_add(type, hook_path, is_async != 0, timeout);
        }
    }
    
    fclose(f);
    return 0;
}

// Get hooks info for status display
int spf_hooks_get_info(char* buf, size_t len) {
    int written = 0;
    
    pthread_mutex_lock(&g_hooks.lock);
    
    written += snprintf(buf + written, len - written, 
                       "Hooks enabled: %s\nHooks dir: %s\n", 
                       g_hooks.enabled ? "yes" : "no", g_hooks.hooks_dir);
    
    for (int t = 0; t < SPF_HOOK_COUNT && written < (int)len - 100; t++) {
        if (g_hooks.hook_count[t] > 0) {
            written += snprintf(buf + written, len - written, 
                               "%s hooks: %d\n", hook_type_names[t], g_hooks.hook_count[t]);
            for (int i = 0; i < g_hooks.hook_count[t] && written < (int)len - 100; i++) {
                written += snprintf(buf + written, len - written,
                                   "  - %s%s\n", g_hooks.hooks[t][i].path,
                                   g_hooks.hooks[t][i].async ? " (async)" : "");
            }
        }
    }
    
    pthread_mutex_unlock(&g_hooks.lock);
    return written;
}
