/*
 * SPF Access Logging & DNS Resolution
 * Cloud LB feature: structured access logs for analysis
 * rinetd pain point: hostname resolution for backends
 */

#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>

static FILE* g_access_log = NULL;
static pthread_mutex_t g_access_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_access_log_path[SPF_PATH_MAX] = {0};

int spf_access_log_init(const char* path) {
    pthread_mutex_lock(&g_access_log_lock);
    
    if (g_access_log) {
        fclose(g_access_log);
        g_access_log = NULL;
    }
    
    if (!path || path[0] == '\0') {
        pthread_mutex_unlock(&g_access_log_lock);
        return 0;
    }
    
    g_access_log = fopen(path, "a");
    if (!g_access_log) {
        spf_log(SPF_LOG_ERROR, "access_log: cannot open %s", path);
        pthread_mutex_unlock(&g_access_log_lock);
        return -1;
    }
    
    strncpy(g_access_log_path, path, SPF_PATH_MAX - 1);
    spf_log(SPF_LOG_INFO, "access_log: logging to %s", path);
    
    pthread_mutex_unlock(&g_access_log_lock);
    return 0;
}

void spf_access_log_close(void) {
    pthread_mutex_lock(&g_access_log_lock);
    if (g_access_log) {
        fclose(g_access_log);
        g_access_log = NULL;
    }
    g_access_log_path[0] = '\0';
    pthread_mutex_unlock(&g_access_log_lock);
}

// JSON structured access log (like AWS ALB logs)
void spf_access_log(const char* client_ip, uint16_t client_port, uint32_t rule_id,
                   const char* backend, uint64_t bytes_in, uint64_t bytes_out,
                   uint64_t duration_ms, int status) {
    
    pthread_mutex_lock(&g_access_log_lock);
    
    if (!g_access_log) {
        pthread_mutex_unlock(&g_access_log_lock);
        return;
    }
    
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm* t = gmtime_r(&now, &tm_buf);
    char ts[64];
    if (t) {
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", t);
    } else {
        snprintf(ts, sizeof(ts), "1970-01-01T00:00:00Z");
    }
    
    // JSON format similar to cloud LB logs
    fprintf(g_access_log, 
        "{\"timestamp\":\"%s\",\"client_ip\":\"%s\",\"client_port\":%u,"
        "\"rule_id\":%u,\"backend\":\"%s\",\"bytes_in\":%lu,\"bytes_out\":%lu,"
        "\"duration_ms\":%lu,\"status\":%d}\n",
        ts, client_ip ? client_ip : "", client_port,
        rule_id, backend ? backend : "", bytes_in, bytes_out,
        duration_ms, status);
    
    fflush(g_access_log);
    pthread_mutex_unlock(&g_access_log_lock);
}

// DNS hostname resolution for backends
// rinetd only supports IP addresses - this is a major pain point
int spf_resolve_hostname(const char* hostname, char* ip_out, size_t ip_len) {
    if (!hostname || !ip_out || ip_len < 16) return -1;
    
    // Check if already an IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) {
        strncpy(ip_out, hostname, ip_len - 1);
        ip_out[ip_len - 1] = '\0';
        return 0;
    }
    
    // IPv6 check
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, hostname, &addr6) == 1) {
        strncpy(ip_out, hostname, ip_len - 1);
        ip_out[ip_len - 1] = '\0';
        return 0;
    }
    
    // DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Prefer IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    int err = getaddrinfo(hostname, NULL, &hints, &result);
    if (err != 0) {
        spf_log(SPF_LOG_WARN, "dns: failed to resolve %s: %s", hostname, gai_strerror(err));
        return -1;
    }
    
    if (!result) {
        return -1;
    }
    
    struct sockaddr_in* sa = (struct sockaddr_in*)result->ai_addr;
    if (!inet_ntop(AF_INET, &sa->sin_addr, ip_out, ip_len)) {
        freeaddrinfo(result);
        return -1;
    }
    
    freeaddrinfo(result);
    spf_log(SPF_LOG_DEBUG, "dns: resolved %s -> %s", hostname, ip_out);
    return 0;
}

// Resolve all backends for a rule (call on rule add or periodically)
int spf_resolve_rule_backends(spf_rule_t* rule) {
    if (!rule) return -1;
    
    int resolved = 0;
    for (int i = 0; i < rule->backend_count; i++) {
        char ip[SPF_IP_MAX_LEN];
        if (spf_resolve_hostname(rule->backends[i].host, ip, sizeof(ip)) == 0) {
            // Only update if different
            if (strcmp(rule->backends[i].host, ip) != 0) {
                spf_log(SPF_LOG_INFO, "dns: backend %s resolved to %s", 
                       rule->backends[i].host, ip);
                // Keep original hostname? For now, update to IP
                strncpy(rule->backends[i].host, ip, SPF_IP_MAX_LEN - 1);
            }
            resolved++;
        }
    }
    
    return resolved;
}
