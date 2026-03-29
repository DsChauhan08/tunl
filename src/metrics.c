#include "common.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static int g_metrics_fd = -1;
static pthread_t g_metrics_thread;
static volatile bool g_metrics_running = false;
static volatile bool g_metrics_started = false;

typedef struct {
    const char* name;
    const char* help;
    const char* type;
} metric_def_t;

static const metric_def_t metrics[] = {
    {"spf_connections_active", "Current active connections", "gauge"},
    {"spf_connections_total", "Total connections since start", "counter"},
    {"spf_bytes_in_total", "Total bytes received", "counter"},
    {"spf_bytes_out_total", "Total bytes sent", "counter"},
    {"spf_blocked_total", "Total blocked IPs", "counter"},
    {"spf_rules_active", "Active forwarding rules", "gauge"},
    {"spf_uptime_seconds", "Uptime in seconds", "counter"},
    {"spf_admin_auth_failures_total", "Failed admin authentications", "counter"},
    {"spf_admin_lockouts_total", "Admin lockouts triggered", "counter"},
    {"spf_admin_cmd_rate_limited_total", "Admin commands rate-limited", "counter"},
    {"spf_admin_service_token_auth_success_total", "Successful service-token admin auth", "counter"},
    {"spf_admin_service_token_auth_fail_total", "Failed service-token admin auth", "counter"},
    {"spf_admin_temp_grants_created_total", "Temporary admin grants created", "counter"},
    {NULL, NULL, NULL}
};

int metrics_format(spf_state_t* state, char* buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

    int written = 0;
    uint64_t uptime = spf_time_sec() - state->start_time;

    for (int i = 0; metrics[i].name; i++) {
        if ((size_t)written >= len) {
            buf[len - 1] = '\0';
            return (int)(len - 1);
        }
        written += snprintf(buf + written, len - written,
            "# HELP %s %s\n# TYPE %s %s\n",
            metrics[i].name, metrics[i].help,
            metrics[i].name, metrics[i].type);
    }

    pthread_mutex_lock(&state->stats_lock);
    if ((size_t)written >= len) {
        pthread_mutex_unlock(&state->stats_lock);
        buf[len - 1] = '\0';
        return (int)(len - 1);
    }
    written += snprintf(buf + written, len - written,
        "spf_connections_active %u\n"
        "spf_connections_total %lu\n"
        "spf_bytes_in_total %lu\n"
        "spf_bytes_out_total %lu\n"
        "spf_blocked_total %lu\n"
        "spf_rules_active %u\n"
        "spf_uptime_seconds %lu\n"
        "spf_admin_auth_failures_total %lu\n"
        "spf_admin_lockouts_total %lu\n"
        "spf_admin_service_token_auth_success_total %lu\n"
        "spf_admin_service_token_auth_fail_total %lu\n"
        "spf_admin_cmd_rate_limited_total %lu\n"
        "spf_admin_temp_grants_created_total %lu\n",
        state->active_conns,
        state->total_conns,
        state->total_bytes_in,
        state->total_bytes_out,
        state->blocked_count,
        state->rule_count,
        uptime,
        state->admin_auth_failures,
        state->admin_lockouts,
        state->admin_service_token_auth_success,
        state->admin_service_token_auth_fail,
        state->admin_cmd_rate_limited,
        state->admin_temp_grants_created);
    pthread_mutex_unlock(&state->stats_lock);

    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active) {
            spf_rule_t* r = &state->rules[i];
            for (int j = 0; j < r->backend_count; j++) {
                if ((size_t)written >= len) {
                    buf[len - 1] = '\0';
                    return (int)(len - 1);
                }
                spf_backend_t* b = &r->backends[j];
                written += snprintf(buf + written, len - written,
                    "spf_backend_up{rule=\"%u\",backend=\"%s:%u\"} %d\n"
                    "spf_backend_conns{rule=\"%u\",backend=\"%s:%u\"} %u\n",
                    r->id, b->host, b->port, b->state == SPF_BACKEND_UP ? 1 : 0,
                    r->id, b->host, b->port, b->active_conns);
            }
        }
    }

    return written;
}

static void handle_metrics_request(int fd, spf_state_t* state) {
    char req[1024];
    ssize_t n = recv(fd, req, sizeof(req), 0);
    if (n <= 0) {
        close(fd);
        return;
    }

    char body[8192];
    int body_len = metrics_format(state, body, sizeof(body));

    char resp[8192 + 256];
    int resp_len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        body_len, body);

    send(fd, resp, resp_len, 0);
    close(fd);
}

static void* metrics_worker(void* arg) {
    spf_state_t* state = (spf_state_t*)arg;

    g_metrics_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_metrics_fd < 0) return NULL;

    int opt = 1;
    setsockopt(g_metrics_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(state->config.metrics.port);

    if (bind(g_metrics_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "metrics: bind failed");
        close(g_metrics_fd);
        return NULL;
    }

    listen(g_metrics_fd, 5);
    spf_log(SPF_LOG_INFO, "metrics: listening on :%u", state->config.metrics.port);

    while (g_metrics_running && state->running) {
        if (g_metrics_fd >= FD_SETSIZE) {
            spf_log(SPF_LOG_ERROR, "metrics: fd >= FD_SETSIZE");
            break;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_metrics_fd, &fds);
        struct timeval tv = {1, 0};

        if (select(g_metrics_fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;

        int client = accept(g_metrics_fd, NULL, NULL);
        if (client >= 0) {
            handle_metrics_request(client, state);
        }
    }

    close(g_metrics_fd);
    return NULL;
}

int metrics_start(spf_state_t* state) {
    if (!state->config.metrics.enabled) {
        spf_log(SPF_LOG_INFO, "metrics: disabled");
        return 0;
    }

    g_metrics_running = true;
    int rc = pthread_create(&g_metrics_thread, NULL, metrics_worker, state);
    if (rc == 0) {
        g_metrics_started = true;
    }
    return rc;
}

void metrics_stop(void) {
    g_metrics_running = false;
    if (g_metrics_fd >= 0) {
        close(g_metrics_fd);
        g_metrics_fd = -1;
    }
    if (g_metrics_started) {
        pthread_join(g_metrics_thread, NULL);
        g_metrics_started = false;
    }
}
