#ifndef SPF_PLATFORM_ESP32

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

spf_state_t g_state;
static int g_ctrl_fd = -1;
static volatile sig_atomic_t g_shutdown = 0;

typedef struct {
    int client_fd;
    int target_fd;
    SSL* client_ssl;
    SSL* target_ssl;
    struct sockaddr_in client_addr;
    spf_rule_t* rule;
    uint8_t backend_idx;
    uint32_t conn_idx;
} session_t;

static void release_conn_slot(uint32_t conn_idx, bool rollback_total) {
    pthread_mutex_lock(&g_state.stats_lock);
    if (conn_idx < SPF_MAX_CONNECTIONS && g_state.connections[conn_idx].active) {
        g_state.connections[conn_idx].active = false;
        g_state.connections[conn_idx].bytes_in = 0;
        g_state.connections[conn_idx].bytes_out = 0;
    }
    if (g_state.active_conns > 0) {
        g_state.active_conns--;
    }
    if (rollback_total && g_state.total_conns > 0) {
        g_state.total_conns--;
    }
    pthread_mutex_unlock(&g_state.stats_lock);
}

static bool parse_u16_strict(const char* s, uint16_t* out) {
    if (!s || !*s || !out) {
        return false;
    }
    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v == 0 || v > 65535UL) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

static bool is_loopback_bind(const char* ip) {
    if (!ip || !*ip) {
        return false;
    }
    if (strcmp(ip, "localhost") == 0 || strcmp(ip, "::1") == 0) {
        return true;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return false;
    }

    uint32_t v = ntohl(addr.s_addr);
    return (v >> 24) == 127;
}

static bool is_admin_ip_allowed(const struct sockaddr_in* addr) {
    if (!addr) {
        return false;
    }
    pthread_mutex_lock(&g_state.lock);
    uint8_t allow_count = g_state.config.admin.allowlist_count;
    char allow_copy[SPF_MAX_ADMIN_ALLOWLIST][SPF_IP_MAX_LEN];
    for (uint8_t i = 0; i < allow_count; i++) {
        strncpy(allow_copy[i], g_state.config.admin.allowlist[i], SPF_IP_MAX_LEN);
    }
    pthread_mutex_unlock(&g_state.lock);

    if (allow_count == 0) {
        return true;
    }

    char ip[SPF_IP_MAX_LEN];
    if (!inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip))) {
        return false;
    }

    for (uint8_t i = 0; i < allow_count; i++) {
        if (strcmp(ip, allow_copy[i]) == 0) {
            return true;
        }
    }
    return false;
}

static int admin_allowlist_add(const char* ip) {
    if (!ip || !*ip) {
        return -1;
    }

    struct in_addr parsed;
    if (inet_pton(AF_INET, ip, &parsed) != 1) {
        return -1;
    }

    pthread_mutex_lock(&g_state.lock);
    for (uint8_t i = 0; i < g_state.config.admin.allowlist_count; i++) {
        if (strcmp(g_state.config.admin.allowlist[i], ip) == 0) {
            pthread_mutex_unlock(&g_state.lock);
            return 1;
        }
    }

    if (g_state.config.admin.allowlist_count >= SPF_MAX_ADMIN_ALLOWLIST) {
        pthread_mutex_unlock(&g_state.lock);
        return -2;
    }

    strncpy(g_state.config.admin.allowlist[g_state.config.admin.allowlist_count], ip, SPF_IP_MAX_LEN - 1);
    g_state.config.admin.allowlist[g_state.config.admin.allowlist_count][SPF_IP_MAX_LEN - 1] = '\0';
    g_state.config.admin.allowlist_count++;
    pthread_mutex_unlock(&g_state.lock);
    return 0;
}

static int admin_allowlist_del(const char* ip) {
    if (!ip || !*ip) {
        return -1;
    }

    pthread_mutex_lock(&g_state.lock);
    for (uint8_t i = 0; i < g_state.config.admin.allowlist_count; i++) {
        if (strcmp(g_state.config.admin.allowlist[i], ip) == 0) {
            for (uint8_t j = i; j + 1 < g_state.config.admin.allowlist_count; j++) {
                strncpy(g_state.config.admin.allowlist[j], g_state.config.admin.allowlist[j + 1], SPF_IP_MAX_LEN);
            }
            g_state.config.admin.allowlist_count--;
            pthread_mutex_unlock(&g_state.lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_state.lock);
    return 1;
}

static int admin_allowlist_set_csv(const char* csv) {
    if (!csv) {
        return -1;
    }

    char parsed[SPF_MAX_ADMIN_ALLOWLIST][SPF_IP_MAX_LEN];
    uint8_t count = 0;

    char tmp[512];
    strncpy(tmp, csv, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char* saveptr = NULL;
    char* tok = strtok_r(tmp, ",", &saveptr);
    while (tok && count < SPF_MAX_ADMIN_ALLOWLIST) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char* end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        *end = '\0';

        if (*tok) {
            struct in_addr parsed_ip;
            if (inet_pton(AF_INET, tok, &parsed_ip) != 1) {
                return -1;
            }
            strncpy(parsed[count], tok, SPF_IP_MAX_LEN - 1);
            parsed[count][SPF_IP_MAX_LEN - 1] = '\0';
            count++;
        }

        tok = strtok_r(NULL, ",", &saveptr);
    }

    pthread_mutex_lock(&g_state.lock);
    g_state.config.admin.allowlist_count = count;
    for (uint8_t i = 0; i < count; i++) {
        strncpy(g_state.config.admin.allowlist[i], parsed[i], SPF_IP_MAX_LEN);
    }
    pthread_mutex_unlock(&g_state.lock);
    return 0;
}

static int parse_backend_index_strict(const char* s, uint8_t* out) {
    if (!s || !*s || !out) {
        return -1;
    }
    char* end = NULL;
    errno = 0;
    unsigned long idx = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || idx >= SPF_MAX_BACKENDS) {
        return -1;
    }
    *out = (uint8_t)idx;
    return 0;
}

static int rule_backend_set_weight(spf_rule_t* rule, uint8_t idx, uint16_t weight) {
    if (!rule || idx >= rule->backend_count || weight == 0) {
        return -1;
    }
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].weight = weight;
    pthread_mutex_unlock(&rule->backends[idx].lock);
    return 0;
}

static int rule_backend_set_state(spf_rule_t* rule, uint8_t idx, spf_backend_state_t state) {
    if (!rule || idx >= rule->backend_count) {
        return -1;
    }
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].state = state;
    pthread_mutex_unlock(&rule->backends[idx].lock);
    return 0;
}

static int rule_backend_drain(spf_rule_t* rule, uint8_t idx, uint32_t timeout_sec, uint32_t* active_left) {
    if (!rule || idx >= rule->backend_count) {
        return -1;
    }

    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].state = SPF_BACKEND_DRAIN;
    pthread_mutex_unlock(&rule->backends[idx].lock);

    uint64_t deadline_ms = spf_time_ms() + ((uint64_t)timeout_sec * 1000ULL);
    for (;;) {
        pthread_mutex_lock(&rule->backends[idx].lock);
        uint32_t active = rule->backends[idx].active_conns;
        pthread_mutex_unlock(&rule->backends[idx].lock);

        if (active == 0) {
            rule_backend_set_state(rule, idx, SPF_BACKEND_DOWN);
            if (active_left) {
                *active_left = 0;
            }
            return 0;
        }

        if (timeout_sec == 0 || spf_time_ms() >= deadline_ms) {
            if (active_left) {
                *active_left = active;
            }
            return 1;
        }

        usleep(100000);
    }
}

static int save_runtime_config(void) {
    const char* path = g_state.config.config_path[0] ? g_state.config.config_path : "spf.conf";
    return config_save(&g_state, path);
}

static bool parse_backend_token(const char* token, spf_backend_t* out) {
    if (!token || !*token || !out) {
        return false;
    }

    char tmp[96];
    strncpy(tmp, token, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char* colon = strchr(tmp, ':');
    if (!colon) {
        return false;
    }

    *colon = '\0';
    const char* host = tmp;
    const char* port_s = colon + 1;

    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) {
        return false;
    }

    uint16_t port = 0;
    if (!parse_u16_strict(port_s, &port)) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    strncpy(out->host, host, SPF_IP_MAX_LEN - 1);
    out->host[SPF_IP_MAX_LEN - 1] = '\0';
    out->port = port;
    out->weight = 1;
    out->state = SPF_BACKEND_UP;
    return true;
}

static ssize_t send_plain_once(int fd, const uint8_t* buf, size_t len) {
    for (;;) {
        ssize_t n = send(fd, buf, len, 0);
        if (n >= 0) {
            return n;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

static ssize_t send_tls_once(SSL* ssl, const uint8_t* buf, size_t len) {
    ssize_t n = tls_write(ssl, buf, len);
    if (n < 0) {
        return -1;
    }
    return n;
}

static int forward_buffer(session_t* s, bool to_target, spf_bucket_t* bucket,
                          const uint8_t* buf, size_t len, uint64_t* counter) {
    size_t off = 0;

    while (off < len && !g_shutdown && g_state.running) {
        uint64_t allowed = spf_bucket_consume(bucket, len - off);
        if (allowed == 0) {
            usleep(1000);
            continue;
        }

        ssize_t sent;
        if (to_target) {
            if (s->target_ssl) {
                sent = send_tls_once(s->target_ssl, buf + off, allowed);
            } else {
                sent = send_plain_once(s->target_fd, buf + off, allowed);
            }
        } else {
            if (s->client_ssl) {
                sent = send_tls_once(s->client_ssl, buf + off, allowed);
            } else {
                sent = send_plain_once(s->client_fd, buf + off, allowed);
            }
        }

        if (sent < 0) {
            return -1;
        }
        if (sent == 0) {
            usleep(1000);
            continue;
        }

        off += (size_t)sent;
        *counter += (uint64_t)sent;
    }

    return off == len ? 0 : -1;
}

void sig_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

int send_proxy_proto_v2(int fd, struct sockaddr_in* src, struct sockaddr_in* dst) {
    uint8_t hdr[28] = {0};
    memcpy(hdr, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    hdr[12] = 0x21;
    hdr[13] = 0x11;
    hdr[14] = 0x00;
    hdr[15] = 12;
    memcpy(&hdr[16], &src->sin_addr, 4);
    memcpy(&hdr[20], &dst->sin_addr, 4);
    memcpy(&hdr[24], &src->sin_port, 2);
    memcpy(&hdr[26], &dst->sin_port, 2);
    return send(fd, hdr, 28, 0) == 28 ? 0 : -1;
}

void* session_thread(void* arg) {
    session_t* s = (session_t*)arg;
    
    spf_lb_conn_start(s->rule, s->backend_idx);
    
    int flag = 1;
    setsockopt(s->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(s->target_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    spf_bucket_t bucket;
    spf_bucket_init(&bucket, s->rule->rate_bps ? s->rule->rate_bps : 100*1024*1024, 2.0);
    
    uint8_t buf[SPF_BUFFER_SIZE];
    fd_set fds;
    struct timeval tv;
    int maxfd = (s->client_fd > s->target_fd ? s->client_fd : s->target_fd) + 1;
    
    // Check for FD_SETSIZE overflow
    if (s->client_fd >= FD_SETSIZE || s->target_fd >= FD_SETSIZE) {
        spf_log(SPF_LOG_ERROR, "fd >= FD_SETSIZE, cannot use select");
        close(s->client_fd);
        close(s->target_fd);
        spf_lb_conn_end(s->rule, s->backend_idx);
        free(s);
        return NULL;
    }
    
    uint64_t bytes_in = 0, bytes_out = 0;
    
    while (!g_shutdown && g_state.running) {
        FD_ZERO(&fds);
        FD_SET(s->client_fd, &fds);
        FD_SET(s->target_fd, &fds);
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        
        int r = select(maxfd, &fds, NULL, NULL, &tv);
        if (r <= 0) break;
        
        if (FD_ISSET(s->client_fd, &fds)) {
            ssize_t n;
            if (s->client_ssl) {
                n = tls_read(s->client_ssl, buf, sizeof(buf));
                if (n == 0) continue; // WANT_READ/WRITE
            } else {
                n = recv(s->client_fd, buf, sizeof(buf), 0);
            }
            if (n < 0) break; // Error
            if (n == 0 && !s->client_ssl) break; // EOF (for tcp)
            
            if (forward_buffer(s, true, &bucket, buf, (size_t)n, &bytes_in) < 0) {
                break;
            }
        }
        
        if (FD_ISSET(s->target_fd, &fds)) {
            ssize_t n;
            if (s->target_ssl) {
                n = tls_read(s->target_ssl, buf, sizeof(buf));
                if (n == 0) continue; // WANT_READ/WRITE
            } else {
                n = recv(s->target_fd, buf, sizeof(buf), 0);
            }
            if (n < 0) break;
            if (n == 0 && !s->target_ssl) break;
            
            if (forward_buffer(s, false, &bucket, buf, (size_t)n, &bytes_out) < 0) {
                break;
            }
        }
    }
    
    if (s->client_ssl) { SSL_shutdown(s->client_ssl); SSL_free(s->client_ssl); }
    if (s->target_ssl) { SSL_shutdown(s->target_ssl); SSL_free(s->target_ssl); }
    close(s->client_fd);
    close(s->target_fd);
    
    spf_lb_conn_end(s->rule, s->backend_idx);
    
    pthread_mutex_lock(&g_state.stats_lock);
    g_state.total_bytes_in += bytes_in;
    g_state.total_bytes_out += bytes_out;
    if (s->conn_idx < SPF_MAX_CONNECTIONS) {
        g_state.connections[s->conn_idx].active = false;
        g_state.connections[s->conn_idx].bytes_in = bytes_in;
        g_state.connections[s->conn_idx].bytes_out = bytes_out;
    }
    if (g_state.active_conns > 0) {
        g_state.active_conns--;
    }
    pthread_mutex_unlock(&g_state.stats_lock);
    
    free(s);
    return NULL;
}

void* health_worker(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    while (!g_shutdown && g_state.running && rule->active) {
        for (int i = 0; i < rule->backend_count; i++) {
            spf_backend_t* b = &rule->backends[i];
            if (b->state == SPF_BACKEND_DRAIN) continue;
            
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b->port);
            inet_pton(AF_INET, b->host, &addr.sin_addr);
            
            int ok = connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0;
            close(fd);
            
            pthread_mutex_lock(&b->lock);
            if (ok) {
                if (b->state == SPF_BACKEND_DOWN) {
                    b->state = SPF_BACKEND_UP;
                    spf_event_push(&g_state, SPF_EVENT_HEALTH_UP, b->host, b->port, rule->id, "backend recovered");
                    spf_log(SPF_LOG_INFO, "backend %s:%u up", b->host, b->port);
                }
                b->health_fails = 0;
            } else {
                b->health_fails++;
                if (b->health_fails >= 3 && b->state == SPF_BACKEND_UP) {
                    b->state = SPF_BACKEND_DOWN;
                    spf_event_push(&g_state, SPF_EVENT_HEALTH_DOWN, b->host, b->port, rule->id, "health check failed");
                    spf_log(SPF_LOG_WARN, "backend %s:%u down", b->host, b->port);
                }
            }
            b->last_health_check = spf_time_sec();
            pthread_mutex_unlock(&b->lock);
        }
        
        sleep(SPF_HEALTH_INTERVAL_MS / 1000);
    }
    
    return NULL;
}

void* listener_thread(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(rule->listen_port);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "bind port %u failed: %s", rule->listen_port, strerror(errno));
        close(fd);
        return NULL;
    }
    
    listen(fd, 256);
    spf_log(SPF_LOG_INFO, "rule %u listening on :%u", rule->id, rule->listen_port);
    
    pthread_create(&rule->health_thread, NULL, health_worker, rule);
    pthread_detach(rule->health_thread);
    
    while (!g_shutdown && g_state.running && rule->active) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {1, 0};
        
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli_fd < 0) continue;
        
        // Fix DoS: Set timeouts immediately to prevent slow handshake hanging the listener
        struct timeval tv_cli = {10, 0}; // 10s timeout
        setsockopt(cli_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_cli, sizeof(tv_cli));
        setsockopt(cli_fd, SOL_SOCKET, SO_SNDTIMEO, &tv_cli, sizeof(tv_cli));
        
        char cli_ip[SPF_IP_MAX_LEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, sizeof(cli_ip));
        
        if (g_state.config.security.enabled) {
            if (spf_is_blocked(&g_state, cli_ip)) {
                close(cli_fd);
                continue;
            }
            
            if (!spf_register_attempt(&g_state, cli_ip)) {
                close(cli_fd);
                continue;
            }
        }
        
        if (g_state.config.security.enabled && spf_geoip_is_blocked(&g_state, cli_ip)) {
            spf_event_push(&g_state, SPF_EVENT_GEOBLOCK, cli_ip, ntohs(cli_addr.sin_port), rule->id, "geo blocked");
            close(cli_fd);
            continue;
        }
        
        int backend_idx = spf_lb_select_backend(rule, cli_ip);
        if (backend_idx < 0) {
            spf_log(SPF_LOG_WARN, "no healthy backend for rule %u", rule->id);
            close(cli_fd);
            continue;
        }
        
        spf_backend_t* b = &rule->backends[backend_idx];
        
        int tgt_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tgt_fd < 0) {
            close(cli_fd);
            continue;
        }
        
        struct sockaddr_in tgt_addr = {0};
        tgt_addr.sin_family = AF_INET;
        tgt_addr.sin_port = htons(b->port);
        inet_pton(AF_INET, b->host, &tgt_addr.sin_addr);
        
        struct timeval tv_conn = {5, 0};
        setsockopt(tgt_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_conn, sizeof(tv_conn));
        setsockopt(tgt_fd, SOL_SOCKET, SO_SNDTIMEO, &tv_conn, sizeof(tv_conn));
        
        if (connect(tgt_fd, (struct sockaddr*)&tgt_addr, sizeof(tgt_addr)) < 0) {
            close(tgt_fd);
            close(cli_fd);
            continue;
        }
        
        if (g_state.config.security.proxy_proto) {
            send_proxy_proto_v2(tgt_fd, &cli_addr, &tgt_addr);
        }
        
        pthread_mutex_lock(&g_state.stats_lock);
        int conn_idx = -1;
        for (int i = 0; i < SPF_MAX_CONNECTIONS; i++) {
            if (!g_state.connections[i].active) {
                conn_idx = i;
                break;
            }
        }
        if (conn_idx < 0) {
            pthread_mutex_unlock(&g_state.stats_lock);
            close(tgt_fd);
            close(cli_fd);
            continue;
        }
        
        g_state.connections[conn_idx].active = true;
        g_state.connections[conn_idx].id = g_state.next_conn_id++;
        strncpy(g_state.connections[conn_idx].client_ip, cli_ip, SPF_IP_MAX_LEN - 1);
        g_state.connections[conn_idx].client_port = ntohs(cli_addr.sin_port);
        g_state.connections[conn_idx].rule_id = rule->id;
        g_state.connections[conn_idx].backend_idx = backend_idx;
        g_state.connections[conn_idx].start_time = spf_time_sec();
        g_state.active_conns++;
        g_state.total_conns++;
        pthread_mutex_unlock(&g_state.stats_lock);
        
        spf_event_push(&g_state, SPF_EVENT_CONN_OPEN, cli_ip, ntohs(cli_addr.sin_port), rule->id, b->host);
        
        session_t* sess = (session_t*)calloc(1, sizeof(session_t));
        if (!sess) {
            spf_log(SPF_LOG_ERROR, "oom in listener");
            close(cli_fd);
            close(tgt_fd);
            release_conn_slot((uint32_t)conn_idx, true);
            continue;
        }
        
        sess->client_fd = cli_fd;
        sess->target_fd = tgt_fd;
        sess->client_addr = cli_addr;
        sess->rule = rule;
        sess->backend_idx = backend_idx;
        sess->conn_idx = conn_idx;
        
        // Setup TLS
        if (rule->tls_terminate) {
            sess->client_ssl = tls_accept(cli_fd);
            if (!sess->client_ssl) {
                spf_log(SPF_LOG_ERROR, "tls accept failed");
                close(cli_fd);
                close(tgt_fd);
                release_conn_slot((uint32_t)conn_idx, true);
                free(sess);
                continue;
            }
        }
        
        // Connect to target (TLS if needed)
        // ... (assume target logic is similar, kept simplistic here for brevity)
        
        pthread_t t;
        pthread_create(&t, NULL, session_thread, sess);
        pthread_detach(t);
    }
    
    close(fd);
    spf_log(SPF_LOG_INFO, "rule %u listener stopped", rule->id);
    return NULL;
}

static bool ctrl_send(int fd, SSL* ssl, const char* msg) {
    size_t len = strlen(msg);
    size_t off = 0;

    while (off < len) {
        ssize_t n;
        if (ssl) {
            n = tls_write(ssl, msg + off, len - off);
            if (n == 0) {
                usleep(1000);
                continue;
            }
        } else {
            n = send(fd, msg + off, len - off, 0);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                usleep(1000);
                continue;
            }
        }
        if (n <= 0) {
            return false;
        }
        off += (size_t)n;
    }

    return true;
}

static ssize_t ctrl_recv(int fd, SSL* ssl, char* buf, size_t len) {
    if (ssl) {
        return tls_read(ssl, buf, len);
    }
    return recv(fd, buf, len, 0);
}

void handle_ctrl(int fd, SSL* ssl) {
    char buf[SPF_BUFFER_SIZE];
    bool authed = g_state.config.admin.token[0] == '\0';
    
    if (!ctrl_send(fd, ssl, "SPF v" SPF_VERSION " Control\n")) return;
    if (!authed && !ctrl_send(fd, ssl, "AUTH required\n")) return;
    if (!ctrl_send(fd, ssl, "> ")) return;
    
    while (!g_shutdown) {
        ssize_t n = ctrl_recv(fd, ssl, buf, sizeof(buf) - 1);
        if (n < 0) break;
        if (n == 0) {
            if (ssl) {
                usleep(1000);
                continue;
            }
            break;
        }
        buf[n] = '\0';
        
        char* nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        char* cr = strchr(buf, '\r'); if (cr) *cr = '\0';
        if (strlen(buf) == 0) {
            if (!ctrl_send(fd, ssl, "> ")) break;
            continue;
        }
        
        char resp[SPF_RES_MAX_LEN] = {0};
        
        if (strncmp(buf, "QUIT", 4) == 0) {
            break;
        }
        else if (strncmp(buf, "AUTH ", 5) == 0) {
            if (spf_verify_token(&g_state, buf + 5)) {
                authed = true;
                snprintf(resp, sizeof(resp), "OK authenticated\n");
            } else {
                spf_event_push(&g_state, SPF_EVENT_AUTH_FAIL, "", 0, 0, "bad token");
                snprintf(resp, sizeof(resp), "ERR bad token\n");
            }
        }
        else if (!authed) {
            snprintf(resp, sizeof(resp), "ERR auth required\n");
        }
        else if (strncmp(buf, "HELP", 4) == 0) {
            snprintf(resp, sizeof(resp),
                "Commands:\n"
                "  AUTH <token>       - authenticate\n"
                "  STATUS             - system stats\n"
                "  RULES              - list rules\n"
                "  BACKENDS <id>      - show backends\n"
                "  ADD <port> <ip:port> [algo] - add rule\n"
                "  DEL <id>           - delete rule\n"
                "  PAUSE <id>         - stop accepting for rule\n"
                "  RESUME <id>        - resume accepting for rule\n"
                "  DRAIN <id> <idx> [sec] - drain backend index\n"
                "  SETWEIGHT <id> <idx> <w> - set backend weight\n"
                "  SETSTATE <id> <idx> <UP|DOWN|DRAIN> - set backend state\n"
                "  ADMINALLOWLIST     - list admin allowlist\n"
                "  ADMINALLOW <ip>    - add admin allowlist ip\n"
                "  ADMINDENY <ip>     - remove admin allowlist ip\n"
                "  ADMINSET <csv>     - replace admin allowlist\n"
                "  SAVE               - save runtime config\n"
                "  RELOAD             - reload config from disk\n"
                "  HEALTH <id>        - backend health snapshot\n"
                "  BLOCK <ip> [sec]   - block ip\n"
                "  UNBLOCK <ip>       - unblock ip\n"
                "  LOGS [n]           - recent events\n"
                "  METRICS            - prometheus\n"
                "  QUIT               - close\n");
        }
        else if (strncmp(buf, "STATUS", 6) == 0) {
            uint64_t up = spf_time_sec() - g_state.start_time;
            snprintf(resp, sizeof(resp),
                "--- SPF STATUS ---\n"
                "Version: %s\n"
                "Uptime: %luh %lum %lus\n"
                "Active Conns: %u\n"
                "Total Conns: %lu\n"
                "Bytes In: %lu\n"
                "Bytes Out: %lu\n"
                "Rules: %u\n"
                "Blocked IPs: %lu\n",
                SPF_VERSION,
                up/3600, (up%3600)/60, up%60,
                g_state.active_conns,
                g_state.total_conns,
                g_state.total_bytes_in,
                g_state.total_bytes_out,
                g_state.rule_count,
                g_state.blocked_count);
        }
        else if (strncmp(buf, "RULES", 5) == 0) {
            char* p = resp;
            p += snprintf(p, sizeof(resp), "--- RULES ---\n");
            for (int i = 0; i < SPF_MAX_RULES && p - resp < SPF_RES_MAX_LEN - 100; i++) {
                if (g_state.rules[i].active) {
                    spf_rule_t* r = &g_state.rules[i];
                    p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                        "ID:%u Port:%u Backends:%u LB:%d\n",
                        r->id, r->listen_port, r->backend_count, r->lb_algo);
                }
            }
        }
        else if (strncmp(buf, "BACKENDS ", 9) == 0) {
            uint32_t id;
            if (sscanf(buf + 9, "%u", &id) == 1) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                if (r) {
                    char* p = resp;
                    p += snprintf(p, sizeof(resp), "--- BACKENDS for %u ---\n", id);
                    for (int i = 0; i < r->backend_count; i++) {
                        spf_backend_t* b = &r->backends[i];
                        p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                            "%s:%u w=%u state=%s conns=%u\n",
                            b->host, b->port, b->weight,
                            b->state == SPF_BACKEND_UP ? "UP" : b->state == SPF_BACKEND_DOWN ? "DOWN" : "DRAIN",
                            b->active_conns);
                    }
                } else {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                }
            }
        }
        else if (strncmp(buf, "ADD ", 4) == 0) {
            uint16_t port = 0;
            char backend[256];
            char algo[16] = "rr";
            int parsed = sscanf(buf + 4, "%hu %255s %15s", &port, backend, algo);
            
            if (parsed >= 2 && port > 0) {
                spf_rule_t rule = {0};
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                uint32_t rule_rand = 0;
                memcpy(&rule_rand, rnd, sizeof(rule_rand));
                rule.id = rule_rand % 90000 + 10000;
                rule.listen_port = port;
                rule.enabled = true;
                rule.rate_bps = 100 * 1024 * 1024;
                
                if (strcmp(algo, "lc") == 0) rule.lb_algo = SPF_LB_LEASTCONN;
                else if (strcmp(algo, "ip") == 0) rule.lb_algo = SPF_LB_IPHASH;
                else if (strcmp(algo, "w") == 0) rule.lb_algo = SPF_LB_WEIGHTED;
                else rule.lb_algo = SPF_LB_ROUNDROBIN;
                
                bool bad_backend = false;
                char* saveptr = NULL;
                char* tok = strtok_r(backend, ",", &saveptr);
                while (tok && rule.backend_count < SPF_MAX_BACKENDS) {
                    spf_backend_t parsed_backend;
                    if (!parse_backend_token(tok, &parsed_backend)) {
                        bad_backend = true;
                        break;
                    }
                    rule.backends[rule.backend_count] = parsed_backend;
                    rule.backend_count++;
                    tok = strtok_r(NULL, ",", &saveptr);
                }
                
                if (bad_backend) {
                    snprintf(resp, sizeof(resp), "ERR bad backend format (use IPv4 host:port list)\n");
                }
                else if (rule.backend_count > 0) {
                    if (spf_add_rule(&g_state, &rule) == 0) {
                        spf_rule_t* added = spf_get_rule(&g_state, rule.id);
                        if (added) {
                            if (!added->listener_started) {
                                if (pthread_create(&added->listen_thread, NULL, listener_thread, added) == 0) {
                                    pthread_detach(added->listen_thread);
                                    added->listener_started = true;
                                } else {
                                    snprintf(resp, sizeof(resp), "ERR failed to start listener\n");
                                    goto send_resp;
                                }
                            }
                            snprintf(resp, sizeof(resp), "OK rule %u added\n", rule.id);
                        } else {
                            snprintf(resp, sizeof(resp), "ERR internal error\n");
                        }
                    } else {
                        snprintf(resp, sizeof(resp), "ERR failed to add rule\n");
                    }
                } else {
                    snprintf(resp, sizeof(resp), "ERR bad backend format\n");
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: ADD <port> <host:port,...> [rr|lc|ip|w]\n");
            }
        }
        else if (strncmp(buf, "DEL ", 4) == 0) {
            uint32_t id;
            if (sscanf(buf + 4, "%u", &id) == 1) {
                if (spf_del_rule(&g_state, id) == 0) {
                    snprintf(resp, sizeof(resp), "OK deleted\n");
                } else {
                    snprintf(resp, sizeof(resp), "ERR not found\n");
                }
            }
        }
        else if (strncmp(buf, "PAUSE ", 6) == 0) {
            uint32_t id;
            if (sscanf(buf + 6, "%u", &id) == 1) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else {
                    pthread_mutex_lock(&r->lock);
                    r->enabled = false;
                    pthread_mutex_unlock(&r->lock);
                    snprintf(resp, sizeof(resp), "OK paused %u\n", id);
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: PAUSE <id>\n");
            }
        }
        else if (strncmp(buf, "RESUME ", 7) == 0) {
            uint32_t id;
            if (sscanf(buf + 7, "%u", &id) == 1) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else {
                    pthread_mutex_lock(&r->lock);
                    r->enabled = true;
                    pthread_mutex_unlock(&r->lock);
                    snprintf(resp, sizeof(resp), "OK resumed %u\n", id);
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: RESUME <id>\n");
            }
        }
        else if (strncmp(buf, "DRAIN ", 6) == 0) {
            uint32_t id;
            char idx_str[16] = {0};
            uint32_t timeout = 30;
            int parsed = sscanf(buf + 6, "%u %15s %u", &id, idx_str, &timeout);
            if (parsed >= 2) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                uint8_t idx = 0;
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else if (parse_backend_index_strict(idx_str, &idx) != 0 || idx >= r->backend_count) {
                    snprintf(resp, sizeof(resp), "ERR invalid backend index\n");
                } else {
                    uint32_t active_left = 0;
                    int rc = rule_backend_drain(r, idx, timeout, &active_left);
                    if (rc == 0) {
                        snprintf(resp, sizeof(resp), "OK drained backend %u for rule %u\n", idx, id);
                    } else {
                        snprintf(resp, sizeof(resp), "OK draining backend %u rule %u active=%u\n", idx, id, active_left);
                    }
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: DRAIN <id> <idx> [seconds]\n");
            }
        }
        else if (strncmp(buf, "SETWEIGHT ", 10) == 0) {
            uint32_t id;
            char idx_str[16] = {0};
            uint16_t weight = 0;
            int parsed = sscanf(buf + 10, "%u %15s %hu", &id, idx_str, &weight);
            if (parsed == 3) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                uint8_t idx = 0;
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else if (parse_backend_index_strict(idx_str, &idx) != 0) {
                    snprintf(resp, sizeof(resp), "ERR invalid backend index\n");
                } else if (rule_backend_set_weight(r, idx, weight) != 0) {
                    snprintf(resp, sizeof(resp), "ERR failed to set weight\n");
                } else {
                    snprintf(resp, sizeof(resp), "OK weight set rule=%u backend=%u weight=%u\n", id, idx, weight);
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: SETWEIGHT <id> <idx> <weight>\n");
            }
        }
        else if (strncmp(buf, "SETSTATE ", 9) == 0) {
            uint32_t id;
            char idx_str[16] = {0};
            char state_str[16] = {0};
            int parsed = sscanf(buf + 9, "%u %15s %15s", &id, idx_str, state_str);
            if (parsed == 3) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                uint8_t idx = 0;
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else if (parse_backend_index_strict(idx_str, &idx) != 0) {
                    snprintf(resp, sizeof(resp), "ERR invalid backend index\n");
                } else {
                    spf_backend_state_t st;
                    if (strcmp(state_str, "UP") == 0) st = SPF_BACKEND_UP;
                    else if (strcmp(state_str, "DOWN") == 0) st = SPF_BACKEND_DOWN;
                    else if (strcmp(state_str, "DRAIN") == 0) st = SPF_BACKEND_DRAIN;
                    else {
                        snprintf(resp, sizeof(resp), "ERR state must be UP|DOWN|DRAIN\n");
                        goto send_resp;
                    }
                    if (rule_backend_set_state(r, idx, st) != 0) {
                        snprintf(resp, sizeof(resp), "ERR failed to set state\n");
                    } else {
                        snprintf(resp, sizeof(resp), "OK state set rule=%u backend=%u\n", id, idx);
                    }
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: SETSTATE <id> <idx> <UP|DOWN|DRAIN>\n");
            }
        }
        else if (strncmp(buf, "ADMINALLOWLIST", 14) == 0) {
            char* p = resp;
            pthread_mutex_lock(&g_state.lock);
            p += snprintf(p, SPF_RES_MAX_LEN - (p - resp), "--- ADMIN ALLOWLIST (%u) ---\n", g_state.config.admin.allowlist_count);
            for (uint8_t i = 0; i < g_state.config.admin.allowlist_count && p - resp < SPF_RES_MAX_LEN - 64; i++) {
                p += snprintf(p, SPF_RES_MAX_LEN - (p - resp), "%s\n", g_state.config.admin.allowlist[i]);
            }
            pthread_mutex_unlock(&g_state.lock);
        }
        else if (strncmp(buf, "ADMINALLOW ", 11) == 0) {
            char ip[SPF_IP_MAX_LEN] = {0};
            if (sscanf(buf + 11, "%45s", ip) == 1) {
                int rc = admin_allowlist_add(ip);
                if (rc == 0) snprintf(resp, sizeof(resp), "OK admin allow %s\n", ip);
                else if (rc == 1) snprintf(resp, sizeof(resp), "OK already allowed %s\n", ip);
                else if (rc == -2) snprintf(resp, sizeof(resp), "ERR allowlist full\n");
                else snprintf(resp, sizeof(resp), "ERR invalid ip\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: ADMINALLOW <ip>\n");
            }
        }
        else if (strncmp(buf, "ADMINDENY ", 10) == 0) {
            char ip[SPF_IP_MAX_LEN] = {0};
            if (sscanf(buf + 10, "%45s", ip) == 1) {
                int rc = admin_allowlist_del(ip);
                if (rc == 0) snprintf(resp, sizeof(resp), "OK admin deny %s\n", ip);
                else if (rc == 1) snprintf(resp, sizeof(resp), "ERR not present\n");
                else snprintf(resp, sizeof(resp), "ERR invalid ip\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: ADMINDENY <ip>\n");
            }
        }
        else if (strncmp(buf, "ADMINSET ", 9) == 0) {
            if (admin_allowlist_set_csv(buf + 9) == 0) {
                snprintf(resp, sizeof(resp), "OK admin allowlist replaced\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: ADMINSET <ip1,ip2,...>\n");
            }
        }
        else if (strncmp(buf, "SAVE", 4) == 0) {
            if (save_runtime_config() == 0) {
                snprintf(resp, sizeof(resp), "OK config saved\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR failed to save config\n");
            }
        }
        else if (strncmp(buf, "RELOAD", 6) == 0) {
            if (spf_reload_config(&g_state) == 0) {
                snprintf(resp, sizeof(resp), "OK config reloaded\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR failed to reload config\n");
            }
        }
        else if (strncmp(buf, "HEALTH ", 7) == 0) {
            uint32_t id;
            if (sscanf(buf + 7, "%u", &id) == 1) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                if (!r) {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                } else {
                    char* p = resp;
                    p += snprintf(p, SPF_RES_MAX_LEN - (p - resp), "--- HEALTH %u ---\n", id);
                    for (int i = 0; i < r->backend_count && p - resp < SPF_RES_MAX_LEN - 120; i++) {
                        spf_backend_t* b = &r->backends[i];
                        p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                            "idx=%d %s:%u state=%s conns=%u fails=%u last=%lu\n",
                            i,
                            b->host,
                            b->port,
                            b->state == SPF_BACKEND_UP ? "UP" : b->state == SPF_BACKEND_DOWN ? "DOWN" : "DRAIN",
                            b->active_conns,
                            b->health_fails,
                            b->last_health_check);
                    }
                }
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: HEALTH <id>\n");
            }
        }
        else if (strncmp(buf, "BLOCK ", 6) == 0) {
            char ip[64] = {0};
            uint64_t dur = 3600;
            int parsed = sscanf(buf + 6, "%63s %lu", ip, &dur);
            if (parsed >= 1 && ip[0] != '\0') {
                spf_block_ip(&g_state, ip, dur);
                snprintf(resp, sizeof(resp), "OK blocked %s for %lu sec\n", ip, dur);
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: BLOCK <ip> [seconds]\n");
            }
        }
        else if (strncmp(buf, "UNBLOCK ", 8) == 0) {
            char ip[64];
            if (sscanf(buf + 8, "%63s", ip) == 1) {
                spf_unblock_ip(&g_state, ip);
                snprintf(resp, sizeof(resp), "OK unblocked %s\n", ip);
            }
        }
        else if (strncmp(buf, "LOGS", 4) == 0) {
            uint32_t n = 10;
            sscanf(buf + 4, "%u", &n);
            if (n > 50) n = 50;
            
            spf_event_t events[50];
            uint32_t actual;
            spf_event_get_recent(&g_state, events, n, &actual);
            
            char* p = resp;
            p += snprintf(p, sizeof(resp), "--- LAST %u EVENTS ---\n", actual);
            for (uint32_t i = 0; i < actual && p - resp < SPF_RES_MAX_LEN - 150; i++) {
                p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                    "%lu type=%d %s:%u %s\n",
                    events[i].timestamp, events[i].type,
                    events[i].src_ip, events[i].src_port,
                    events[i].details);
            }
        }
        else if (strncmp(buf, "METRICS", 7) == 0) {
            int n = metrics_format(&g_state, resp, sizeof(resp) - 1);
            if (n < 0) {
                snprintf(resp, sizeof(resp), "ERR metrics formatting failed\n");
            } else {
                resp[sizeof(resp) - 1] = '\0';
            }
        }
        else {
            snprintf(resp, sizeof(resp), "ERR unknown cmd\n");
        }
send_resp:
        if (!ctrl_send(fd, ssl, resp)) break;
        if (!ctrl_send(fd, ssl, "> ")) break;
    }
}

void* ctrl_thread(void* arg) {
    (void)arg;
    
    g_ctrl_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(g_ctrl_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_state.config.admin.bind_addr, &addr.sin_addr);
    addr.sin_port = htons(g_state.config.admin.port);
    
    if (bind(g_ctrl_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "ctrl bind failed: %s", strerror(errno));
        return NULL;
    }
    
    listen(g_ctrl_fd, 5);
    spf_log(SPF_LOG_INFO, "ctrl listening on %s:%u", g_state.config.admin.bind_addr, g_state.config.admin.port);
    
    while (!g_shutdown && g_state.running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_ctrl_fd, &fds);
        struct timeval tv = {1, 0};
        
        if (select(g_ctrl_fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli = accept(g_ctrl_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli >= 0) {
            if (!is_admin_ip_allowed(&cli_addr)) {
                char ip[SPF_IP_MAX_LEN] = {0};
                inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
                spf_log(SPF_LOG_WARN, "admin connection denied by allowlist: %s", ip);
                close(cli);
                continue;
            }
            SSL* admin_ssl = NULL;
            if (g_state.config.admin.tls_enabled) {
                admin_ssl = tls_accept(cli);
                if (!admin_ssl) {
                    spf_log(SPF_LOG_WARN, "admin tls handshake failed");
                    close(cli);
                    continue;
                }
            }

            spf_log(SPF_LOG_INFO, "admin connected");
            handle_ctrl(cli, admin_ssl);
            spf_log(SPF_LOG_INFO, "admin disconnected");

            if (admin_ssl) {
                tls_close(admin_ssl);
            }
            close(cli);
        }
    }
    
    close(g_ctrl_fd);
    return NULL;
}

void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    umask(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main(int argc, char** argv) {
    const char* config_path = "spf.conf";
    char* bind_addr = NULL;
    char* token = NULL;
    char* ca = NULL;
    char* cert = NULL;
    char* key = NULL;
    int port = 0; // 0 means not set via CLI
    bool daemon_mode = false;
    
    static struct option opts[] = {
        {"config", required_argument, 0, 'C'},
        {"admin-bind", required_argument, 0, 'b'},
        {"admin-port", required_argument, 0, 'p'},
        {"token", required_argument, 0, 't'},
        {"admin-allow", required_argument, 0, 'a'},
        {"mtls", no_argument, 0, 'm'},
        {"ca", required_argument, 0, 'A'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    char* admin_allow = NULL;
    bool cli_mtls = false;
    bool cli_port_set = false;
    int c;
    while ((c = getopt_long(argc, argv, "C:b:p:t:a:mA:c:k:dh", opts, NULL)) != -1) {
        switch (c) {
            case 'C': config_path = optarg; break;
            case 'b': bind_addr = optarg; break;
            case 'p': {
                uint16_t parsed_port = 0;
                if (!parse_u16_strict(optarg, &parsed_port)) {
                    fprintf(stderr, "Invalid --admin-port: %s\n", optarg ? optarg : "(null)");
                    return 1;
                }
                port = (int)parsed_port;
                cli_port_set = true;
                break;
            }
            case 't': token = optarg; break;
            case 'a': admin_allow = optarg; break;
            case 'm': cli_mtls = true; break;
            case 'A': ca = optarg; break;
            case 'c': cert = optarg; break;
            case 'k': key = optarg; break;
            case 'd': daemon_mode = true; break;
            case 'h':
                printf("SPF v%s - Production Network Forwarder\n\n", SPF_VERSION);
                printf("Usage: %s [options]\n\n", argv[0]);
                printf("Options:\n");
                printf("  -C, --config <path>    Config file (default: spf.conf)\n");
                printf("  -b, --admin-bind <ip>  Bind address (default: 127.0.0.1)\n");
                printf("  -p, --admin-port <n>   Control port (default: 8081)\n");
                printf("  -t, --token <str>      Auth token (required for remote)\n");
                printf("  -a, --admin-allow <ip1,ip2> Admin allowlist\n");
                printf("  -m, --mtls             Require client TLS certificates\n");
                printf("  -A, --ca <path>        Client CA bundle for mTLS\n");
                printf("  -c, --cert <path>      TLS certificate\n");
                printf("  -k, --key <path>       TLS private key\n");
                printf("  -d, --daemon           Run as daemon\n");
                printf("  -h, --help             Show this help\n");
                return 0;
        }
    }
    
    if (daemon_mode) daemonize();
    
    spf_init(&g_state);
    
    // Load config first
    if (spf_load_config(&g_state, config_path) < 0) {
        // If default config fails, just warn (unless specific config was requested)
        if (strcmp(config_path, "spf.conf") != 0) {
            fprintf(stderr, "Error: cannot load config file %s\n", config_path);
            return 1;
        } else {
             // For default, maybe it doesn't exist yet, which is fine
        }
    }

    if (bind_addr) {
        strncpy(g_state.config.admin.bind_addr, bind_addr, SPF_IP_MAX_LEN - 1);
        g_state.config.admin.bind_addr[SPF_IP_MAX_LEN - 1] = '\0';
    }
    if (token) {
        strncpy(g_state.config.admin.token, token, SPF_TOKEN_MAX - 1);
        g_state.config.admin.token[SPF_TOKEN_MAX - 1] = '\0';
    }
    if (cert) {
        strncpy(g_state.config.admin.cert_path, cert, SPF_PATH_MAX - 1);
        g_state.config.admin.cert_path[SPF_PATH_MAX - 1] = '\0';
    }
    if (key) {
        strncpy(g_state.config.admin.key_path, key, SPF_PATH_MAX - 1);
        g_state.config.admin.key_path[SPF_PATH_MAX - 1] = '\0';
    }
    if (ca) {
        strncpy(g_state.config.admin.ca_path, ca, SPF_PATH_MAX - 1);
        g_state.config.admin.ca_path[SPF_PATH_MAX - 1] = '\0';
    }
    if (admin_allow) {
        if (admin_allowlist_set_csv(admin_allow) != 0) {
            fprintf(stderr, "Invalid --admin-allow list, must be comma-separated IPv4 addresses\n");
            return 1;
        }
    }
    if (cli_mtls) {
        g_state.config.admin.require_client_cert = true;
    }
    
    // Override port if set via CLI
    if (cli_port_set) {
        g_state.config.admin.port = port;
    } else if (g_state.config.admin.port == 0) {
        g_state.config.admin.port = SPF_CTRL_PORT_DEFAULT;
    }

    if (!is_loopback_bind(g_state.config.admin.bind_addr) && g_state.config.admin.token[0] == '\0') {
        fprintf(stderr, "Refusing to expose admin control on non-loopback without --token\n");
        return 1;
    }

    if (g_state.config.admin.port == SPF_METRICS_PORT_DEFAULT && g_state.config.metrics.enabled) {
        spf_log(SPF_LOG_WARN, "admin and metrics ports overlap on %u", g_state.config.admin.port);
    }
    
    const char* tls_cert = g_state.config.admin.cert_path[0] ? g_state.config.admin.cert_path : cert;
    const char* tls_key = g_state.config.admin.key_path[0] ? g_state.config.admin.key_path : key;
    if ((tls_cert && !tls_key) || (!tls_cert && tls_key)) {
        fprintf(stderr, "Both TLS cert and key are required together\n");
        return 1;
    }
    if ((g_state.config.admin.tls_enabled || g_state.config.admin.require_client_cert) && (!tls_cert || !tls_key)) {
        fprintf(stderr, "TLS-enabled admin control requires cert and key\n");
        return 1;
    }
    if (g_state.config.admin.tls_enabled || (tls_cert && tls_key)) {
        if (tls_init(tls_cert, tls_key) == 0) {
            g_state.config.admin.tls_enabled = true;
            spf_log(SPF_LOG_INFO, "tls enabled");
            if (g_state.config.admin.require_client_cert) {
                if (g_state.config.admin.ca_path[0]) {
                    if (tls_set_client_ca(g_state.config.admin.ca_path) != 0) {
                        fprintf(stderr, "Failed to load mTLS client CA bundle\n");
                        return 1;
                    }
                }
                if (tls_require_client_cert() != 0) {
                    fprintf(stderr, "Failed to enable mTLS\n");
                    return 1;
                }
                spf_log(SPF_LOG_INFO, "admin mTLS required");
            }
        } else {
            fprintf(stderr, "Failed to initialize TLS\n");
            return 1;
        }
    }

    if (g_state.config.admin.require_client_cert && !g_state.config.admin.tls_enabled) {
        fprintf(stderr, "mTLS requires TLS cert/key configuration\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    if (!daemon_mode) {
        printf("=== SPF v%s ===\n", SPF_VERSION);
        printf("Control: nc %s %d\n", g_state.config.admin.bind_addr, g_state.config.admin.port);
        if (token) printf("Token required for auth\n");
    }
    
    pthread_t ct;
    pthread_create(&ct, NULL, ctrl_thread, NULL);

    if (metrics_start(&g_state) != 0) {
        spf_log(SPF_LOG_ERROR, "metrics: failed to start worker");
    }

    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (!g_state.rules[i].active) {
            continue;
        }
        if (pthread_create(&g_state.rules[i].listen_thread, NULL, listener_thread, &g_state.rules[i]) != 0) {
            spf_log(SPF_LOG_ERROR, "failed to start listener for rule %u", g_state.rules[i].id);
        } else {
            pthread_detach(g_state.rules[i].listen_thread);
            g_state.rules[i].listener_started = true;
        }
    }
    
    while (!g_shutdown && g_state.running) {
        sleep(1);
    }
    
    spf_log(SPF_LOG_INFO, "shutting down...");
    g_state.running = false;
    
    if (g_ctrl_fd >= 0) close(g_ctrl_fd);
    
    pthread_join(ct, NULL);
    metrics_stop();
    tls_cleanup();
    spf_shutdown(&g_state);
    
    return 0;
}

#endif
