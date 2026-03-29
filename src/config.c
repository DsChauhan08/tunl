#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

static char* trim(char* s);

static bool parse_u16_value(const char* s, uint16_t* out) {
    if (!s || !*s || !out) return false;
    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v == 0 || v > 65535UL) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

static bool parse_u32_value(const char* s, uint32_t* out) {
    if (!s || !*s || !out) return false;
    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > 0xFFFFFFFFUL) {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

static bool parse_u64_value(const char* s, uint64_t* out) {
    if (!s || !*s || !out) return false;
    char* end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static int parse_admin_allowlist(spf_admin_cfg_t* admin, const char* val) {
    if (!admin || !val) return -1;

    admin->allowlist_count = 0;
    char tmp[512];
    strncpy(tmp, val, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char* saveptr = NULL;
    char* tok = strtok_r(tmp, ",", &saveptr);
    while (tok && admin->allowlist_count < SPF_MAX_ADMIN_ALLOWLIST) {
        tok = trim(tok);
        if (*tok) {
            struct in_addr addr;
            if (inet_pton(AF_INET, tok, &addr) != 1) {
                spf_log(SPF_LOG_WARN, "config: invalid admin allowlist ip '%s'", tok);
                tok = strtok_r(NULL, ",", &saveptr);
                continue;
            }
            strncpy(admin->allowlist[admin->allowlist_count], tok, SPF_IP_MAX_LEN - 1);
            admin->allowlist[admin->allowlist_count][SPF_IP_MAX_LEN - 1] = '\0';
            admin->allowlist_count++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

static char* trim(char* s) {
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    if (len == 0) return s;
    char* e = s + len - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static int parse_backend(const char* str, spf_backend_t* b) {
    char host[SPF_IP_MAX_LEN];
    uint16_t port = 0;
    uint16_t weight = 1;
    
    if (sscanf(str, "%45[^:]:%hu:%hu", host, &port, &weight) >= 2 && port > 0) {
        strncpy(b->host, host, SPF_IP_MAX_LEN - 1);
        b->host[SPF_IP_MAX_LEN - 1] = '\0';
        b->port = port;
        b->weight = weight ? weight : 1;
        b->state = SPF_BACKEND_UP;
        return 0;
    }
    return -1;
}

int spf_load_config(spf_state_t* state, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        spf_log(SPF_LOG_ERROR, "config: cannot open %s", path);
        return -1;
    }
    
    strncpy(state->config.config_path, path, SPF_PATH_MAX - 1);
    state->config.config_path[SPF_PATH_MAX - 1] = '\0';
    
    char line[512];
    char section[32] = "";
    spf_rule_t* current_rule = NULL;
    
    while (fgets(line, sizeof(line), f)) {
        char* s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        
        if (*s == '[') {
            char* e = strchr(s, ']');
            if (e) {
                *e = '\0';
                strncpy(section, s + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }
        
        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = trim(s);
        char* val = trim(eq + 1);
        
        spf_log(SPF_LOG_DEBUG, "config: section=[%s] key=[%s] val=[%s]", section, key, val);
        
        if (strcmp(section, "admin") == 0) {
            if (strcmp(key, "bind") == 0) {
                strncpy(state->config.admin.bind_addr, val, SPF_IP_MAX_LEN - 1);
                state->config.admin.bind_addr[SPF_IP_MAX_LEN - 1] = '\0';
            } else if (strcmp(key, "port") == 0) {
                uint16_t p = 0;
                if (parse_u16_value(val, &p)) {
                    state->config.admin.port = p;
                } else {
                    spf_log(SPF_LOG_WARN, "config: invalid admin.port '%s'", val);
                }
            } else if (strcmp(key, "token") == 0) {
                strncpy(state->config.admin.token, val, SPF_TOKEN_MAX - 1);
                state->config.admin.token[SPF_TOKEN_MAX - 1] = '\0';
            } else if (strcmp(key, "readonly_token") == 0) {
                strncpy(state->config.admin.readonly_token, val, SPF_TOKEN_MAX - 1);
                state->config.admin.readonly_token[SPF_TOKEN_MAX - 1] = '\0';
            } else if (strcmp(key, "cert") == 0) {
                strncpy(state->config.admin.cert_path, val, SPF_PATH_MAX - 1);
                state->config.admin.cert_path[SPF_PATH_MAX - 1] = '\0';
            } else if (strcmp(key, "key") == 0) {
                strncpy(state->config.admin.key_path, val, SPF_PATH_MAX - 1);
                state->config.admin.key_path[SPF_PATH_MAX - 1] = '\0';
            } else if (strcmp(key, "ca") == 0) {
                strncpy(state->config.admin.ca_path, val, SPF_PATH_MAX - 1);
                state->config.admin.ca_path[SPF_PATH_MAX - 1] = '\0';
            } else if (strcmp(key, "tls") == 0) {
                state->config.admin.tls_enabled = strcmp(val, "true") == 0;
            } else if (strcmp(key, "mtls") == 0) {
                state->config.admin.require_client_cert = strcmp(val, "true") == 0;
            } else if (strcmp(key, "readonly") == 0) {
                state->config.admin.read_only_mode = strcmp(val, "true") == 0;
            } else if (strcmp(key, "allowlist") == 0) {
                parse_admin_allowlist(&state->config.admin, val);
            } else if (strcmp(key, "max_cmds_per_min") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.max_cmds_per_min = v;
                }
            } else if (strcmp(key, "auth_fail_threshold") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.auth_fail_threshold = v;
                }
            } else if (strcmp(key, "auth_lockout_sec") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.auth_lockout_sec = v;
                }
            } else if (strcmp(key, "idle_timeout_sec") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.idle_timeout_sec = v;
                }
            } else if (strcmp(key, "service_token_max_ttl_sec") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.service_token_max_ttl_sec = v;
                }
            } else if (strcmp(key, "temp_grant_max_ttl_sec") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.admin.temp_grant_max_ttl_sec = v;
                }
            } else if (strcmp(key, "audit_log") == 0) {
                strncpy(state->config.admin.audit_log_path, val, SPF_PATH_MAX - 1);
                state->config.admin.audit_log_path[SPF_PATH_MAX - 1] = '\0';
            }
        }
        else if (strcmp(section, "security") == 0) {
            if (strcmp(key, "enabled") == 0) {
                state->config.security.enabled = strcmp(val, "true") == 0;
            } else if (strcmp(key, "rate_per_ip") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.security.rate_per_ip = v;
                }
            } else if (strcmp(key, "rate_global") == 0) {
                uint32_t v = 0;
                if (parse_u32_value(val, &v)) {
                    state->config.security.rate_global = v;
                }
            } else if (strcmp(key, "webhook") == 0) {
                strncpy(state->config.security.webhook_url, val, sizeof(state->config.security.webhook_url) - 1);
                state->config.security.webhook_url[sizeof(state->config.security.webhook_url) - 1] = '\0';
            } else if (strcmp(key, "ddos") == 0) {
                state->config.security.ddos_protection = strcmp(val, "true") == 0;
            } else if (strcmp(key, "proxy_proto") == 0) {
                state->config.security.proxy_proto = strcmp(val, "true") == 0;
            }
        }
        else if (strcmp(section, "metrics") == 0) {
            if (strcmp(key, "enabled") == 0) {
                state->config.metrics.enabled = strcmp(val, "true") == 0;
            } else if (strcmp(key, "port") == 0) {
                uint16_t p = 0;
                if (parse_u16_value(val, &p)) {
                    state->config.metrics.port = p;
                }
            }
        }
        else if (strncmp(section, "rule.", 5) == 0) {
            if (strcmp(key, "listen") == 0) {
                spf_rule_t rule = {0};
                uint16_t listen_port = 0;
                if (!parse_u16_value(val, &listen_port)) {
                    spf_log(SPF_LOG_WARN, "config: invalid rule listen port '%s'", val);
                    current_rule = NULL;
                    continue;
                }
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                uint32_t r;
                memcpy(&r, rnd, 4);
                rule.id = r % 90000 + 10000;
                rule.listen_port = listen_port;
                rule.enabled = true;
                rule.active = true;
                rule.listener_started = false;
                rule.rate_bps = 100 * 1024 * 1024;
                
                pthread_mutex_lock(&state->lock);
                for (int i = 0; i < SPF_MAX_RULES; i++) {
                    if (!state->rules[i].active) {
                        // Safe copy avoiding mutex overwrite (similar to core.c fix)
                        if (state->rules[i].active || state->rules[i].id != 0) {
                            pthread_mutex_destroy(&state->rules[i].lock);
                        }
                        memcpy(&state->rules[i], &rule, sizeof(rule));
                        pthread_mutex_init(&state->rules[i].lock, NULL);
                        current_rule = &state->rules[i];
                        state->rule_count++;
                        break;
                    }
                }
                pthread_mutex_unlock(&state->lock);
            }
            else if (strcmp(key, "backend") == 0 && current_rule) {
                if (current_rule->backend_count < SPF_MAX_BACKENDS) {
                    parse_backend(val, &current_rule->backends[current_rule->backend_count]);
                    pthread_mutex_init(&current_rule->backends[current_rule->backend_count].lock, NULL);
                    current_rule->backend_count++;
                }
            }
            else if (strcmp(key, "backend_tls") == 0 && current_rule && current_rule->backend_count > 0) {
                current_rule->backends[current_rule->backend_count - 1].tls_enabled = strcmp(val, "true") == 0;
            }
            else if (strcmp(key, "backend_tls_verify") == 0 && current_rule && current_rule->backend_count > 0) {
                current_rule->backends[current_rule->backend_count - 1].tls_verify = strcmp(val, "true") == 0;
            }
            else if (strcmp(key, "backend_tls_sni") == 0 && current_rule && current_rule->backend_count > 0) {
                spf_backend_t* b = &current_rule->backends[current_rule->backend_count - 1];
                strncpy(b->tls_server_name, val, sizeof(b->tls_server_name) - 1);
                b->tls_server_name[sizeof(b->tls_server_name) - 1] = '\0';
            }
            else if (strcmp(key, "backend_tls_ca") == 0 && current_rule && current_rule->backend_count > 0) {
                spf_backend_t* b = &current_rule->backends[current_rule->backend_count - 1];
                strncpy(b->tls_ca_path, val, sizeof(b->tls_ca_path) - 1);
                b->tls_ca_path[sizeof(b->tls_ca_path) - 1] = '\0';
            }
            else if (strcmp(key, "backend_tls_pin_sha256") == 0 && current_rule && current_rule->backend_count > 0) {
                spf_backend_t* b = &current_rule->backends[current_rule->backend_count - 1];
                strncpy(b->tls_pin_sha256, val, sizeof(b->tls_pin_sha256) - 1);
                b->tls_pin_sha256[sizeof(b->tls_pin_sha256) - 1] = '\0';
                b->tls_pin_enabled = true;
            }
            else if (strcmp(key, "lb") == 0 && current_rule) {
                if (strcmp(val, "rr") == 0) current_rule->lb_algo = SPF_LB_ROUNDROBIN;
                else if (strcmp(val, "lc") == 0) current_rule->lb_algo = SPF_LB_LEASTCONN;
                else if (strcmp(val, "ip") == 0) current_rule->lb_algo = SPF_LB_IPHASH;
                else if (strcmp(val, "w") == 0) current_rule->lb_algo = SPF_LB_WEIGHTED;
            }
            else if (strcmp(key, "tls") == 0 && current_rule) {
                current_rule->tls_terminate = strcmp(val, "true") == 0;
            }
            else if (strcmp(key, "rate") == 0 && current_rule) {
                uint64_t rate = 0;
                if (parse_u64_value(val, &rate)) {
                    current_rule->rate_bps = rate;
                }
            }
        }
    }
    
    fclose(f);
    spf_log(SPF_LOG_INFO, "config: loaded %s (%u rules)", path, state->rule_count);
    return 0;
}

int spf_reload_config(spf_state_t* state) {
    if (state->config.config_path[0] == '\0') {
        return -1;
    }
    
    spf_log(SPF_LOG_INFO, "config: reloading...");
    return spf_load_config(state, state->config.config_path);
}

int config_save(spf_state_t* state, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    
    fprintf(f, "[admin]\n");
    fprintf(f, "bind = %s\n", state->config.admin.bind_addr);
    fprintf(f, "port = %u\n", state->config.admin.port);
    if (state->config.admin.token[0]) {
        fprintf(f, "token = %s\n", state->config.admin.token);
    }
    if (state->config.admin.readonly_token[0]) {
        fprintf(f, "readonly_token = %s\n", state->config.admin.readonly_token);
    }
    fprintf(f, "tls = %s\n", state->config.admin.tls_enabled ? "true" : "false");
    fprintf(f, "mtls = %s\n", state->config.admin.require_client_cert ? "true" : "false");
    fprintf(f, "readonly = %s\n", state->config.admin.read_only_mode ? "true" : "false");
    fprintf(f, "max_cmds_per_min = %u\n", state->config.admin.max_cmds_per_min);
    fprintf(f, "auth_fail_threshold = %u\n", state->config.admin.auth_fail_threshold);
    fprintf(f, "auth_lockout_sec = %u\n", state->config.admin.auth_lockout_sec);
    fprintf(f, "idle_timeout_sec = %u\n", state->config.admin.idle_timeout_sec);
    fprintf(f, "service_token_max_ttl_sec = %u\n", state->config.admin.service_token_max_ttl_sec);
    fprintf(f, "temp_grant_max_ttl_sec = %u\n", state->config.admin.temp_grant_max_ttl_sec);
    if (state->config.admin.audit_log_path[0]) {
        fprintf(f, "audit_log = %s\n", state->config.admin.audit_log_path);
    }
    if (state->config.admin.ca_path[0]) {
        fprintf(f, "ca = %s\n", state->config.admin.ca_path);
    }
    if (state->config.admin.allowlist_count > 0) {
        fprintf(f, "allowlist = ");
        for (uint8_t i = 0; i < state->config.admin.allowlist_count; i++) {
            fprintf(f, "%s%s", i ? "," : "", state->config.admin.allowlist[i]);
        }
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
    
    fprintf(f, "[security]\n");
    fprintf(f, "enabled = %s\n", state->config.security.enabled ? "true" : "false");
    fprintf(f, "proxy_proto = %s\n", state->config.security.proxy_proto ? "true" : "false");
    fprintf(f, "\n");
    
    fprintf(f, "[metrics]\n");
    fprintf(f, "enabled = %s\n", state->config.metrics.enabled ? "true" : "false");
    fprintf(f, "port = %u\n", state->config.metrics.port);
    fprintf(f, "\n");
    
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active) {
            spf_rule_t* r = &state->rules[i];
            fprintf(f, "[rule.%u]\n", r->id);
            fprintf(f, "listen = %u\n", r->listen_port);
            
            const char* lb = "rr";
            if (r->lb_algo == SPF_LB_LEASTCONN) lb = "lc";
            else if (r->lb_algo == SPF_LB_IPHASH) lb = "ip";
            else if (r->lb_algo == SPF_LB_WEIGHTED) lb = "w";
            fprintf(f, "lb = %s\n", lb);
            
            for (int j = 0; j < r->backend_count; j++) {
                fprintf(f, "backend = %s:%u:%u\n", 
                    r->backends[j].host, r->backends[j].port, r->backends[j].weight);
                if (r->backends[j].tls_enabled) {
                    fprintf(f, "backend_tls = true\n");
                }
                if (r->backends[j].tls_verify) {
                    fprintf(f, "backend_tls_verify = true\n");
                }
                if (r->backends[j].tls_server_name[0]) {
                    fprintf(f, "backend_tls_sni = %s\n", r->backends[j].tls_server_name);
                }
                if (r->backends[j].tls_ca_path[0]) {
                    fprintf(f, "backend_tls_ca = %s\n", r->backends[j].tls_ca_path);
                }
                if (r->backends[j].tls_pin_enabled && r->backends[j].tls_pin_sha256[0]) {
                    fprintf(f, "backend_tls_pin_sha256 = %s\n", r->backends[j].tls_pin_sha256);
                }
            }
            fprintf(f, "\n");
        }
    }
    
    fclose(f);
    spf_log(SPF_LOG_INFO, "config: saved to %s", path);
    return 0;
}

void config_dump(spf_state_t* state) {
    spf_log(SPF_LOG_INFO, "--- CONFIG ---");
    spf_log(SPF_LOG_INFO, "admin.bind = %s", state->config.admin.bind_addr);
    spf_log(SPF_LOG_INFO, "admin.port = %u", state->config.admin.port);
    spf_log(SPF_LOG_INFO, "rules = %u", state->rule_count);
}
