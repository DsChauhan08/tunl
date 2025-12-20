#include "common.h"
#include <string.h>
#include <limits.h>

static int lb_round_robin(spf_rule_t* rule);
static int lb_least_conn(spf_rule_t* rule);
static int lb_ip_hash(spf_rule_t* rule, const char* ip);
static int lb_weighted(spf_rule_t* rule);
static int lb_random(spf_rule_t* rule);
int lb_select(spf_rule_t* rule, const char* client_ip) {
    pthread_mutex_lock(&rule->lock);
    
    if (rule->backend_count == 0) {
        pthread_mutex_unlock(&rule->lock);
        return -1;
    }
    
    int selected = -1;
    
    switch (rule->lb_algo) {
        case SPF_LB_ROUNDROBIN:
            selected = lb_round_robin(rule);
            break;
        case SPF_LB_LEASTCONN:
            selected = lb_least_conn(rule);
            break;
        case SPF_LB_IPHASH:
            selected = lb_ip_hash(rule, client_ip);
            break;
        case SPF_LB_WEIGHTED:
            selected = lb_weighted(rule);
            break;
        case SPF_LB_RANDOM:
            selected = lb_random(rule);
            break;
    }
    
    pthread_mutex_unlock(&rule->lock);
    return selected;
}

static int lb_round_robin(spf_rule_t* rule) {
    for (int tries = 0; tries < rule->backend_count; tries++) {
        int idx = rule->rr_index % rule->backend_count;
        rule->rr_index++;
        if (rule->backends[idx].state == SPF_BACKEND_UP) {
            return idx;
        }
    }
    return -1;
}

static int lb_least_conn(spf_rule_t* rule) {
    int selected = -1;
    uint32_t min_conns = UINT32_MAX;
    
    for (int i = 0; i < rule->backend_count; i++) {
        if (rule->backends[i].state == SPF_BACKEND_UP &&
            rule->backends[i].active_conns < min_conns) {
            min_conns = rule->backends[i].active_conns;
            selected = i;
        }
    }
    return selected;
}

static int lb_ip_hash(spf_rule_t* rule, const char* ip) {
    uint32_t h = spf_hash_ip(ip);
    int start = h % rule->backend_count;
    
    for (int i = 0; i < rule->backend_count; i++) {
        int idx = (start + i) % rule->backend_count;
        if (rule->backends[idx].state == SPF_BACKEND_UP) {
            return idx;
        }
    }
    return -1;
}

static int lb_weighted(spf_rule_t* rule) {
    uint32_t total = 0;
    for (int i = 0; i < rule->backend_count; i++) {
        if (rule->backends[i].state == SPF_BACKEND_UP) {
            total += rule->backends[i].weight;
        }
    }
    
    if (total == 0) return -1;
    
    uint8_t rnd[4];
    spf_random_bytes(rnd, 4);
    uint32_t r = (*(uint32_t*)rnd) % total;
    
    uint32_t acc = 0;
    for (int i = 0; i < rule->backend_count; i++) {
        if (rule->backends[i].state == SPF_BACKEND_UP) {
            acc += rule->backends[i].weight;
            if (r < acc) {
                return i;
            }
        }
    }
    return -1;
}

static int lb_random(spf_rule_t* rule) {
    int up_count = 0;
    int up_idx[SPF_MAX_BACKENDS];
    
    for (int i = 0; i < rule->backend_count; i++) {
        if (rule->backends[i].state == SPF_BACKEND_UP) {
            up_idx[up_count++] = i;
        }
    }
    
    if (up_count == 0) return -1;
    
    uint8_t rnd;
    spf_random_bytes(&rnd, 1);
    return up_idx[rnd % up_count];
}

void lb_conn_start(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].active_conns++;
    rule->backends[idx].total_conns++;
    pthread_mutex_unlock(&rule->backends[idx].lock);
}

void lb_conn_end(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    if (rule->backends[idx].active_conns > 0) {
        rule->backends[idx].active_conns--;
    }
    pthread_mutex_unlock(&rule->backends[idx].lock);
}

void lb_set_weight(spf_rule_t* rule, uint8_t idx, uint16_t weight) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].weight = weight;
    pthread_mutex_unlock(&rule->backends[idx].lock);
}

void lb_drain(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].state = SPF_BACKEND_DRAIN;
    pthread_mutex_unlock(&rule->backends[idx].lock);
    spf_log(SPF_LOG_INFO, "lb: backend %s:%u draining", 
            rule->backends[idx].host, rule->backends[idx].port);
}

int lb_add_backend(spf_rule_t* rule, const char* host, uint16_t port, uint16_t weight) {
    pthread_mutex_lock(&rule->lock);
    
    if (rule->backend_count >= SPF_MAX_BACKENDS) {
        pthread_mutex_unlock(&rule->lock);
        return -1;
    }
    
    int idx = rule->backend_count;
    strncpy(rule->backends[idx].host, host, SPF_IP_MAX_LEN - 1);
    rule->backends[idx].port = port;
    rule->backends[idx].weight = weight ? weight : 1;
    rule->backends[idx].state = SPF_BACKEND_UP;
    rule->backends[idx].active_conns = 0;
    pthread_mutex_init(&rule->backends[idx].lock, NULL);
    rule->backend_count++;
    
    pthread_mutex_unlock(&rule->lock);
    spf_log(SPF_LOG_INFO, "lb: added backend %s:%u weight=%u", host, port, weight);
    return idx;
}

// Dead code: implementation unsafe (mutex copy) and unused
/*
int lb_remove_backend(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return -1;
    
    pthread_mutex_lock(&rule->lock);
    
    for (int i = idx; i < rule->backend_count - 1; i++) {
        rule->backends[i] = rule->backends[i + 1];
    }
    rule->backend_count--;
    
    pthread_mutex_unlock(&rule->lock);
    return 0;
}
*/

int lb_get_healthy_count(spf_rule_t* rule) {
    int count = 0;
    pthread_mutex_lock(&rule->lock);
    for (int i = 0; i < rule->backend_count; i++) {
        if (rule->backends[i].state == SPF_BACKEND_UP) {
            count++;
        }
    }
    pthread_mutex_unlock(&rule->lock);
    return count;
}
