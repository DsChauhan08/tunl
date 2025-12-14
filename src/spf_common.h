#ifndef SPF_COMMON_H
#define SPF_COMMON_H

#include <stdint.h>
#include <stdbool.h>

#if defined(ESP32) || defined(ESP_PLATFORM)
    #define SPF_PLATFORM_ESP32
#elif defined(_WIN32) || defined(_WIN64)
    #define SPF_PLATFORM_WINDOWS
#elif defined(__linux__)
    #define SPF_PLATFORM_LINUX
#elif defined(__APPLE__)
    #define SPF_PLATFORM_MACOS
#else
    #define SPF_PLATFORM_GENERIC
#endif

// limits
#define SPF_MAX_CONNECTIONS 32
#define SPF_MAX_RULES 8
#define SPF_BUFFER_SIZE 2048
#define SPF_MAX_IP_TRACKERS 256

#define SPF_AUTH_TOKEN_SIZE 64
#define SPF_SCAN_THRESHOLD 5
#define SPF_SCAN_WINDOW_SEC 30
#define SPF_BLOCK_FIRST_SEC 600

typedef struct {
    uint16_t listen_port;
    char target_ip[46];
    uint16_t target_port;
    bool enabled;
    uint32_t max_connections;
    uint64_t rate_bps;
    uint8_t rule_id;
} spf_rule_t;


typedef struct {
   uint64_t conn_id;
    char client_ip[46];
    uint16_t client_port;
    uint16_t listen_port;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t start_time;
    bool active;
} spf_conn_stats_t;

typedef struct {
    char ip[46];
    uint32_t count;
    uint64_t first_timestamp;
    uint8_t strikes;
    uint64_t block_until;
    bool blocked;
} spf_tracker_t;

typedef struct {
    uint64_t rate;
    uint64_t capacity;
    double tokens;
    uint64_t last_refill;
} spf_token_bucket_t;


typedef struct {
    bool tls_enabled;
    char auth_token[SPF_AUTH_TOKEN_SIZE + 1];
    bool require_auth;
    char cert_path[256];
    char key_path[256];
} spf_security_t;

typedef struct {
    spf_rule_t rules[SPF_MAX_RULES];
    spf_conn_stats_t connections[SPF_MAX_CONNECTIONS];
    spf_tracker_t trackers[SPF_MAX_IP_TRACKERS];
    spf_security_t security;
    uint32_t rule_count;
    uint32_t active_connections;
    uint64_t next_conn_id;
    bool running;
} spf_state_t;


void spf_init(spf_state_t* state);
int spf_add_rule(spf_state_t* state, const spf_rule_t* rule);
bool spf_is_blocked(spf_state_t* state, const char* ip);
bool spf_register_attempt(spf_state_t* state, const char* ip);
void spf_token_bucket_init(spf_token_bucket_t* tb, uint64_t rate, double burst);
uint64_t spf_token_bucket_consume(spf_token_bucket_t* tb, uint64_t want);

#endif 
