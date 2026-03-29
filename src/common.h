#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

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

#define SPF_VERSION "2.0.0"

#define SPF_MAX_CONNECTIONS 4096
#define SPF_MAX_RULES 128
#define SPF_MAX_BACKENDS 16
#define SPF_MAX_IP_TRACKERS 8192
#define SPF_MAX_EVENTS 4096
#define SPF_MAX_BLOCKLIST 65536

#define SPF_BUFFER_SIZE 8192
#define SPF_CMD_MAX_LEN 512
#define SPF_RES_MAX_LEN 4096
#define SPF_IP_MAX_LEN 46
#define SPF_PATH_MAX 512
#define SPF_TOKEN_MAX 128
#define SPF_MAX_ADMIN_ALLOWLIST 32
#define SPF_MAX_ADMIN_TRACKERS 256
#define SPF_MAX_STAGED_CHANGES 64
#define SPF_MAX_SERVICE_TOKENS 128
#define SPF_MAX_TEMP_ADMIN_GRANTS 128

#define SPF_CTRL_PORT_DEFAULT 8081
#define SPF_METRICS_PORT_DEFAULT 9100

#define SPF_SCAN_THRESHOLD 10
#define SPF_SCAN_WINDOW_SEC 30
#define SPF_BLOCK_FIRST_SEC 600
#define SPF_BLOCK_SECOND_SEC 3600
#define SPF_BLOCK_PERMA_SEC 86400

#define SPF_HEALTH_INTERVAL_MS 5000
#define SPF_HEALTH_TIMEOUT_MS 2000

typedef enum {
    SPF_LB_ROUNDROBIN = 0,
    SPF_LB_LEASTCONN,
    SPF_LB_IPHASH,
    SPF_LB_WEIGHTED,
    SPF_LB_RANDOM
} spf_lb_algo_t;

typedef enum {
    SPF_BACKEND_UP = 0,
    SPF_BACKEND_DOWN,
    SPF_BACKEND_DRAIN
} spf_backend_state_t;

typedef enum {
    SPF_EVENT_CONN_OPEN = 0,
    SPF_EVENT_CONN_CLOSE,
    SPF_EVENT_AUTH_FAIL,
    SPF_EVENT_BLOCKED,
    SPF_EVENT_RATE_LIMITED,
    SPF_EVENT_HEALTH_DOWN,
    SPF_EVENT_HEALTH_UP,
    SPF_EVENT_GEOBLOCK,
    SPF_EVENT_THREAT_MATCH,
    SPF_EVENT_ANOMALY,
    SPF_EVENT_DDOS,
    SPF_EVENT_ADMIN_LOCKOUT,
    SPF_EVENT_ADMIN_RATE_LIMIT
} spf_event_type_t;

typedef enum {
    SPF_LOG_DEBUG = 0,
    SPF_LOG_INFO,
    SPF_LOG_WARN,
    SPF_LOG_ERROR,
    SPF_LOG_SECURITY
} spf_log_level_t;

typedef struct {
    char host[SPF_IP_MAX_LEN];
    uint16_t port;
    uint16_t weight;
    spf_backend_state_t state;
    uint32_t active_conns;
    uint64_t total_conns;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t last_health_check;
    uint8_t health_fails;
    bool tls_enabled;
    bool tls_verify;
    bool tls_pin_enabled;
    char tls_server_name[SPF_IP_MAX_LEN];
    char tls_ca_path[SPF_PATH_MAX];
    char tls_pin_sha256[65];
    pthread_mutex_t lock;
} spf_backend_t;

typedef struct {
    uint32_t id;
    char name[64];
    uint16_t listen_port;
    bool enabled;
    bool active;
    bool tls_terminate;
    spf_lb_algo_t lb_algo;
    spf_backend_t backends[SPF_MAX_BACKENDS];
    uint8_t backend_count;
    uint32_t rr_index;
    uint64_t rate_bps;
    uint32_t max_conns;
    pthread_t listen_thread;
    pthread_t health_thread;
    bool listener_started;
    pthread_mutex_t lock;
} spf_rule_t;

typedef struct {
    uint64_t id;
    char client_ip[SPF_IP_MAX_LEN];
    uint16_t client_port;
    uint32_t rule_id;
    uint8_t backend_idx;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t start_time;
    bool active;
    bool proxy_proto_sent;
} spf_conn_t;

typedef struct {
    char ip[SPF_IP_MAX_LEN];
    uint32_t count;
    uint64_t first_ts;
    uint64_t last_ts;
    uint8_t strikes;
    uint64_t block_until;
    bool blocked;
    uint64_t bytes_total;
    uint32_t conns_total;
} spf_tracker_t;

typedef struct {
    uint64_t rate;
    uint64_t capacity;
    double tokens;
    uint64_t last_refill;
} spf_bucket_t;

typedef struct {
    spf_event_type_t type;
    uint64_t timestamp;
    char src_ip[SPF_IP_MAX_LEN];
    uint16_t src_port;
    uint32_t rule_id;
    char details[256];
} spf_event_t;

typedef struct {
    char bind_addr[SPF_IP_MAX_LEN];
    uint16_t port;
    char token[SPF_TOKEN_MAX];
    char readonly_token[SPF_TOKEN_MAX];
    bool tls_enabled;
    bool require_client_cert;
    bool read_only_mode;
    char cert_path[SPF_PATH_MAX];
    char key_path[SPF_PATH_MAX];
    char ca_path[SPF_PATH_MAX];
    char allowlist[SPF_MAX_ADMIN_ALLOWLIST][SPF_IP_MAX_LEN];
    uint8_t allowlist_count;
    uint32_t max_cmds_per_min;
    uint32_t auth_fail_threshold;
    uint32_t auth_lockout_sec;
    uint32_t idle_timeout_sec;
    uint32_t service_token_max_ttl_sec;
    uint32_t temp_grant_max_ttl_sec;
    char audit_log_path[SPF_PATH_MAX];
} spf_admin_cfg_t;

typedef struct {
    char key[64];
    char value[256];
} spf_staged_change_t;

typedef struct {
    uint32_t id;
    char label[64];
    char token[SPF_TOKEN_MAX];
    bool read_only;
    uint32_t max_uses;
    uint32_t uses;
    uint64_t created_ts;
    uint64_t expires_at;
    uint64_t last_used_ts;
    char last_used_ip[SPF_IP_MAX_LEN];
    bool active;
} spf_service_token_t;

typedef struct {
    char ip[SPF_IP_MAX_LEN];
    uint64_t created_ts;
    uint64_t expires_at;
    bool active;
} spf_temp_admin_grant_t;

typedef struct {
    bool enabled;
    char countries_block[64][3];
    uint8_t country_count;
    char blocklist_urls[8][256];
    uint8_t blocklist_count;
    uint32_t rate_per_ip;
    uint32_t rate_global;
    char webhook_url[256];
    bool ddos_protection;
    bool proxy_proto;
    bool anomaly_detection;
} spf_security_cfg_t;

typedef struct {
    bool enabled;
    uint16_t port;
} spf_metrics_cfg_t;

typedef struct {
    spf_admin_cfg_t admin;
    spf_security_cfg_t security;
    spf_metrics_cfg_t metrics;
    char config_path[SPF_PATH_MAX];
    bool daemon_mode;
    spf_log_level_t log_level;
} spf_config_t;

typedef struct {
    uint32_t* ips;
    uint32_t count;
    uint32_t capacity;
    pthread_rwlock_t lock;
} spf_blocklist_t;

typedef struct {
    spf_event_t events[SPF_MAX_EVENTS];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    pthread_mutex_t lock;
} spf_event_log_t;

typedef struct {
    spf_rule_t rules[SPF_MAX_RULES];
    spf_conn_t connections[SPF_MAX_CONNECTIONS];
    spf_tracker_t trackers[SPF_MAX_IP_TRACKERS];
    spf_blocklist_t blocklist;
    spf_event_log_t events;
    spf_config_t config;
    uint32_t rule_count;
    uint32_t active_conns;
    uint64_t next_conn_id;
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;
    uint64_t total_conns;
    uint64_t blocked_count;
    uint64_t admin_auth_failures;
    uint64_t admin_lockouts;
    uint64_t admin_cmd_rate_limited;
    uint64_t admin_service_token_auth_success;
    uint64_t admin_service_token_auth_fail;
    uint64_t admin_temp_grants_created;
    spf_staged_change_t staged_changes[SPF_MAX_STAGED_CHANGES];
    uint32_t staged_change_count;
    spf_service_token_t service_tokens[SPF_MAX_SERVICE_TOKENS];
    uint32_t next_service_token_id;
    spf_temp_admin_grant_t temp_admin_grants[SPF_MAX_TEMP_ADMIN_GRANTS];
    spf_admin_cfg_t last_admin_snapshot;
    bool has_admin_snapshot;
    char audit_prev_hash[65];
    uint64_t audit_seq;
    uint64_t start_time;
    volatile bool running;
    bool authenticated;
    pthread_mutex_t lock;
    pthread_mutex_t stats_lock;
    pthread_mutex_t audit_lock;
} spf_state_t;

typedef enum {
    SPF_CTRL_CMD_UNKNOWN = 0,
    SPF_CTRL_CMD_AUTH,
    SPF_CTRL_CMD_STATUS,
    SPF_CTRL_CMD_RULES,
    SPF_CTRL_CMD_BACKENDS,
    SPF_CTRL_CMD_ADD,
    SPF_CTRL_CMD_DEL,
    SPF_CTRL_CMD_PAUSE,
    SPF_CTRL_CMD_RESUME,
    SPF_CTRL_CMD_DRAIN,
    SPF_CTRL_CMD_SETWEIGHT,
    SPF_CTRL_CMD_SETSTATE,
    SPF_CTRL_CMD_ADMINALLOWLIST,
    SPF_CTRL_CMD_ADMINALLOW,
    SPF_CTRL_CMD_ADMINDENY,
    SPF_CTRL_CMD_ADMINSET,
    SPF_CTRL_CMD_SAVE,
    SPF_CTRL_CMD_RELOAD,
    SPF_CTRL_CMD_HEALTH,
    SPF_CTRL_CMD_READONLY,
    SPF_CTRL_CMD_BLOCK,
    SPF_CTRL_CMD_UNBLOCK,
    SPF_CTRL_CMD_LOGS,
    SPF_CTRL_CMD_METRICS,
    SPF_CTRL_CMD_TLSINFO,
    SPF_CTRL_CMD_TOKENADD,
    SPF_CTRL_CMD_TOKENLIST,
    SPF_CTRL_CMD_TOKENDEL,
    SPF_CTRL_CMD_ACCESSGRANT,
    SPF_CTRL_CMD_ACCESSGRANTS,
    SPF_CTRL_CMD_ACCESSREVOKE,
    SPF_CTRL_CMD_STAGE,
    SPF_CTRL_CMD_APPLY,
    SPF_CTRL_CMD_ROLLBACK,
    SPF_CTRL_CMD_QUIT,
    SPF_CTRL_CMD_HELP
} spf_ctrl_cmd_kind_t;

#ifdef __cplusplus
extern "C" {
#endif

extern spf_state_t g_state;

void spf_init(spf_state_t* state);
void spf_shutdown(spf_state_t* state);

int spf_add_rule(spf_state_t* state, const spf_rule_t* rule);
int spf_del_rule(spf_state_t* state, uint32_t rule_id);
spf_rule_t* spf_get_rule(spf_state_t* state, uint32_t rule_id);

bool spf_is_blocked(spf_state_t* state, const char* ip);
bool spf_register_attempt(spf_state_t* state, const char* ip);
void spf_block_ip(spf_state_t* state, const char* ip, uint64_t duration_sec);
void spf_unblock_ip(spf_state_t* state, const char* ip);

void spf_bucket_init(spf_bucket_t* tb, uint64_t rate, double burst);
uint64_t spf_bucket_consume(spf_bucket_t* tb, uint64_t want);

int spf_load_config(spf_state_t* state, const char* path);
int spf_reload_config(spf_state_t* state);
int config_save(spf_state_t* state, const char* path);

bool spf_verify_token(spf_state_t* state, const char* token);
void spf_generate_token(char* buf, size_t len);

void spf_log(spf_log_level_t level, const char* fmt, ...);
void spf_event_push(spf_state_t* state, spf_event_type_t type, const char* ip, uint16_t port, uint32_t rule_id, const char* details);
void spf_event_get_recent(spf_state_t* state, spf_event_t* out, uint32_t count, uint32_t* actual);

int metrics_start(spf_state_t* state);
void metrics_stop(void);
int metrics_format(spf_state_t* state, char* buf, size_t len);

spf_ctrl_cmd_kind_t spf_ctrl_classify_command(const char* line);
int spf_audit_init(spf_state_t* state);
void spf_audit_log(spf_state_t* state, const char* actor_ip, const char* role,
                   const char* action, const char* result, const char* details);

int spf_lb_select_backend(spf_rule_t* rule, const char* client_ip);
void spf_lb_conn_start(spf_rule_t* rule, uint8_t backend_idx);
void spf_lb_conn_end(spf_rule_t* rule, uint8_t backend_idx);

void* spf_health_worker(void* arg);
void spf_health_check_backend(spf_rule_t* rule, uint8_t idx);

int spf_blocklist_load(spf_blocklist_t* bl, const char* url);
bool spf_blocklist_contains(spf_blocklist_t* bl, const char* ip);

bool spf_geoip_is_blocked(spf_state_t* state, const char* ip);
int spf_geoip_init(const char* db_path);
void spf_geoip_cleanup(void);

int spf_webhook_alert(const char* url, const spf_event_t* event);

uint64_t spf_time_ms(void);
uint64_t spf_time_sec(void);
void spf_random_bytes(uint8_t* buf, size_t len);
uint32_t spf_hash_ip(const char* ip);

// TLS
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

int tls_init(const char* cert, const char* key);
void tls_cleanup(void);
SSL_CTX* tls_get_server_ctx(void);
SSL_CTX* tls_get_client_ctx(void);
SSL* tls_accept(int fd);
SSL* tls_connect(int fd, const char* hostname);
ssize_t tls_read(SSL* ssl, void* buf, size_t len);
ssize_t tls_write(SSL* ssl, const void* buf, size_t len);
void tls_close(SSL* ssl);
int tls_set_client_cert(const char* cert, const char* key);
int tls_set_client_ca(const char* ca_path);
int tls_require_client_cert(void);
int tls_set_backend_trust(const char* ca_path);
int tls_verify_peer_name(SSL* ssl, const char* expected_name);
int tls_verify_peer_pin_sha256(SSL* ssl, const char* expected_hex);
const char* tls_get_cipher(SSL* ssl);
const char* tls_get_version(SSL* ssl);

#ifdef __cplusplus
}
#endif

#endif
