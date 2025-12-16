#ifndef SPF_PLATFORM_ESP32

#include "spf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/stat.h>

static spf_state_t g_state;
static int g_control_fd = -1;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    spf_rule_t rule;
    uint32_t conn_idx;
} session_data_t;

// helprs

void lock_state() {
    pthread_mutex_lock(&g_state.lock);
}

void unlock_state() {
    pthread_mutex_unlock(&g_state.lock);
}

void signal_handler(int sig) {
    // bye
    printf("\nReceived signal %d, shutting down...\n", sig);
    lock_state();
    g_state.running = false;
    unlock_state();
    if (g_control_fd > 0) close(g_control_fd);
    exit(0);
}

// session stuf

void* session_thread(void* arg) {
    session_data_t* data = (session_data_t*)arg;
    
    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (target_fd < 0) {
        close(data->client_fd);
        free(data);
        lock_state();
        g_state.active_connections--;
        unlock_state();
        return nullptr;
    }
    
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(data->rule.target_port);
    inet_pton(AF_INET, data->rule.target_ip, &target_addr.sin_addr);
    
    // connect w/ timeout
    if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        // fail connect
        close(target_fd);
        close(data->client_fd);
        free(data);
        lock_state();
        g_state.active_connections--;
        unlock_state();
        return nullptr;
    }
    
    int flag = 1;
    setsockopt(data->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    spf_token_bucket_t tb;
    spf_token_bucket_init(&tb, data->rule.rate_bps, 1.0);
    
    uint8_t buffer[SPF_BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;
    int maxfd = (data->client_fd > target_fd ? data->client_fd : target_fd) + 1;
    
    // loop
    while (g_state.running) {
        FD_ZERO(&readfds);
        FD_SET(data->client_fd, &readfds);
        FD_SET(target_fd, &readfds);
        
        timeout.tv_sec = 60; // 60s idle
        timeout.tv_usec = 0;
        
        int ready = select(maxfd, &readfds, nullptr, nullptr, &timeout);
        
        if (ready <= 0) break;
        
        if (FD_ISSET(data->client_fd, &readfds)) {
            ssize_t n = recv(data->client_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            
            uint64_t allowed = spf_token_bucket_consume(&tb, n);
            if (allowed > 0) {
                send(target_fd, buffer, allowed, 0);
                lock_state();
                // check bounds lol
                if(data->conn_idx < SPF_MAX_CONNECTIONS && g_state.connections[data->conn_idx].conn_id == data->conn_idx + 1) {
                     g_state.connections[data->conn_idx].bytes_in += allowed;
                }
                unlock_state();
            }
        }
        
        if (FD_ISSET(target_fd, &readfds)) {
            ssize_t n = recv(target_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            
            uint64_t allowed = spf_token_bucket_consume(&tb, n);
            if (allowed > 0) {
                send(data->client_fd, buffer, allowed, 0);
                lock_state();
                 if(data->conn_idx < SPF_MAX_CONNECTIONS) {
                    g_state.connections[data->conn_idx].bytes_out += allowed;
                 }
                unlock_state();
            }
        }
    }
    
    close(data->client_fd);
    close(target_fd);
    
    lock_state();
    if (data->conn_idx < SPF_MAX_CONNECTIONS) {
        g_state.connections[data->conn_idx].active = false;
    }
    g_state.active_connections--;
    unlock_state();
    
    free(data);
    return nullptr;
}


// listner

void* listener_thread(void* arg) {
    // int cast hack
    uint32_t rule_id = (uintptr_t)arg; 
    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return nullptr;
    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    spf_rule_t local_rule;
    
    // get rule
    lock_state();
    bool found = false;
    for(int i=0; i<SPF_MAX_RULES; i++) {
        if(g_state.rules[i].id == rule_id && g_state.rules[i].active) {
            local_rule = g_state.rules[i];
            found = true;
            break;
        }
    }
    unlock_state();
    
    if(!found) { close(listen_fd); return nullptr; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(local_rule.listen_port);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return nullptr;
    }
    
    if (listen(listen_fd, 128) < 0) {
        close(listen_fd);
        return nullptr;
    }
    
    printf("[INFO] Rule %d listening on %d -> %s:%d\n", rule_id, local_rule.listen_port, local_rule.target_ip, local_rule.target_port);
    
    while (g_state.running) {
        // chk active
        lock_state();
        bool active = false;
        for(int i=0; i<SPF_MAX_RULES; i++) {
            if(g_state.rules[i].id == rule_id && g_state.rules[i].active) {
                active = true; break;
            }
        }
        unlock_state();
        if(!active) break;

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        // select nonblock
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_fd, &fds);
        struct timeval tv = {1, 0}; 
        
        int ready = select(listen_fd + 1, &fds, NULL, NULL, &tv);
        if(ready <= 0) continue;

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) continue;
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        lock_state();
        if (spf_is_blocked(&g_state, client_ip)) {
            unlock_state();
            close(client_fd);
            continue;
        }
        
        if (!spf_register_attempt(&g_state, client_ip)) {
            printf("[WARN] Auto-blocked %s\n", client_ip);
            unlock_state();
            close(client_fd);
            continue;
        }
        
        // find slot
        int32_t conn_idx = -1;
        for (uint32_t i = 0; i < SPF_MAX_CONNECTIONS; i++) {
            if (!g_state.connections[i].active) {
                conn_idx = i;
                break;
            }
        }
        
        if (conn_idx == -1) {
            unlock_state();
            close(client_fd);
            continue;
        }
        
        g_state.connections[conn_idx].active = true;
        g_state.connections[conn_idx].conn_id = conn_idx + 1; // simple id
        strncpy(g_state.connections[conn_idx].client_ip, client_ip, 45);
        g_state.connections[conn_idx].client_port = ntohs(client_addr.sin_port);
        g_state.connections[conn_idx].listen_port = local_rule.listen_port;
        g_state.connections[conn_idx].bytes_in = 0;
        g_state.connections[conn_idx].bytes_out = 0;
        g_state.connections[conn_idx].start_time = time(NULL);
        g_state.active_connections++;
        unlock_state();
        
        session_data_t* data = (session_data_t*)malloc(sizeof(session_data_t));
        data->client_fd = client_fd;
        data->client_addr = client_addr;
        data->rule = local_rule;
        data->conn_idx = conn_idx;
        
        pthread_t thread;
        pthread_create(&thread, nullptr, session_thread, data);
        pthread_detach(thread);
    }
    
    close(listen_fd);
    printf("[INFO] Rule %d listener stopped\n", rule_id);
    return nullptr;
}

// ctrl proto

void handle_control_client(int fd) {
    char buf[SPF_BUFFER_SIZE];
    const char* welcome = "SPF Control Protocol v1.0\nType HELP for commands\n> ";
    send(fd, welcome, strlen(welcome), 0);
    
    while(true) {
        ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        
        // trim
        char* p = strchr(buf, '\n');
        if(p) *p = 0;
        p = strchr(buf, '\r');
        if(p) *p = 0;
        
        if (strlen(buf) == 0) {
            send(fd, "> ", 2, 0);
            continue;
        }
        
        char resp[SPF_RES_MAX_LEN];
        memset(resp, 0, sizeof(resp));
        
        if (strncmp(buf, "HELP", 4) == 0) {
            snprintf(resp, sizeof(resp), 
                "Commands:\n"
                "  STATUS              - System status & stats\n"
                "  ADD <src> <tgt_ip> <tgt_port>  - Add forward rule\n"
                "  DEL <id>            - Delete rule by ID\n"
                "  BLOCK <ip>          - Ban an IP address\n"
                "  HELP                - This menu\n"
                "  QUIT                - Close console\n");
        }
        else if (strncmp(buf, "STATUS", 6) == 0) {
            lock_state();
            snprintf(resp, sizeof(resp), 
                "--- STATUS ---\n"
                "Active Conns: %d\n"
                "Rules: %d\n"
                "Running: %s\n"
                "--- RULES ---\n",
                g_state.active_connections,
                g_state.rule_count,
                g_state.running ? "YES" : "NO");
            
            for(int i=0; i<SPF_MAX_RULES; i++) { // limits
                if (g_state.rules[i].active) {
                    char line[128];
                    snprintf(line, sizeof(line), "ID %d: %d -> %s:%d\n", 
                        g_state.rules[i].id, 
                        g_state.rules[i].listen_port,
                        g_state.rules[i].target_ip,
                        g_state.rules[i].target_port);
                    strncat(resp, line, sizeof(resp) - strlen(resp) - 1);
                }
            }
            unlock_state();
        }
        else if (strncmp(buf, "ADD ", 4) == 0) {
            int port, t_port;
            char t_ip[64];
            if (sscanf(buf + 4, "%d %s %d", &port, t_ip, &t_port) == 3) {
                spf_rule_t new_rule;
                memset(&new_rule, 0, sizeof(new_rule));
                new_rule.listen_port = port;
                strncpy(new_rule.target_ip, t_ip, sizeof(new_rule.target_ip)-1);
                new_rule.target_port = t_port;
                new_rule.enabled = true;
                new_rule.rate_bps = 1024 * 1024 * 10; // 10Mbps default
                new_rule.id = rand() % 9000 + 1000;
                new_rule.active = true;
                
                lock_state();
                bool added = false;
                for(int i=0; i<SPF_MAX_RULES; i++) {
                    if (!g_state.rules[i].active) {
                        g_state.rules[i] = new_rule;
                        g_state.rule_count++;
                        
                        // spawn
                        pthread_create(&g_state.rules[i].thread_id, NULL, listener_thread, (void*)(uintptr_t)new_rule.id);
                        pthread_detach(g_state.rules[i].thread_id);
                        
                        added = true;
                        snprintf(resp, sizeof(resp), "OK Rule added ID %d\n", new_rule.id);
                        break;
                    }
                }
                if (!added) snprintf(resp, sizeof(resp), "ERR Max rules reached\n");
                unlock_state();
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: ADD <port> <ip> <port>\n");
            }
        }
        else if (strncmp(buf, "DEL ", 4) == 0) {
            int id;
            if (sscanf(buf + 4, "%d", &id) == 1) {
                lock_state();
                bool found = false;
                for(int i=0; i<SPF_MAX_RULES; i++) {
                    if (g_state.rules[i].active && g_state.rules[i].id == id) {
                        g_state.rules[i].active = false; // logic sees this
                        g_state.rule_count--;
                        found = true;
                        break;
                    }
                }
                unlock_state();
                if(found) snprintf(resp, sizeof(resp), "OK Rule deleted\n");
                else snprintf(resp, sizeof(resp), "ERR Rule ID not found\n");
            }
        }
        else if (strncmp(buf, "QUIT", 4) == 0) {
            break;
        }
        else {
            snprintf(resp, sizeof(resp), "ERR Unknown command\n");
        }
        
        send(fd, resp, strlen(resp), 0);
        send(fd, "> ", 2, 0);
    }
    close(fd);
}

void* control_server_thread(void* arg) {
    int port = (uintptr_t)arg;
    g_control_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    int opt = 1;
    setsockopt(g_control_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(g_control_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Control bind failed");
        return nullptr;
    }
    
    listen(g_control_fd, 5);
    printf("[INFO] Control Server listening on port %d\n", port);
    
    while(g_state.running) {
        int client = accept(g_control_fd, NULL, NULL);
        if (client >= 0) {
            printf("[INFO] Admin connected\n");
            // spawn 4 admin
            pthread_t t;
            // int cast hack
            handle_control_client(client); // seq handle 
        }
    }
    return nullptr;
}


void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS); // parent bye
    
    if (setsid() < 0) exit(EXIT_FAILURE);
    
    // fork again no term
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    
    umask(0);
    chdir("/");
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main(int argc, char** argv) {
    bool daemon_mode = false;
    int control_port = SPF_CTRL_PORT_DEFAULT;
    
    // ez cli
    int c;
    while (1) {
        static struct option long_options[] = {
            {"admin-port", required_argument, 0, 'a'},
            {"daemon", no_argument, 0, 'd'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        
        int option_index = 0;
        c = getopt_long(argc, argv, "a:dh", long_options, &option_index);
        
        if (c == -1) break;
        
        switch (c) {
            case 'a':
                control_port = atoi(optarg);
                break;
            case 'd':
                daemon_mode = true;
                break;
            case 'h':
                printf("Usage: %s [--admin-port PORT] [--daemon]\n", argv[0]);
                return 0;
            case '?':
                break;
        }
    }
    
    if (daemon_mode) {
        daemonize();
    } else {
        printf("=== SPF Pro - Independent Network Forwarder ===\n");
    }
    
    spf_init(&g_state);
    pthread_mutex_init(&g_state.lock, NULL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // start ctrl
    pthread_t ctrl_thread;
    pthread_create(&ctrl_thread, NULL, control_server_thread, (void*)(uintptr_t)control_port);
    
    if (!daemon_mode) {
        printf("System Ready. Use 'nc localhost %d' to manage.\n", control_port);
    }
    
    // keep alive
    while(g_state.running) {
        sleep(1);
    }
    
    pthread_mutex_destroy(&g_state.lock);
    return 0;
}

#endif 
