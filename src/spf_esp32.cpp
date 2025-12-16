// esp32 custom proto
#ifdef SPF_PLATFORM_ESP32

#include "spf_common.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
// not used

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* DEFAULT_AUTH_TOKEN = "CHANGE_ME_SECURE_TOKEN_HERE";

static spf_state_t g_state;
static WiFiServer g_control_server(SPF_CTRL_PORT_DEFAULT);

// only 1 main forwarder
// manual sockets hard
// mvp pro polling
#define MAX_ESP_CLIENTS 8
static WiFiServer* g_forward_servers[SPF_MAX_RULES] = {0};
static WiFiClient g_clients[MAX_ESP_CLIENTS];
static WiFiClient g_targets[MAX_ESP_CLIENTS]; // map clients
static int g_client_rule_map[MAX_ESP_CLIENTS]; // index
static spf_token_bucket_t g_tbs[MAX_ESP_CLIENTS];
static bool g_slots[MAX_ESP_CLIENTS] = {0};

void spf_init_esp() {
    spf_init(&g_state);
    // no mutex on esp32
    // header has it
    // no tasks no need
    // init if can
    // pthread_mutex_init(&g_state.lock, NULL); 
}

void handle_control_client(WiFiClient& client) {
    if (!client.connected()) return;
    
    // simple read
    // read line
    if (client.available()) {
        String line = client.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) return;
        
        String resp = "";
        
        if (line.startsWith("HELP")) {
            resp = "Commands:\nSTATUS\nADD <port> <ip> <port>\nDEL <id>\n";
        }
        else if (line.startsWith("STATUS")) {
            resp = "--- STATUS ---\nActive: " + String(g_state.active_connections) + 
                   "\nRunning: YES\n--- RULES ---\n";
            for(int i=0; i<SPF_MAX_RULES; i++) {
                if(g_state.rules[i].active) {
                    resp += "ID " + String(g_state.rules[i].id) + ": " + 
                            String(g_state.rules[i].listen_port) + " -> " + 
                            String(g_state.rules[i].target_ip) + ":" + 
                            String(g_state.rules[i].target_port) + "\n";
                }
            }
        }
        else if (line.startsWith("ADD ")) {
            // basic parse
            // ADD 9000 1.2.3.4 80
            int first_space = line.indexOf(' ');
            int second_space = line.indexOf(' ', first_space + 1);
            int third_space = line.indexOf(' ', second_space + 1);
            
            if (first_space > 0 && second_space > 0 && third_space > 0) {
                int port = line.substring(first_space + 1, second_space).toInt();
                String ip = line.substring(second_space + 1, third_space);
                int t_port = line.substring(third_space + 1).toInt();
                
                spf_rule_t new_rule = {0};
                new_rule.listen_port = port;
                strlcpy(new_rule.target_ip, ip.c_str(), sizeof(new_rule.target_ip));
                new_rule.target_port = t_port;
                new_rule.active = true;
                new_rule.id = millis() % 10000;
                new_rule.rate_bps = 1000000;
                
                spf_add_rule(&g_state, &new_rule);
                
                // start listnr
                for(int i=0; i<SPF_MAX_RULES; i++) {
                     if(g_state.rules[i].id == new_rule.id) {
                         g_forward_servers[i] = new WiFiServer(port);
                         g_forward_servers[i]->begin();
                         break;
                     }
                }
                
                resp = "OK Rule " + String(new_rule.id);
            } else {
                resp = "ERR Parse";
            }
        }
        else if (line.startsWith("DEL ")) {
            int id = line.substring(4).toInt();
            bool found = false;
            for(int i=0; i<SPF_MAX_RULES; i++) {
                if(g_state.rules[i].active && g_state.rules[i].id == id) {
                    g_state.rules[i].active = false;
                    // stop srv
                    if(g_forward_servers[i]) {
                        // close it
                        delete g_forward_servers[i];
                        g_forward_servers[i] = NULL;
                    }
                    g_state.rule_count--;
                    found = true;
                }
            }
            resp = found ? "OK" : "ERR Not found";
        }
        else {
            resp = "ERR Unknown";
        }
        
        client.println(resp);
        client.print("> ");
    }
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n\n=== SPF ESP32 Pro ===");
    spf_init_esp();
    
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("Connecting");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nConnected! IP: " + WiFi.localIP().toString());
    
    g_control_server.begin();
    Serial.println("Control Server on port " + String(SPF_CTRL_PORT_DEFAULT));
    Serial.println("Use: nc " + WiFi.localIP().toString() + " " + String(SPF_CTRL_PORT_DEFAULT));
}

void loop() {
    // 1. ctrl
    WiFiClient control_client = g_control_server.available();
    if (control_client) {
        Serial.println("Admin connected");
        control_client.println("SPF ESP32 Control\n> ");
        while(control_client.connected()) {
            handle_control_client(control_client);
            // block admin ok
            // state ok
            if (!control_client.available()) delay(10);
        }
        Serial.println("Admin disconnected");
    }
    
    // 2. new conns
    for(int i=0; i<SPF_MAX_RULES; i++) {
        if(g_state.rules[i].active && g_forward_servers[i]) {
            WiFiClient new_client = g_forward_servers[i]->available();
            if (new_client) {
                // find slot
                int slot = -1;
                for(int j=0; j<MAX_ESP_CLIENTS; j++) {
                    if(!g_slots[j]) { slot = j; break; }
                }
                
                if (slot >= 0) {
                    Serial.printf("New Client for Rule %d -> Slot %d\n", g_state.rules[i].id, slot);
                    g_clients[slot] = new_client;
                    g_client_rule_map[slot] = i;
                    
                    if (g_targets[slot].connect(g_state.rules[i].target_ip, g_state.rules[i].target_port)) {
                        g_slots[slot] = true;
                        g_state.active_connections++;
                        spf_token_bucket_init(&g_tbs[slot], g_state.rules[i].rate_bps, 1.0);
                        
                        // nodelay
                        g_clients[slot].setNoDelay(true);
                        g_targets[slot].setNoDelay(true);
                    } else {
                        Serial.println("Target connect failed");
                        g_clients[slot].stop();
                    }
                } else {
                    Serial.println("Max clients reached");
                    new_client.stop();
                }
            }
        }
    }
    
    // 3. pump data
    uint8_t buf[1024];
    for(int j=0; j<MAX_ESP_CLIENTS; j++) {
        if(g_slots[j]) {
            if(!g_clients[j].connected() || !g_targets[j].connected()) {
                Serial.printf("Client %d disconnected\n", j);
                g_clients[j].stop();
                g_targets[j].stop();
                g_slots[j] = false;
                g_state.active_connections--;
                continue;
            }
            
            // cl -> tg
            if(g_clients[j].available()) {
                int len = g_clients[j].read(buf, sizeof(buf));
                if(len > 0) {
                    uint64_t allowed = spf_token_bucket_consume(&g_tbs[j], len);
                    if(allowed > 0) {
                         g_targets[j].write(buf, allowed);
                         // no stats yet
                         // save mem
                    }
                }
            }
            
            // tg -> cl
            if(g_targets[j].available()) {
                int len = g_targets[j].read(buf, sizeof(buf));
                if(len > 0) {
                    uint64_t allowed = spf_token_bucket_consume(&g_tbs[j], len);
                    if(allowed > 0) {
                         g_clients[j].write(buf, allowed);
                    }
                }
            }
        }
    }
    
    // delay 4 power
    // delay(1); 
}

#endif
