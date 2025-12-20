#ifdef SPF_PLATFORM_ESP32

#include "common.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <Preferences.h>

#define MAX_CLIENTS 8

static spf_state_t g_state;
static Preferences prefs;
static WiFiServer g_ctrl(SPF_CTRL_PORT_DEFAULT);
static WiFiServer* g_servers[SPF_MAX_RULES] = {0};
static WiFiClient g_clients[MAX_CLIENTS];
static WiFiClient g_targets[MAX_CLIENTS];
static int g_rule_map[MAX_CLIENTS];
static spf_bucket_t g_buckets[MAX_CLIENTS];
static bool g_slots[MAX_CLIENTS] = {0};

String wifi_ssid;
String wifi_pass;
String auth_token;

void load_config() {
    prefs.begin("spf", true);
    wifi_ssid = prefs.getString("ssid", "");
    wifi_pass = prefs.getString("pass", "");
    auth_token = prefs.getString("token", "");
    prefs.end();
}

void save_config(const char* ssid, const char* pass, const char* token) {
    prefs.begin("spf", false);
    if (ssid) prefs.putString("ssid", ssid);
    if (pass) prefs.putString("pass", pass);
    if (token) prefs.putString("token", token);
    prefs.end();
}

void handle_ctrl_client(WiFiClient& client, bool& authed) {
    if (!client.available()) return;
    
    String line = client.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) return;
    
    String resp = "";
    
    if (line.startsWith("AUTH ")) {
        String tok = line.substring(5);
        if (auth_token.length() == 0 || tok == auth_token) {
            authed = true;
            resp = "OK auth\n";
        } else {
            resp = "ERR bad token\n";
        }
    }
    else if (!authed && auth_token.length() > 0) {
        resp = "ERR auth required\n";
    }
    else if (line.startsWith("HELP")) {
        resp = "AUTH SETUP STATUS ADD DEL QUIT\n";
    }
    else if (line.startsWith("SETUP ")) {
        int s1 = line.indexOf(' ');
        int s2 = line.indexOf(' ', s1 + 1);
        int s3 = line.indexOf(' ', s2 + 1);
        if (s1 > 0 && s2 > 0 && s3 > 0) {
            String ssid = line.substring(s1 + 1, s2);
            String pass = line.substring(s2 + 1, s3);
            String tok = line.substring(s3 + 1);
            save_config(ssid.c_str(), pass.c_str(), tok.c_str());
            resp = "OK saved, restart\n";
        } else {
            resp = "ERR SETUP <ssid> <pass> <token>\n";
        }
    }
    else if (line.startsWith("STATUS")) {
        resp = "--- STATUS ---\n";
        resp += "Active: " + String(g_state.active_conns) + "\n";
        resp += "Rules: " + String(g_state.rule_count) + "\n";
        resp += "IP: " + WiFi.localIP().toString() + "\n";
        resp += "Free heap: " + String(ESP.getFreeHeap()) + "\n";
        for (int i = 0; i < SPF_MAX_RULES; i++) {
            if (g_state.rules[i].active) {
                resp += "Rule " + String(g_state.rules[i].id) + ": ";
                resp += String(g_state.rules[i].listen_port) + " -> ";
                resp += String(g_state.rules[i].backends[0].host) + ":";
                resp += String(g_state.rules[i].backends[0].port) + "\n";
            }
        }
    }
    else if (line.startsWith("ADD ")) {
        int s1 = line.indexOf(' ');
        int s2 = line.indexOf(' ', s1 + 1);
        int s3 = line.indexOf(' ', s2 + 1);
        
        if (s1 > 0 && s2 > 0 && s3 > 0) {
            int port = line.substring(s1 + 1, s2).toInt();
            String ip = line.substring(s2 + 1, s3);
            int tport = line.substring(s3 + 1).toInt();
            
            spf_rule_t rule = {0};
            rule.id = millis() % 90000 + 10000;
            rule.listen_port = port;
            strlcpy(rule.backends[0].host, ip.c_str(), SPF_IP_MAX_LEN);
            rule.backends[0].port = tport;
            rule.backends[0].state = SPF_BACKEND_UP;
            rule.backend_count = 1;
            rule.active = true;
            rule.rate_bps = 1000000;
            
            spf_add_rule(&g_state, &rule);
            
            for (int i = 0; i < SPF_MAX_RULES; i++) {
                if (g_state.rules[i].id == rule.id) {
                    g_servers[i] = new WiFiServer(port);
                    g_servers[i]->begin();
                    break;
                }
            }
            resp = "OK " + String(rule.id) + "\n";
        } else {
            resp = "ERR ADD <port> <ip> <port>\n";
        }
    }
    else if (line.startsWith("DEL ")) {
        int id = line.substring(4).toInt();
        bool found = false;
        for (int i = 0; i < SPF_MAX_RULES; i++) {
            if (g_state.rules[i].active && g_state.rules[i].id == id) {
                g_state.rules[i].active = false;
                if (g_servers[i]) {
                    delete g_servers[i];
                    g_servers[i] = NULL;
                }
                g_state.rule_count--;
                found = true;
            }
        }
        resp = found ? "OK\n" : "ERR not found\n";
    }
    else if (line.startsWith("QUIT")) {
        client.stop();
        return;
    }
    else {
        resp = "ERR ?\n";
    }
    
    client.print(resp);
    client.print("> ");
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n=== SPF v" SPF_VERSION " ESP32 ===");
    
    spf_init(&g_state);
    load_config();
    
    if (wifi_ssid.length() == 0) {
        Serial.println("No WiFi config! Connect to serial and use SETUP cmd");
        Serial.println("SETUP <ssid> <password> <auth_token>");
        while (true) {
            if (Serial.available()) {
                String cmd = Serial.readStringUntil('\n');
                cmd.trim();
                if (cmd.startsWith("SETUP ")) {
                    int s1 = cmd.indexOf(' ');
                    int s2 = cmd.indexOf(' ', s1 + 1);
                    int s3 = cmd.indexOf(' ', s2 + 1);
                    if (s1 > 0 && s2 > 0 && s3 > 0) {
                        String ssid = cmd.substring(s1 + 1, s2);
                        String pass = cmd.substring(s2 + 1, s3);
                        String tok = cmd.substring(s3 + 1);
                        save_config(ssid.c_str(), pass.c_str(), tok.c_str());
                        Serial.println("Saved! Restarting...");
                        delay(500);
                        ESP.restart();
                    }
                }
            }
            delay(100);
        }
    }
    
    if (auth_token.length() > 0) {
        strncpy(g_state.config.admin.token, auth_token.c_str(), SPF_TOKEN_MAX - 1);
    }
    
    WiFi.begin(wifi_ssid.c_str(), wifi_pass.c_str());
    Serial.print("Connecting");
    int tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries < 30) {
        delay(500);
        Serial.print(".");
        tries++;
    }
    
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\nFailed! Check creds");
        delay(5000);
        ESP.restart();
    }
    
    Serial.println("\nConnected: " + WiFi.localIP().toString());
    g_ctrl.begin();
    Serial.println("Ctrl: nc " + WiFi.localIP().toString() + " " + String(SPF_CTRL_PORT_DEFAULT));
}

void loop() {
    WiFiClient ctrl_client = g_ctrl.available();
    if (ctrl_client) {
        Serial.println("Admin connected");
        bool authed = auth_token.length() == 0;
        ctrl_client.println("SPF v" SPF_VERSION " ESP32");
        if (!authed) ctrl_client.println("AUTH required");
        ctrl_client.print("> ");
        
        while (ctrl_client.connected()) {
            handle_ctrl_client(ctrl_client, authed);
            if (!ctrl_client.available()) delay(10);
        }
        Serial.println("Admin disconnected");
    }
    
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (g_state.rules[i].active && g_servers[i]) {
            WiFiClient newc = g_servers[i]->available();
            if (newc) {
                int slot = -1;
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (!g_slots[j]) { slot = j; break; }
                }
                
                if (slot >= 0) {
                    Serial.printf("Conn rule %d slot %d\n", g_state.rules[i].id, slot);
                    g_clients[slot] = newc;
                    g_rule_map[slot] = i;
                    
                    if (g_targets[slot].connect(g_state.rules[i].backends[0].host, g_state.rules[i].backends[0].port)) {
                        g_slots[slot] = true;
                        g_state.active_conns++;
                        spf_bucket_init(&g_buckets[slot], g_state.rules[i].rate_bps, 1.0);
                        g_clients[slot].setNoDelay(true);
                        g_targets[slot].setNoDelay(true);
                    } else {
                        Serial.println("Target fail");
                        g_clients[slot].stop();
                    }
                } else {
                    Serial.println("Max clients");
                    newc.stop();
                }
            }
        }
    }
    
    uint8_t buf[1024];
    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (g_slots[j]) {
            if (!g_clients[j].connected() || !g_targets[j].connected()) {
                Serial.printf("Slot %d closed\n", j);
                g_clients[j].stop();
                g_targets[j].stop();
                g_slots[j] = false;
                g_state.active_conns--;
                continue;
            }
            
            if (g_clients[j].available()) {
                int len = g_clients[j].read(buf, sizeof(buf));
                if (len > 0) {
                    uint64_t allowed = spf_bucket_consume(&g_buckets[j], len);
                    if (allowed > 0) g_targets[j].write(buf, allowed);
                }
            }
            
            if (g_targets[j].available()) {
                int len = g_targets[j].read(buf, sizeof(buf));
                if (len > 0) {
                    uint64_t allowed = spf_bucket_consume(&g_buckets[j], len);
                    if (allowed > 0) g_clients[j].write(buf, allowed);
                }
            }
        }
    }
}

#endif
