#ifdef SPF_PLATFORM_ESP32

#include "spf_common.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiServer.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>

const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* DEFAULT_AUTH_TOKEN = "CHANGE_ME_SECURE_TOKEN_HERE";

static spf_state_t g_state;
static WebServer g_http_server(8080);
static WiFiServer* g_forward_server = nullptr;
static TaskHandle_t g_forward_task = nullptr;

void generate_auth_token(char* token, size_t len) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (size_t i = 0; i < len - 1; i++) {
        token[i] = charset[esp_random() % (sizeof(charset) - 1)];
    }
    token[len - 1] = '\0';
}

bool verify_auth(WebServer& server) {
    if (!g_state.security.require_auth) {
        return true;
    }
    
    if (!server.hasHeader("Authorization")) {
        server.send(401, "application/json", "{\"error\":\"Missing Authorization header\"}");
        return false;
    }
    
    String auth = server.header("Authorization");
    String expected = "Bearer " + String(g_state.security.auth_token);
    
    if (auth != expected) {
        server.send(403, "application/json", "{\"error\":\"Invalid token\"}");
        return false;
    }
    
    return true;
}

void handle_status() {
    if (!verify_auth(g_http_server)) return;
    
    StaticJsonDocument<4096> doc;
    JsonArray conns = doc.createNestedArray("connections");
    
    for (uint32_t i = 0; i < SPF_MAX_CONNECTIONS; i++) {
        if (g_state.connections[i].active) {
            JsonObject conn = conns.createNestedObject();
            conn["id"] = g_state.connections[i].conn_id;
            conn["client"] = g_state.connections[i].client_ip;
            conn["bytes_in"] = g_state.connections[i].bytes_in;
            conn["bytes_out"] = g_state.connections[i].bytes_out;
        }
    }
    
    JsonArray blocked = doc.createNestedArray("blocked");
    uint64_t now = millis() / 1000;
    for (uint32_t i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        if (g_state.trackers[i].blocked && g_state.trackers[i].block_until > now) {
            JsonObject b = blocked.createNestedObject();
            b["ip"] = g_state.trackers[i].ip;
            b["until"] = g_state.trackers[i].block_until;
        }
    }
    
    doc["active_connections"] = g_state.active_connections;
    doc["tls_enabled"] = g_state.security.tls_enabled;
    
    String response;
    serializeJson(doc, response);
    g_http_server.send(200, "application/json", response);
}

void handle_rules() {
    if (!verify_auth(g_http_server)) return;
    
    StaticJsonDocument<1024> doc;
    DeserializationError error = deserializeJson(doc, g_http_server.arg("plain"));
    
    if (error) {
        g_http_server.send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
        return;
    }
    
    spf_rule_t rule = {0};
    rule.listen_port = doc["listen"] | 9000;
    strlcpy(rule.target_ip, doc["target_ip"] | "127.0.0.1", sizeof(rule.target_ip));
    rule.target_port = doc["target_port"] | 25565;
    rule.enabled = doc["enabled"] | true;
    rule.max_connections = doc["max_conn"] | 8;
    rule.rate_bps = doc["rate_bps"] | 200000;
    
    if (spf_add_rule(&g_state, &rule) == 0) {
        g_http_server.send(200, "application/json", "{\"ok\":true}");
    } else {
        g_http_server.send(500, "application/json", "{\"error\":\"Failed to add rule\"}");
    }
}

void handle_health() {
    g_http_server.send(200, "application/json", "{\"status\":\"ok\"}");
}

void handle_session(WiFiClient& client, const spf_rule_t* rule, uint32_t conn_idx) {
    WiFiClient target;
    
    if (!target.connect(rule->target_ip, rule->target_port)) {
        Serial.printf("Failed to connect to target %s:%d\n", rule->target_ip, rule->target_port);
        client.stop();
        return;
    }
    
    Serial.printf("Session %llu established\n", g_state.connections[conn_idx].conn_id);
    
    spf_token_bucket_t tb;
    spf_token_bucket_init(&tb, rule->rate_bps, 1.0);
    
    uint8_t buffer[SPF_BUFFER_SIZE];
    unsigned long last_activity = millis();
    const unsigned long timeout = 30000; 
    
    while (client.connected() && target.connected()) {
        if (millis() - last_activity > timeout) {
            Serial.println("Session timeout");
            break;
        }
        
        if (client.available()) {
            int len = client.read(buffer, sizeof(buffer));
            if (len > 0) {
                uint64_t allowed = spf_token_bucket_consume(&tb, len);
                if (allowed > 0) {
                    target.write(buffer, allowed);
                    g_state.connections[conn_idx].bytes_in += allowed;
                    last_activity = millis();
                }
            }
        }
        
        if (target.available()) {
            int len = target.read(buffer, sizeof(buffer));
            if (len > 0) {
                uint64_t allowed = spf_token_bucket_consume(&tb, len);
                if (allowed > 0) {
                    client.write(buffer, allowed);
                    g_state.connections[conn_idx].bytes_out += allowed;
                    last_activity = millis();
                }
            }
        }
        
        delay(1); 
    }
    
    client.stop();
    target.stop();
    g_state.connections[conn_idx].active = false;
    g_state.active_connections--;
    
    Serial.printf("Session %llu closed\n", g_state.connections[conn_idx].conn_id);
}

void forward_task(void* param) {
    spf_rule_t* rule = (spf_rule_t*)param;
    
    if (g_forward_server) {
        delete g_forward_server;
    }
    
    g_forward_server = new WiFiServer(rule->listen_port);
    g_forward_server->begin();
    
    Serial.printf("Forwarder listening on port %d\n", rule->listen_port);
    
    while (g_state.running) {
        WiFiClient client = g_forward_server->available();
        
        if (client) {
            String client_ip = client.remoteIP().toString();
            
            if (spf_is_blocked(&g_state, client_ip.c_str())) {
                Serial.printf("Blocked connection from %s\n", client_ip.c_str());
                client.stop();
                continue;
            }
            
            if (!spf_register_attempt(&g_state, client_ip.c_str())) {
                Serial.printf("Auto-blocked %s\n", client_ip.c_str());
                client.stop();
                continue;
            }
            
            if (g_state.active_connections >= rule->max_connections) {
                Serial.println("Connection limit reached");
                client.stop();
                continue;
            }
            
            uint32_t conn_idx = 0;
            for (uint32_t i = 0; i < SPF_MAX_CONNECTIONS; i++) {
                if (!g_state.connections[i].active) {
                    conn_idx = i;
                    break;
                }
            }
            
            g_state.connections[conn_idx].conn_id = g_state.next_conn_id++;
            g_state.connections[conn_idx].active = true;
            strlcpy(g_state.connections[conn_idx].client_ip, client_ip.c_str(), 
                    sizeof(g_state.connections[conn_idx].client_ip));
            g_state.connections[conn_idx].client_port = client.remotePort();
            g_state.connections[conn_idx].bytes_in = 0;
            g_state.connections[conn_idx].bytes_out = 0;
            g_state.connections[conn_idx].start_time = millis() / 1000;
            g_state.active_connections++;

            handle_session(client, rule, conn_idx);
        }
        
        delay(10);
    }
    
    vTaskDelete(NULL);
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n\n=== SPF Network Forwarder ===");
    Serial.println("ESP32 MVP with TLS/Auth");
    spf_init(&g_state);
    
    g_state.security.tls_enabled = false; 
    g_state.security.require_auth = true;
    
    if (strcmp(DEFAULT_AUTH_TOKEN, "CHANGE_ME_SECURE_TOKEN_HERE") == 0) {
        Serial.println("WARNING: Generating random auth token");
        generate_auth_token(g_state.security.auth_token, SPF_AUTH_TOKEN_SIZE);
        Serial.printf("AUTH TOKEN: %s\n", g_state.security.auth_token);
        Serial.println("SAVE THIS TOKEN - Required for API access!");
    } else {
        strlcpy(g_state.security.auth_token, DEFAULT_AUTH_TOKEN, 
                sizeof(g_state.security.auth_token));
    }
    
    Serial.printf("Connecting to WiFi: %s\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    
    Serial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());
    
    g_http_server.on("/status", HTTP_GET, handle_status);
    g_http_server.on("/rules", HTTP_POST, handle_rules);
    g_http_server.on("/health", HTTP_GET, handle_health);
    
    g_http_server.begin();
    Serial.printf("HTTP control server: http://%s:8080\n", WiFi.localIP().toString().c_str());
    Serial.println("Endpoints: /status (GET), /rules (POST), /health (GET)");
    
    spf_rule_t default_rule = {
        .listen_port = 9000,
        .target_ip = "192.168.1.100",
        .target_port = 25565,
        .enabled = true,
        .max_connections = 8,
        .rate_bps = 200000,
        .rule_id = 0
    };
    strlcpy(default_rule.target_ip, "192.168.1.100", sizeof(default_rule.target_ip));
    
    spf_add_rule(&g_state, &default_rule);
    
    // Start forwarder task
    g_state.running = true;
    xTaskCreatePinnedToCore(
        forward_task,
        "forwarder",
        8192,
        &g_state.rules[0],
        1,
        &g_forward_task,
        1
    );
    
    Serial.println("\n=== System Ready ===");
    Serial.println("SECURITY NOTICE:");
    Serial.println("- Auth token required for all API calls");
    Serial.println("- Use: Authorization: Bearer <token>");
    Serial.println("- Consider enabling TLS for production");
}

void loop() {
    g_http_server.handleClient();
    delay(10);
}

#endif
