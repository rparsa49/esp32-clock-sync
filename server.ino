#include <WiFi.h>
#include <WiFiUdp.h>
#include <time.h>
#include <string.h> 
#include "mbedtls/sha256.h"
#include "esp_system.h"

// Set up the ESP32 as a Wi-Fi Access Point instead of using an external router
const char* AP_SSID = "ESP32_AP"; 
const char* AP_PASS = "12345678"; 
const size_t HS_HEADER_LEN = 8;

const int UDP_PORT = 12345;

// Root (pre-shared) key used for the handshake
const uint8_t ROOT_KEY[] = "cosc160"; 
const size_t ROOT_KEY_LEN = 7;

const size_t HMAC_TAG_LEN = 1; 
const size_t SHA256_OUTPUT_LEN = 32;
const size_t SHA256_BLOCK_SIZE = 64;

// Session key derived during handshake; used for sync packets
uint8_t SESSION_KEY[SHA256_OUTPUT_LEN];
size_t SESSION_KEY_LEN = 16;
bool sessionKeyReady = false;

bool handshakeComplete = false;

// Sync packet definitions
const char REQUEST_FLAG[] = "REQUESTSYNC"; 
const size_t HEADER_FLAG_LEN = 12;          

WiFiUDP Udp;

struct __attribute__((packed)) PacketPayload {
    char header[HEADER_FLAG_LEN]; 
    uint32_t seq_num;            
    uint64_t T1;                  
    uint64_t T2;                  
    uint64_t T3;                 
}; 

const size_t PAYLOAD_SIZE = sizeof(PacketPayload); 
const size_t PACKET_SIZE = PAYLOAD_SIZE + HMAC_TAG_LEN;

struct __attribute__((packed)) HandshakeInitPayload {
    char header[HS_HEADER_LEN];   // "HS_INIT"
    uint32_t clientNonce;
};

struct __attribute__((packed)) HandshakeRespPayload {
    char header[HS_HEADER_LEN];   // "HS_RESP"
    uint32_t clientNonce;
    uint32_t serverNonce;
};

const size_t HS_INIT_PAYLOAD_SIZE = sizeof(HandshakeInitPayload);
const size_t HS_RESP_PAYLOAD_SIZE = sizeof(HandshakeRespPayload);
const size_t HS_INIT_PACKET_SIZE  = HS_INIT_PAYLOAD_SIZE + HMAC_TAG_LEN;
const size_t HS_RESP_PACKET_SIZE  = HS_RESP_PAYLOAD_SIZE + HMAC_TAG_LEN;

// Handshake packet definitions
const char HS_INIT_FLAG[] = "HS_INIT";
const char HS_RESP_FLAG[] = "HS_RESP";

// Time helper
uint64_t get_high_res_time() {
    return esp_timer_get_time();
}

// HMAC helper
void hmac_sha256_custom(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t* hmacResult) {
    uint8_t K_ipad[SHA256_BLOCK_SIZE];
    uint8_t K_opad[SHA256_BLOCK_SIZE];
    uint8_t innerHash[SHA256_OUTPUT_LEN];
    mbedtls_sha256_context ctx;

    memset(K_ipad, 0, SHA256_BLOCK_SIZE);
    memset(K_opad, 0, SHA256_BLOCK_SIZE);
    
    memcpy(K_ipad, key, keyLen);
    memcpy(K_opad, key, keyLen);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        K_ipad[i] ^= 0x36;
        K_opad[i] ^= 0x5C;
    }

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); 
    mbedtls_sha256_update(&ctx, K_ipad, SHA256_BLOCK_SIZE);
    mbedtls_sha256_update(&ctx, msg, msgLen);
    mbedtls_sha256_finish(&ctx, innerHash);
    mbedtls_sha256_free(&ctx);

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, K_opad, SHA256_BLOCK_SIZE);
    mbedtls_sha256_update(&ctx, innerHash, SHA256_OUTPUT_LEN);
    mbedtls_sha256_finish(&ctx, hmacResult);
    mbedtls_sha256_free(&ctx);
}

// Session key derivation
void derive_session_key(uint32_t clientNonce, uint32_t serverNonce) {
    // Key material = ROOT_KEY || clientNonce || serverNonce
    uint8_t material[ROOT_KEY_LEN + sizeof(clientNonce) + sizeof(serverNonce)];
    memcpy(material, ROOT_KEY, ROOT_KEY_LEN);
    memcpy(material + ROOT_KEY_LEN, &clientNonce, sizeof(clientNonce));
    memcpy(material + ROOT_KEY_LEN + sizeof(clientNonce), &serverNonce, sizeof(serverNonce));

    uint8_t fullHash[SHA256_OUTPUT_LEN];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, material, sizeof(material));
    mbedtls_sha256_finish(&ctx, fullHash);
    mbedtls_sha256_free(&ctx);

    // Use first SESSION_KEY_LEN bytes as session key
    memcpy(SESSION_KEY, fullHash, SESSION_KEY_LEN);
    sessionKeyReady = true;

    Serial.print("Session key derived. First byte: 0x");
    Serial.println(SESSION_KEY[0], HEX);
}

// HMAC Tag Calculator
uint8_t calculate_hmac_tag(const uint8_t* payload, size_t payloadLen) {
    uint8_t hmacResult[SHA256_OUTPUT_LEN]; 
    hmac_sha256_custom(SESSION_KEY, SESSION_KEY_LEN, payload, payloadLen, hmacResult);
    
    // Truncate to the first byte (HMAC-8) as specified
    return hmacResult[0]; 
}

// Packet validation for sync packets
bool validate_packet(const uint8_t* packet) {
    // The payload is the first 40 bytes
    const uint8_t* payload = packet; 
    // The tag is the last byte
    const uint8_t received_tag = packet[PAYLOAD_SIZE];
    
    uint8_t calculated_tag = calculate_hmac_tag(payload, PAYLOAD_SIZE);

    if (calculated_tag == received_tag) {
        return true;
    } else {
        Serial.println("SECURITY ALERT: HMAC tag mismatch! Packet discarded.");
        return false;
    }
}

// Handshake handler
void handleHandshake(int packetSize) {
    IPAddress remoteIP = Udp.remoteIP();
    int remotePort = Udp.remotePort();
    Serial.println("Packet size is: " + packetSize);
    if (packetSize != HS_INIT_PACKET_SIZE) {
        // Drain and ignore unexpected packets during handshake phase
        uint8_t trash[256];
        while (Udp.available()) {
            Udp.read(trash, sizeof(trash));
        }
        Serial.println("Unexpected packet size during handshake; waiting for HS_INIT...");
        return;
    }

    // Read the handshake-init packet
    uint8_t buffer[HS_INIT_PACKET_SIZE];
    Udp.read(buffer, HS_INIT_PACKET_SIZE);

    HandshakeInitPayload initPayload;
    memcpy(&initPayload, buffer, HS_INIT_PAYLOAD_SIZE);
    uint8_t receivedTag = buffer[HS_INIT_PAYLOAD_SIZE];

    // Check header
    if (strncmp(initPayload.header, HS_INIT_FLAG, strlen(HS_INIT_FLAG)) != 0) {
        Serial.println("Invalid handshake header; expecting HS_INIT.");
        return;
    }

    // Verify HMAC using ROOT_KEY (handshake always uses root key)
    uint8_t expectedHmac[SHA256_OUTPUT_LEN];
    hmac_sha256_custom(ROOT_KEY, ROOT_KEY_LEN,
                       (uint8_t*)&initPayload, HS_INIT_PAYLOAD_SIZE,
                       expectedHmac);

    if (receivedTag != expectedHmac[0]) {
        Serial.println("Handshake HMAC mismatch; ignoring HS_INIT.");
        return;
    }

    uint32_t clientNonce = initPayload.clientNonce;
    uint32_t serverNonce = esp_random();   // 32-bit random nonce

    // Derive per-session HMAC key
    derive_session_key(clientNonce, serverNonce);

    // Build handshake response
    HandshakeRespPayload respPayload;
    memset(&respPayload, 0, sizeof(respPayload));
    memcpy(respPayload.header, HS_RESP_FLAG, strlen(HS_RESP_FLAG));
    respPayload.clientNonce = clientNonce;
    respPayload.serverNonce = serverNonce;

    uint8_t fullResp[HS_RESP_PACKET_SIZE];
    memcpy(fullResp, &respPayload, HS_RESP_PAYLOAD_SIZE);

    uint8_t respHmac[SHA256_OUTPUT_LEN];
    hmac_sha256_custom(ROOT_KEY, ROOT_KEY_LEN,
                       (uint8_t*)&respPayload, HS_RESP_PAYLOAD_SIZE,
                       respHmac);
    fullResp[HS_RESP_PAYLOAD_SIZE] = respHmac[0];

    // Send handshake response
    Udp.beginPacket(remoteIP, remotePort);
    Udp.write(fullResp, HS_RESP_PACKET_SIZE);
    Udp.endPacket();

    handshakeComplete = true;

    Serial.println("=== Handshake complete ===");
    Serial.print("Client nonce: "); Serial.println(clientNonce);
    Serial.print("Server nonce: "); Serial.println(serverNonce);
}

// Set up
void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("Configuring ESP32 as Wi-Fi Access Point...");

    WiFi.mode(WIFI_AP);

    bool apStarted = WiFi.softAP(AP_SSID, AP_PASS);

    if (!apStarted) {
        Serial.println("ERROR: Failed to start Access Point!");
        while (true) {
            delay(1000);
        }
    }

    IPAddress apIP = WiFi.softAPIP();
    Serial.println("Access Point started.");
    Serial.print("AP SSID: ");
    Serial.println(AP_SSID);
    Serial.print("AP IP Address: ");
    Serial.println(apIP);

    // Start UDP server on this port
    Udp.begin(UDP_PORT);
    Serial.print("Listening on UDP Port: ");
    Serial.println(UDP_PORT);

    Serial.println("Waiting for handshake (HS_INIT) from client...");
}

// Loop
void loop() {
    int packetSize = Udp.parsePacket();

    if (!packetSize) {
        delay(10); 
        return;
    }

    if (!handshakeComplete) {
        // --- First phase: handle handshake ---
        handleHandshake(packetSize);
        return;
    }

    // --- Second phase: normal sync packets ---
    // Record T2: Server's time of arrival (before heavy processing)
    uint64_t T2 = get_high_res_time();
    IPAddress remoteIP = Udp.remoteIP();
    int remotePort = Udp.remotePort();

    // Read the full sync packet (Payload + Tag)
    uint8_t receivedPacket[PACKET_SIZE];
    if (packetSize != PACKET_SIZE) {
        // Drain and ignore if size is wrong
        uint8_t trash[256];
        while (Udp.available()) {
            Udp.read(trash, sizeof(trash));
        }
        Serial.print("ERROR: Received packet size mismatch (Expected ");
        Serial.print(PACKET_SIZE); Serial.print(", Got "); Serial.print(packetSize); Serial.println(")");
        return;
    }

    Udp.read(receivedPacket, PACKET_SIZE);

    // Unpack the payload to check the header
    PacketPayload requestPayload;
    memcpy(&requestPayload, receivedPacket, PAYLOAD_SIZE);
    
    // --- Flag Check ---
    if (strcmp(requestPayload.header, REQUEST_FLAG) != 0) {
        Serial.print("ERROR: Invalid Header Flag from ");
        Serial.print(remoteIP);
        Serial.print(". Received: ["); Serial.print(requestPayload.header); Serial.println("]");
        return;
    }
    
    // --- Security Check ---
    if (validate_packet(receivedPacket)) {
        // T3 = get_high_res_time(): Server's time of departure
        uint64_t T3 = get_high_res_time();
        
        // Reply payload construction
        PacketPayload replyPayload;
        
        // Copy header and sequence number
        memcpy(replyPayload.header, REQUEST_FLAG, HEADER_FLAG_LEN);
        replyPayload.seq_num = requestPayload.seq_num + 1;
        
        // Fill timestamps
        replyPayload.T1 = requestPayload.T1; // Original T1 from client
        replyPayload.T2 = T2;               // Server's T2 (Arrival)
        replyPayload.T3 = T3;               // Server's T3 (Departure)

        // Calculate HMAC for the reply payload (now using SESSION_KEY)
        uint8_t hmac_Tag = calculate_hmac_tag((uint8_t*)&replyPayload, PAYLOAD_SIZE);

        // Construct the final reply packet
        uint8_t fullReply[PACKET_SIZE];
        memcpy(fullReply, &replyPayload, PAYLOAD_SIZE);
        fullReply[PAYLOAD_SIZE] = hmac_Tag;
        
        // Send the full reply packet
        Udp.beginPacket(remoteIP, remotePort);
        Udp.write(fullReply, PACKET_SIZE);
        Udp.endPacket();
        
        Serial.println("--- Sync Request Processed ---");
        Serial.print("Client IP: "); Serial.println(remoteIP);
        Serial.print("Sequence: "); Serial.println(requestPayload.seq_num);
        Serial.print("T2 (Arrival us): "); Serial.println((long)T2);
        Serial.print("T3 (Departure us): "); Serial.println((long)T3);

    } else {
        // Discarding packet due to bad HMAC (logged inside validate_packet)
    }

    delay(10); 
}
