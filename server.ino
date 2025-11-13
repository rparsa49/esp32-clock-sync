
#include <WiFi.h>
#include <WiFiUdp.h>
#include <time.h>
#include <string.h> 
#include "mbedtls/sha256.h"

const char* AP_SSID = "ESP32_AP"; 
const char* AP_PASS = "12345678";

const int UDP_PORT = 12345;
const uint8_t SHARED_SECRET_KEY[] = "cosc160"; 
const size_t KEY_LEN = 7;
const size_t HMAC_TAG_LEN = 1; 
const size_t SHA256_OUTPUT_LEN = 32;
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
const size_t SHA256_BLOCK_SIZE = 64; 

uint64_t get_high_res_time() {
    return esp_timer_get_time();
}

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

uint8_t calculate_hmac_tag(const uint8_t* payload, size_t payloadLen) {
    uint8_t hmacResult[SHA256_OUTPUT_LEN]; 
    hmac_sha256_custom(SHARED_SECRET_KEY, KEY_LEN, payload, payloadLen, hmacResult);
    
    // Truncate to the first byte (HMAC-8) as specified
    return hmacResult[0]; 
}

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
}

void loop() {
    // Check for incoming packets
    int packetSize = Udp.parsePacket();

    if (packetSize) {
        // Record T2: Server's time of arrival (must be recorded before any heavy processing)
        uint64_t T2 = get_high_res_time();
        IPAddress remoteIP = Udp.remoteIP();
        int remotePort = Udp.remotePort();

        // Read the full packet (Payload + Tag)
        uint8_t receivedPacket[PACKET_SIZE];
        Udp.read(receivedPacket, PACKET_SIZE);
        
        // --- 1. Basic Size and Header Check ---
        if (packetSize != PACKET_SIZE) {
            Serial.print("ERROR: Received packet size mismatch (Expected ");
            Serial.print(PACKET_SIZE); Serial.print(", Got "); Serial.print(packetSize); Serial.println(")");
            return;
        }

        // Unpack the payload now to check the header
        PacketPayload requestPayload;
        memcpy(&requestPayload, receivedPacket, PAYLOAD_SIZE);
        
        // --- Flag Check ---
        if (strcmp(requestPayload.header, REQUEST_FLAG) != 0) {
            Serial.print("ERROR: Invalid Header Flag from ");
            Serial.print(remoteIP);
            Serial.print(". Received: ["); Serial.print(requestPayload.header); Serial.println("]");
            return;
        }
        
        // --- 2. Security Check ---
        if (validate_packet(receivedPacket)) {
            
            // T3 = get_high_res_time(): Server's time of departure
            uint64_t T3 = get_high_res_time();
            
            // Reply_payload construction
            PacketPayload replyPayload;
            
            // Copy header and sequence number
            memcpy(replyPayload.header, REQUEST_FLAG, HEADER_FLAG_LEN);
            replyPayload.seq_num = requestPayload.seq_num + 1;
            
            // Fill timestamps
            replyPayload.T1 = requestPayload.T1; // Original T1 from client
            replyPayload.T2 = T2;               // Server's T2 (Arrival)
            replyPayload.T3 = T3;               // Server's T3 (Departure)

            // Calculate HMAC for the reply payload
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
    }
    
    // Yield to other tasks
    delay(10); 
}
