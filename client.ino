/* Some parts of our script were drafted and refined with assistance from GPT-5 Thinking.
    These included the HS_INIT message format, session key derivation, and HMAC creation.
    We then made our own improvements and justifications based on testing and observation. 
*/

#include <WiFi.h>
#include <WiFiUdp.h>
#include <time.h>
#include <sys/time.h> 
#include <string.h>   
#include "mbedtls/sha256.h"
#include "esp_system.h"

// Wi-Fi credentials of the server ESP32's access point
const char* WIFI_SSID = "ESP32_AP"; 
const char* PASSPHRASE = "12345678";
const char* SERVER_IP_STR = "192.168.4.1"; 
const int UDP_PORT = 12345;

const long SYNC_INTERVAL_MS = 10000; 
const int UDP_TIMEOUT_MS = 10;
const int  HS_TIMEOUT_MS    = 1000;

// Root (pre-shared) key used for the handshake
const uint8_t ROOT_KEY[]   = "cosc160"; 
const size_t  ROOT_KEY_LEN = 7;

const size_t HMAC_TAG_LEN = 1; 
const size_t SHA256_OUTPUT_LEN = 32;
const size_t SHA256_BLOCK_SIZE  = 64;

// Session key derived during handshake
uint8_t SESSION_KEY[SHA256_OUTPUT_LEN];
size_t SESSION_KEY_LEN  = 16;
bool sessionKeyReady  = false;

bool handshakeComplete = false;

// Sync packet definitions
const char REQUEST_FLAG[] = "REQUESTSYNC";
const size_t HEADER_FLAG_LEN = 12;

WiFiUDP Udp;
IPAddress SERVER_IP;
uint32_t current_seq_num = 0;
uint64_t last_sync_time_ms = 0;

struct __attribute__((packed)) PacketPayload {
    char header[HEADER_FLAG_LEN];
    uint32_t seq_num;
    uint64_t T1;
    uint64_t T2;
    uint64_t T3; 
}; 

const size_t PAYLOAD_SIZE = sizeof(PacketPayload);
const size_t PACKET_SIZE = PAYLOAD_SIZE + HMAC_TAG_LEN; 

// Handshake packet definitions
const char HS_INIT_FLAG[] = "HS_INIT";
const char HS_RESP_FLAG[] = "HS_RESP";
const size_t HS_HEADER_LEN = 8; 

struct __attribute__((packed)) HandshakeInitPayload {
    char header[HS_HEADER_LEN];
    uint32_t clientNonce;
};

struct __attribute__((packed)) HandshakeRespPayload {
    char header[HS_HEADER_LEN];
    uint32_t clientNonce;
    uint32_t serverNonce;
};

const size_t HS_INIT_PAYLOAD_SIZE = sizeof(HandshakeInitPayload);
const size_t HS_RESP_PAYLOAD_SIZE = sizeof(HandshakeRespPayload);
const size_t HS_INIT_PACKET_SIZE  = HS_INIT_PAYLOAD_SIZE + HMAC_TAG_LEN;
const size_t HS_RESP_PACKET_SIZE  = HS_RESP_PAYLOAD_SIZE + HMAC_TAG_LEN;

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

    // Compute Inner Hash
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); 
    mbedtls_sha256_update(&ctx, K_ipad, SHA256_BLOCK_SIZE);
    mbedtls_sha256_update(&ctx, msg, msgLen);
    mbedtls_sha256_finish(&ctx, innerHash);
    mbedtls_sha256_free(&ctx);

    // Compute Outer Hash
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, K_opad, SHA256_BLOCK_SIZE);
    mbedtls_sha256_update(&ctx, innerHash, SHA256_OUTPUT_LEN);
    mbedtls_sha256_finish(&ctx, hmacResult);
    mbedtls_sha256_free(&ctx);
}

// Session key derivation
void derive_session_key(uint32_t clientNonce, uint32_t serverNonce) {
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
        Serial.print("  Received Tag: 0x"); Serial.println(received_tag, HEX);
        Serial.print("  Calculated Tag: 0x"); Serial.println(calculated_tag, HEX);
        return false;
    }
}

// Adjust the local clock by a signed offset (in microseconds)
void update_local_clock(int64_t offset_us) {
    // Get current time
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    // Convert microseconds offset to seconds and microseconds
    long seconds = offset_us / 1000000;
    long microseconds = offset_us % 1000000;

    // Apply offset
    current_time.tv_sec += seconds;
    current_time.tv_usec += microseconds;

    // Handle microsecond overflow/underflow
    if (current_time.tv_usec >= 1000000) {
        current_time.tv_sec++;
        current_time.tv_usec -= 1000000;
    } else if (current_time.tv_usec < 0) {
        current_time.tv_sec--;
        current_time.tv_usec += 1000000;
    }

    // Set the new time
    settimeofday(&current_time, NULL);
    Serial.print("Clock Adjusted by: ");
    Serial.print((float)offset_us / 1000.0, 3);
    Serial.println(" ms");
}

// Compute network delay and clock offset from a 4-timestamp (T1–T4) synchronization exchange and, if needed, adjust the local clock
void calculate_and_adjust(uint64_t T1, uint64_t T2, uint64_t T3, uint64_t T4) {
    int64_t T_diff = (int64_t)T4 - (int64_t)T1;

    int64_t T_server_proc = (int64_t)T3 - (int64_t)T2;

    int64_t delay_us = T_diff - T_server_proc;

    int64_t term1 = (int64_t)T2 - (int64_t)T1;
    int64_t term2 = (int64_t)T3 - (int64_t)T4;
    
    int64_t offset_us = (term1 + term2) / 2;

    Serial.println("--- Synchronization Result ---");
    Serial.print("Delay: ");
    Serial.print((float)delay_us / 1000.0, 3);
    Serial.println(" ms");
    Serial.print("Offset: ");
    Serial.print((float)offset_us / 1000.0, 3);
    Serial.println(" ms");
    
    // Adjust clock only if the offset is non-zero
    if (offset_us != 0) {
        update_local_clock(offset_us);
    }
}

bool send_request(uint64_t T1) {
    // Increment sequence number
    current_seq_num++;
    
    PacketPayload requestPayload;
    
    // Add header and sequence number
    memcpy(requestPayload.header, REQUEST_FLAG, HEADER_FLAG_LEN);
    requestPayload.seq_num = current_seq_num;
    
    requestPayload.T1 = T1;
    requestPayload.T2 = 0;
    requestPayload.T3 = 0; 
    
    // Calculate HMAC for the outgoing payload
    uint8_t hmac_Tag = calculate_hmac_tag((uint8_t*)&requestPayload, PAYLOAD_SIZE);

    // Construct the final request packet
    uint8_t fullRequest[PACKET_SIZE];
    memcpy(fullRequest, &requestPayload, PAYLOAD_SIZE);
    fullRequest[PAYLOAD_SIZE] = hmac_Tag;
    
    // Checks if connection/address is valid
    int begin_status = Udp.beginPacket(SERVER_IP, UDP_PORT);
    if (begin_status == 0) {
        Serial.println("[CRITICAL ERROR] UDP: Udp.beginPacket failed. Check target IP and Wi-Fi status.");
        return false;
    }
    
    // Write Data
    size_t bytesWritten = Udp.write(fullRequest, PACKET_SIZE);
    if (bytesWritten != PACKET_SIZE) {
        Serial.print("[CRITICAL ERROR] UDP: Udp.write failed. Expected ");
        Serial.print(PACKET_SIZE);
        Serial.print(", Wrote ");
        Serial.println(bytesWritten);
    }

    // Checks if transmission succeeded
    int end_status = Udp.endPacket();

    if (end_status == 1 && bytesWritten == PACKET_SIZE) {
        Serial.print("Request Sent OK. Sequence: ");
        Serial.print(current_seq_num);
        Serial.print(", T1: ");
        Serial.println((long)T1);
        return true;
    } else {
        Serial.print("ERROR: UDP Send Failed. beginStatus=");
        Serial.print(begin_status);
        Serial.print(", endStatus=");
        Serial.print(end_status);
        Serial.print(", bytesWritten=");
        Serial.println(bytesWritten);
        return false;
    }
}

bool receive_reply(uint32_t expected_seq, uint64_t& T1_out, uint64_t& T2_out, uint64_t& T3_out, uint64_t& T4_out) {
    unsigned long start_time = millis();

    while (millis() - start_time < UDP_TIMEOUT_MS) {
        if (Udp.parsePacket() == PACKET_SIZE) {
            // Client's time of arrival
            T4_out = get_high_res_time(); 
            
            // Read the full packet
            uint8_t receivedPacket[PACKET_SIZE];
            Udp.read(receivedPacket, PACKET_SIZE);

            // Unpack the payload
            PacketPayload replyPayload;
            memcpy(&replyPayload, receivedPacket, PAYLOAD_SIZE);
            
            // Header and Sequence Check
            if (strcmp(replyPayload.header, REQUEST_FLAG) != 0) {
                Serial.println("ERROR: Reply has invalid Header Flag. Discarding.");
                return false;
            }
            if (replyPayload.seq_num != expected_seq) {
                Serial.print("SECURITY ALERT: Sequence mismatch. Expected ");
                Serial.print(expected_seq);
                Serial.print(", Got ");
                Serial.print(replyPayload.seq_num);
                Serial.println(" (Replay Attack detected or packet loss). Discarding.");
                return false;
            }
            
            // Security Check
            if (validate_packet(receivedPacket)) {
                // If valid, store the timestamps for calculation
                T1_out = replyPayload.T1;
                T2_out = replyPayload.T2;
                T3_out = replyPayload.T3;
                
                Serial.println("Reply Received and Authenticated.");
                return true;
            } else {
                // Discarding
                return false;
            }
        }
        delay(1); 
    }

    Serial.println("TIMEOUT: No reply received within timeout window.");
    return false;
}

// Handshake from client side
bool performHandshake() {
    Serial.println("Starting handshake (HS_INIT -> HS_RESP)...");

    uint32_t clientNonce = esp_random();

    // Build HS_INIT payload
    HandshakeInitPayload initPayload;
    memset(&initPayload, 0, sizeof(initPayload));
    memcpy(initPayload.header, HS_INIT_FLAG, strlen(HS_INIT_FLAG));
    initPayload.clientNonce = clientNonce;

    uint8_t initPacket[HS_INIT_PACKET_SIZE];
    memcpy(initPacket, &initPayload, HS_INIT_PAYLOAD_SIZE);

    // HMAC over HS_INIT using ROOT_KEY
    uint8_t initHmac[SHA256_OUTPUT_LEN];
    hmac_sha256_custom(ROOT_KEY, ROOT_KEY_LEN,
                       (uint8_t*)&initPayload, HS_INIT_PAYLOAD_SIZE,
                       initHmac);
    initPacket[HS_INIT_PAYLOAD_SIZE] = initHmac[0];

    // Send HS_INIT
    if (Udp.beginPacket(SERVER_IP, UDP_PORT) == 0) {
        Serial.println("Handshake: beginPacket failed.");
        return false;
    }
    size_t written = Udp.write(initPacket, HS_INIT_PACKET_SIZE);
    int endStatus  = Udp.endPacket();

    if (endStatus != 1 || written != HS_INIT_PACKET_SIZE) {
        Serial.println("Handshake: failed to send HS_INIT.");
        return false;
    }

    // Wait for HS_RESP
    unsigned long start = millis();
    while (millis() - start < (unsigned long)HS_TIMEOUT_MS) {
        int packetSize = Udp.parsePacket();
        if (packetSize == HS_RESP_PACKET_SIZE) {
            uint8_t buffer[HS_RESP_PACKET_SIZE];
            Udp.read(buffer, HS_RESP_PACKET_SIZE);

            HandshakeRespPayload respPayload;
            memcpy(&respPayload, buffer, HS_RESP_PAYLOAD_SIZE);
            uint8_t receivedTag = buffer[HS_RESP_PAYLOAD_SIZE];

            // Check header
            if (strncmp(respPayload.header, HS_RESP_FLAG, strlen(HS_RESP_FLAG)) != 0) {
                Serial.println("Handshake: invalid HS_RESP header, ignoring.");
                return false;
            }

            // Verify HMAC with ROOT_KEY
            uint8_t expectedHmac[SHA256_OUTPUT_LEN];
            hmac_sha256_custom(ROOT_KEY, ROOT_KEY_LEN,
                               (uint8_t*)&respPayload, HS_RESP_PAYLOAD_SIZE,
                               expectedHmac);

            if (receivedTag != expectedHmac[0]) {
                Serial.println("Handshake: HMAC mismatch on HS_RESP.");
                return false;
            }

            // Check nonce echo
            if (respPayload.clientNonce != clientNonce) {
                Serial.println("Handshake: clientNonce mismatch in HS_RESP.");
                return false;
            }

            uint32_t serverNonce = respPayload.serverNonce;

            // Derive session key
            derive_session_key(clientNonce, serverNonce);

            handshakeComplete = true;

            Serial.println("=== Handshake complete on client ===");
            Serial.print("Client nonce: "); Serial.println(clientNonce);
            Serial.print("Server nonce: "); Serial.println(serverNonce);

            return true;
        }
        delay(10);
    }

    Serial.println("Handshake: timed out waiting for HS_RESP.");
    return false;
}

void setup() {
    Serial.begin(115200);

    SERVER_IP.fromString(SERVER_IP_STR);
    
    Serial.print("Connecting to SSID: ");
    Serial.println(WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, PASSPHRASE);

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }

    Serial.println("\nWi-Fi Connected.");
    Serial.print("Client IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.print("Target Server IP: ");
    Serial.println(SERVER_IP_STR);
    
    // Initialize UDP
    Udp.begin(UDP_PORT);

    // Run handshake once at startup
    if (!performHandshake()) {
        Serial.println("Initial handshake failed; will retry in loop.");
    }
}

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Lost Wi-Fi connection, attempting reconnect...");
        WiFi.begin(WIFI_SSID, PASSPHRASE);
        delay(5000); 
        return;
    }

    // If handshake not done yet, retry
    if (!handshakeComplete) {
        if (!performHandshake()) {
            delay(1000);
            return;
        }
    }

    // Regular sync
    if (millis() - last_sync_time_ms >= (uint64_t)SYNC_INTERVAL_MS) {
        last_sync_time_ms = millis();
        
        uint64_t T1, T2 = 0, T3 = 0, T4 = 0;
        
        T1 = get_high_res_time();
        
        if (send_request(T1)) {
            if (receive_reply(current_seq_num, T1, T2, T3, T4)) {
                calculate_and_adjust(T1, T2, T3, T4);
            }
        }
    }
    
    delay(10); 
}

