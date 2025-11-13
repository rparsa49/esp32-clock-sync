#include <WiFi.h>
#include <WiFiUdp.h>
#include <time.h>
#include <sys/time.h> 
#include <string.h>   
#include "mbedtls/sha256.h"

const char* WIFI_SSID = "ESP32_AP"; 
const char* PASSPHRASE = "12345678";
const char* SERVER_IP_STR = "192.168.4.1"; 
const int UDP_PORT = 12345; 
const long SYNC_INTERVAL_MS = 10000; 
const int UDP_TIMEOUT_MS = 10; 
const uint8_t SHARED_SECRET_KEY[] = "cosc160"; 
const size_t KEY_LEN = 7;
const size_t HMAC_TAG_LEN = 1; 
const size_t SHA256_OUTPUT_LEN = 32;

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
const size_t SHA256_BLOCK_SIZE = 64; 

uint64_t get_high_res_time() {
    return esp_timer_get_time();
}

void hmac_sha256_custom(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t* hmacResult) {
    uint8_t K_ipad[SHA256_BLOCK_SIZE];
    uint8_t K_opad[SHA256_BLOCK_SIZE];
    uint8_t innerHash[SHA256_OUTPUT_LEN];
    mbedtls_sha256_context ctx;

    // Prepare Padded Keys K_ipad and K_opad
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
        Serial.print("  Received Tag: 0x"); Serial.println(received_tag, HEX);
        Serial.print("  Calculated Tag: 0x"); Serial.println(calculated_tag, HEX);
        return false;
    }
}

void update_local_clock(int64_t offset_us) {
    // Get current time
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    // Convert microseconds offset to seconds and microseconds component
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
    Serial.print((float)offset_us / 1000.0, 3); // Print in milliseconds
    Serial.println(" ms");
}

void calculate_and_adjust(uint64_t T1, uint64_t T2, uint64_t T3, uint64_t T4) {
    // T_diff = T4 - T1
    int64_t T_diff = (int64_t)T4 - (int64_t)T1;

    // T_server_proc = T3 - T2
    int64_t T_server_proc = (int64_t)T3 - (int64_t)T2;

    // 1. Calculate Round Trip Delay (Delta): (T4-T1)-(T3-T2)
    int64_t delay_us = T_diff - T_server_proc;

    // (T2-T1) is Server's clock minus Client's clock, adjusted by path delay
    int64_t term1 = (int64_t)T2 - (int64_t)T1;
    // (T3-T4) is Server's clock minus Client's clock, adjusted by path delay
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
    current_seq_num++; // Increment sequence number
    
    PacketPayload requestPayload;
    
    // Populate header and sequence number
    memcpy(requestPayload.header, REQUEST_FLAG, HEADER_FLAG_LEN);
    requestPayload.seq_num = current_seq_num;
    
    requestPayload.T1 = T1;
    requestPayload.T2 = 0;
    requestPayload.T3 = 0; 
    
    // Calculate HMAC for the *outgoing* payload
    uint8_t hmac_Tag = calculate_hmac_tag((uint8_t*)&requestPayload, PAYLOAD_SIZE);

    // Construct the final request packet
    uint8_t fullRequest[PACKET_SIZE];
    memcpy(fullRequest, &requestPayload, PAYLOAD_SIZE);
    fullRequest[PAYLOAD_SIZE] = hmac_Tag;
    
    // 1. Begin Packet - Checks if connection/address is valid (returns 1 on success, 0 on failure)
    int begin_status = Udp.beginPacket(SERVER_IP, UDP_PORT);
    if (begin_status == 0) {
        Serial.println("[CRITICAL ERROR] UDP: Udp.beginPacket failed. Check target IP and Wi-Fi status.");
        return false;
    }
    
    // 2. Write Data - Check bytes written
    size_t bytesWritten = Udp.write(fullRequest, PACKET_SIZE);
    if (bytesWritten != PACKET_SIZE) {
        Serial.print("[CRITICAL ERROR] UDP: Udp.write failed. Expected ");
        Serial.print(PACKET_SIZE);
        Serial.print(", Wrote ");
        Serial.println(bytesWritten);
    }

    // 3. End Packet - Checks if transmission succeeded (returns 1 on success, 0 on failure)
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
            // Record T4: Client's time of arrival
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
            
            // Security Check (HMAC)
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

void setup() {
    Serial.begin(115200);

    // Convert server IP string to IPAddress object
    SERVER_IP.fromString(SERVER_IP_STR);
    
    // Wi-Fi Connection (Open Network)
    Serial.print("Connecting to open SSID: ");
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
}

void loop() {
    
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Lost Wi-Fi connection, attempting reconnect...");
        WiFi.begin(WIFI_SSID);
        delay(5000); 
        return;
    }

    // Check if it's time to synchronize
    if (millis() - last_sync_time_ms >= SYNC_INTERVAL_MS) {
        last_sync_time_ms = millis();
        
        // Define storage for the four timestamps
        uint64_t T1, T2 = 0, T3 = 0, T4 = 0;
        
        // T1 = get_high_res_time()
        T1 = get_high_res_time();
        
        // send_request()
        if (send_request(T1)) {
            // Reply_result = receive_reply()
            if (receive_reply(current_seq_num, T1, T2, T3, T4)) {
                // calculate_and_adjust()
                calculate_and_adjust(T1, T2, T3, T4);
            }
        }
    }
    
    // Yield to other tasks
    delay(10); 
}