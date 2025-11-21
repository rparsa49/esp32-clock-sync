# COSC 160 - Secure ESP32 Clock Synchronization

This project implements a secure time-synchronization protocol between two ESP32 micro-controllers over Wi-Fi and UDP.

- The **server ESP32** acts as a Wi-Fi Access Point and time server.
- The **client ESP32** connects to the server ESP32's Access Point, performs an authenticated handshake, and then periodically synchronizes it's local clock to the server.

Both handshake and sync packets are integrity-protected with an HMAC-SHA256 tag derived from a shared root key and per-session nonces.

---

## File Structure

- `server.ino`  
  ESP32 code that:
  - Starts a Wi-Fi AP (`ESP32_AP` / `12345678`)
  - Listens for handshake and sync packets over UDP port `12345`
  - Derives a per-session HMAC key
  - Responds to sync requests with server timestamps

- `client.ino`  
  ESP32 code that:
  - Connects to the server’s AP as a Wi-Fi station
  - Performs an authenticated handshake with the server
  - Periodically sends sync requests and receives replies
  - Computes network delay and clock offset
  - **Adjusts the client ESP32’s system clock** using `settimeofday()` when an offset is detected

---

## Hardware & Software Requirements

- 2 × ESP32 micro-controllers
- Arduino IDE (or PlatformIO) with ESP32 support installed
- Serial monitor (e.g., Arduino Serial Monitor) at **115200 baud**

---

## Platform Notes

### Windows-specific setup

On Windows, the ESP32 board may not show up in the Arduino IDE **Port** menu until the
USB-to-UART driver is installed.

Most ESP32 dev boards use one of these USB chips:

- **CP210x** (Silicon Labs)  
- **CH340** (WCH)  

If the board is not visible under **Tools → Port**, install the appropriate driver for
your board (check the silkscreen on the board or the vendor’s product page):

- For CP210x: install the “CP210x USB to UART Bridge VCP” driver from Silicon Labs. (this is the one that we downloaded) 
- For CH340: install the CH340 USB-Serial driver from WCH.

After installing the driver:

1. Unplug and re-plug the ESP32.
2. Reopen Arduino IDE (if needed).
3. Select the new **COMx** entry under **Tools → Port**.

#### Uploading on Windows (BOOT button)

On **Windows**, we reliably had to use the ESP32’s **BOOT** button when uploading:

1. Connect ESP32 via USB.
2. In Arduino IDE, click **Upload**.
3. When the status bar says **“Connecting…”**, press and **hold the BOOT button**.
4. Release BOOT once you see the upload progress (…% bar) or “Writing at 0x…”.

If you do not hold BOOT during the “Connecting…” phase on Windows, the board may fail
to enter download mode and you can see errors like `Failed to connect to ESP32: Timed out waiting for packet header`.

#### Uploading on macOS

On **macOS**, the ESP32 usually enters bootloader mode automatically and **does not
require holding BOOT**. You can typically:

1. Plug in the ESP32.
2. Select the `/dev/cu.usbserial-*` or `/dev/cu.SLAB_USBtoUART` port.
3. Click **Upload** and wait for it to complete.

If uploads fail on macOS, pressing **EN/RESET** once when “Connecting…” appears can
sometimes help, but we generally did **not** need to hold BOOT on macOS.

---

## Network & Security Parameters

These are defined at the top of both files:

- **Wi-Fi**
  - AP SSID (server): `ESP32_AP`
  - AP password: `12345678`
  - UDP port: `12345`
  - Server IP (from client’s perspective): `192.168.4.1`

- **Crypto**
  - Root key (pre-shared): `"cosc160"`
  - Session key length: 16 bytes (first 16 bytes of SHA-256 output)
  - HMAC tag: **HMAC-8** (first byte of full HMAC-SHA256)
 
If needed, these can be changed in the `#define`/`const` section at the top of each file.

---

## Protocol Overview

### 1. Handshake (Session Key Establishment)

Performed once when the client starts (or after failures).

1. **Client → Server (HS_INIT)**  
   - Client generates random 32-bit `clientNonce`.  
   - Builds `HS_INIT` payload: header `"HS_INIT"` + `clientNonce`.  
   - Computes HMAC-SHA256 over this payload with the **root key** and sends  
     `HS_INIT payload || HMAC[0]` (HMAC-8).

2. **Server validates & responds (HS_RESP)**  
   - Checks header `"HS_INIT"` and verifies HMAC with the root key.  
   - Generates random 32-bit `serverNonce`.  
   - Derives **session key** = SHA-256(`ROOT_KEY || clientNonce || serverNonce`), uses first 16 bytes.  
   - Builds `HS_RESP` payload: header `"HS_RESP"` + echoed `clientNonce` + `serverNonce`.  
   - Adds HMAC (root key, HMAC-8) and sends `HS_RESP payload || HMAC[0]`.

3. **Client validates & derives session key**  
   - Verifies header `"HS_RESP"`, HMAC (root key), and echoed `clientNonce`.  
   - Derives the same session key using (`ROOT_KEY, clientNonce, serverNonce`).  
   - Sets `handshakeComplete = true` and `sessionKeyReady = true`.

From this point on, **all sync packets** are authenticated with HMAC using the session key.

### 2. Secure Sync Exchange

Periodically (every `SYNC_INTERVAL_MS = 10000` ms) the client and server perform a 4-timestamp exchange.

**Packet payload (both directions):**

```c
struct PacketPayload {
    char header[HEADER_FLAG_LEN];   // "REQUESTSYNC"
    uint32_t seq_num;               // Sequence number
    uint64_t T1;                    // Client send time (request)
    uint64_t T2;                    // Server receive time
    uint64_t T3;                    // Server send time
};

```

The on-wire packet is payload || HMAC_TAG, where HMAC_TAG is 1 byte (HMAC-8).

1. **Client → Server (request)**
    - Increments current_seq_num.
    - Records T1 = esp_timer_get_time().
    - Builds payload with header "REQUESTSYNC", seq_num = current_seq_num, T1 = T1, and T2 = T3 = 0.
    - Computes HMAC-SHA256 over the payload with the session key, uses first byte as tag.
    - Sends the packet over UDP.

2. **Server → Client (reply)**
    - On a packet of expected size, records T2 = esp_timer_get_time() (arrival).
    - Verifies header and HMAC (session key); discards if invalid.
    - Records T3 = esp_timer_get_time() (departure).
    - Builds reply payload with header "REQUESTSYNC", seq_num (server uses request.seq_num + 1), and timestamps T1, T2, T3.
    - Adds HMAC (session key, HMAC-8) and sends back.

3. **Client processes reply & adjusts clock**
    - Records T4 = esp_timer_get_time() on receipt.
    - Verifies header, sequence number, and HMAC (session key).
    - If valid, calls:
      - calculate_and_adjust(T1, T2, T3, T4);
      - calculate_and_adjust computes network delay and clock offset using an NTP-style formula and, if offset_us != 0, calls:
      - update_local_clock(offset_us);
      - update_local_clock uses gettimeofday and settimeofday to adjust the client ESP32’s own system time.

---

## How to Run the Demo

1. **Server ESP32**
   - Open server.ino in Arduino IDE.
   - Select your ESP32 board and the correct serial port.
   - Upload the sketch (use BOOT / EN as needed per platform notes above).
   - Open Serial Monitor at 115200 baud.
   - You should see messages indicating:
     - AP started (ESP32_AP)
     - UDP server listening “Waiting for handshake (HS_INIT) from client…”

2. **Client ESP32**
   - Open client.ino on the second ESP32.
   - Ensure WIFI_SSID, PASSPHRASE, and SERVER_IP_STR match the server.
   - Select board and port, then upload.
   - Open Serial Monitor at 115200 baud.
   - You should see:
     - Connection to ESP32_AP
     - Handshake logs (HS_INIT / HS_RESP, session key derived)
     - Periodic sync logs every ~10 seconds:
       - Request/response logs
       - Printed delay and offset
         - “Clock Adjusted by … ms” when the offset is non-zero
