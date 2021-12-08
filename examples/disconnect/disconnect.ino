#include <WiFi.h>
#include <WireGuard-ESP32.h>
#include <WiFiUdp.h>

// WiFi configuration --- UPDATE this configuration for your WiFi AP
char ssid[] = "ssid";
char password[] = "password";

// WireGuard configuration --- UPDATE this configuration from JSON
char private_key[] = "(Private Key) ";  // [Interface] PrivateKey
IPAddress local_ip(1,2,3,4);            // [Interface] Address
char public_key[] = "(Public Key)";     // [Peer] PublicKey
char endpoint_address[] = "link.arc.soracom.io";    // [Peer] Endpoint
int endpoint_port = 11010;              // [Peer] Endpoint

const char host_inside_vpn[] = "10.0.0.1";
const char host_outside_vpn[] = "192.168.2.1";

static constexpr const uint32_t UPDATE_INTERVAL_MS = 5000;

static WireGuard wg;

void setup()
{
    esp_log_level_set("*", ESP_LOG_DEBUG);
    
    Serial.begin(115200);
    Serial.println("Connecting to the AP...");
    WiFi.begin(ssid, password);
    while( !WiFi.isConnected() ) {
        delay(1000);
    }
    
    Serial.println("Adjusting system time...");
    configTime(9 * 60 * 60, 0, "ntp.jst.mfeed.ad.jp", "ntp.nict.jp", "time.google.com");

    Serial.println("WiFi Connected.");
}

void loop()
{
    static uint64_t send_count = 0;
    static uint64_t loop_count = 0;
    if( loop_count % 5 == 0) {
        if( !wg.is_initialized() ) {
            Serial.println("Initializing WG interface...");
            if( !wg.begin(
                    local_ip,
                    private_key,
                    endpoint_address,
                    public_key,
                    endpoint_port) ) {
                Serial.println("Failed to initialize WG interface.");
            }
        }
        else {
            Serial.println("Shutting down WG interface...");
            wg.end();
        }
    }
    loop_count++;

    WiFiUDP client;
    const char* host = wg.is_initialized() ? host_inside_vpn : host_outside_vpn;
    if( !client.beginPacket(host, 23080) ) {
        Serial.println("Failed to begin packet...");
        delay(5000);
        return;
    }

    uint64_t uptime_msec = millis();
    uint8_t buffer[16];
    buffer[ 0] = (uptime_msec >>  0) & 0xff;
    buffer[ 1] = (uptime_msec >>  8) & 0xff;
    buffer[ 2] = (uptime_msec >> 16) & 0xff;
    buffer[ 3] = (uptime_msec >> 24) & 0xff;
    buffer[ 4] = (uptime_msec >> 32) & 0xff;
    buffer[ 5] = (uptime_msec >> 40) & 0xff;
    buffer[ 6] = (uptime_msec >> 48) & 0xff;
    buffer[ 7] = (uptime_msec >> 56) & 0xff;
    buffer[ 8] = (send_count  >>  0) & 0xff;
    buffer[ 9] = (send_count  >>  8) & 0xff;
    buffer[10] = (send_count  >> 16) & 0xff;
    buffer[11] = (send_count  >> 24) & 0xff;
    buffer[12] = (send_count  >> 32) & 0xff;
    buffer[13] = (send_count  >> 40) & 0xff;
    buffer[14] = (send_count  >> 48) & 0xff;
    buffer[15] = (send_count  >> 56) & 0xff;

    Serial.printf("Sending uptime %lu [ms], count=%d\r\n", uptime_msec, send_count);
    client.write(buffer, sizeof(buffer));
    client.endPacket();

    send_count++;

    IPAddress result;
    if( WiFi.hostByName("www.google.com", result) ) {
        Serial.printf("hostByName: %s\r\n", result.toString().c_str());
    }
    else {
        Serial.printf("hostByName failed\r\n");
    }

    delay(UPDATE_INTERVAL_MS);
}
