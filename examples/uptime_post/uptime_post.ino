#include <WiFi.h>
#include <WireGuard-ESP32.h>
#include <HTTPClient.h>

// WiFi configuration --- UPDATE this configuration for your WiFi AP
char ssid[] = "ssid";
char password[] = "password";

// WireGuard configuration --- UPDATE this configuration from JSON
char private_key[] = "(Private Key) ";  // [Interface] PrivateKey
IPAddress local_ip(1,2,3,4);            // [Interface] Address
char public_key[] = "(Public Key)";     // [Peer] PublicKey
char endpoint_address[] = "link.arc.soracom.io";    // [Peer] Endpoint
int endpoint_port = 11010;              // [Peer] Endpoint

static constexpr const uint32_t UPDATE_INTERVAL_MS = 5000;

static WireGuard wg;
static HTTPClient httpClient;

void setup()
{
    Serial.begin(115200);
    Serial.println("Connecting to the AP...");
    WiFi.begin(ssid, password);
    while( !WiFi.isConnected() ) {
        delay(1000);
    }
    Serial.println("Adjusting system time...");
    configTime(9 * 60 * 60, 0, "ntp.jst.mfeed.ad.jp", "ntp.nict.jp", "time.google.com");

    Serial.println("Connected. Initializing WireGuard...");
    wg.begin(
        local_ip,
        private_key,
        endpoint_address,
        public_key,
        endpoint_port);
}

void loop()
{
    WiFiClient client;

    if( !client.connect("uni.soracom.io", 80) ) {
        Serial.println("Failed to connect...");
        delay(5000);
        return;
    }
    
    uint64_t uptime_msec = millis();
    Serial.printf("Sending uptime %lu [ms]\r\n", uptime_msec);
    String json;
    json += "{\"uptime_msec\":";
    json.concat(static_cast<unsigned long>(uptime_msec));
    json += "}";
    Serial.printf("payload: %s\r\n", json.c_str());
    
    client.write("POST / HTTP/1.1\r\n");
    client.write("Host: harvest.soracom.io\r\n");
    client.write("Connection: Keep-Alive\r\n");
    client.write("Keep-Alive: timeout=5, max=2\r\n");
    client.write("Content-Type: application/json\r\n");
    client.write("Content-Length: ");
    client.write(String(json.length(), 10).c_str());
    client.write("\r\n\r\n");
    client.write(json.c_str());

    while(client.connected()) {
        auto line = client.readStringUntil('\n');
        Serial.write(line.c_str());
        Serial.write("\n");
        if( line == "\r" ) break;
    }
    if(client.connected()) {
        uint8_t buffer[256];
        size_t bytesToRead = 0;
        while((bytesToRead = client.available()) > 0) {
            bytesToRead = bytesToRead > sizeof(buffer) ? sizeof(buffer) : bytesToRead;
            auto bytesRead = client.readBytes(buffer, bytesToRead); 
            Serial.write(buffer, bytesRead);
        }
    }
    delay(UPDATE_INTERVAL_MS);
}
