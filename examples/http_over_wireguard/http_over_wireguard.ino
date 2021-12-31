#include <WiFi.h>
#include <WireGuard-ESP32.h>

// WiFi configuration --- UPDATE this configuration for your WiFi AP
char ssid[] = "MyWifiESSID";
char password[] = "my-wifi-password";

// WireGuard configuration --- UPDATE this configuration from JSON
char private_key[] = "gH2YqDa+St6x5eFhomVQDwtV1F0YMQd3HtOElPkZgVY=";
IPAddress local_ip(10, 217, 59, 2);
char public_key[] = "X6NJW+IznvItD3B5TseUasRPjPzF0PkM5+GaLIjdBG4=";
char endpoint_address[] = "192.168.178.133"; // IP of Wireguard endpoint to connect to.
int endpoint_port = 19628;

static WireGuard wg;
static HTTPClient httpClient;

void setup()
{
    Serial.begin(115200);
    Serial.println("Connecting to the AP...");
    WiFi.begin(ssid, password);
    while( !WiFi.isConnected() ) {
        delay(100);
    }
    Serial.println(WiFi.localIP());
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

    /**
     * Connect to
     * python3 -m http.server
     */
    if( !client.connect("10.217.59.1", 8000) ) {
        Serial.println("Failed to connect...");
        delay(1000);
        return;
    } else { // Client connected successfully. Send dummy HTTP request.
        client.write("GET /wireguard-test HTTP/1.1\r\n");
        client.write("Host: wireguard.test.com\r\n");
        client.write("\r\n\r\n");
    }

}
