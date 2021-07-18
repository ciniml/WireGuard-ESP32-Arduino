/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"

extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
}

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

#define TAG "WireGuard"

void WireGuard::begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort) {
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
	ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 255);
	ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);

	assert(privateKey != NULL);
	assert(remotePeerAddress != NULL);
	assert(remotePeerPublicKey != NULL);
	assert(remotePeerPort != 0);

	// Setup the WireGuard device structure
	wg.private_key = privateKey;
    wg.listen_port = remotePeerPort;
	
	wg.bind_netif = NULL;

	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(wg_netif);

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(&peer);
	peer.public_key = remotePeerPublicKey;
	peer.preshared_key = NULL;
	// Allow all IPs through tunnel
    {
        ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_mask = allowed_mask;
    }
	// If we know the endpoint's address can add here
    {
        ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        struct addrinfo *res = NULL;
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));
        ESP_ERROR_CHECK(lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) == 0 ? ESP_OK : ESP_FAIL);
        struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
        inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        lwip_freeaddrinfo(res);

        peer.endpoint_ip = endpoint_ip;
        ESP_LOGI(TAG, "%s is %3d.%3d.%3d.%3d"
			, remotePeerAddress
            , (endpoint_ip.u_addr.ip4.addr >>  0) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >>  8) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff
            );
    }
	peer.endport_port = remotePeerPort;

    // Initialize the platform
    wireguard_platform_init();
	// Register the new WireGuard peer with the netwok interface
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
		// Start outbound connection to peer
        ESP_LOGI(TAG, "connecting wireguard...");
		wireguardif_connect(wg_netif, wireguard_peer_index);
		// Set default interface to WG device.
        netif_set_default(wg_netif);
	}
}