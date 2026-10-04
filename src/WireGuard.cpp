/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif_types.h"
#include "esp_netif_net_stack.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/esp_netif_net_stack.h"
#include "lwip/netif.h"
#include "lwip/opt.h"
#include "lwip/netdb.h"
#include "lwip/tcpip.h"

#include "esp32-hal-log.h"

extern "C"
{
#include "wireguardif.h"
#include "wireguard-platform.h"
}

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static esp_netif_t *wg_esp_netif = NULL;
static struct netif *previous_default_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

#define TAG "[WireGuard] "

typedef struct
{
	esp_netif_driver_base_t base;
	struct netif *lwip_nif;
} wg_driver_glue_t;

static err_t wg_lwip_init(netif *netif)
{
	return ERR_OK;
}

static void wg_lwip_input(void *h, void *buffer, size_t len, void *eb)
{
	if (buffer)
	{
		pbuf_free((struct pbuf *)buffer);
	}
}

static esp_err_t wg_driver_transmit(void *h, void *buffer, size_t len)
{
	log_w(TAG "wg_driver_transmit called unexpectedly, len=%u", (unsigned)len);
	esp_netif_free_rx_buffer(h, buffer);

	return ESP_OK;
}

static void wg_driver_free_rx(void *h, void *buffer) {}

static esp_err_t wg_post_attach(esp_netif_t *esp_netif, void *args)
{
	wg_driver_glue_t *glue = (wg_driver_glue_t *)args;
	const esp_netif_driver_ifconfig_t ifc = {
			.handle = glue,
			.transmit = wg_driver_transmit,
			.driver_free_rx_buffer = wg_driver_free_rx,
	};
	esp_netif_set_driver_config(esp_netif, &ifc);
	glue->base.netif = esp_netif;

	return ESP_OK;
}

/* ------------------------------------------------------------- */
static wg_driver_glue_t *create_wg_glue(struct netif *lwip)
{
	auto *g = (wg_driver_glue_t *)calloc(1, sizeof(wg_driver_glue_t));
	g->base.post_attach = wg_post_attach;
	g->lwip_nif = lwip;
	return g;
}

// Resolve the underlying (transport) netif that WireGuard packets are sent over.
// Prefer the current default-route interface so the tunnel works over whatever
// underlay is active (WiFi STA, Ethernet, or cellular/PPP), and fall back to the
// WiFi station interface by if-key for backward compatibility. Must be called
// before the WG netif becomes the default interface (i.e. before netif_add /
// netif_set_default) and without holding the TCPIP core lock, since esp_netif
// APIs acquire that lock internally.
static struct netif *resolve_underlying_netif()
{
	struct netif *underlay = netif_default;
	if (underlay != NULL)
	{
		return underlay;
	}

	esp_netif_t *handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
	if (handle != NULL)
	{
		char impl_name[8] = {0};
		if (esp_netif_get_netif_impl_name(handle, impl_name) == ESP_OK)
		{
			underlay = netif_find(impl_name);
		}
	}
	return underlay;
}

bool WireGuard::begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort)
{
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
	ip_addr_t netmask = IPADDR4_INIT(static_cast<uint32_t>(Subnet));
	ip_addr_t gateway = IPADDR4_INIT(static_cast<uint32_t>(Gateway));

	assert(privateKey != NULL);
	assert(remotePeerAddress != NULL);
	assert(remotePeerPublicKey != NULL);
	assert(remotePeerPort != 0);

	// Setup the WireGuard device structure
	wg.private_key = privateKey;
	wg.listen_port = remotePeerPort;

	// Resolve the underlying transport interface up front (no TCPIP core lock
	// held here) and pass it to wireguardif_init via bind_netif.
	wg.bind_netif = resolve_underlying_netif();
	if (wg.bind_netif == NULL)
	{
		log_e(TAG "failed to resolve underlying netif. Is the network up?");
		return false;
	}

	// Initialize the first WireGuard peer structure
	wireguardif_peer_init(&peer);

	// Initialize the platform (seeds the CTR-DRBG used for key generation)
	if (!wireguard_platform_init())
	{
		log_e(TAG "failed to initialize crypto RNG.");
		return false;
	}

	// If we know the endpoint's address can add here
	bool success_get_endpoint_ip = false;
	for (int retry = 0; retry < 5; retry++)
	{
		ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		struct addrinfo *res = NULL;
		struct addrinfo hint;
		memset(&hint, 0, sizeof(hint));
		memset(&endpoint_ip, 0, sizeof(endpoint_ip));
		if (lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) != 0)
		{
			vTaskDelay(pdMS_TO_TICKS(2000));
			continue;
		}
		success_get_endpoint_ip = true;
		struct in_addr addr4 = ((struct sockaddr_in *)(res->ai_addr))->sin_addr;
		inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
		lwip_freeaddrinfo(res);

		peer.endpoint_ip = endpoint_ip;
		log_i(TAG "%s is %3d.%3d.%3d.%3d", remotePeerAddress, (endpoint_ip.u_addr.ip4.addr >> 0) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 8) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff);
		break;
	}
	if (!success_get_endpoint_ip)
	{
		log_e(TAG "failed to get endpoint ip.");
		return false;
	}

	LOCK_TCPIP_CORE();
	// Register the new WireGuard network interface with lwIP
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);
	UNLOCK_TCPIP_CORE();
	if (wg_netif == nullptr)
	{
		log_e(TAG "failed to initialize WG netif.");
		return false;
	}

	esp_netif_inherent_config_t inh = ESP_NETIF_INHERENT_DEFAULT_ETH();
	inh.flags = (esp_netif_flags_t)(ESP_NETIF_FLAG_AUTOUP);
	inh.route_prio = 20;
	inh.get_ip_event = 0;
	inh.lost_ip_event = 0;
	inh.if_key = "WG_DEF";
	inh.if_desc = "wg";

	static const esp_netif_netstack_config_t wg_netstack = {
			.lwip = {
					.init_fn = wg_lwip_init,
					.input_fn = wg_lwip_input,
			}};
	esp_netif_config_t cfg = {
			.base = &inh,
			.driver = nullptr,
			.stack = &wg_netstack,
	};

	wg_esp_netif = esp_netif_new(&cfg);
	if (!wg_esp_netif)
	{
		log_w(TAG "esp_netif_new failed");
		return false;
	}

	// DHCP client is not stopped by default; ignore ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED.
	esp_netif_dhcpc_stop(wg_esp_netif);
	wg_driver_glue_t *wg_glue = create_wg_glue(wg_netif);
	esp_err_t attach_err = esp_netif_attach(wg_esp_netif, wg_glue);
	if (attach_err != ESP_OK)
	{
		log_w(TAG "esp_netif_attach failed: %s", esp_err_to_name(attach_err));
	}

	ip_event_got_ip_t evt = {};
	evt.esp_netif = wg_esp_netif;
	evt.ip_changed = true;
	evt.ip_info.ip.addr = ipaddr.u_addr.ip4.addr;
	evt.ip_info.gw.addr = gateway.u_addr.ip4.addr;
	evt.ip_info.netmask.addr = netmask.u_addr.ip4.addr;

	esp_err_t ipinfo_err = esp_netif_set_ip_info(wg_esp_netif, &evt.ip_info);
	if (ipinfo_err != ESP_OK)
	{
		log_w(TAG "esp_netif_set_ip_info failed: %s", esp_err_to_name(ipinfo_err));
	}
	esp_netif_action_connected(wg_esp_netif, NULL, 0, NULL);

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	LOCK_TCPIP_CORE();
	netif_set_up(wg_netif);
	netif_set_link_up(wg_netif);
	UNLOCK_TCPIP_CORE();

	peer.public_key = remotePeerPublicKey;
	peer.preshared_key = NULL;
	// Allow all IPs through tunnel
	{
		ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		peer.allowed_ip = allowed_ip;
		ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
		peer.allowed_mask = allowed_mask;
	}

	peer.endport_port = remotePeerPort;

	// Register the new WireGuard peer with the network interface.
	// The periodic timer (wireguardif_tmr) runs in the tcpip thread and reads
	// the same peer state, so hold the TCPIP core lock while mutating peers to
	// avoid a data race. wireguardif_add_peer()/wireguardif_connect() only touch
	// the device/peer structs (no lwIP core calls), so this does not recurse.
	LOCK_TCPIP_CORE();
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip))
	{
		// Start outbound connection to peer
		log_i(TAG "connecting wireguard...");
		wireguardif_connect(wg_netif, wireguard_peer_index);
		// Save the current default interface for restoring when shutting down the WG interface.
		previous_default_netif = netif_default;
		// Set default interface to WG device.
		netif_set_default(wg_netif);
	}
	UNLOCK_TCPIP_CORE();

	this->_is_initialized = true;
	return true;
}

esp_netif_t *WireGuard::netif()
{
	return wg_esp_netif;
}

bool WireGuard::begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort)
{
	// Maintain compatiblity with old begin
	auto subnet = IPAddress(255, 255, 255, 255);
	auto gateway = IPAddress(0, 0, 0, 0);
	return WireGuard::begin(localIP, subnet, gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort);
}

void WireGuard::end()
{
	if (!this->_is_initialized)
		return;

	LOCK_TCPIP_CORE();
	// Restore the default interface.
	netif_set_default(previous_default_netif);
	previous_default_netif = nullptr;
	// Disconnect the WG interface.
	wireguardif_disconnect(wg_netif, wireguard_peer_index);
	// Remove peer from the WG interface
	wireguardif_remove_peer(wg_netif, wireguard_peer_index);
	wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
	// Shutdown the wireguard interface.
	wireguardif_shutdown(wg_netif);
	// Remove the WG interface;
	netif_remove(wg_netif);
	UNLOCK_TCPIP_CORE();

	// esp_netif_destroy() acquires the TCPIP core lock internally, so it must
	// be called outside of the LOCK_TCPIP_CORE()/UNLOCK_TCPIP_CORE() section.
	esp_netif_destroy(wg_esp_netif);

	wg_netif = nullptr;
	wg_esp_netif = nullptr;
	this->_is_initialized = false;
}