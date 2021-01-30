# WireGuard Implementation for lwIP

This project is a C implementation of the [WireGuard&reg;](https://www.wireguard.com/) protocol intended to be used with the [lwIP IP stack](https://www.nongnu.org/lwip/)

# Motivation

There is a desire to use secure communication in smaller embedded devices to communicate with off-premises devices; WireGuard&reg; seems perfect for this task due to its small code base and secure nature

This project tackles the problem of using WireGuard&reg; on embedded systems in that it is:
- malloc-free so fits into a fixed RAM size
- written entirely in C
- has low memory requirements in terms of stack size, flash storage and RAM
- compatible with the popular lwIP IP stack

# Code Layout

The code is split into four main portions

- wireguard.c contains the bulk of the WireGuard&reg; protocol code and is not specific to any particular IP stack
- wireguardif.c contains the lwIP integration code and makes a netif network interface and handles periodic tasks such as keepalive/expiration timers
- wireguard-platform.h contains the definition of the four functions to be implemented per platform (a sample implementation is given in wireguard-platform.sample)
- crypto code (see below)

## Crypto Code

The supplied cryptographic routines are written entirely in C and are not optimised for any particular platform. These work and use little memory but will probably be slow on your platform.

You probably want to swap out the suplied versions for optimised C or assembly versions or those available throught the O/S or crypto libraries on your platform. Simply edit the crypto.h header file to point at the routines you want to use.

The crypto routines supplied are:
- BLAKE2S - adapted from the implementation in the RFC itself at https://tools.ietf.org/html/rfc7693
- CHACHA20 - adapted from code at https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
- HCHACHA20 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- POLY1305 - taken from https://github.com/floodyberry/poly1305-donna
- CHACHA20POLY1305 - implemented from scratch following description here https://tools.ietf.org/html/rfc7539
- AEAD_XChaCha20_Poly1305 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- X25519 - taken from STROBE project at https://sourceforge.net/p/strobe, in addition there is a version optimised for Cortex-M0 processors which requires very little stack taken from https://munacl.cryptojedi.org/curve25519-cortexm0.shtml

# Integrating into your platform

You will need to implement a platform file that provides four functions
- a monotonic counter used for calculating time differences - e.g. sys_now() from lwIP
- a tain64n timestamp function, although there are workarounds if you don't have access to a realtime clock
- an indication of whether the system is currently under load and should generate cookie reply messages
- a good random number generator

# lwIP Code Example
(note error checking omitted)

    #include "wireguardif.h"
    
    static struct netif wg_netif_struct = {0};
    static struct netif *wg_netif = NULL;
    static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

    static void wireguard_setup() {
    	struct wireguard_interface wg;
    	struct wireguardif_peer peer;
    	ip_addr_t ipaddr = IPADDR4_INIT_BYTES(192, 168, 40, 10);
    	ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
    	ip_addr_t gateway = IPADDR4_INIT_BYTES(192, 168, 40, 1);

    	// Setup the WireGuard device structure
    	wg.private_key = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
    	wg.listen_port = 51820;
    	wg.bind_netif = NULL;

    	// Register the new WireGuard network interface with lwIP
    	wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

    	// Mark the interface as administratively up, link up flag is set automatically when peer connects
    	netif_set_up(wg_netif);

    	// Initialise the first WireGuard peer structure
    	wireguardif_peer_init(&peer);
    	peer.public_key = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";
    	peer.preshared_key = NULL;
    	// Allow all IPs through tunnel
    	peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    	peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);

    	// If we know the endpoint's address can add here
    	peer.endpoint_ip = IPADDR4_INIT_BYTES(10, 0, 0, 12);
    	peer.endport_port = 12345;

    	// Register the new WireGuard peer with the netwok interface
    	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

    	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
    		// Start outbound connection to peer
    		wireguardif_connect(wg_net, wireguard_peer_index);
    	}
    }


# More Information

WireGuard&reg; was created and developed by Jason A. Donenfeld. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. See https://www.wireguard.com/ for more information

This project is not approved, sponsored or affiliated with WireGuard or with the community.

- The whitepaper https://www.wireguard.com/papers/wireguard.pdf
- The Wikipedia page https://en.wikipedia.org/wiki/WireGuard 

# License

The code is copyrighted under BSD 3 clause Copyright (c) 2021 Daniel Hope (www.floorsense.nz)

See LICENSE for details

# Contact

Daniel Hope at Smartalock
