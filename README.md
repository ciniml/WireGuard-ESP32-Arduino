# WireGuard Implementation for lwIP

This project is a C implementation of the [WireGuard protocol](https://www.wireguard.com) intended to be used with the [lwIP IP stack](https://www.nongnu.org/lwip/)

# Motivation

There is a desire to use secure communication in smaller embedded devices to communicate with off-premises devices; WireGuard seems perfect for this task due to its small code base and secure nature

This project tackles the problem of using WireGuard on embedded systems in that it is:
- malloc-free so fits into a fixed RAM size
- written entirely in C
- has low memory requirements in terms of stack size, flash storage and RAM
- compatible with the popular lwIP IP stack

# Code Layout

The code is split into four main portions

- wireguard.c contains the bulk of the WireGuard protocol code and is not specific to any particular IP stack
- wireguardif.c contains the lwIP integration code and makes a netif network interface and handles periodic tasks such as keepalive/xpiration timers
- wireguard-platform.h contains the definition of the four functions to be implemented per platform (a sample implementation is given in wireguard-platform.sample)
- crypto code (see below)

## Crypto Code

The supplied cryptographic routines are written entirely in C and are not optimised for any particular platform. These work and use little memory but will probably be slow on your platform.
You probably want to swap them out for optimised C or assembly versions

The crypto routines are:
- BLAKE2S - adapted from the implementation in the RFC itself at https://tools.ietf.org/html/rfc7693
- CHACHA20 - adapted from code at https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
- HCHACHA20 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- POLY1305 - taken from https://github.com/floodyberry/poly1305-donna
- CHACHA20POLY1305 - implemented from scratch following description here https://tools.ietf.org/html/rfc7539
- AEAD_XChaCha20_Poly1305 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- X25519 - taken from STROBE prject at https://sourceforge.net/p/strobe

# Integrating into your platform

You will need to implement a platform file that provides four functions
- a monotonic counter used for calculating time differences - e.g. sys_now() from lwIP
- a tain64n timestamp function, although there are workarounds if you don't have access to a realtime clock
- an indication of whether the system is currently under load and should generate cookie reply messages
- a good random number generator

# More Information

Wireguard was created and developed by Jason A. Donenfeld. See https://www.wireguard.com/ for more information

- The whitepaper https://www.wireguard.com/papers/wireguard.pdf
- The Wikipedia page https://en.wikipedia.org/wiki/WireGuard 

# License

The code is copyrighted under BSD 3 clause Copyright (c) 2021 Daniel Hope (www.floorsense.nz)

See LICENSE for details

# Contact

Daniel Hope at Smartalock
