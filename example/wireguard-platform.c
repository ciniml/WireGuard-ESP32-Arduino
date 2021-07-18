#include "wireguard-platform.h"

#include <stdlib.h>
#include "crypto.h"
#include "lwip/sys.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h"

// This file contains a sample Wireguard platform integration

static struct mbedtls_ctr_drbg_context random_context;
static struct mbedtls_entropy_context entropy_context;

static int entropy_hw_random_source( void *data, unsigned char *output, size_t len, size_t *olen ) {
    esp_fill_random(output, len);
	*olen = len;
    return 0;
}

void wireguard_platform_init() {
	mbedtls_entropy_init(&entropy_context);
	mbedtls_ctr_drbg_init(&random_context);
	mbedtls_entropy_add_source(&entropy_context, entropy_hw_random_source, NULL, 134, MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_ctr_drbg_seed(&random_context, mbedtls_entropy_func, &entropy_context, NULL, 0);
}

void wireguard_random_bytes(void *bytes, size_t size) {
	uint8_t *out = (uint8_t *)bytes;
	mbedtls_ctr_drbg_random(&random_context, bytes, size);
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

// CHANGE THIS TO GET THE ACTUAL UNIX TIMESTMP IN MILLIS - HANDSHAKES WILL FAIL IF THIS DOESN'T INCREASE EACH TIME CALLED
void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	uint64_t millis = sys_now();

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
	uint32_t nanos = (millis % 1000) * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load() {
	return false;
}

