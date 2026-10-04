/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>
#include "esp_netif.h"

class WireGuard
{
private:
    bool _is_initialized = false;

public:
    esp_netif_t *netif();
    bool begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort);
    bool begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
};
